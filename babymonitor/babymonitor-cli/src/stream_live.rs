//! `babymonitor-cli stream` — the assembled **LIVE** A/V driver (gated under
//! `--features live`).
//!
//! This is the ONE driver that wires the full pipeline end-to-end with the real
//! `babymonitor-core` building blocks:
//!
//! ```text
//! 1 auth        load the on-disk Session (sid/uid/ecode)            [offline-real]
//! 2 discovery   SCD921 devId + localKey + pv + p2pType(=4 WebRTC)   [owner-injected]
//! 3 mqtt creds  derive_credentials (clientId/username/password)     [offline-real]
//! 4 broker      RumqttcTransport TLS connect (live-tls, 8883)       [LIVE I/O]
//! 5 signaling   302 offer -> trickle -> answer (MqttSignalingSession) [LIVE I/O]
//! 6 ICE         host-direct UDP + connectivity check                [LIVE I/O]
//! 7 media       MediaEngine pump: suite-3 AES-128-CBC + 20B HMAC-SHA1
//!               / KCP / fixed-12B RTP -> H.264 (conv 1) + S16LE audio (conv 2)
//! 8 output      ffmpeg -> MPEG-TS over HTTP (vlc/mpv/ffplay)        [offline-real]
//! ```
//!
//! # Honest gating (never a fabricated stream)
//!
//! Stages 4–6 are the **unreachable live I/O** in this static-analysis sandbox:
//! there is no Tuya broker and no camera. The driver does NOT mock them with a
//! fake that pretends to stream — it reaches the real socket calls
//! ([`connect_and_negotiate`], [`mtransport::connect_host_direct`]) and surfaces
//! the honest failure. The runtime credentials those stages need (stage 2 + the
//! per-session MQTT/P2P secrets) come from the owner's live session, injected as a
//! gitignored `secrets/stream_runtime.json` bundle (the project's token-injectable
//! discipline). Absent that bundle, the driver returns [`Error::StreamPending`]
//! with a precise account of what is missing and which live API yields it.
//!
//! The media→output back half (stages 7–8) is the SAME code the offline
//! `--replay-annexb`/cap4 path proves byte-exact; only the live socket front half
//! is environmentally gated.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use babymonitor_core::session::{Session, SessionStore};
use babymonitor_core::stream::media::audio;
use babymonitor_core::stream::media::h264::H264Depacketizer;
use babymonitor_core::stream::media::stun::{self, IceRole};
use babymonitor_core::stream::media::transport::{
    self as mtransport, IceCredentials, MediaTransport,
};
use babymonitor_core::stream::media::MediaEngine;
use babymonitor_core::stream::mqtt_auth::{derive_credentials, MqttAuthInputs};
use babymonitor_core::stream::rtc_config::RtcConfig;
use babymonitor_core::stream::sdp::{build_offer_sdp, OfferSdpParams};
use babymonitor_core::stream::session::{
    NegotiationOutcome, OsRandom, RandomSource, SignalingFlow,
};
use babymonitor_core::stream::signaling::ParsedAnswer;
use babymonitor_core::stream::topics;
use babymonitor_core::stream::transport::{
    connect_and_negotiate, BrokerConfig, LiveSignalingParams,
};
use babymonitor_core::stream::StreamCredentials;
use babymonitor_core::Error;
use serde::Deserialize;

use crate::stream::{OutputMode, StreamArgs};

/// Default path of the owner-injected runtime bundle (gitignored).
const RUNTIME_BUNDLE: &str = "secrets/stream_runtime.json";

/// Bounded receive budget for the camera answer (phase 1), counted in POLLS (not
/// wall-time): a poll BLOCKS up to the transport's eventloop-drive window (~100 ms)
/// only when idle — any inbound frame (answer/candidate/heartbeat) returns it
/// sooner. So ≈ 60 s of *idle* wait, less under inbound traffic; generous for a
/// cloud-relayed answer from a camera waking from idle.
const MAX_ANSWER_POLLS: usize = 600;

/// Extra polls AFTER the answer to collect the camera's TRICKLED ICE candidates
/// (phase 2). The answer SDP carries none (cap3/cap4), so the host candidate the
/// media transport needs only arrives here. Poll count (≈ 30 s idle); see
/// TASK-0083 (early-exit once a host candidate is in hand to cut time-to-frame).
const TRICKLE_POLLS: usize = 300;

/// No extra sleep between 302 polls: the live transport's `recv_timeout` blocks
/// while driving the eventloop (it both flushes our publishes and waits for an
/// answer), so it already paces the loop. Offline tests pass `Duration::ZERO` too.
const SIGNALING_POLL_INTERVAL: Duration = Duration::ZERO;

/// How often to send an RFC 7675 consent-refresh STUN check on the media path.
const CONSENT_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Generous wait for the FIRST media datagram. Camera startup (encoder warm-up)
/// can exceed 20 s, so we do not give up on the session until this elapses with no
/// media at all (TASK-0077 AC#3).
const FIRST_MEDIA_TIMEOUT: Duration = Duration::from_secs(60);

/// Once media has started flowing, this much continuous silence means the session
/// ended (camera stopped / path lost) and we stop cleanly.
const STEADY_IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// Sleep between empty media-receive polls (keeps the loop responsive without
/// busy-spinning the UDP socket).
const MEDIA_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The owner-injected runtime credentials for ONE live stream session.
///
/// Every field is **per-session secret/PII** recovered from the account owner's
/// own live device session (see `re/live_stream_run.md` for the exact APIs). This
/// is NOT a fabricated wire format — it is precisely the set of runtime inputs the
/// core [`StreamCredentials`] / [`BrokerConfig`] / [`MqttAuthInputs`] types
/// already require, gathered into one gitignored file (the project's
/// token-injectable pattern). NO value is ever logged.
#[derive(Deserialize)]
struct StreamRuntime {
    /// The Tuya MQTT broker endpoint + 302 topics (login `baseConfig` + device id).
    broker: BrokerInputs,
    /// The SCD921 device record fields (`m.life.my.group.device.list`).
    device: DeviceInputs,
    /// The per-camera P2P config (`CameraInfoBean` / `rtc.config.get`).
    camera: CameraInputs,
    /// The MQTT CONNECT derivation inputs (`SdkMqttCertificationInfo` + master G).
    mqtt: MqttInputs,
}

#[derive(Deserialize)]
struct BrokerInputs {
    host: String,
    port: u16,
    #[serde(default = "default_true")]
    tls: bool,
    publish_topic: String,
    subscribe_topic: String,
    partner_identity: String,
}

#[derive(Deserialize)]
struct DeviceInputs {
    dev_id: String,
    local_key: String,
    #[serde(default = "default_pv")]
    pv: String,
    /// `skills.p2pType`; MUST be 4 (THING/WebRTC-over-MQTT) for this path.
    p2p_type: i32,
}

#[derive(Deserialize)]
struct CameraInputs {
    p2p_id: String,
    #[serde(default)]
    p2p_key: String,
    #[serde(default = "default_json_array")]
    ices: String,
    #[serde(default = "default_json_object")]
    session: String,
    token: String,
    #[serde(default = "default_json_object")]
    skill: String,
    /// `rtc.config p2pConfig.tcpRelay` (compact JSON) — echoed as the offer
    /// `msg.tcp_token`. Empty/absent ⇒ the offer omits it. (TASK-0080)
    #[serde(default)]
    tcp_relay: String,
    /// `rtc.config p2pConfig.log` (compact JSON) — passed through as the offer
    /// `msg.log`. Empty/absent ⇒ the offer omits it. (TASK-0080)
    #[serde(default)]
    log: String,
}

#[derive(Deserialize)]
struct MqttInputs {
    token: String,
    app_id: String,
    ch_key: String,
    /// Master key **G** as lowercase hex (`sign::assemble_master_key_g`).
    master_key_g_hex: String,
}

fn default_true() -> bool {
    true
}
fn default_pv() -> String {
    "2.2".to_string()
}
fn default_json_array() -> String {
    "[]".to_string()
}
fn default_json_object() -> String {
    "{}".to_string()
}

/// Entry point for the gated LIVE `stream` path. Assembles + drives the pipeline,
/// or returns an honest [`Error::StreamPending`] at the first unreachable gate.
///
/// # Errors
/// - [`Error::StreamPending`] when no session / no runtime bundle is injected
///   (the static-analysis-sandbox state), with a precise account of what is
///   missing.
/// - [`Error::Transport`]/[`Error::StreamConfig`] from a real live step (broker
///   connect, signaling, ICE) when the owner runs it for real and a step fails.
pub fn run_live_stream(args: &StreamArgs) -> Result<(), Error> {
    // ── Stage 1: auth (load the on-disk session) ───────────────────────────
    let store = SessionStore::default_path()?;
    let Some(session) = store.load()? else {
        return stream_pending_no_session();
    };
    eprintln!("stream (live): stage 1 auth — session present (sid/uid/ecode redacted).");

    // ── Stage 2: runtime bundle (device + per-camera + mqtt-auth inputs) ───
    // SELF-SUFFICIENT (TASK-0078): if no hand-written bundle is injected, AUTO-BUILD
    // it in-process from the session — fetch+decrypt rtc.config.get, derive the
    // broker host + 302 topics, and assemble the per-camera/mqtt inputs. The manual
    // bundle is still honored (back-compat / override).
    let bundle_path = PathBuf::from(RUNTIME_BUNDLE);
    let runtime = match load_runtime(&bundle_path)? {
        Some(rt) => {
            eprintln!(
                "stream (live): stage 2 — using the injected runtime bundle {}.",
                bundle_path.display()
            );
            rt
        }
        None => {
            eprintln!(
                "stream (live): stage 2 — no runtime bundle at {}; AUTO-BUILDING it in-process \
                 from the session (rtc.config.get + derived broker/topics, TASK-0078)…",
                bundle_path.display()
            );
            build_runtime_from_session(&session)?
        }
    };
    if runtime.device.p2p_type != 4 {
        return Err(Error::StreamConfig(format!(
            "device p2pType is {} — this WebRTC-over-MQTT path needs p2pType=4 (THING/WebRTC); \
             a p2pType=2 device uses the legacy PPCS transport (out of scope)",
            runtime.device.p2p_type
        )));
    }
    eprintln!(
        "stream (live): stage 2 discovery — SCD921 devId+localKey+pv loaded, p2pType=4 (WebRTC)."
    );

    // ── Stage 3: derive the MQTT CONNECT credentials (offline-real) ────────
    let mut broker = build_broker_config(&session, &runtime)?;
    eprintln!(
        "stream (live): stage 3 mqtt-creds — clientId/username/password derived (password redacted)."
    );

    // TASK-0080 AC#3: `--diag-topics` arms the 302 topic diagnostic. The camera
    // never answered on the RE-derived `smart/mb/in/<devId>` in live test #1; the
    // diagnostic ALSO subscribes the uid inbound + the user personal topic and logs
    // the EXACT topic + header.type of any inbound 302, so the real answer topic is
    // revealed live (devId vs uid vs personal). The env var is the core-layer switch
    // (read by both the transport subscribe + the poll_inbound type log).
    if args.diag_topics {
        std::env::set_var(babymonitor_core::stream::transport::WILDCARD_DIAG_ENV, "1");
        broker = broker.with_diag_topics(topics::diag_extra_topics(
            &runtime.device.dev_id,
            &runtime.camera.p2p_id,
        ));
        eprintln!(
            "stream (live): --diag-topics ARMED — strict subscribe stays '{}'; ALSO probing {:?} \
             + the inbound wildcard; each inbound 302 logs topic + header.type (bodies withheld).",
            broker.subscribe_topic, broker.diag_extra_topics
        );
    }

    // ── Stages 4-6: connect the broker, run 302 signaling, open ICE ────────
    // These touch real sockets — reached, not faked. In this sandbox there is no
    // broker/camera, so they return the honest failure (never a fake answer).
    let creds = build_stream_credentials(&runtime);
    creds.validate()?;
    let session_handles = SessionHandles::mint(&creds.dev_id)?;
    let offer = build_offer(&creds, &session_handles)?;
    eprintln!(
        "stream (live): stage 4-6 — connecting broker {}:{} (TLS={}), publishing 302 offer, awaiting answer…",
        broker.host, broker.port, broker.tls
    );

    let outcome = negotiate(&broker, &creds, &offer)?;
    let answer = &outcome.answer;
    eprintln!(
        "stream (live): answer received — remote ICE creds + media key extracted; {} trickled candidate(s) collected.",
        outcome.remote_candidates.len()
    );

    let ice = IceCredentials {
        local_ufrag: session_handles.ice_ufrag.clone(),
        local_pwd: session_handles.ice_pwd.clone(),
        remote_ufrag: answer.remote_ufrag.clone(),
        remote_pwd: answer.remote_pwd.clone(),
    };
    let (mut transport, host) =
        open_media_transport(answer, &outcome.remote_candidates, &ice, &session_handles)?;
    eprintln!(
        "stream (live): stage 6 ICE — host-direct UDP to {} (nomination check sent).",
        host.socket_addr()
    );

    // ── Stages 7-8: media pump -> H.264 + S16LE audio -> MPEG-TS output ────
    // Suite 3 (AES-128-CBC + 20B HMAC-SHA1) is the cap3/cap4-observed default; the
    // negotiated security_level rides the answer header (cap4 == 3).
    let mut engine = MediaEngine::from_security_level(3, answer.media_key.clone())?;
    // The consent/keepalive context: refresh OUR check ~every 5 s, and answer the
    // camera's inbound checks, so neither side's consent-to-send expires mid-stream.
    let keepalive = PathKeepalive::new(ice, &host)?;
    pump_to_output(args, &mut engine, &mut transport, &keepalive)
}

/// Mint the per-session local handles (ICE ufrag/pwd, media key, the unix-second
/// `o-session`, the 8-char sessionid random suffix, and the `trace_id`) the offer
/// needs, all shaped byte-faithfully to the cap3 offer (TASK-0080).
///
/// # cap3 byte shape (the live no-answer fix)
///
/// In the cap3 offer (`emulator_captures/cap3/signaling_plaintext.jsonl` msg 1):
/// - `header.sessionid` = `<devId><unix_seconds><8-char base62>`
///   (`bf3e…ufmo` + `1782489574` + `vhBJTOjV`),
/// - the SDP origin line `o=- <unix_seconds> 1 IN IP4 …` uses the **same**
///   `unix_seconds` that is embedded in the sessionid, and the SDP
///   `a=msid-semantic: WMS <sessionid>` repeats the full sessionid,
/// - `header.trace_id` = `<uuidv4>_<devId>_<unix_millis>`
///   (`53756d7d-…-afc21d3b9cc9_bf3e…ufmo_1782489573111`).
///
/// So [`SessionHandles::mint`] samples one wall-clock instant and derives
/// `o_session` (seconds), the sessionid suffix, and the trace_id (millis) from it,
/// rather than the previous random `o_session` + `<devId><trace_id>` sessionid
/// (which did not match the capture). The sessionid itself is assembled in
/// [`build_offer`] (it needs the `devId`).
struct SessionHandles {
    ice_ufrag: String,
    ice_pwd: String,
    media_key: [u8; 16],
    /// Unix **seconds** — the SDP `o=` origin id AND the timestamp embedded in
    /// the sessionid (cap3 couples these; they are NOT independent).
    o_session: u64,
    /// The 8-char base62 random suffix of the sessionid (cap3: `vhBJTOjV`).
    session_rand: String,
    /// The 8-char base62 random suffix of the `msg.tcp_token.sessionId` — cap3
    /// mints it as `<devId><o_session><8-rand>` with the SAME `o_session` seconds
    /// as the header sessionid but a DISTINCT random suffix (`VegSi8BW`). (TASK-0080)
    tcp_session_rand: String,
    /// `header.trace_id` = `<uuidv4>_<devId>_<unix_millis>` (cap3).
    trace_id: String,
}

impl SessionHandles {
    fn mint(dev_id: &str) -> Result<Self, Error> {
        let rng = OsRandom;
        let mut media_key = [0u8; 16];
        rng.fill(&mut media_key)?;
        // One wall-clock sample feeds both the o-session/sessionid seconds and
        // the trace_id millis (cap3 samples them ~1 s apart; using one instant is
        // internally consistent and within the captured tolerance).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::StreamConfig(format!("system clock before unix epoch: {e}")))?;
        Ok(Self {
            ice_ufrag: mint_b62(&rng, 4)?,
            ice_pwd: mint_b62(&rng, 24)?,
            media_key,
            o_session: now.as_secs(),
            session_rand: mint_b62(&rng, 8)?,
            tcp_session_rand: mint_b62(&rng, 8)?,
            trace_id: format!("{}_{}_{}", mint_uuid_v4(&rng)?, dev_id, now.as_millis()),
        })
    }
}

/// A built offer (the SDP + the routing flow + the cap3 `msg` relay/log
/// descriptors) ready to publish over 302.
struct Offer {
    sdp: String,
    flow: SignalingFlow,
    /// `msg.tcp_token` — the rtc.config `tcpRelay` with its `sessionId` re-minted
    /// to `<devId><o_session><8-rand>` (cap3). `None` if rtc.config carried none.
    tcp_token: Option<babymonitor_core::stream::signaling::TcpToken>,
    /// `msg.log` — the rtc.config `log` sink, passed through verbatim (cap3).
    /// `None` if absent.
    log: Option<serde_json::Value>,
}

/// Mint an `n`-char base62 token from OS entropy (ICE ufrag/pwd, trace id).
fn mint_b62<R: RandomSource>(rng: &R, n: usize) -> Result<String, Error> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut bytes = vec![0u8; n];
    rng.fill(&mut bytes)?;
    Ok(bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect())
}

/// Mint an RFC-4122 **v4** UUID (`8-4-4-4-12` lowercase hex) from OS entropy —
/// the first segment of the cap3 `trace_id` (`<uuidv4>_<devId>_<unix_millis>`).
///
/// Generated locally (16 random bytes with the version nibble forced to `4` and
/// the variant bits to `10xx`) to avoid pulling the `uuid` crate into the live
/// tree. The exact UUID value is irrelevant to the camera (it echoes the whole
/// trace_id back verbatim); only the **shape** must match a real client's offer.
fn mint_uuid_v4<R: RandomSource>(rng: &R) -> Result<String, Error> {
    let mut b = [0u8; 16];
    rng.fill(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    ))
}

/// Load + parse the owner-injected runtime bundle, or `Ok(None)` if it is absent.
///
/// # Errors
/// [`Error::StreamConfig`] if the bundle exists but cannot be read/parsed.
fn load_runtime(path: &Path) -> Result<Option<StreamRuntime>, Error> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::StreamConfig(format!("parse {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::StreamConfig(format!("read {}: {e}", path.display()))),
    }
}

/// Assemble the [`StreamCredentials`] from the runtime bundle (NO secret logged).
fn build_stream_credentials(runtime: &StreamRuntime) -> StreamCredentials {
    StreamCredentials {
        token: runtime.camera.token.clone(),
        p2p_id: runtime.camera.p2p_id.clone(),
        dev_id: runtime.device.dev_id.clone(),
        skill: runtime.camera.skill.clone(),
        p2p_key: runtime.camera.p2p_key.clone(),
        ices: runtime.camera.ices.clone(),
        session: runtime.camera.session.clone(),
        tcp_relay: runtime.camera.tcp_relay.clone(),
        log: runtime.camera.log.clone(),
        local_key: runtime.device.local_key.clone(),
        pv: runtime.device.pv.clone(),
    }
}

/// Derive the MQTT CONNECT creds and wrap them in a [`BrokerConfig`].
///
/// # Errors
/// [`Error::StreamConfig`] if `master_key_g_hex` is not valid hex, or the session
/// lacks the `ecode` the password derivation needs.
fn build_broker_config(session: &Session, runtime: &StreamRuntime) -> Result<BrokerConfig, Error> {
    let ecode = session.ecode.as_deref().ok_or_else(|| {
        Error::StreamConfig(
            "the session has no `ecode` — the MQTT password (doCommandNative cmd2) and username \
             md5tail both salt with the per-session ecode; re-login to capture it"
                .to_string(),
        )
    })?;
    let master_key_g = hex_decode(&runtime.mqtt.master_key_g_hex)
        .ok_or_else(|| Error::StreamConfig("mqtt.master_key_g_hex is not valid hex".to_string()))?;
    let mqtt_creds = derive_credentials(&MqttAuthInputs {
        partner_identity: &runtime.broker.partner_identity,
        uid: &session.uid,
        token: &runtime.mqtt.token,
        ecode,
        app_id: &runtime.mqtt.app_id,
        ch_key: &runtime.mqtt.ch_key,
        master_key_g: &master_key_g,
    })?;
    Ok(BrokerConfig::from_credentials(
        mqtt_creds,
        runtime.broker.host.clone(),
        runtime.broker.port,
        runtime.broker.tls,
        runtime.broker.publish_topic.clone(),
        runtime.broker.subscribe_topic.clone(),
    ))
}

/// Build the Tuya `imm` offer SDP + the routing flow for this session.
///
/// The `sessionid` is built cap3-faithfully: `<devId><unix_seconds><8-rand>`,
/// where `unix_seconds` is the SAME value the SDP `o=` origin line carries and
/// the `a=msid-semantic: WMS` line repeats the whole sessionid (TASK-0080). The
/// routing ids: `from` = `creds.p2p_id` (the account **uid** — cap3 offer
/// `header.from` == SDP `cname` == uid; rtc.config top-level `p2pId` is "" for
/// p2pType=4, so the live assembler fills `p2p_id` from `session.uid`), `to` =
/// `creds.dev_id` (the camera devId — cap3 `header.to`).
fn build_offer(creds: &StreamCredentials, h: &SessionHandles) -> Result<Offer, Error> {
    let sessionid = format!("{}{}{}", creds.dev_id, h.o_session, h.session_rand);
    let sdp = build_offer_sdp(&OfferSdpParams {
        o_session: h.o_session,
        stream_id: sessionid.clone(),
        ice_ufrag: h.ice_ufrag.clone(),
        ice_pwd: h.ice_pwd.clone(),
        media_key: h.media_key.to_vec(),
        cname: creds.p2p_id.clone(),
        rtpmap_param: 330,
    })?;
    let flow = SignalingFlow::new(
        creds.p2p_id.clone(),
        creds.dev_id.clone(),
        sessionid,
        h.trace_id.clone(),
    );
    let tcp_token = build_tcp_token(creds, h);
    let log = parse_log(&creds.log);
    Ok(Offer {
        sdp,
        flow,
        tcp_token,
        log,
    })
}

/// Build the offer `msg.tcp_token` from the rtc.config `tcpRelay` descriptor,
/// re-minting its `sessionId` as `<devId><o_session><8-rand>` (cap3: the offer's
/// `tcp_token.sessionId` shares the header sessionid's `o_session` seconds but
/// carries a DISTINCT 8-char random suffix — `confidence: cap3-inferred`).
///
/// Returns `None` (offer omits `tcp_token`) if rtc.config carried no usable
/// `tcpRelay` — a malformed/empty descriptor is skipped rather than failing the run.
fn build_tcp_token(
    creds: &StreamCredentials,
    h: &SessionHandles,
) -> Option<babymonitor_core::stream::signaling::TcpToken> {
    if creds.tcp_relay.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<babymonitor_core::stream::signaling::TcpToken>(&creds.tcp_relay) {
        Ok(mut t) => {
            t.session_id = format!("{}{}{}", creds.dev_id, h.o_session, h.tcp_session_rand);
            Some(t)
        }
        Err(e) => {
            eprintln!(
                "stream (live): rtc.config tcpRelay is present but not a usable tcp_token ({e}); \
                 offer omits msg.tcp_token"
            );
            None
        }
    }
}

/// Parse the rtc.config `log` sink into the opaque `msg.log` passthrough. `None`
/// (offer omits `log`) if absent or not a JSON object.
fn parse_log(log_json: &str) -> Option<serde_json::Value> {
    if log_json.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<serde_json::Value>(log_json) {
        Ok(v) if v.is_object() => Some(v),
        _ => None,
    }
}

/// LIVE: connect the broker, run the 302 offer/answer exchange, and collect the
/// camera's trickled ICE candidates ([`NegotiationOutcome`]).
fn negotiate(
    broker: &BrokerConfig,
    creds: &StreamCredentials,
    offer: &Offer,
) -> Result<NegotiationOutcome, Error> {
    let ices = parse_ice_servers(&creds.ices);
    let offer_args = offer.flow.make_offer_args(
        offer.sdp.clone(),
        ices,
        offer.tcp_token.clone(),
        offer.log.clone(),
    );
    let local_candidates: Vec<String> = Vec::new(); // host-direct: rely on the camera's host candidate
    let params = LiveSignalingParams {
        flow: offer.flow.clone(),
        local_key: creds.local_key.as_bytes(),
        dev_id: &creds.dev_id,
        pv: &creds.pv,
        offer_args: &offer_args,
        local_candidates: &local_candidates,
        max_polls: MAX_ANSWER_POLLS,
        trickle_polls: TRICKLE_POLLS,
        poll_interval: SIGNALING_POLL_INTERVAL,
    };
    connect_and_negotiate(broker, params)
}

/// LIVE: build the remote candidate set (the TRICKLED candidates merged with any
/// in the answer SDP — the latter is empty in practice, cap3/cap4), select the
/// camera's host candidate, open a connected UDP transport to it, and send the
/// initial nominating ICE connectivity check (so the camera opens consent and
/// starts sending media).
fn open_media_transport(
    answer: &ParsedAnswer,
    trickled: &[String],
    ice: &IceCredentials,
    h: &SessionHandles,
) -> Result<(mtransport::UdpMediaTransport, mtransport::IceCandidate), Error> {
    // The camera's answer SDP carries NO a=candidate lines (cap3/cap4 ground
    // truth); its host/srflx candidates arrive as trickled 302 `candidate`
    // messages. Merge any in-SDP candidates (usually none) with the trickled set;
    // skip (do not abort on) an unparseable trickled line — ICE tolerates unknown
    // candidates, and the others may still be reachable.
    let mut candidates = mtransport::parse_candidates_from_sdp(&answer.sdp)?;
    for line in trickled {
        match mtransport::parse_candidate(line) {
            Ok(c) => candidates.push(c),
            Err(e) => eprintln!("stream (live): skipping unparseable trickled candidate: {e}"),
        }
    }
    if candidates.is_empty() {
        return Err(Error::Transport(
            "no ICE candidates from the camera (none in the answer SDP — expected — and none \
             trickled over 302 within the window): host-direct needs a host candidate. If the \
             camera is remote/NAT'd, a srflx/relay path (STUN/TURN) is required (documented stub)."
                .to_string(),
        ));
    }
    // Bind an ephemeral local UDP socket on all interfaces.
    let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let (transport, host) = mtransport::connect_host_direct(local, &candidates)?;
    // Build + send the nominating check, MESSAGE-INTEGRITY-keyed by the camera pwd.
    let check = ice.build_check(
        random_txid()?,
        host.priority,
        IceRole::Controlling(controlling_tiebreaker()?),
        true, // USE-CANDIDATE on the host-direct nominated pair
        Some("babymonitor-rs"),
    )?;
    transport.send_datagram(&check)?;
    let _ = h; // local ICE creds already folded into `ice`
    Ok((transport, host))
}

/// The media-path consent/keepalive context (RFC 7675). Holds what is needed to
/// (a) send periodic outbound consent-refresh checks to the camera and (b) answer
/// the camera's inbound connectivity checks so its consent-to-send stays fresh.
struct PathKeepalive {
    ice: IceCredentials,
    peer: SocketAddr,
    priority: u32,
    tiebreaker: u64,
}

impl PathKeepalive {
    fn new(ice: IceCredentials, host: &mtransport::IceCandidate) -> Result<Self, Error> {
        Ok(Self {
            ice,
            peer: host.socket_addr(),
            priority: host.priority,
            tiebreaker: controlling_tiebreaker()?,
        })
    }

    /// Build a fresh outbound consent-refresh Binding Request (new txid each call,
    /// no USE-CANDIDATE — the pair is already nominated; this is RFC 7675
    /// keepalive). MESSAGE-INTEGRITY-keyed by the camera's ICE password.
    fn refresh_check(&self) -> Result<Vec<u8>, Error> {
        self.ice.build_check(
            random_txid()?,
            self.priority,
            IceRole::Controlling(self.tiebreaker),
            false,
            Some("babymonitor-rs"),
        )
    }

    /// If `dg` is an authenticated inbound connectivity check from the camera,
    /// return the Binding Success to reply with (so the camera keeps streaming);
    /// otherwise `None` (a success/error response to our own check, or an
    /// unauthenticated/foreign packet — nothing to send). Pure: no socket I/O, so
    /// it is offline-testable.
    ///
    /// # Errors
    /// [`Error::Transport`] only if the STUN encode/verify primitives fail.
    fn consent_reply(&self, dg: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let msg = stun::StunMessage::decode(dg)?;
        if msg.msg_type == stun::BINDING_REQUEST
            && stun::verify_message_integrity(dg, self.ice.local_pwd.as_bytes())?
        {
            // The camera (controlled agent) checks us with USERNAME
            // `<localUfrag>:<remoteUfrag>` keyed by OUR local pwd; reply keyed by
            // the same local pwd, reflecting the camera's address.
            let resp =
                stun::encode_binding_success(msg.txid, self.peer, self.ice.local_pwd.as_bytes())?;
            return Ok(Some(resp));
        }
        Ok(None)
    }
}

/// Whether a received datagram is STUN (magic cookie at bytes[4..8]) rather than
/// media. STUN connectivity checks share the media 5-tuple (cap4 carried ~559 STUN
/// packets on the media path), so the pump MUST split them out — a STUN packet fed
/// to the suite-3 media decoder would fail its HMAC and abort the stream.
fn is_stun(dg: &[u8]) -> bool {
    dg.len() >= stun::HEADER_LEN && dg[4..8] == stun::MAGIC_COOKIE.to_be_bytes()
}

/// Monotonic timers for the media pump: a generous first-media window, a steady
/// idle window once media is flowing, and the consent-refresh cadence. Pure given
/// the injected durations, so the timeout/refresh decisions are unit-testable
/// without a network or real waits (tests use zero/large durations).
struct PumpTimers {
    started: Instant,
    last_media: Option<Instant>,
    last_consent: Instant,
    first_media_timeout: Duration,
    steady_idle_timeout: Duration,
    consent_interval: Duration,
}

impl PumpTimers {
    fn new(
        first_media_timeout: Duration,
        steady_idle_timeout: Duration,
        consent_interval: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last_media: None,
            last_consent: now,
            first_media_timeout,
            steady_idle_timeout,
            consent_interval,
        }
    }

    /// The live cadence (TASK-0077 AC#2/#3).
    fn live() -> Self {
        Self::new(
            FIRST_MEDIA_TIMEOUT,
            STEADY_IDLE_TIMEOUT,
            CONSENT_REFRESH_INTERVAL,
        )
    }

    fn mark_media(&mut self) {
        self.last_media = Some(Instant::now());
    }

    fn consent_due(&self) -> bool {
        self.last_consent.elapsed() >= self.consent_interval
    }

    fn mark_consent(&mut self) {
        self.last_consent = Instant::now();
    }

    /// `Some(reason)` if the idle window expired — a generous first-media window
    /// before any media, then a shorter steady-idle window once it is flowing.
    fn idle_reason(&self) -> Option<String> {
        match self.last_media {
            None if self.started.elapsed() >= self.first_media_timeout => Some(format!(
                "no media within {:?} of startup (camera never sent a first frame)",
                self.first_media_timeout
            )),
            Some(t) if t.elapsed() >= self.steady_idle_timeout => Some(format!(
                "media idle for {:?} (session ended / camera silent)",
                self.steady_idle_timeout
            )),
            _ => None,
        }
    }
}

/// LIVE: the media receive loop — split STUN (consent) from media, route each
/// decoded unit by conv (video → H.264 Annex-B; audio → S16LE), feed the MPEG-TS
/// muxer, and keep the ICE path alive (send a consent refresh ~every 5 s, answer
/// the camera's inbound checks).
fn pump_to_output(
    args: &StreamArgs,
    engine: &mut MediaEngine,
    transport: &mut mtransport::UdpMediaTransport,
    keep: &PathKeepalive,
) -> Result<(), Error> {
    let mut sink = LiveAvSink::spawn(args)?;
    let mut depay = H264Depacketizer::new();
    let mut buf = vec![0u8; 2048];
    eprintln!(
        "stream (live): stage 7-8 media — pumping; connect a player: vlc http://127.0.0.1:{}/stream.ts",
        args.port
    );
    let mut timers = PumpTimers::live();
    loop {
        // RFC 7675 consent freshness: keep our consent-to-send alive during the
        // (possibly >20 s) startup AND the sustained stream.
        if timers.consent_due() {
            transport.send_datagram(&keep.refresh_check()?)?;
            timers.mark_consent();
        }
        match transport.recv_datagram(&mut buf)? {
            Some(n) => {
                let dg = &buf[..n];
                if is_stun(dg) {
                    // A camera connectivity check (answer it so the camera keeps
                    // streaming) or a response to ours (nothing to send). A
                    // malformed STUN-looking packet is logged + ignored, never
                    // fatal to the stream.
                    match keep.consent_reply(dg) {
                        Ok(Some(reply)) => {
                            transport.send_datagram(&reply)?;
                        }
                        Ok(None) => {}
                        Err(e) => eprintln!("stream (live): ignoring malformed STUN packet: {e}"),
                    }
                } else {
                    match engine.push_datagram(dg) {
                        Ok(units) => {
                            // A valid (authenticated) media datagram — the path is
                            // alive even if this one did not complete a frame yet.
                            timers.mark_media();
                            for u in &units {
                                if u.is_video() {
                                    for nal in depay.push(&u.payload)? {
                                        sink.write_video(&nal)?;
                                    }
                                } else if u.is_downstream_audio() {
                                    sink.write_audio(audio::downstream_pcm_s16le(&u.payload))?;
                                }
                            }
                        }
                        // A foreign-session / corrupt datagram (failed HMAC or
                        // PKCS#7) is a drop, NOT a stream-fatal error: cap4 shows
                        // foreign-session datagrams can share the media path. Log +
                        // continue so one stray packet does not tear the session down
                        // (TASK-0077 AC#2 — keep the path alive). The HMAC/padding
                        // gates still reject it, so nothing mis-decoded slips through.
                        Err(e) => {
                            eprintln!("stream (live): dropping undecodable media datagram: {e}");
                        }
                    }
                }
            }
            None => {
                if let Some(reason) = timers.idle_reason() {
                    eprintln!("stream (live): {reason}; stopping.");
                    break;
                }
                std::thread::sleep(MEDIA_POLL_INTERVAL);
            }
        }
    }
    sink.finish()
}

/// Generate a random 12-byte STUN transaction id.
fn random_txid() -> Result<[u8; 12], Error> {
    let mut t = [0u8; 12];
    OsRandom.fill(&mut t)?;
    Ok(t)
}

/// Generate a random 64-bit ICE controlling tiebreaker.
fn controlling_tiebreaker() -> Result<u64, Error> {
    let mut b = [0u8; 8];
    OsRandom.fill(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

/// Parse the cloud `ices` JSON into typed ICE servers (empty on parse failure).
fn parse_ice_servers(ices: &str) -> Vec<babymonitor_core::stream::signaling::IceServer> {
    serde_json::from_str(ices).unwrap_or_default()
}

/// Decode a lowercase/uppercase hex string to bytes, or `None` if malformed.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

// ── Honest gate reporters ────────────────────────────────────────────────────

fn stream_pending_no_session() -> Result<(), Error> {
    eprintln!(
        "stream (live): NO session on disk. Stage 1 (auth) is the project's known block: the \
         from-scratch cloud login hits the server-side identity gate (ILLEGAL_CLIENT_ID). Inject a \
         captured live session into the SessionStore (README §6 / re/live_stream_run.md), then re-run."
    );
    Err(Error::StreamPending)
}

// ─────────────────────────────────────────────────────────────────────────────
// SELF-SUFFICIENT runtime assembly (TASK-0078): build the StreamRuntime in-process
// from the session — no hand-written secrets/stream_runtime.json required.
// ─────────────────────────────────────────────────────────────────────────────

/// The `secrets/` directory + extracted APK the live REST + sign machinery reads.
/// Same defaults as the other live entry points (the CLI runs from the repo root).
const SECRETS_DIR: &str = "secrets";
const APK_PATH: &str = "extracted/xapk/com.philips.ph.babymonitorplus.apk";

/// The minimal device-record fields the runtime needs, parsed from the captured
/// device-list (`secrets/tuya_device_list.json`). The camera is the record whose
/// `skills.p2pType` is present (`device.rs` `is_camera`). NO value is logged.
struct CameraDeviceRecord {
    dev_id: String,
    local_key: String,
    pv: String,
    p2p_type: i32,
}

/// AUTO-BUILD the runtime bundle in-process from the injected session (TASK-0078).
///
/// This is the self-sufficient path: instead of a hand-written
/// `secrets/stream_runtime.json`, it gathers every input from the session +
/// `secrets/` + ONE live `rtc.config.get`:
/// - **device**  ← `secrets/tuya_device_list.json` (devId, localKey, pv, p2pType);
/// - **camera**  ← live `rtc.config.get` (ices, session, auth token, the WebRTC
///   `from`/cname = the account uid — top-level `p2pId` is "" for p2pType=4);
/// - **broker**  ← the captured login `User.domain.mobileMqttsUrl` (:8883) + the
///   DERIVED 302 topics `smart/mb/out|in/<devId>` + `User.partnerIdentity`;
/// - **mqtt**    ← `User.sid` (= `MqttConnectConfig.token`) + the offline-derived
///   appId/chKey/master-key-G ([`crate::live::derive_mqtt_key_material`]).
///
/// The media `a=aes-key` is NOT taken from `rtc.config session.aesKey` — it is
/// MINTED per session by [`SessionHandles::mint`] (cap3: offer == answer aes-key,
/// both != that session's `rtc.config session.aesKey`).
///
/// # Errors
/// [`Error::StreamConfig`] if a prerequisite secret is missing or the live
/// `rtc.config.get` fails (the latter is the honest live gate in this sandbox —
/// there is no broker/cloud to reach).
fn build_runtime_from_session(session: &Session) -> Result<StreamRuntime, Error> {
    let secrets_dir = PathBuf::from(SECRETS_DIR);
    let apk_path = PathBuf::from(APK_PATH);
    let store = SessionStore::default_path()?;

    // (a) The captured login User → broker host (domain.mobileMqttsUrl) + the
    // MQTT CONNECT user-prefix (partnerIdentity). Both are account-stable values
    // the login persisted to gitignored secrets/tuya_session.json.
    let user = read_json(&secrets_dir.join("tuya_session.json")).map_err(|e| {
        Error::StreamConfig(format!(
            "auto-build: cannot read secrets/tuya_session.json (the captured login User, source \
             of the MQTT broker host + partnerIdentity): {e}. Run the live login first."
        ))
    })?;
    let mqtt_host = nested_str(&user, &["domain", "mobileMqttsUrl"]).ok_or_else(|| {
        Error::StreamConfig(
            "auto-build: secrets/tuya_session.json has no domain.mobileMqttsUrl (the MQTT broker \
             host, host:8883). Re-run the live login to capture the User domain."
                .to_string(),
        )
    })?;
    let partner_identity = nested_str(&user, &["partnerIdentity"]).ok_or_else(|| {
        Error::StreamConfig(
            "auto-build: secrets/tuya_session.json has no partnerIdentity (the MQTT CONNECT \
             username prefix)."
                .to_string(),
        )
    })?;

    // (b) The device-list → the SCD921 record (devId/localKey/pv/p2pType).
    let dev = find_camera_record(&secrets_dir)?;
    if dev.p2p_type != 4 {
        return Err(Error::StreamConfig(format!(
            "auto-build: device p2pType is {} — this WebRTC-over-MQTT path needs p2pType=4 \
             (a p2pType=2 device uses the legacy PPCS transport, out of scope).",
            dev.p2p_type
        )));
    }

    // (c) The live rtc.config.get → the per-camera WebRTC config (THE live gate).
    let rtc_result = crate::live::fetch_rtc_config(&secrets_dir, &apk_path, &store, &dev.dev_id)
        .map_err(|e| Error::StreamConfig(format!("auto-build: rtc.config.get failed: {e}")))?;
    let rtc = RtcConfig::from_rtc_result(&rtc_result)?;

    // (d) The offline-derived MQTT static key material (appId/chKey/master-key-G).
    let km = crate::live::derive_mqtt_key_material(&secrets_dir, &apk_path)
        .map_err(|e| Error::StreamConfig(format!("auto-build: mqtt key material: {e}")))?;

    assemble_runtime(session, &dev, &rtc, &partner_identity, &mqtt_host, &km)
}

/// PURE assembly of the [`StreamRuntime`] from already-fetched inputs (no network,
/// no secret read) — split out so the field mapping is unit-testable offline.
fn assemble_runtime(
    session: &Session,
    dev: &CameraDeviceRecord,
    rtc: &RtcConfig,
    partner_identity: &str,
    mqtt_host: &str,
    km: &crate::live::DerivedMqttKeyMaterial,
) -> Result<StreamRuntime, Error> {
    // The WebRTC signaling `from` / SDP cname is the account uid (cap3: offer
    // header.from == sdp cname == uid). rtc.config carries it as session.uid; the
    // top-level p2pId is "" for p2pType=4, so we never use it as `from`.
    let from_id = if rtc.uid.is_empty() {
        session.uid.clone()
    } else {
        rtc.uid.clone()
    };

    Ok(StreamRuntime {
        broker: BrokerInputs {
            host: mqtt_host.to_string(),
            port: 8883,
            tls: true,
            publish_topic: topics::publish_topic(&dev.dev_id),
            subscribe_topic: topics::subscribe_topic(&dev.dev_id),
            partner_identity: partner_identity.to_string(),
        },
        device: DeviceInputs {
            dev_id: dev.dev_id.clone(),
            local_key: dev.local_key.clone(),
            pv: dev.pv.clone(),
            p2p_type: dev.p2p_type,
        },
        camera: CameraInputs {
            p2p_id: from_id,
            p2p_key: String::new(), // no p2pKey on the WebRTC (p2pType=4) path
            ices: rtc.ices_json.clone(),
            session: rtc.session_json.clone(),
            token: rtc.auth.clone(),
            skill: rtc.skill.clone(),
            tcp_relay: rtc.tcp_relay_json.clone(),
            log: rtc.log_json.clone(),
        },
        mqtt: MqttInputs {
            token: session.sid.clone(), // MqttConnectConfig.token = User.sid
            app_id: km.app_id.clone(),
            ch_key: km.ch_key.clone(),
            master_key_g_hex: km.master_key_g_hex.clone(),
        },
    })
}

/// Read + parse a JSON file into a [`serde_json::Value`].
fn read_json(path: &Path) -> Result<serde_json::Value, Error> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::StreamConfig(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::StreamConfig(format!("parse {}: {e}", path.display())))
}

/// Navigate a nested `{"a":{"b":"v"}}` string field by key path; `None` if any
/// hop is absent or the leaf is not a non-empty string.
fn nested_str(v: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

/// Find the SCD921 camera record in the captured device-list.
///
/// Accepts `secrets/tuya_device_list.json` (single-home) or
/// `tuya_device_list_0.json` (first home of a multi-home account). The file is the
/// decrypted business envelope (`{result:[…records…], …}`) or a bare records array.
/// The camera is the record carrying `skills.p2pType` (the camera-specific signal,
/// `device.rs` `is_camera`). `pv` defaults to `"2.2"` when absent on the record.
fn find_camera_record(secrets_dir: &Path) -> Result<CameraDeviceRecord, Error> {
    let path = {
        let p = secrets_dir.join("tuya_device_list.json");
        if p.exists() {
            p
        } else {
            secrets_dir.join("tuya_device_list_0.json")
        }
    };
    let v = read_json(&path).map_err(|e| {
        Error::StreamConfig(format!(
            "auto-build: cannot read the captured device-list ({e}). Run `devices list --live` first."
        ))
    })?;
    let records = device_records(&v).ok_or_else(|| {
        Error::StreamConfig(format!(
            "auto-build: {} is not a device-list (no `result` array nor a records array)",
            path.display()
        ))
    })?;

    for rec in records {
        if let Some(p2p_type) = record_p2p_type(rec) {
            let dev_id = rec
                .get("devId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let local_key = rec
                .get("localKey")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if dev_id.is_empty() || local_key.is_empty() {
                continue;
            }
            let pv = rec
                .get("pv")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("2.2")
                .to_string();
            return Ok(CameraDeviceRecord {
                dev_id: dev_id.to_string(),
                local_key: local_key.to_string(),
                pv,
                p2p_type,
            });
        }
    }
    Err(Error::StreamConfig(
        "auto-build: no camera (a record with skills.p2pType) found in the captured device-list"
            .to_string(),
    ))
}

/// Extract the device records array from an envelope (`{result:[…]}`) or a bare
/// array. A single-record object is wrapped so a one-device capture still parses.
fn device_records(v: &serde_json::Value) -> Option<Vec<&serde_json::Value>> {
    if let Some(arr) = v.get("result").and_then(serde_json::Value::as_array) {
        return Some(arr.iter().collect());
    }
    if let Some(arr) = v.as_array() {
        return Some(arr.iter().collect());
    }
    if v.get("devId").is_some() {
        return Some(vec![v]);
    }
    None
}

/// The `skills.p2pType` of a device record — present only on a camera. `skills`
/// may be a JSON object OR a JSON string; both are handled.
fn record_p2p_type(rec: &serde_json::Value) -> Option<i32> {
    let skills = rec.get("skills")?;
    let as_i32 = |v: &serde_json::Value| v.get("p2pType").and_then(serde_json::Value::as_i64);
    let raw = match skills {
        serde_json::Value::Object(_) => as_i32(skills),
        serde_json::Value::String(s) => {
            let parsed: serde_json::Value = serde_json::from_str(s).ok()?;
            parsed.get("p2pType").and_then(serde_json::Value::as_i64)
        }
        _ => None,
    }?;
    i32::try_from(raw).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Live A/V sink: video on ffmpeg stdin + downstream S16LE audio on a FIFO
// ─────────────────────────────────────────────────────────────────────────────

/// A live A/V MPEG-TS sink: ffmpeg reads H.264 Annex-B on stdin and downstream
/// S16LE audio from a FIFO this process feeds incrementally (16 kHz mono → AAC).
struct LiveAvSink {
    sink: crate::stream::OutputSink,
    audio: Option<AudioFifo>,
}

impl LiveAvSink {
    /// Spawn the live A/V muxer. For `--output stdout` (raw Annex-B) there is no
    /// audio mux — only video is written.
    fn spawn(args: &StreamArgs) -> Result<Self, Error> {
        if args.output == OutputMode::Stdout {
            let sink = crate::stream::OutputSink::spawn(
                args.output,
                args.port,
                args.ts_out.as_ref(),
                None,
            )?;
            return Ok(Self { sink, audio: None });
        }
        let (output_args, target) =
            crate::stream::ffmpeg_output_target(args.output, args.port, args.ts_out.as_ref())?;
        let args_ref: Vec<&str> = output_args.iter().map(String::as_str).collect();
        let fifo = AudioFifo::create()?;
        let cmd = crate::stream::build_ffmpeg_cmd(
            &args_ref,
            Some((fifo.path(), audio::DOWNSTREAM_SAMPLE_RATE_HZ)),
        );
        let sink = crate::stream::spawn_ffmpeg_sink(cmd, target)?;
        Ok(Self {
            sink,
            audio: Some(fifo),
        })
    }

    fn write_video(&mut self, nal: &[u8]) -> Result<(), Error> {
        self.sink.write_annexb(nal)
    }

    fn write_audio(&mut self, pcm: &[u8]) -> Result<(), Error> {
        if let Some(fifo) = &mut self.audio {
            fifo.send(pcm)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<(), Error> {
        if let Some(fifo) = self.audio {
            fifo.finish()?;
        }
        self.sink.finish()
    }
}

/// The live-audio FIFO writer: a background thread opens the FIFO for writing
/// (rendezvous with ffmpeg's read-open) and drains S16LE chunks from a channel.
struct AudioFifo {
    tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    path: PathBuf,
}

impl AudioFifo {
    /// Create a uniquely-named FIFO (via `mkfifo`) + the writer thread.
    fn create() -> Result<Self, Error> {
        use std::io::Write as _;
        let path = std::env::temp_dir().join(format!(
            "babymonitor-audio-{}-{}.s16le",
            std::process::id(),
            now_nanos()
        ));
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .map_err(|e| Error::Transport(format!("spawning mkfifo: {e}")))?;
        if !status.success() {
            return Err(Error::Transport(format!(
                "mkfifo {} failed ({status})",
                path.display()
            )));
        }
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let writer_path = path.clone();
        let handle = std::thread::spawn(move || -> std::io::Result<()> {
            // Blocks until ffmpeg opens the read end (rendezvous).
            let mut f = std::fs::OpenOptions::new().write(true).open(&writer_path)?;
            while let Ok(chunk) = rx.recv() {
                if let Err(e) = f.write_all(&chunk) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(e);
                }
            }
            Ok(())
        });
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
            path,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn send(&mut self, pcm: &[u8]) -> Result<(), Error> {
        if let Some(tx) = &self.tx {
            tx.send(pcm.to_vec())
                .map_err(|_| Error::Transport("audio FIFO writer exited".to_string()))?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), Error> {
        drop(self.tx.take());
        let joined = self.handle.take().map(std::thread::JoinHandle::join);
        let _ = std::fs::remove_file(&self.path);
        match joined {
            Some(Ok(Ok(()))) | None => Ok(()),
            Some(Ok(Err(e))) => Err(Error::Transport(format!("audio FIFO write failed: {e}"))),
            Some(Err(_)) => Err(Error::Transport("audio FIFO writer panicked".to_string())),
        }
    }
}

impl Drop for AudioFifo {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SYNTHETIC 16-byte localKey for the test fixtures (CLAUDE.md). Injected into
    // the JSON via a placeholder so the raw-string source line never carries a
    // localKey-shaped literal the secret scanner would flag.
    const SYNTH_LK: &str = "0123456789abcdef"; // secret-scan:allow (synthetic test localKey)
    const LK_PLACEHOLDER: &str = "LK_PLACEHOLDER";

    fn fill_lk(json: &str) -> Vec<u8> {
        json.replace(LK_PLACEHOLDER, SYNTH_LK).into_bytes()
    }

    #[test]
    fn hex_decode_roundtrip() {
        assert_eq!(hex_decode("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(hex_decode("0").is_none()); // odd length
        assert!(hex_decode("zz").is_none()); // non-hex
    }

    // ── TASK-0078: self-sufficient runtime assembly (offline-validated) ────────

    fn synth_session() -> Session {
        // SYNTHETIC session — never a real sid/uid (CLAUDE.md).
        Session {
            sid: "SYNTH_SID_000000000000000000000000000000000000000000000000".into(),
            uid: "eu0000000000000synth".into(),
            ecode: Some("0123456789abcdef".into()),
            mobile_api_base: "https://a1.tuyaeu.com".into(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        }
    }

    fn synth_rtc() -> RtcConfig {
        // Reuse the core parser on a synthetic rtc.config result — no real values.
        let v = serde_json::json!({
            "id": "synthdev0001ufmo",
            "motoId": "signaling00000",
            "p2pType": 4,
            "auth": "U1lOVEhfQVVUSF9CNjQ9",
            "skill": "{\"webrtc\":3}",
            "p2pConfig": {
                "ices": [{"urls": "stun:1.2.3.4:3478"}],
                "transmission": "kcp",
                "session": {
                    "aesKey": "00112233445566778899aabbccddeeff",
                    "icePassword": "SynthIcePwd0123456789012",
                    "iceUfrag": "SyUf",
                    "sessionId": "synthSID01",
                    "uid": "eu0000000000000synth",
                    "devId": "synthdev0001ufmo"
                }
            }
        });
        RtcConfig::from_rtc_result(&v).unwrap()
    }

    fn synth_km() -> crate::live::DerivedMqttKeyMaterial {
        crate::live::DerivedMqttKeyMaterial {
            app_id: "synthAppKey".into(),
            ch_key: "0a1b2c3d".into(),
            master_key_g_hex: "00112233445566778899aabbccddeeff".into(),
        }
    }

    #[test]
    fn assemble_runtime_maps_every_field() {
        let session = synth_session();
        let dev = CameraDeviceRecord {
            dev_id: "synthdev0001ufmo".into(),
            local_key: SYNTH_LK.into(),
            pv: "2.2".into(),
            p2p_type: 4,
        };
        let rtc = synth_rtc();
        let km = synth_km();
        let rt = assemble_runtime(&session, &dev, &rtc, "PARTNERX", "m1.tuyaeu.com", &km).unwrap();

        // broker: host + derived topics + partnerIdentity + 8883/TLS.
        assert_eq!(rt.broker.host, "m1.tuyaeu.com");
        assert_eq!(rt.broker.port, 8883);
        assert!(rt.broker.tls);
        assert_eq!(rt.broker.publish_topic, "smart/mb/out/synthdev0001ufmo");
        assert_eq!(rt.broker.subscribe_topic, "smart/mb/in/synthdev0001ufmo");
        assert_eq!(rt.broker.partner_identity, "PARTNERX");

        // device.
        assert_eq!(rt.device.dev_id, "synthdev0001ufmo");
        assert_eq!(rt.device.pv, "2.2");
        assert_eq!(rt.device.p2p_type, 4);

        // camera: p2p_id is the uid (the WebRTC from/cname), token is the rtc auth,
        // ices/session come from rtc.config, p2p_key empty.
        assert_eq!(rt.camera.p2p_id, "eu0000000000000synth");
        assert_eq!(rt.camera.token, "U1lOVEhfQVVUSF9CNjQ9");
        assert!(rt.camera.p2p_key.is_empty());
        let ices: Vec<babymonitor_core::stream::signaling::IceServer> =
            serde_json::from_str(&rt.camera.ices).unwrap();
        assert_eq!(ices.len(), 1);

        // mqtt: token == sid (MqttConnectConfig.token = User.sid).
        assert_eq!(rt.mqtt.token, session.sid);
        assert_eq!(rt.mqtt.app_id, "synthAppKey");
        assert_eq!(rt.mqtt.ch_key, "0a1b2c3d");

        // The assembled bundle is a valid set of stream credentials.
        let creds = build_stream_credentials(&rt);
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn assemble_runtime_falls_back_to_session_uid_when_rtc_uid_empty() {
        let session = synth_session();
        let dev = CameraDeviceRecord {
            dev_id: "d".into(),
            local_key: SYNTH_LK.into(),
            pv: "2.2".into(),
            p2p_type: 4,
        };
        let mut rtc = synth_rtc();
        rtc.uid = String::new(); // rtc.config gave no session.uid
        let rt = assemble_runtime(&session, &dev, &rtc, "P", "h", &synth_km()).unwrap();
        assert_eq!(
            rt.camera.p2p_id, session.uid,
            "from/cname falls back to session.uid"
        );
    }

    #[test]
    fn find_camera_record_picks_the_p2ptype_record() {
        // Envelope shape {result:[ non-camera, camera ]} with skills as an object.
        let json = format!(
            r#"{{"result":[
                {{"devId":"plugABC","localKey":"{SYNTH_LK}","skills":{{}}}},
                {{"devId":"camXYZ","localKey":"{SYNTH_LK}","pv":"2.2","skills":{{"p2pType":4}}}}
            ]}}"#
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let recs = device_records(&v).unwrap();
        assert_eq!(recs.len(), 2);
        // The camera is the second record.
        assert_eq!(record_p2p_type(recs[0]), None);
        assert_eq!(record_p2p_type(recs[1]), Some(4));
    }

    #[test]
    fn record_p2p_type_handles_skills_as_json_string() {
        let rec = serde_json::json!({
            "devId": "x",
            "skills": "{\"p2pType\":4,\"webrtc\":1}"
        });
        assert_eq!(record_p2p_type(&rec), Some(4));
    }

    #[test]
    fn nested_str_navigates_and_rejects_empty() {
        let v = serde_json::json!({"domain": {"mobileMqttsUrl": "m1.tuyaeu.com"}, "empty": ""});
        assert_eq!(
            nested_str(&v, &["domain", "mobileMqttsUrl"]).as_deref(),
            Some("m1.tuyaeu.com")
        );
        assert!(nested_str(&v, &["domain", "absent"]).is_none());
        assert!(nested_str(&v, &["empty"]).is_none(), "empty string is None");
    }

    #[test]
    fn runtime_bundle_parses_synthetic() {
        // SYNTHETIC values only (CLAUDE.md) — never real account data.
        let json = r#"{
            "broker": {"host":"a1.tuyaeu.com","port":8883,"publish_topic":"p","subscribe_topic":"s","partner_identity":"PARTNERX"},
            "device": {"dev_id":"SYNTH_DEV","local_key":"LK_PLACEHOLDER","pv":"2.2","p2p_type":4},
            "camera": {"p2p_id":"SYNTH_P2P","token":"SYNTH_TOKEN"},
            "mqtt": {"token":"SYNTH_MQTT_TOKEN","app_id":"SYNTH_APP","ch_key":"0a1b2c3d","master_key_g_hex":"00112233"}
        }"#;
        let rt: StreamRuntime = serde_json::from_slice(&fill_lk(json)).unwrap();
        assert_eq!(rt.device.p2p_type, 4);
        assert_eq!(rt.broker.port, 8883);
        assert!(rt.broker.tls, "tls defaults true");
        assert_eq!(rt.camera.ices, "[]", "ices defaults to empty array");
        // StreamCredentials assemble + validate from the bundle.
        let creds = build_stream_credentials(&rt);
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn build_offer_produces_imm_sdp() {
        let creds = build_stream_credentials(&synthetic_runtime());
        let h = SessionHandles::mint(&creds.dev_id).unwrap();
        let offer = build_offer(&creds, &h).unwrap();
        assert!(offer.sdp.contains("imm 6001"));
        assert!(offer.sdp.contains(&format!("a=ice-ufrag:{}", h.ice_ufrag)));
    }

    // TASK-0080: the offer routing ids + sessionid must be cap3-byte-shaped, the
    // #1 fix for the silent camera. sessionid = <devId><unix_seconds><8-rand>;
    // the SDP o-line + WMS msid use the SAME unix_seconds / full sessionid; the
    // trace_id is <uuidv4>_<devId>_<unix_millis>.
    #[test]
    fn build_offer_sessionid_and_traceid_match_cap3_shape() {
        let creds = build_stream_credentials(&synthetic_runtime());
        let dev = &creds.dev_id; // "D" in the synthetic runtime
        let h = SessionHandles::mint(dev).unwrap();
        let offer = build_offer(&creds, &h).unwrap();

        // sessionid = <devId><o_session><session_rand>, 8-char base62 suffix.
        let expected_sessionid = format!("{}{}{}", dev, h.o_session, h.session_rand);
        assert_eq!(offer.flow.sessionid(), expected_sessionid);
        assert!(expected_sessionid.starts_with(dev.as_str()));
        assert_eq!(
            h.session_rand.len(),
            8,
            "sessionid random suffix is 8 chars"
        );
        assert!(h.session_rand.chars().all(|c| c.is_ascii_alphanumeric()));

        // The SDP o-line carries the SAME unix_seconds embedded in the sessionid,
        // and WMS repeats the whole sessionid (cap3 coupling).
        assert!(
            offer
                .sdp
                .contains(&format!("o=- {} 1 IN IP4 127.0.0.1", h.o_session)),
            "o-line uses the sessionid's unix_seconds"
        );
        assert!(
            offer
                .sdp
                .contains(&format!("a=msid-semantic: WMS {expected_sessionid}")),
            "WMS msid repeats the full sessionid"
        );

        // from == uid (creds.p2p_id == cname); to == devId.
        assert_eq!(offer.flow.from(), creds.p2p_id);
        assert_eq!(offer.flow.to(), creds.dev_id);
        assert!(offer
            .sdp
            .contains(&format!("a=ssrc:0 cname:{}", creds.p2p_id)));

        // trace_id = <uuidv4>_<devId>_<unix_millis> — three `_`-joined parts.
        let parts: Vec<&str> = h.trace_id.split('_').collect();
        assert_eq!(parts.len(), 3, "trace_id has uuid_devId_millis shape");
        assert_eq!(parts[0].len(), 36, "uuid segment is 36 chars (8-4-4-4-12)");
        assert_eq!(parts[0].as_bytes()[14], b'4', "uuid version nibble is 4");
        assert_eq!(
            parts[1],
            dev.as_str(),
            "trace_id middle segment is the devId"
        );
        assert!(
            parts[2].chars().all(|c| c.is_ascii_digit()),
            "millis are digits"
        );
    }

    // TASK-0080 AC#2: the offer carries `msg.tcp_token` (from rtc.config `tcpRelay`,
    // with the `sessionId` RE-MINTED to `<devId><o_session><8-rand>`, cap3) and
    // `msg.log` (rtc.config `log`, verbatim). Absent rtc.config descriptors ⇒ the
    // offer omits both (graceful).
    #[test]
    fn build_offer_includes_tcp_token_and_log_from_rtc_config() {
        // SYNTHETIC rtc.config tcpRelay + log (CLAUDE.md — no real values).
        let mut creds = build_stream_credentials(&synthetic_runtime());
        creds.tcp_relay = r#"{"credential":"SYNTHTCP=","domain":"localhost","sessionId":"ORIG_RELAY_SID","urls":["tcp4:9.9.9.9:1443"],"urlsEx":["tcp6:[2a05:dead:beef::2]:1443"],"username":"1700000000:D"}"#.into();
        creds.log = r#"{"api":"thing.m.rtc.log","interval":60,"level":2,"size":1024,"tcp":{"address":"3.3.3.3","domain":"x.example","key":"SYNTHLOGKEY","port":9093},"topic":"/av/moto/log"}"#.into();

        let h = SessionHandles::mint(&creds.dev_id).unwrap();
        let offer = build_offer(&creds, &h).unwrap();

        let tcp = offer
            .tcp_token
            .as_ref()
            .expect("offer carries msg.tcp_token");
        // sessionId is RE-MINTED as <devId><o_session><tcp_session_rand> — NOT the
        // rtc.config original, and uses the SAME o_session seconds as the header.
        assert_eq!(
            tcp.session_id,
            format!("{}{}{}", creds.dev_id, h.o_session, h.tcp_session_rand)
        );
        assert_ne!(
            tcp.session_id, "ORIG_RELAY_SID",
            "tcp_token.sessionId is re-minted, not the rtc.config value"
        );
        assert_eq!(h.tcp_session_rand.len(), 8);
        // The relay descriptor fields are carried through verbatim.
        assert_eq!(tcp.urls, vec!["tcp4:9.9.9.9:1443".to_string()]);
        assert_eq!(tcp.urls_ex.len(), 1, "IPv6 urlsEx preserved");
        assert_eq!(tcp.username, "1700000000:D");
        assert_eq!(tcp.domain, "localhost");

        // log is passed through verbatim (opaque object).
        let log = offer.log.as_ref().expect("offer carries msg.log");
        assert_eq!(log["api"], "thing.m.rtc.log");
        assert_eq!(log["tcp"]["port"], 9093);

        // Absent rtc.config descriptors ⇒ the offer omits tcp_token + log.
        creds.tcp_relay = String::new();
        creds.log = String::new();
        let offer2 = build_offer(&creds, &h).unwrap();
        assert!(offer2.tcp_token.is_none(), "no tcpRelay ⇒ no msg.tcp_token");
        assert!(offer2.log.is_none(), "no log ⇒ no msg.log");
    }

    fn synthetic_runtime() -> StreamRuntime {
        let json = r#"{
            "broker": {"host":"h","port":8883,"publish_topic":"p","subscribe_topic":"s","partner_identity":"PX"},
            "device": {"dev_id":"D","local_key":"LK_PLACEHOLDER","p2p_type":4},
            "camera": {"p2p_id":"P","token":"T"},
            "mqtt": {"token":"MT","app_id":"A","ch_key":"c","master_key_g_hex":"00"}
        }"#;
        serde_json::from_slice(&fill_lk(json)).unwrap()
    }

    // ── ICE path-keepalive (RFC 7675) — offline-validated pure pieces ──────
    // SYNTHETIC ICE creds — never a real session value (CLAUDE.md).
    const LOCAL_UFRAG: &str = "LOCL";
    const LOCAL_PWD: &str = "SyntheticLocalPwd0123456"; // secret-scan:allow (synthetic test pwd)
    const REMOTE_UFRAG: &str = "RMTE";
    const REMOTE_PWD: &str = "SyntheticRemotePwd012345"; // secret-scan:allow (synthetic test pwd)

    fn make_keepalive() -> PathKeepalive {
        let ice = IceCredentials {
            local_ufrag: LOCAL_UFRAG.into(),
            local_pwd: LOCAL_PWD.into(),
            remote_ufrag: REMOTE_UFRAG.into(),
            remote_pwd: REMOTE_PWD.into(),
        };
        let host =
            mtransport::parse_candidate("candidate:1 1 UDP 2130706431 192.0.2.9 5000 typ host")
                .unwrap();
        PathKeepalive::new(ice, &host).unwrap()
    }

    // We answer the camera's inbound connectivity check (keyed by OUR local pwd)
    // with a Binding Success that echoes the txid, reflects the camera address, and
    // authenticates under the same local pwd — so the camera keeps streaming.
    #[test]
    fn keepalive_answers_camera_consent_check() {
        let keep = make_keepalive();
        let inbound = stun::BindingRequest {
            txid: *b"camcheck0001",
            username: format!("{LOCAL_UFRAG}:{REMOTE_UFRAG}"),
            priority: 0x6eff_ffff,
            role: IceRole::Controlled(0x1122_3344_5566_7788),
            use_candidate: false,
            software: Some("cam".into()),
        }
        .encode(LOCAL_PWD.as_bytes())
        .unwrap();

        let reply = keep
            .consent_reply(&inbound)
            .unwrap()
            .expect("an authenticated camera check is answered");
        let msg = stun::StunMessage::decode(&reply).unwrap();
        assert!(msg.is_binding_success());
        assert_eq!(&msg.txid, b"camcheck0001");
        assert_eq!(
            msg.xor_mapped_address().unwrap(),
            Some("192.0.2.9:5000".parse().unwrap())
        );
        assert!(stun::verify_message_integrity(&reply, LOCAL_PWD.as_bytes()).unwrap());
    }

    // A Binding Success (a response to OUR own check) is not something to answer.
    #[test]
    fn keepalive_ignores_non_request_stun() {
        let keep = make_keepalive();
        let success = stun::encode_binding_success(
            *b"resp00000001",
            "192.0.2.9:5000".parse().unwrap(),
            REMOTE_PWD.as_bytes(),
        )
        .unwrap();
        assert!(keep.consent_reply(&success).unwrap().is_none());
    }

    // A camera check with the WRONG key (foreign/spoofed) is not answered.
    #[test]
    fn keepalive_ignores_unauthenticated_check() {
        let keep = make_keepalive();
        let spoof = stun::BindingRequest {
            txid: *b"spoof0000001",
            username: format!("{LOCAL_UFRAG}:{REMOTE_UFRAG}"),
            priority: 1,
            role: IceRole::Controlled(1),
            use_candidate: false,
            software: None,
        }
        .encode(b"the-wrong-ice-password00") // secret-scan:allow (synthetic wrong key)
        .unwrap();
        assert!(keep.consent_reply(&spoof).unwrap().is_none());
    }

    // The outbound consent-refresh check is an ICE keepalive to the camera:
    // USERNAME = <remoteUfrag>:<localUfrag>, keyed by the REMOTE pwd, no
    // USE-CANDIDATE (the pair is already nominated).
    #[test]
    fn keepalive_refresh_check_is_outbound_keyed_by_remote_pwd() {
        let keep = make_keepalive();
        let chk = keep.refresh_check().unwrap();
        let msg = stun::StunMessage::decode(&chk).unwrap();
        assert_eq!(msg.msg_type, stun::BINDING_REQUEST);
        assert_eq!(
            msg.attr(stun::ATTR_USERNAME).unwrap(),
            format!("{REMOTE_UFRAG}:{LOCAL_UFRAG}").as_bytes()
        );
        assert!(stun::verify_message_integrity(&chk, REMOTE_PWD.as_bytes()).unwrap());
        assert!(msg.attr(stun::ATTR_USE_CANDIDATE).is_none());
    }

    // STUN packets (which share the media 5-tuple) are split out from media so the
    // suite-3 decoder never sees one (it would fail HMAC and abort the stream).
    #[test]
    fn is_stun_discriminates_stun_from_media() {
        assert!(is_stun(&make_keepalive().refresh_check().unwrap()));
        // A media-ish datagram: KCP conv (4B) then cmd/frg/wnd — bytes[4..8] is not
        // the STUN magic cookie.
        let media = [0x00u8, 0x02, 0x00, 0x01, 0x51, 0x00, 0x00, 0x20, 0xDE, 0xAD];
        assert!(!is_stun(&media));
        assert!(!is_stun(&[0u8; 4])); // too short
    }

    // ── PumpTimers: generous first-media window + steady idle + consent cadence ─
    #[test]
    fn pump_timers_first_media_window_is_generous() {
        // No media yet: a zero first-media window expires immediately; a large one
        // does not (camera startup can exceed 20 s — AC#3).
        let expired = PumpTimers::new(
            Duration::ZERO,
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        assert!(expired
            .idle_reason()
            .is_some_and(|r| r.contains("first frame")));
        let waiting = PumpTimers::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        assert!(waiting.idle_reason().is_none());
    }

    #[test]
    fn pump_timers_steady_idle_only_after_media() {
        let mut t = PumpTimers::new(
            Duration::from_secs(60),
            Duration::ZERO,
            Duration::from_secs(5),
        );
        // Before any media we are still inside the (large) first-media window.
        assert!(t.idle_reason().is_none());
        t.mark_media();
        // Once media flowed, a zero steady-idle window expires immediately.
        assert!(t.idle_reason().is_some_and(|r| r.contains("idle")));
    }

    #[test]
    fn pump_timers_consent_cadence() {
        let due = PumpTimers::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
            Duration::ZERO,
        );
        assert!(due.consent_due(), "a zero interval is always due");
        let mut not_due = PumpTimers::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        assert!(!not_due.consent_due());
        not_due.mark_consent();
        assert!(!not_due.consent_due());
    }
}
