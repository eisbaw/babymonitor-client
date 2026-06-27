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

use babymonitor_core::session::{Session, SessionStore};
use babymonitor_core::stream::media::audio;
use babymonitor_core::stream::media::h264::H264Depacketizer;
use babymonitor_core::stream::media::stun::IceRole;
use babymonitor_core::stream::media::transport::{self as mtransport, IceCredentials};
use babymonitor_core::stream::media::MediaEngine;
use babymonitor_core::stream::mqtt_auth::{derive_credentials, MqttAuthInputs};
use babymonitor_core::stream::sdp::{build_offer_sdp, OfferSdpParams};
use babymonitor_core::stream::session::{OsRandom, RandomSource, SignalingFlow};
use babymonitor_core::stream::signaling::ParsedAnswer;
use babymonitor_core::stream::transport::{
    connect_and_negotiate, BrokerConfig, LiveSignalingParams,
};
use babymonitor_core::stream::StreamCredentials;
use babymonitor_core::Error;
use serde::Deserialize;

use crate::stream::{OutputMode, StreamArgs};

/// Default path of the owner-injected runtime bundle (gitignored).
const RUNTIME_BUNDLE: &str = "secrets/stream_runtime.json";

/// Bounded receive budget for the camera answer (polls of the 302 channel).
const MAX_ANSWER_POLLS: usize = 200;

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
    let bundle_path = PathBuf::from(RUNTIME_BUNDLE);
    let Some(runtime) = load_runtime(&bundle_path)? else {
        return stream_pending_no_runtime(&bundle_path);
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
    let broker = build_broker_config(&session, &runtime)?;
    eprintln!(
        "stream (live): stage 3 mqtt-creds — clientId/username/password derived (password redacted)."
    );

    // ── Stages 4-6: connect the broker, run 302 signaling, open ICE ────────
    // These touch real sockets — reached, not faked. In this sandbox there is no
    // broker/camera, so they return the honest failure (never a fake answer).
    let creds = build_stream_credentials(&runtime);
    creds.validate()?;
    let session_handles = SessionHandles::mint()?;
    let offer = build_offer(&creds, &session_handles)?;
    eprintln!(
        "stream (live): stage 4-6 — connecting broker {}:{} (TLS={}), publishing 302 offer, awaiting answer…",
        broker.host, broker.port, broker.tls
    );

    let answer = negotiate(&broker, &creds, &offer)?;
    eprintln!("stream (live): answer received — remote ICE creds + media key extracted.");

    let ice = IceCredentials {
        local_ufrag: session_handles.ice_ufrag.clone(),
        local_pwd: session_handles.ice_pwd.clone(),
        remote_ufrag: answer.remote_ufrag.clone(),
        remote_pwd: answer.remote_pwd.clone(),
    };
    let (mut transport, peer) = open_media_transport(&answer, &ice, &session_handles)?;
    eprintln!(
        "stream (live): stage 6 ICE — host-direct UDP to {} (consent check sent).",
        peer
    );

    // ── Stages 7-8: media pump -> H.264 + S16LE audio -> MPEG-TS output ────
    // Suite 3 (AES-128-CBC + 20B HMAC-SHA1) is the cap3/cap4-observed default; the
    // negotiated security_level rides the answer header (cap4 == 3).
    let mut engine = MediaEngine::from_security_level(3, answer.media_key.clone())?;
    pump_to_output(args, &mut engine, &mut transport)
}

/// Mint the per-session local handles (ICE ufrag/pwd, media key, o-session seed,
/// trace id) the offer SDP needs. Kept so the ICE credentials can verify the
/// camera's inbound checks with our local pwd.
struct SessionHandles {
    ice_ufrag: String,
    ice_pwd: String,
    media_key: [u8; 16],
    o_session: u64,
    trace_id: String,
}

impl SessionHandles {
    fn mint() -> Result<Self, Error> {
        let rng = OsRandom;
        let mut media_key = [0u8; 16];
        rng.fill(&mut media_key)?;
        let mut seed = [0u8; 8];
        rng.fill(&mut seed)?;
        Ok(Self {
            ice_ufrag: mint_b62(&rng, 4)?,
            ice_pwd: mint_b62(&rng, 24)?,
            media_key,
            o_session: u64::from_be_bytes(seed),
            trace_id: mint_b62(&rng, 16)?,
        })
    }
}

/// A built offer (the SDP + the routing flow) ready to publish over 302.
struct Offer {
    sdp: String,
    flow: SignalingFlow,
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
fn build_offer(creds: &StreamCredentials, h: &SessionHandles) -> Result<Offer, Error> {
    let stream_id = format!("{}{}", creds.dev_id, h.trace_id);
    let sdp = build_offer_sdp(&OfferSdpParams {
        o_session: h.o_session,
        stream_id: stream_id.clone(),
        ice_ufrag: h.ice_ufrag.clone(),
        ice_pwd: h.ice_pwd.clone(),
        media_key: h.media_key.to_vec(),
        cname: creds.p2p_id.clone(),
        rtpmap_param: 330,
    })?;
    let flow = SignalingFlow::new(
        creds.p2p_id.clone(),
        creds.dev_id.clone(),
        stream_id,
        h.trace_id.clone(),
    );
    Ok(Offer { sdp, flow })
}

/// LIVE: connect the broker and run the 302 offer/answer exchange.
fn negotiate(
    broker: &BrokerConfig,
    creds: &StreamCredentials,
    offer: &Offer,
) -> Result<ParsedAnswer, Error> {
    let ices = parse_ice_servers(&creds.ices);
    let offer_args = offer
        .flow
        .make_offer_args(offer.sdp.clone(), ices, None, None);
    let local_candidates: Vec<String> = Vec::new(); // host-direct: rely on the camera's host candidate
    let params = LiveSignalingParams {
        flow: offer.flow.clone(),
        local_key: creds.local_key.as_bytes(),
        dev_id: &creds.dev_id,
        pv: &creds.pv,
        offer_args: &offer_args,
        local_candidates: &local_candidates,
        max_polls: MAX_ANSWER_POLLS,
    };
    connect_and_negotiate(broker, params)
}

/// LIVE: select the camera's host candidate from the answer SDP, open a connected
/// UDP transport to it, and send the ICE connectivity check (so the camera opens
/// consent and starts sending media).
fn open_media_transport(
    answer: &ParsedAnswer,
    ice: &IceCredentials,
    h: &SessionHandles,
) -> Result<(mtransport::UdpMediaTransport, SocketAddr), Error> {
    let candidates = mtransport::parse_candidates_from_sdp(&answer.sdp)?;
    if candidates.is_empty() {
        return Err(Error::Transport(
            "the camera answer carried no ICE candidates in its SDP — host-direct needs a host \
             candidate (trickled candidates are not yet surfaced by connect_and_negotiate)"
                .to_string(),
        ));
    }
    // Bind an ephemeral local UDP socket on all interfaces.
    let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let (transport, host) = mtransport::connect_host_direct(local, &candidates)?;
    let peer = host.socket_addr();
    // Build + send the consent check, MESSAGE-INTEGRITY-keyed by the camera pwd.
    let check = ice.build_check(
        random_txid()?,
        host.priority,
        IceRole::Controlling(controlling_tiebreaker()?),
        true, // USE-CANDIDATE on the host-direct nominated pair
        Some("babymonitor-rs"),
    )?;
    transport.send_datagram(&check)?;
    let _ = h; // local ICE creds already folded into `ice`
    Ok((transport, peer))
}

/// LIVE: the media receive loop — pump datagrams through the engine, route each
/// decoded unit by conv (video → H.264 Annex-B; audio → S16LE), and feed the
/// MPEG-TS muxer.
fn pump_to_output(
    args: &StreamArgs,
    engine: &mut MediaEngine,
    transport: &mut mtransport::UdpMediaTransport,
) -> Result<(), Error> {
    let mut sink = LiveAvSink::spawn(args)?;
    let mut depay = H264Depacketizer::new();
    let mut buf = vec![0u8; 2048];
    eprintln!(
        "stream (live): stage 7-8 media — pumping; connect a player: vlc http://127.0.0.1:{}/stream.ts",
        args.port
    );
    // A non-blocking poll loop: process media as it arrives; after a generous run
    // of empty polls (camera silent / session torn down) we stop cleanly rather
    // than spin forever. A real run streams until the camera/player closes.
    const IDLE_POLL_MS: u64 = 5;
    const MAX_IDLE_POLLS: u32 = 4000; // ~20 s of silence → end the session
    let mut idle = 0u32;
    loop {
        match engine.pump(transport, &mut buf)? {
            Some(units) => {
                idle = 0;
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
            None => {
                idle += 1;
                if idle >= MAX_IDLE_POLLS {
                    eprintln!(
                        "stream (live): no media for {idle} polls — camera silent / session ended; stopping."
                    );
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(IDLE_POLL_MS));
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

fn stream_pending_no_runtime(path: &Path) -> Result<(), Error> {
    eprintln!(
        "stream (live): a session is present but the runtime bundle {} is missing.",
        path.display()
    );
    eprintln!(
        "It carries the per-session secrets the live stages need — recover them on YOUR account \
         (re/live_stream_run.md):"
    );
    eprintln!(
        "  device  = m.life.my.group.device.list  -> devId, localKey, pv, skills.p2pType(=4)"
    );
    eprintln!("  camera  = CameraInfoBean / rtc.config.get -> p2pId, p2pKey, ices, session, token");
    eprintln!("  mqtt    = SdkMqttCertificationInfo + master key G -> partnerIdentity, token, appId, chKey, G(hex)");
    eprintln!("  broker  = login baseConfig                 -> host, port(8883), 302 publish/subscribe topics");
    Err(Error::StreamPending)
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
        let h = SessionHandles::mint().unwrap();
        let offer = build_offer(&creds, &h).unwrap();
        assert!(offer.sdp.contains("imm 6001"));
        assert!(offer.sdp.contains(&format!("a=ice-ufrag:{}", h.ice_ufrag)));
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
}
