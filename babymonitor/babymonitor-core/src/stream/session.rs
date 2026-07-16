//! Transport-neutral Tuya 302 signaling state machine and carrier seams
//! (`re/webrtc_session.md` §5).
//!
//! [`SignalingSession`] drives one selected [`SignalingTransport`]. MQTT wraps
//! the JSON in message-2.2 through [`MqttSignalingTransport`]; authenticated LAN
//! frame type 32 implements the same trait in `lan_transport`. Offline tests use
//! injected carriers, while the production CLI supplies real MQTT or TCP I/O.
//!
//! [`LiveSessionDriver`] is an older injected core seam retained for focused
//! state-machine tests; it intentionally returns [`crate::Error::StreamPending`]
//! after publishing. The complete signaling→ICE/KCP→media live path is the CLI's
//! `stream_live` driver, not this deliberately socket-free helper.

use std::time::Duration;

use crate::stream::connect::{build_connect_v2, ConnectV2Args, LanMode, CONNECT_SESSION_LEN};
use crate::stream::frame::Frame;
use crate::stream::signaling::{
    OfferEnvelopeArgs, ParsedAnswer, SignalingEnvelope, SignalingPath, SignalingType,
};
use crate::stream::StreamCredentials;
use crate::Error;

/// The recovered `rtc_state` lifecycle (`re/webrtc_session.md` §5).
///
/// The numeric enum the native code switches on (session-struct offset `0x1a`)
/// gates all data transfer; the human-readable names are inferred. We expose a
/// host-facing lifecycle that the driver advances; the data path is only valid
/// in [`SessionState::Active`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Before `connect_v2` is issued.
    Idle,
    /// `connect_v2` sent + local offer published; awaiting the answer.
    Connecting,
    /// Answer received; the media AES key has been extracted from the answer SDP.
    Answered,
    /// ICE connectivity + DTLS-SRTP established; frames may flow (native states
    /// 0/5).
    Active,
    /// Session closed/closing (native state 4) or disconnected.
    Closed,
}

impl SessionState {
    /// Whether the data (frame) path is valid in this state. Only [`Active`]
    /// permits frames — matching the native gate (frame pop reached from the
    /// active data-transfer states, `re/webrtc_session.md` §4b/§5).
    ///
    /// [`Active`]: SessionState::Active
    #[must_use]
    pub fn frames_flow(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A source of random bytes for minting the `connect_session` (and trace ids).
///
/// Injected so tests are deterministic and the live path uses real OS entropy.
/// The default [`OsRandom`] reads `/dev/urandom`; a test supplies a fixed source.
pub trait RandomSource {
    /// Fill `buf` with random bytes.
    ///
    /// # Errors
    /// [`Error::StreamConfig`] if entropy cannot be obtained.
    fn fill(&self, buf: &mut [u8]) -> Result<(), Error>;
}

/// OS entropy via `/dev/urandom` (no extra crate dependency).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), Error> {
        use std::io::Read as _;
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| Error::StreamConfig(format!("open /dev/urandom: {e}")))?;
        f.read_exact(buf)
            .map_err(|e| Error::StreamConfig(format!("read /dev/urandom: {e}")))
    }
}

/// The alphabet for the minted `connect_session` — URL-safe-ish base62 so the
/// 33-char id is JSON/SDP/MQTT-safe. (The native `imm_p2p_misc_rand_string`
/// alphabet is not pinned; base62 is a safe superset of what an id needs and the
/// id is client-minted anyway, `re/webrtc_session.md` §1a.)
const SESSION_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Mint a 33-char `connect_session` (native `rand_string(0x21)` length) from the
/// injected [`RandomSource`].
///
/// # Errors
/// Propagates [`Error::StreamConfig`] if the random source fails.
pub fn mint_connect_session<R: RandomSource>(rng: &R) -> Result<String, Error> {
    let mut bytes = [0u8; CONNECT_SESSION_LEN];
    rng.fill(&mut bytes)?;
    let s: String = bytes
        .iter()
        .map(|b| SESSION_ALPHABET[(*b as usize) % SESSION_ALPHABET.len()] as char)
        .collect();
    debug_assert_eq!(s.chars().count(), CONNECT_SESSION_LEN);
    Ok(s)
}

/// Mint an `n`-char base62 token (ICE ufrag/pwd) from the injected
/// [`RandomSource`] — JSON/SDP-safe, like the native `imm_p2p_misc_rand_string`.
///
/// # Errors
/// Propagates [`Error::StreamConfig`] if the random source fails.
fn mint_token<R: RandomSource>(rng: &R, n: usize) -> Result<String, Error> {
    let mut bytes = vec![0u8; n];
    rng.fill(&mut bytes)?;
    Ok(bytes
        .iter()
        .map(|b| SESSION_ALPHABET[(*b as usize) % SESSION_ALPHABET.len()] as char)
        .collect())
}

/// Parse the cloud `P2pConfig.ices` JSON string into typed ICE servers; on any
/// parse failure returns an empty list (the offer still negotiates via the
/// device's own relays — the echoed `token` is advisory).
fn parse_ice_servers(ices: &str) -> Vec<crate::stream::signaling::IceServer> {
    serde_json::from_str(ices).unwrap_or_default()
}

/// The MQTT transport seam: publish/receive 302 payloads.
///
/// The offline tests implement this with an in-memory fake (no broker); the live
/// path implements it with `rumqttc` against the device's Tuya MQTT channel. The
/// payload bytes here are the complete localKey-AES binary message-2.2 frame
/// (built by [`super::mqtt_crypto::build_302_frame`], cap5-pinned + byte-validated);
/// the transport just publishes them verbatim.
pub trait MqttTransport {
    /// Publish an (encrypted) 302 payload to the device's signaling channel.
    ///
    /// # Errors
    /// [`Error::Transport`] on any publish failure.
    fn publish_302(&mut self, dev_id: &str, pv: &str, payload: &[u8]) -> Result<(), Error>;

    /// Try to receive the next inbound (encrypted) 302 payload, if one is ready.
    /// Returns `Ok(None)` when nothing is pending (non-blocking).
    ///
    /// The returned [`Inbound302`] carries the MQTT `topic` the payload landed on
    /// (when the transport knows it — the live `rumqttc` transport fills it; the
    /// offline fake leaves it `None`). The topic drives the TASK-0080 `--diag-topics`
    /// diagnostic (which inbound topic the camera's answer actually arrives on).
    ///
    /// # Errors
    /// [`Error::Transport`] on a receive failure.
    fn try_recv_302(&mut self) -> Result<Option<Inbound302>, Error>;
}

/// One inbound (still-encrypted) 302 payload plus the MQTT `topic` it arrived on.
///
/// `topic` is `Some` on the live `rumqttc` transport (the broker tells us the
/// publish topic) and `None` on the offline fake (no broker). It is used ONLY for
/// the TASK-0080 topic diagnostic logging — never for routing decisions on the
/// strict path.
#[derive(Debug, Clone)]
pub struct Inbound302 {
    /// The MQTT topic the payload was published on, when the transport knows it.
    pub topic: Option<String>,
    /// The localKey-AES-encrypted 302 frame bytes (decrypted by the caller).
    pub payload: Vec<u8>,
}

/// Legacy injected engine seam used by [`LiveSessionDriver`] state-machine tests.
///
/// It models the older standard-WebRTC-shaped driver without selecting a concrete
/// engine. The production CLI does not await a webrtc-rs implementation: it uses
/// [`crate::stream::media::MediaEngine`] for the camera's custom ICE/KCP/AES media
/// protocol after [`SignalingSession`] completes.
pub trait WebRtcEngine {
    /// Create the local OFFER SDP (standard sections). The Tuya `a=aes-key`
    /// application line is spliced in by [`crate::stream::sdp::inject_aes_key`].
    ///
    /// # Errors
    /// [`Error::WebRtcEngine`] on failure.
    fn create_offer(&mut self) -> Result<String, Error>;

    /// Apply the peer's ANSWER SDP (standard sections); ICE/DTLS proceed.
    ///
    /// # Errors
    /// [`Error::WebRtcEngine`] on failure.
    fn set_answer(&mut self, answer_sdp: &str) -> Result<(), Error>;

    /// Add a remote trickle-ICE candidate.
    ///
    /// # Errors
    /// [`Error::WebRtcEngine`] on failure.
    fn add_remote_candidate(&mut self, candidate: &str) -> Result<(), Error>;

    /// Pull the next decoded-payload-ready [`Frame`], if one is available.
    ///
    /// # Errors
    /// [`Error::WebRtcEngine`] on failure.
    fn recv_frame(&mut self) -> Result<Option<Frame>, Error>;
}

/// The live session driver: wires credentials + a transport + an engine into the
/// session lifecycle.
///
/// Borrows its dependencies (the engine + transport are `&mut`) so the caller
/// owns their lifetimes — consistent with the signer's injected-borrow design.
pub struct LiveSessionDriver<'a, T: MqttTransport, E: WebRtcEngine> {
    creds: &'a StreamCredentials,
    transport: &'a mut T,
    engine: &'a mut E,
    state: SessionState,
}

impl<'a, T: MqttTransport, E: WebRtcEngine> LiveSessionDriver<'a, T, E> {
    /// Construct a driver from injected credentials, transport, and engine.
    pub fn new(creds: &'a StreamCredentials, transport: &'a mut T, engine: &'a mut E) -> Self {
        Self {
            creds,
            transport,
            engine,
            state: SessionState::Idle,
        }
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Build the `connect_v2` control JSON for this session from the injected
    /// credentials + a client-minted `connect_session` and `trace_id`.
    ///
    /// This is the testable, RE-derived control-message step (it does NOT touch
    /// the network or the media engine). The live `run` below is what is gated.
    ///
    /// # Errors
    /// Propagates [`Error::StreamConfig`] from credential validation / minting /
    /// the `connect_v2` builder.
    pub fn build_connect_message<R: RandomSource>(
        &self,
        rng: &R,
        trace_id: &str,
    ) -> Result<String, Error> {
        self.creds.validate()?;
        let connect_session = mint_connect_session(rng)?;
        let args = ConnectV2Args {
            remote_id: self.creds.p2p_id.clone(),
            dev_id: self.creds.dev_id.clone(),
            skill: self.creds.skill.clone(),
            // The signaling token is emitted UNQUOTED in connect_v2; the native
            // default for an empty/non-JSON token is `{}`. A real per-session
            // token is JSON-shaped (`re/webrtc_session.md` §1 step 3). If the
            // injected token is a bare string, wrap it so the control JSON stays
            // valid; here we pass it through and let the builder validate.
            token: wrap_token_as_json(&self.creds.token),
            trace_id: trace_id.to_string(),
            timeout_ms: 10_000,
            lan_mode: LanMode::Cloud,
            connect_session,
        };
        build_connect_v2(&args)
    }

    /// Drive the LIVE session: build the `connect_v2` control JSON + the Tuya
    /// `imm` offer SDP, wrap the offer in the binary message-2.2 302 frame
    /// (AES-ECB/localKey, cap5-pinned), and publish it once through the MQTT
    /// transport seam. Then return
    /// [`Error::StreamPending`].
    ///
    /// # Honest gating
    /// The 302 build + publish path is now real (the offline test sees the one
    /// offer frame published through a fake transport). What remains genuinely
    /// gated, so this returns [`Error::StreamPending`] rather than a stream:
    /// 1. **The live broker.** [`super::transport::RumqttcTransport`] needs the
    ///    Tuya MQTT CONNECT creds, whose password is native-derived
    ///    (`ThingNetworkSecurity.doCommandNative(2, ecode)`) and not statically
    ///    recoverable — see `re/mqtt_signaling.md`.
    /// 2. **The media engine.** webrtc-rs (ICE/DTLS-SRTP/depacketize) is a
    ///    follow-up; no media stack ships in this build.
    /// 3. Every runtime credential rides an authenticated device session this
    ///    core module does not establish.
    ///
    /// # Errors
    /// - [`Error::StreamConfig`] if credentials are invalid.
    /// - [`Error::Transport`] if a publish fails.
    /// - [`Error::StreamPending`] otherwise (the honest not-yet-live state).
    pub fn run<R: RandomSource>(&mut self, rng: &R, trace_id: &str) -> Result<(), Error> {
        self.creds.validate()?;

        // 1. The RE-derived connect_v2 control JSON (offline-valid, testable).
        let _connect_json = self.build_connect_message(rng, trace_id)?;

        // 2. Mint the per-session media key + ICE creds and build the Tuya `imm`
        //    offer SDP byte-for-byte (sdp::build_offer_sdp; the custom `imm`
        //    section webrtc-rs does NOT emit). The engine seam owns the answer +
        //    media path; the offer SDP is ours to build.
        let mut media_key = [0u8; 16];
        rng.fill(&mut media_key)?;
        let mut o_seed = [0u8; 8];
        rng.fill(&mut o_seed)?;
        let offer_sdp = crate::stream::sdp::build_offer_sdp(&crate::stream::sdp::OfferSdpParams {
            o_session: u64::from_be_bytes(o_seed),
            stream_id: format!("{}{trace_id}", self.creds.dev_id),
            ice_ufrag: mint_token(rng, 4)?,
            ice_pwd: mint_token(rng, 24)?,
            media_key: media_key.to_vec(),
            cname: self.creds.p2p_id.clone(),
            rtpmap_param: 330,
        })?;

        // 3. Build one MQTT offer and publish it as a 302 frame (the binary
        //    message-2.2 frame, cap5-pinned) via the shared
        //    [`MqttSignalingSession`] orchestrator — the same transport-coupled
        //    layer the live `rumqttc` path uses.
        let flow = SignalingFlow::new(
            self.creds.p2p_id.clone(),
            self.creds.dev_id.clone(),
            format!("{}{trace_id}", self.creds.dev_id),
            trace_id,
        );
        let ices = parse_ice_servers(&self.creds.ices);
        let args = flow.make_offer_args(offer_sdp, ices, None, None);
        {
            let carrier = MqttSignalingTransport::new(
                &mut *self.transport,
                self.creds.local_key.as_bytes().to_vec(),
                self.creds.dev_id.clone(),
                self.creds.pv.clone(),
            );
            let mut session = MqttSignalingSession::new(carrier, flow);
            session.publish_offer(&args)?;
        }
        self.state = SessionState::Connecting;

        // The offer is published, but the live broker creds (native-derived) and
        // the media engine (webrtc-rs) are not present — surface the honest
        // not-yet-live state rather than fabricate a stream.
        Err(Error::StreamPending)
    }

    /// Dispatch one inbound 302 envelope through the engine (the receive path).
    ///
    /// This is the testable dispatch logic (`re/webrtc_session.md` §2c): an
    /// `answer` feeds the SDP to the engine and extracts the media key; a
    /// `candidate` adds a remote ICE candidate; a `disconnect` closes. It runs
    /// against the injected engine seam, so a fake engine exercises it offline.
    ///
    /// # Errors
    /// Propagates engine / SDP errors.
    pub fn dispatch_inbound(&mut self, env: &SignalingEnvelope) -> Result<(), Error> {
        match env.header.r#type {
            SignalingType::Answer => {
                // Parse the answer (validates + extracts media key + remote ICE
                // creds from the SDP), then hand the SDP to the engine.
                let parsed = env.parse_answer()?;
                self.engine.set_answer(&parsed.sdp)?;
                self.state = SessionState::Answered;
                Ok(())
            }
            SignalingType::Candidate => {
                // A trickle candidate carries its line in msg.candidate; an empty
                // string is the end-of-candidates sentinel (cap3) — nothing to add.
                match env.msg.candidate.as_deref() {
                    Some(line) if !line.trim().is_empty() => self.engine.add_remote_candidate(line),
                    _ => Ok(()),
                }
            }
            SignalingType::Disconnect => {
                self.state = SessionState::Closed;
                Ok(())
            }
            SignalingType::Offer => {
                // The client is the offerer; receiving an offer is unexpected on
                // this path. Fail loud rather than silently ignore.
                Err(Error::Transport(
                    "received an unexpected inbound offer (client is the offerer)".into(),
                ))
            }
        }
    }
}

/// The pure signaling **state machine** (`re/webrtc_session.md` §2c + cap3): it
/// owns the routing ids + lifecycle and produces outbound 302 envelopes for the
/// carrier selected by [`SignalingSession`], then ingests
/// the inbound `answer`, emitting the [`ParsedAnswer`] the media engine consumes.
///
/// This is engine- and transport-free, so the offline tests drive the full
/// offer→trickle→answer sequence with no broker and no webrtc-rs. The bytes it
/// emits are validated against `emulator_captures/cap3/signaling_plaintext.jsonl`.
#[derive(Debug, Clone)]
pub struct SignalingFlow {
    from: String,
    to: String,
    sessionid: String,
    trace_id: String,
    p2p_skill: i64,
    security_level: i64,
    state: SessionState,
}

impl SignalingFlow {
    /// Construct a flow from the routing ids (the `from`/`to`/`sessionid` come
    /// from the session; `trace_id` is the client-minted correlation key).
    #[must_use]
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        sessionid: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            sessionid: sessionid.into(),
            trace_id: trace_id.into(),
            p2p_skill: 1635,   // cap3 offer value
            security_level: 3, // cap3 offer value
            state: SessionState::Idle,
        }
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// `header.from` — the app/account **uid** (cap3 offer `header.from` ==
    /// SDP `cname`).
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    /// `header.to` — the camera **devId** (cap3 offer `header.to`).
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// `header.sessionid` — `<devId><unix_seconds><8-rand>` (cap3).
    #[must_use]
    pub fn sessionid(&self) -> &str {
        &self.sessionid
    }

    /// `header.trace_id` — `<uuidv4>_<devId>_<unix_millis>` (cap3); the key the
    /// app correlates the camera answer on.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Whether an inbound envelope belongs to this active negotiation.
    ///
    /// The APK keys its P2P state map by `trace_id`, so an exact trace match is
    /// mandatory. `sessionid` is a second per-run correlation value: peers may
    /// omit it, but a present value must also match. This prevents an
    /// uncorrelated or delayed answer/candidate from being applied to the current
    /// media session.
    #[must_use]
    pub fn correlates(&self, env: &SignalingEnvelope) -> bool {
        env.header.trace_id.as_deref() == Some(self.trace_id.as_str())
            && env
                .header
                .sessionid
                .as_deref()
                .map_or(true, |session| session == self.sessionid)
    }

    /// Build one outbound offer for the selected carrier.
    pub fn offer_envelope(
        &mut self,
        args: &OfferEnvelopeArgs,
        path: SignalingPath,
    ) -> SignalingEnvelope {
        self.state = SessionState::Connecting;
        SignalingEnvelope::offer(args, path)
    }

    /// Build one outbound candidate for the selected carrier.
    #[must_use]
    pub fn candidate_envelope(&self, line: &str, path: SignalingPath) -> SignalingEnvelope {
        SignalingEnvelope::candidate(
            &self.from,
            &self.to,
            &self.sessionid,
            &self.trace_id,
            line,
            path,
        )
    }

    /// Build the [`OfferEnvelopeArgs`] for this flow from a built SDP + the cloud
    /// ICE/relay descriptors — fills the routing ids from the flow so the caller
    /// only supplies the per-session media bits.
    #[must_use]
    pub fn make_offer_args(
        &self,
        sdp: String,
        ice_servers: Vec<crate::stream::signaling::IceServer>,
        tcp_token: Option<crate::stream::signaling::TcpToken>,
        log: Option<serde_json::Value>,
    ) -> OfferEnvelopeArgs {
        // Destructure into owned locals + field shorthand (keeps the routing-id
        // copy in one place).
        let SignalingFlow {
            from,
            to,
            sessionid,
            trace_id,
            p2p_skill,
            security_level,
            ..
        } = self.clone();
        OfferEnvelopeArgs {
            from,
            to,
            sessionid,
            trace_id,
            p2p_skill,
            security_level,
            sdp,
            ice_servers,
            tcp_token,
            log,
        }
    }

    /// Ingest an inbound 302 envelope. An `answer` advances to
    /// [`SessionState::Answered`] and yields the [`ParsedAnswer`]; a `candidate`
    /// or `disconnect` updates state and yields `None`.
    ///
    /// # Errors
    /// - [`Error::Transport`] on an unexpected inbound `offer`.
    /// - propagated parse/SDP errors on a malformed `answer`.
    pub fn ingest(&mut self, env: &SignalingEnvelope) -> Result<Option<ParsedAnswer>, Error> {
        match env.header.r#type {
            SignalingType::Answer => {
                let parsed = env.parse_answer()?;
                self.state = SessionState::Answered;
                Ok(Some(parsed))
            }
            SignalingType::Candidate => Ok(None),
            SignalingType::Disconnect => {
                self.state = SessionState::Closed;
                Ok(None)
            }
            SignalingType::Offer => Err(Error::Transport(
                "received an unexpected inbound offer (client is the offerer)".into(),
            )),
        }
    }
}

/// What a polled inbound 302 envelope means to the signaling client
/// ([`MqttSignalingSession::poll_inbound`]).
#[derive(Debug, Clone)]
pub enum InboundSignal {
    /// The camera's `answer` — carries the remote ICE creds + media AES key +
    /// relay descriptors extracted from the answer SDP (everything the media
    /// engine needs to start ICE/DTLS). Boxed: [`ParsedAnswer`] is large relative
    /// to the other variants.
    Answer(Box<ParsedAnswer>),
    /// A trickle ICE `candidate` line the camera sent (fed to the ICE engine).
    /// The empty end-of-candidates sentinel is filtered out (yields `Ok(None)`).
    RemoteCandidate(String),
    /// The camera tore the session down (`disconnect`).
    Disconnect,
}

/// The full result of a live 302 negotiation: the camera `answer` PLUS every
/// remote ICE candidate the camera **trickled** as separate 302 `candidate`
/// messages.
///
/// This pairing matters because the camera's answer SDP carries **no**
/// `a=candidate:` lines (cap3 + cap4 ground truth: 0 candidates in the answer
/// SDP). The camera trickles its host/srflx candidates as separate `candidate`
/// messages — some interleaved before the answer, most AFTER it — so
/// `remote_candidates`, NOT the answer SDP, is the remote candidate set the media
/// transport selects a host candidate from. A driver that required candidates in
/// the answer SDP would fail every real session even on a LAN.
#[derive(Debug, Clone)]
pub struct NegotiationOutcome {
    /// The parsed camera answer (remote ICE creds + media key + relay descriptors).
    pub answer: ParsedAnswer,
    /// The remote ICE candidate lines (`a=candidate:…`) trickled over 302, in
    /// arrival order and de-duplicated (a carrier may retransmit one).
    /// The empty end-of-candidates sentinel is filtered out.
    pub remote_candidates: Vec<String>,
}

/// One already-unwrapped signaling envelope received from a carrier.
#[derive(Debug, Clone)]
pub struct InboundEnvelope {
    /// Carrier-specific source label used only by diagnostics (the MQTT broker
    /// topic or the stable label `lan`).
    pub source: Option<String>,
    /// Raw `{header,msg}` JSON, with the carrier's framing/authentication removed.
    pub json: Vec<u8>,
}

/// Transport-neutral carrier for Tuya 302 signaling envelopes.
///
/// Implementations own their wire framing and authentication.  The session
/// layer emits exactly one envelope using [`path`](Self::path); it never clones
/// an envelope onto a second carrier.
pub trait SignalingTransport {
    /// Header path placed on every outbound envelope for this carrier.
    fn path(&self) -> SignalingPath;

    /// Authenticate/frame and send one raw signaling JSON document.
    fn send_json(&mut self, json: &[u8]) -> Result<(), Error>;

    /// Receive one authenticated/unframed signaling JSON document, if ready.
    fn try_recv_json(&mut self) -> Result<Option<InboundEnvelope>, Error>;

    /// Frames rejected before yielding JSON. The default suits transports whose
    /// authentication failure is returned as an error; MQTT overrides it because
    /// unrelated protocols share its topic.
    fn rejected_before_json(&self) -> usize {
        0
    }
}

/// Message-2.2 framing adapter that preserves the existing MQTT carrier seam.
///
/// `MqttTransport` remains deliberately low-level (encrypted broker payloads),
/// while this adapter presents the same raw-JSON contract as the local frame-32
/// carrier.  This is the boundary that prevents a `path:"lan"` envelope from
/// accidentally being published to MQTT again.
pub struct MqttSignalingTransport<'a, T: MqttTransport> {
    transport: &'a mut T,
    local_key: Vec<u8>,
    dev_id: String,
    pv: String,
    seq: u32,
    order: u32,
    inbound_undecodable: usize,
}

impl<'a, T: MqttTransport> MqttSignalingTransport<'a, T> {
    /// Wrap an injected low-level MQTT carrier.
    #[must_use]
    pub fn new(
        transport: &'a mut T,
        local_key: Vec<u8>,
        dev_id: impl Into<String>,
        pv: impl Into<String>,
    ) -> Self {
        let (seq, order) = seed_so();
        Self {
            transport,
            local_key,
            dev_id: dev_id.into(),
            pv: pv.into(),
            seq,
            order,
            inbound_undecodable: 0,
        }
    }

    fn next_so(&mut self) -> (u32, u32) {
        let current = (self.seq, self.order);
        self.seq = self.seq.wrapping_add(1);
        self.order = self.order.wrapping_add(1);
        current
    }
}

impl<T: MqttTransport> SignalingTransport for MqttSignalingTransport<'_, T> {
    fn path(&self) -> SignalingPath {
        SignalingPath::Mqtt
    }

    fn send_json(&mut self, json: &[u8]) -> Result<(), Error> {
        let (sequence, order) = self.next_so();
        let frame = crate::stream::mqtt_crypto::build_302_frame(
            json,
            &self.local_key,
            &self.pv,
            sequence,
            order,
            now_unix(),
        )?;
        self.transport.publish_302(&self.dev_id, &self.pv, &frame)
    }

    fn try_recv_json(&mut self) -> Result<Option<InboundEnvelope>, Error> {
        let Some(inbound) = self.transport.try_recv_302()? else {
            return Ok(None);
        };
        let json = match crate::stream::mqtt_crypto::parse_302_frame(
            &inbound.payload,
            &self.local_key,
            &self.pv,
        ) {
            Ok(json) => json,
            Err(error) => {
                self.inbound_undecodable += 1;
                if crate::stream::transport::diag_enabled() {
                    let topic = inbound.topic.as_deref().unwrap_or("<unknown>");
                    eprintln!(
                        "302 diag: inbound on topic='{topic}' is not a decodable 302 frame ({error}); skipped"
                    );
                }
                return Ok(None);
            }
        };
        Ok(Some(InboundEnvelope {
            source: inbound.topic,
            json,
        }))
    }

    fn rejected_before_json(&self) -> usize {
        self.inbound_undecodable
    }
}

/// A 302 signaling session bound to one [`SignalingTransport`]: the engine-free
/// orchestrator that publishes one offer/candidate per selected carrier and
/// parses inbound JSON into [`InboundSignal`]s. MQTT message-2.2 and local Tuya
/// frame-32 authentication live entirely in their carrier adapters.
pub struct SignalingSession<T: SignalingTransport> {
    transport: T,
    flow: SignalingFlow,
    /// Inbound JSON documents yielded by the selected carrier.
    inbound_seen: usize,
    /// Of those, documents that were not valid signaling envelopes.
    inbound_undecodable: usize,
}

/// Cloud compatibility alias: the same transport-neutral session over the
/// message-2.2 MQTT adapter.
pub type MqttSignalingSession<'a, T> = SignalingSession<MqttSignalingTransport<'a, T>>;

/// Seed the `(s, o)` counters from independent OS entropy so no two sessions for
/// the same device alias a `(devId,s,o)` tuple inside the camera's 5 s dedup
/// window (a same-second retry / separate CLI run would otherwise silently get
/// `12003 cloud command repeat`). Best-effort: a time+golden-ratio mix is the
/// fallback if `/dev/urandom` is unreadable (keeps `s != o`).
fn seed_so() -> (u32, u32) {
    let mut b = [0u8; 8];
    if OsRandom.fill(&mut b).is_ok() {
        (
            u32::from_be_bytes(b[0..4].try_into().unwrap()),
            u32::from_be_bytes(b[4..8].try_into().unwrap()),
        )
    } else {
        let t = now_unix() as u32;
        (t, t ^ 0x9E37_79B9)
    }
}

impl<T: SignalingTransport> SignalingSession<T> {
    /// Construct a session over exactly one selected carrier.
    #[must_use]
    pub fn new(transport: T, flow: SignalingFlow) -> Self {
        Self {
            transport,
            flow,
            inbound_seen: 0,
            inbound_undecodable: 0,
        }
    }

    /// The current signaling lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.flow.state()
    }

    /// Serialize and send one envelope through the selected carrier.
    fn publish_envelope(&mut self, env: &SignalingEnvelope) -> Result<(), Error> {
        self.transport.send_json(&env.to_json()?)
    }

    /// Publish the `offer` once over the selected carrier.
    /// Advances the flow to [`SessionState::Connecting`].
    ///
    /// # Errors
    /// [`Error::SignalingParse`]/[`Error::SdpAesKey`] on framing, or
    /// [`Error::Transport`] on a publish failure.
    pub fn publish_offer(&mut self, args: &OfferEnvelopeArgs) -> Result<(), Error> {
        let env = self.flow.offer_envelope(args, self.transport.path());
        self.publish_envelope(&env)
    }

    /// Publish one trickle `candidate` line once over the selected carrier. An
    /// empty `line` is the valid end-of-candidates sentinel (cap3).
    ///
    /// # Errors
    /// As [`publish_offer`](Self::publish_offer).
    pub fn publish_candidate(&mut self, line: &str) -> Result<(), Error> {
        let env = self.flow.candidate_envelope(line, self.transport.path());
        self.publish_envelope(&env)
    }

    /// Poll the selected carrier for the next authenticated 302 JSON, parse it, and
    /// classify it as an [`InboundSignal`]. Non-blocking: `Ok(None)` when nothing
    /// is pending (or an empty-sentinel candidate arrived).
    ///
    /// # Errors
    /// - [`Error::Transport`] on a transport receive failure or an unexpected
    ///   inbound `offer` (the client is the offerer).
    /// - [`Error::SignalingParse`]/[`Error::SdpAesKey`] on a malformed answer.
    pub fn poll_inbound(&mut self) -> Result<Option<InboundSignal>, Error> {
        let Some(inbound) = self.transport.try_recv_json()? else {
            return Ok(None);
        };
        // Count carrier-authenticated JSON so a timeout can distinguish a silent
        // camera from unrelated/invalid inbound data.
        self.inbound_seen += 1;
        let diag = crate::stream::transport::diag_enabled();
        let source = inbound.source.as_deref().unwrap_or("<local>");
        let env = match SignalingEnvelope::from_json(&inbound.json) {
            Ok(env) => env,
            Err(e) => {
                self.inbound_undecodable += 1;
                if diag {
                    eprintln!(
                        "302 diag: inbound from '{source}' is not a signaling envelope ({e}); skipped"
                    );
                }
                return Ok(None);
            }
        };
        if !self.flow.correlates(&env) {
            if diag {
                eprintln!(
                    "302 diag: ignored stale/unrelated {:?} from '{source}' (session/trace mismatch)",
                    env.header.r#type
                );
            }
            return Ok(None);
        }
        if diag {
            // Log carrier source + header.type, never the body.
            eprintln!(
                "302 diag: accepted 302 from '{source}' header.type={:?} (body withheld)",
                env.header.r#type
            );
        }
        match env.header.r#type {
            SignalingType::Answer => {
                let parsed = self.flow.ingest(&env)?.ok_or_else(|| {
                    Error::SignalingParse("answer envelope yielded no ParsedAnswer".to_string())
                })?;
                Ok(Some(InboundSignal::Answer(Box::new(parsed))))
            }
            SignalingType::Candidate => {
                // Advance lifecycle (no-op) + surface a non-empty remote candidate;
                // the empty end-of-candidates sentinel is filtered to None.
                self.flow.ingest(&env)?;
                match env.msg.candidate.as_deref() {
                    Some(line) if !line.trim().is_empty() => {
                        Ok(Some(InboundSignal::RemoteCandidate(line.to_string())))
                    }
                    _ => Ok(None),
                }
            }
            SignalingType::Disconnect => {
                self.flow.ingest(&env)?;
                Ok(Some(InboundSignal::Disconnect))
            }
            SignalingType::Offer => Err(Error::Transport(
                "received an unexpected inbound offer (client is the offerer)".to_string(),
            )),
        }
    }

    /// Drive the full offer/answer exchange AND collect the camera's **trickled**
    /// ICE candidates ([`NegotiationOutcome`]) — the robust live path (TASK-0077).
    ///
    /// Phase 1 (answer wait): publish the `offer`, then each local `candidate`
    /// plus the end-of-candidates sentinel over the selected carrier, then poll up to
    /// `answer_polls` times for the camera `answer`, collecting any remote
    /// `candidate` that arrives interleaved before it.
    ///
    /// Phase 2 (trickle window): after the answer, keep polling up to
    /// `trickle_polls` more times, collecting the remote `candidate` messages the
    /// camera trickles AFTER the answer. This is essential: the answer SDP carries
    /// no `a=candidate:` lines (cap3/cap4), so the host candidate the media
    /// transport needs *only* arrives here. A `disconnect` ends the window early.
    ///
    /// `poll_interval` is slept after an empty (non-blocking) poll to pace the live
    /// carrier; offline tests pass [`Duration::ZERO`] (a no-op sleep)
    /// so they run instantly against a pre-loaded fake transport.
    ///
    /// Transport-generic, so the offline tests run the whole exchange — including
    /// post-answer trickle — through a mock transport with the frames pre-loaded.
    ///
    /// # Errors
    /// - publish/framing errors (see [`publish_offer`](Self::publish_offer));
    /// - [`Error::Transport`] if the camera `disconnect`s before the answer, or if
    ///   no answer arrives within `answer_polls` polls (the honest no-answer state
    ///   — never a fabricated stream).
    pub fn negotiate_with_trickle(
        &mut self,
        offer_args: &OfferEnvelopeArgs,
        local_candidates: &[String],
        answer_polls: usize,
        trickle_polls: usize,
        poll_interval: Duration,
        // Early-exit the trickle window the instant the collected remote candidates
        // are sufficient (e.g. a usable `typ host` arrived) — avoids draining the
        // full `trickle_polls` (~30 s) before the media path can be opened. The live
        // path passes [`has_usable_host_candidate`]; the answer-only `negotiate`
        // wrapper passes `|_| false`.
        stop_when: impl Fn(&[String]) -> bool,
    ) -> Result<NegotiationOutcome, Error> {
        self.publish_offer(offer_args)?;
        for line in local_candidates {
            self.publish_candidate(line)?;
        }
        self.publish_candidate("")?; // end-of-candidates sentinel (cap3)

        let mut remote_candidates: Vec<String> = Vec::new();

        // Phase 1: wait for the answer, collecting any interleaved remote candidate.
        let mut answer: Option<ParsedAnswer> = None;
        for _ in 0..answer_polls {
            match self.poll_inbound()? {
                Some(InboundSignal::Answer(a)) => {
                    answer = Some(*a);
                    break;
                }
                Some(InboundSignal::RemoteCandidate(line)) => {
                    push_unique(&mut remote_candidates, line);
                }
                Some(InboundSignal::Disconnect) => {
                    return Err(Error::Transport(
                        "camera disconnected before sending an answer".to_string(),
                    ));
                }
                None => sleep_nonzero(poll_interval),
            }
        }
        let carrier_undecodable = self.transport.rejected_before_json();
        // JSON yielded by the carrier is already counted in `self.inbound_seen`;
        // add only frames the carrier rejected before it could yield JSON.
        let total_seen = self.inbound_seen + carrier_undecodable;
        let total_undecodable = self.inbound_undecodable + carrier_undecodable;
        let answer = match answer {
            Some(a) => a,
            // Distinguish a silent camera from rejected carrier frames (for MQTT,
            // commonly a wrong localKey/pv). LAN authentication failures surface
            // directly before this loop.
            None if total_seen > 0 && total_seen == total_undecodable => {
                return Err(Error::Transport(format!(
                    "received {} frame(s) on the selected 302 carrier but NONE decoded as a 302 under the \
                     configured localKey/pv — likely a wrong localKey or pv (not camera-silent)",
                    total_seen
                )));
            }
            None => {
                return Err(Error::Transport(format!(
                    "no answer received within {answer_polls} polls (camera silent; \
                     {} inbound frame(s) seen, {} undecodable)",
                    total_seen, total_undecodable
                )));
            }
        };

        // A usable candidate may have arrived interleaved BEFORE the answer — then
        // there is nothing to wait for; skip the trickle window entirely.
        if stop_when(&remote_candidates) {
            return Ok(NegotiationOutcome {
                answer,
                remote_candidates,
            });
        }

        // Phase 2: the trickle window — collect the candidates the camera sends
        // AFTER the answer (the answer SDP itself carries none; cap3/cap4). Stop as
        // soon as `stop_when` is satisfied (a usable host candidate is in hand).
        for _ in 0..trickle_polls {
            match self.poll_inbound()? {
                Some(InboundSignal::RemoteCandidate(line)) => {
                    push_unique(&mut remote_candidates, line);
                    if stop_when(&remote_candidates) {
                        break;
                    }
                }
                Some(InboundSignal::Disconnect) => break,
                // A retransmitted answer is ignored; we already have one.
                Some(InboundSignal::Answer(_)) => {}
                None => sleep_nonzero(poll_interval),
            }
        }

        Ok(NegotiationOutcome {
            answer,
            remote_candidates,
        })
    }

    /// Drive the offer/answer exchange and return just the camera `answer`
    /// (no post-answer trickle window). A thin wrapper over
    /// [`negotiate_with_trickle`](Self::negotiate_with_trickle); the live path uses
    /// the trickle variant so it actually collects the host candidate.
    ///
    /// # Errors
    /// As [`negotiate_with_trickle`](Self::negotiate_with_trickle).
    pub fn negotiate(
        &mut self,
        offer_args: &OfferEnvelopeArgs,
        local_candidates: &[String],
        max_polls: usize,
    ) -> Result<ParsedAnswer, Error> {
        Ok(self
            .negotiate_with_trickle(
                offer_args,
                local_candidates,
                max_polls,
                0,
                Duration::ZERO,
                |_| false,
            )?
            .answer)
    }
}

/// Whether `lines` already contain a usable `typ host` ICE candidate — the
/// early-exit predicate for the trickle window (the host-direct media path needs
/// exactly one). True if any line parses to a [`CandidateKind::Host`].
///
/// [`CandidateKind::Host`]: crate::stream::media::transport::CandidateKind::Host
#[must_use]
pub fn has_usable_host_candidate(lines: &[String]) -> bool {
    use crate::stream::media::transport::{parse_candidate, CandidateKind};
    lines
        .iter()
        .filter_map(|l| parse_candidate(l).ok())
        .any(|c| c.kind == CandidateKind::Host)
}

/// Append `line` to `out` only if not already present. A carrier/camera may
/// retransmit a trickle candidate, so dedupe by exact line.
fn push_unique(out: &mut Vec<String>, line: String) {
    if !out.contains(&line) {
        out.push(line);
    }
}

/// Sleep only for a non-zero duration. A live carrier may pace its non-blocking
/// polls here; offline tests pass
/// [`Duration::ZERO`], for which this is an instant no-op (no scheduler hit).
fn sleep_nonzero(d: Duration) {
    if !d.is_zero() {
        std::thread::sleep(d);
    }
}

/// Current unix time in whole seconds — the outer 302 frame `t` field.
fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// If `token` is already a JSON value, pass it through (the native `%.*s`
/// unquoted emit); otherwise wrap a bare string as a JSON string so the
/// `connect_v2` control JSON stays valid. This makes the seam robust to either
/// shape of injected token without silently corrupting the message.
fn wrap_token_as_json(token: &str) -> String {
    if token.is_empty() {
        return String::new(); // builder defaults empty → {}
    }
    if serde_json::from_str::<serde_json::Value>(token).is_ok() {
        token.to_string()
    } else {
        // Encode as a JSON string literal.
        serde_json::Value::String(token.to_string()).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::test_support::synth_credentials;

    // A deterministic RandomSource for tests (fixed bytes → reproducible id).
    struct FixedRandom(u8);
    impl RandomSource for FixedRandom {
        fn fill(&self, buf: &mut [u8]) -> Result<(), Error> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0.wrapping_add(i as u8);
            }
            Ok(())
        }
    }

    // A fake MQTT transport with an inbound queue (no broker).
    #[derive(Default)]
    struct FakeTransport {
        published: Vec<Vec<u8>>,
        inbound: std::collections::VecDeque<Vec<u8>>,
    }
    impl MqttTransport for FakeTransport {
        fn publish_302(&mut self, _dev_id: &str, _pv: &str, payload: &[u8]) -> Result<(), Error> {
            self.published.push(payload.to_vec());
            Ok(())
        }
        fn try_recv_302(&mut self) -> Result<Option<Inbound302>, Error> {
            Ok(self.inbound.pop_front().map(|payload| Inbound302 {
                topic: None,
                payload,
            }))
        }
    }

    // A fake WebRTC engine recording what the dispatch fed it.
    #[derive(Default)]
    struct FakeEngine {
        answer_sdp: Option<String>,
        candidates: Vec<String>,
    }
    impl WebRtcEngine for FakeEngine {
        fn create_offer(&mut self) -> Result<String, Error> {
            Ok("v=0\r\nm=application 9 x 98\r\na=ice-options:trickle\r\na=mid:2\r\n".into())
        }
        fn set_answer(&mut self, answer_sdp: &str) -> Result<(), Error> {
            self.answer_sdp = Some(answer_sdp.to_string());
            Ok(())
        }
        fn add_remote_candidate(&mut self, candidate: &str) -> Result<(), Error> {
            self.candidates.push(candidate.to_string());
            Ok(())
        }
        fn recv_frame(&mut self) -> Result<Option<Frame>, Error> {
            Ok(None)
        }
    }

    #[test]
    fn mint_connect_session_is_33_chars_alphanumeric() {
        let s = mint_connect_session(&FixedRandom(0)).unwrap();
        assert_eq!(s.chars().count(), CONNECT_SESSION_LEN);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        // Deterministic for a fixed source.
        let s2 = mint_connect_session(&FixedRandom(0)).unwrap();
        assert_eq!(s, s2);
        // Different seed → different id.
        let s3 = mint_connect_session(&FixedRandom(7)).unwrap();
        assert_ne!(s, s3);
    }

    #[test]
    fn build_connect_message_produces_valid_connect_v2() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
        let json = driver
            .build_connect_message(&FixedRandom(1), "trace-xyz")
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["cmd"], "connect_v2");
        assert_eq!(v["args"]["remote_id"], "SYNTH_P2PID_0000");
        assert_eq!(v["args"]["trace_id"], "trace-xyz");
        // 33-char connect_session present.
        assert_eq!(
            v["args"]["connect_session"].as_str().unwrap().len(),
            CONNECT_SESSION_LEN
        );
    }

    // Build a synthetic cap3-shaped answer envelope carrying the given SDP.
    fn answer_env(sdp: &str) -> SignalingEnvelope {
        let json = format!(
            "{{\"header\":{{\"from\":\"DEV\",\"to\":\"USER\",\"path\":\"mqtt\",\
             \"sessionid\":\"SESS\",\"sub_dev_id\":\"\",\"trace_id\":\"trace-1\",\"type\":\"answer\"}},\
             \"msg\":{{\"sdp\":{}}}}}",
            serde_json::Value::String(sdp.to_string())
        );
        SignalingEnvelope::from_json(json.as_bytes()).unwrap()
    }

    // The LIVE driver MUST report StreamPending — never a fake stream — but it now
    // DOES build + publish one MQTT offer before gating.
    #[test]
    fn run_publishes_offer_then_stream_pending() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        {
            let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
            let r = driver.run(&FixedRandom(3), "trace-run");
            assert!(
                matches!(r, Err(Error::StreamPending)),
                "live session is gated on broker creds + media engine; must report pending"
            );
            assert_eq!(driver.state(), SessionState::Connecting);
        }
        // The offer WAS published once; the frame parses back to a
        // valid offer envelope under the device localKey (proves the 302 frame
        // build path is real, not stubbed).
        assert_eq!(t.published.len(), 1, "offer published once over MQTT");
        for frame in &t.published {
            let inner = crate::stream::mqtt_crypto::parse_302_frame(
                frame,
                creds.local_key.as_bytes(),
                &creds.pv,
            )
            .unwrap();
            let env = SignalingEnvelope::from_json(&inner).unwrap();
            assert_eq!(env.header.r#type, SignalingType::Offer);
            assert!(env.msg.sdp.as_deref().unwrap().contains("imm 6001"));
        }
    }

    // NEGATIVE: run with invalid credentials fails on validation FIRST (loud),
    // proving we validate before doing any work.
    #[test]
    fn run_validates_credentials_first() {
        let mut creds = synth_credentials();
        creds.dev_id = String::new();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
        assert!(matches!(
            driver.run(&FixedRandom(0), "trace"),
            Err(Error::StreamConfig(_))
        ));
        assert!(
            t.published.is_empty(),
            "nothing published on a bad-cred run"
        );
    }

    // Dispatch: an ANSWER feeds the SDP to the engine + extracts the media key,
    // and advances the state.
    #[test]
    fn dispatch_answer_feeds_engine_and_extracts_key() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let answer_sdp = "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=ice-options:trickle\r\na=aes-key:00112233445566778899aabbccddeeff\r\na=mid:imm0\r\n";
        let env = answer_env(answer_sdp);
        {
            let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
            driver.dispatch_inbound(&env).unwrap();
            assert_eq!(driver.state(), SessionState::Answered);
            assert!(!driver.state().frames_flow());
        }
        assert_eq!(e.answer_sdp.as_deref(), Some(answer_sdp));
    }

    // Dispatch: a CANDIDATE is added to the engine; an empty (sentinel) one is not.
    #[test]
    fn dispatch_candidate_adds_to_engine() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let env = SignalingEnvelope::candidate(
            "U",
            "D",
            "S",
            "t",
            "a=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\n",
            SignalingPath::Lan,
        );
        let sentinel = SignalingEnvelope::candidate("U", "D", "S", "t", "", SignalingPath::Mqtt);
        {
            let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
            driver.dispatch_inbound(&env).unwrap();
            driver.dispatch_inbound(&sentinel).unwrap(); // empty → no-op
        }
        assert_eq!(
            e.candidates.len(),
            1,
            "only the non-empty candidate is added"
        );
    }

    // NEGATIVE: dispatching an ANSWER with no a=aes-key must error (the media key
    // is mandatory in the answer).
    #[test]
    fn dispatch_answer_without_key_errors() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
        let env =
            answer_env("v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:x\r\na=ice-pwd:y\r\n");
        assert!(matches!(
            driver.dispatch_inbound(&env),
            Err(Error::SdpAesKey(_))
        ));
    }

    // NEGATIVE: an unexpected inbound OFFER (client is the offerer) is rejected.
    #[test]
    fn dispatch_unexpected_offer_errors() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
        let json = br#"{"header":{"type":"offer"},"msg":{"sdp":"v=0\r\n"}}"#;
        let env = SignalingEnvelope::from_json(json).unwrap();
        assert!(matches!(
            driver.dispatch_inbound(&env),
            Err(Error::Transport(_))
        ));
    }

    // The SignalingFlow state machine: one selected carrier's offer → trickle
    // candidate → answer → ParsedAnswer, advancing state at each step.
    #[test]
    fn signaling_flow_offer_trickle_answer() {
        use crate::stream::signaling::IceServer;
        let mut flow = SignalingFlow::new("USER", "DEV", "SESS", "trace-1");
        assert_eq!(flow.state(), SessionState::Idle);

        let sdp = crate::stream::sdp::build_offer_sdp(&crate::stream::sdp::OfferSdpParams {
            o_session: 1782489574,
            stream_id: "SESS".into(),
            ice_ufrag: "SYN1".into(),
            ice_pwd: "SYNTHICEPWD1111111111111".into(),
            media_key: vec![0u8; 16],
            cname: "USER".into(),
            rtpmap_param: 330,
        })
        .unwrap();
        let args = flow.make_offer_args(
            sdp,
            vec![IceServer {
                urls: "stun:1.2.3.4:3478".into(),
                username: None,
                credential: None,
                ttl: None,
            }],
            None,
            None,
        );
        let offer = flow.offer_envelope(&args, SignalingPath::Mqtt);
        assert_eq!(flow.state(), SessionState::Connecting);
        assert_eq!(offer.header.path, Some(SignalingPath::Mqtt));
        assert!(offer.msg.sdp.as_deref().unwrap().contains("imm 6001"));

        let cand = flow.candidate_envelope(
            "a=candidate:1 1 UDP 2130706431 10.0.2.15 58363 typ host\r\n",
            SignalingPath::Mqtt,
        );
        assert_eq!(cand.header.r#type, SignalingType::Candidate);

        // A candidate ingests to None; an answer ingests to ParsedAnswer.
        assert!(flow.ingest(&cand).unwrap().is_none());
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        let parsed = flow
            .ingest(&answer)
            .unwrap()
            .expect("answer yields ParsedAnswer");
        assert_eq!(flow.state(), SessionState::Answered);
        assert_eq!(parsed.remote_ufrag, "SYN0");
        assert_eq!(parsed.media_key.len(), 16);
    }

    // NEGATIVE: the flow rejects an unexpected inbound offer.
    #[test]
    fn signaling_flow_rejects_inbound_offer() {
        let mut flow = SignalingFlow::new("U", "D", "S", "t");
        let json = br#"{"header":{"type":"offer"},"msg":{"sdp":"v=0\r\n"}}"#;
        let env = SignalingEnvelope::from_json(json).unwrap();
        assert!(matches!(flow.ingest(&env), Err(Error::Transport(_))));
    }

    // ── MqttSignalingSession (transport-coupled orchestrator) ──────────────
    // These drive the publish/poll/answer wiring through the in-memory
    // FakeTransport — NO broker — proving the live rumqttc path's logic offline.

    const SYNTH_LK: &[u8; 16] = b"0123456789abcdef"; // secret-scan:allow (synthetic test key)

    fn synth_offer_args() -> OfferEnvelopeArgs {
        let sdp = crate::stream::sdp::build_offer_sdp(&crate::stream::sdp::OfferSdpParams {
            o_session: 1782489574,
            stream_id: "SESS".into(),
            ice_ufrag: "SYN1".into(),
            ice_pwd: "SYNTHICEPWD1111111111111".into(),
            media_key: vec![0u8; 16],
            cname: "USER".into(),
            rtpmap_param: 330,
        })
        .unwrap();
        SignalingFlow::new("USER", "DEV", "SESS", "trace-1").make_offer_args(
            sdp,
            vec![],
            None,
            None,
        )
    }

    // Build an inbound 302 FRAME (message-2.2 binary frame: pv+crc+s+o+AES) from an
    // envelope, exactly as the camera would put it on the wire.
    fn frame_for(env: &SignalingEnvelope) -> Vec<u8> {
        let inner = env.to_json().unwrap();
        crate::stream::mqtt_crypto::build_302_frame(&inner, SYNTH_LK, "2.2", 1, 1, 0).unwrap()
    }

    fn new_session(t: &mut FakeTransport) -> MqttSignalingSession<'_, FakeTransport> {
        let carrier = MqttSignalingTransport::new(t, SYNTH_LK.to_vec(), "DEV", "2.2");
        MqttSignalingSession::new(
            carrier,
            SignalingFlow::new("USER", "DEV", "SESS", "trace-1"),
        )
    }

    // Publish: the offer + a candidate each go out exactly once over MQTT,
    // and each published payload decrypts back to the right type/path under the
    // device localKey (proves the framing is real, not stubbed).
    #[test]
    fn session_publishes_offer_and_candidates_once_on_selected_path() {
        let mut t = FakeTransport::default();
        let args = synth_offer_args();
        {
            let mut s = new_session(&mut t);
            s.publish_offer(&args).unwrap();
            s.publish_candidate("a=candidate:1 1 UDP 2130706431 10.0.2.15 58363 typ host\r\n")
                .unwrap();
            assert_eq!(s.state(), SessionState::Connecting);
        }
        assert_eq!(t.published.len(), 2, "offer + candidate are each sent once");
        let mut got = Vec::new();
        for (i, frame) in t.published.iter().enumerate() {
            let inner =
                crate::stream::mqtt_crypto::parse_302_frame(frame, SYNTH_LK, "2.2").unwrap();
            let env = SignalingEnvelope::from_json(&inner).unwrap();
            let want = if i == 0 {
                SignalingType::Offer
            } else {
                SignalingType::Candidate
            };
            assert_eq!(env.header.r#type, want);
            got.push(env.header.path.unwrap());
        }
        assert_eq!(got, vec![SignalingPath::Mqtt, SignalingPath::Mqtt]);
    }

    // Poll: an inbound answer frame decrypts + parses into an Answer signal that
    // carries the camera's ICE ufrag/pwd + 16-byte media key; state → Answered.
    #[test]
    fn session_poll_parses_inbound_answer() {
        let mut t = FakeTransport::default();
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        t.inbound.push_back(frame_for(&answer));
        let mut s = new_session(&mut t);
        match s.poll_inbound().unwrap().expect("answer surfaced") {
            InboundSignal::Answer(a) => {
                assert_eq!(a.remote_ufrag, "SYN0");
                assert_eq!(a.remote_pwd, "SYNTHICEPWD0000000000000");
                assert_eq!(a.media_key.len(), 16);
            }
            other => panic!("expected Answer, got {other:?}"),
        }
        assert_eq!(s.state(), SessionState::Answered);
        // Inbound drained → next poll is None.
        assert!(s.poll_inbound().unwrap().is_none());
    }

    #[test]
    fn session_ignores_wrong_trace_and_session_before_current_answer() {
        let sdp = "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n";
        let mut wrong_trace = answer_env(sdp);
        wrong_trace.header.trace_id = Some("stale-trace".to_string());
        let mut wrong_session = answer_env(sdp);
        wrong_session.header.sessionid = Some("STALE-SESSION".to_string());
        let mut uncorrelated = answer_env(sdp);
        uncorrelated.header.trace_id = None;
        uncorrelated.header.sessionid = None;
        let current = answer_env(sdp);

        let mut t = FakeTransport::default();
        t.inbound.push_back(frame_for(&wrong_trace));
        t.inbound.push_back(frame_for(&wrong_session));
        t.inbound.push_back(frame_for(&uncorrelated));
        t.inbound.push_back(frame_for(&current));
        let mut session = new_session(&mut t);
        assert!(session.poll_inbound().unwrap().is_none());
        assert!(session.poll_inbound().unwrap().is_none());
        assert!(session.poll_inbound().unwrap().is_none());
        assert!(matches!(
            session.poll_inbound().unwrap(),
            Some(InboundSignal::Answer(_))
        ));
    }

    // Poll: a non-empty inbound candidate surfaces as RemoteCandidate; the empty
    // end-of-candidates sentinel is filtered to None.
    #[test]
    fn session_poll_surfaces_remote_candidate_and_filters_sentinel() {
        let mut t = FakeTransport::default();
        let cand = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            "a=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\n",
            SignalingPath::Mqtt,
        );
        let sentinel =
            SignalingEnvelope::candidate("DEV", "USER", "SESS", "trace-1", "", SignalingPath::Mqtt);
        t.inbound.push_back(frame_for(&cand));
        t.inbound.push_back(frame_for(&sentinel));
        let mut s = new_session(&mut t);
        match s.poll_inbound().unwrap() {
            Some(InboundSignal::RemoteCandidate(line)) => assert!(line.contains("typ host")),
            other => panic!("expected RemoteCandidate, got {other:?}"),
        }
        assert!(
            s.poll_inbound().unwrap().is_none(),
            "empty sentinel candidate yields None"
        );
    }

    // NEGATIVE: an inbound OFFER (client is the offerer) is rejected loud.
    #[test]
    fn session_poll_rejects_inbound_offer() {
        let mut t = FakeTransport::default();
        let args = synth_offer_args();
        let offer = SignalingEnvelope::offer(&args, SignalingPath::Mqtt);
        t.inbound.push_back(frame_for(&offer));
        let mut s = new_session(&mut t);
        assert!(matches!(s.poll_inbound(), Err(Error::Transport(_))));
    }

    // Poll on an empty transport is a non-blocking None.
    #[test]
    fn session_poll_none_when_empty() {
        let mut t = FakeTransport::default();
        let mut s = new_session(&mut t);
        assert!(s.poll_inbound().unwrap().is_none());
    }

    // NEGATIVE: a frame built under one localKey cannot be decrypted with another
    // — an inbound frame we cannot decrypt (wrong localKey, or any junk/other-
    //   protocol frame the camera multiplexes onto our topic) is SKIPPED, never
    //   returned as garbage and never an abort. (Validated live: the camera sends
    //   `protocol:23` status frames on `smart/mb/in/<devId>` interleaved with the
    //   real Answer/Candidate 302s; aborting on them would kill the negotiation.)
    #[test]
    fn session_poll_skips_undecodable_inbound() {
        let mut t = FakeTransport::default();
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:x\r\na=ice-pwd:y\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        t.inbound.push_back(frame_for(&answer)); // built with SYNTH_LK
        let carrier = MqttSignalingTransport::new(
            &mut t,
            b"fedcba9876543210".to_vec(), // secret-scan:allow (synthetic wrong key)
            "DEV",
            "2.2",
        );
        let mut s =
            MqttSignalingSession::new(carrier, SignalingFlow::new("USER", "DEV", "SESS", "t"));
        // Wrong key ⇒ the frame is undecodable ⇒ skipped (Ok(None)), not an error.
        assert!(s.poll_inbound().unwrap().is_none());
    }

    // negotiate(): publish offer + candidate + sentinel once each, then poll
    // for the pre-loaded answer and return the ParsedAnswer. Full exchange offline.
    #[test]
    fn session_negotiate_full_exchange_returns_answer() {
        let mut t = FakeTransport::default();
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        t.inbound.push_back(frame_for(&answer));
        let args = synth_offer_args();
        let cands = vec!["a=candidate:1 1 UDP 2130706431 10.0.2.15 58363 typ host\r\n".to_string()];
        let parsed = {
            let mut s = new_session(&mut t);
            s.negotiate(&args, &cands, 4).expect("answer negotiated")
        };
        assert_eq!(parsed.remote_ufrag, "SYN0");
        assert_eq!(parsed.media_key.len(), 16);
        // offer + one candidate + end-of-candidates sentinel = 3 frames.
        assert_eq!(t.published.len(), 3);
    }

    // A wrong localKey must NOT be reported as "camera silent": frames arrive on
    // the topic but none decode, so negotiate surfaces a DISTINCT misconfig error
    // (restores the fail-fast diagnostic the skip-undecodable change would mask).
    #[test]
    fn session_negotiate_wrong_localkey_reports_distinct_error() {
        let mut t = FakeTransport::default();
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:x\r\na=ice-pwd:y\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        // Frames built under SYNTH_LK; the session below uses a DIFFERENT key, so
        // every arrived frame is undecodable.
        t.inbound.push_back(frame_for(&answer));
        t.inbound.push_back(frame_for(&answer));
        let args = synth_offer_args();
        let cands: Vec<String> = Vec::new();
        let err = {
            let carrier = MqttSignalingTransport::new(
                &mut t,
                b"fedcba9876543210".to_vec(), // secret-scan:allow (synthetic wrong key)
                "DEV",
                "2.2",
            );
            let mut s =
                MqttSignalingSession::new(carrier, SignalingFlow::new("USER", "DEV", "SESS", "t"));
            s.negotiate(&args, &cands, 8)
                .expect_err("wrong localKey must not negotiate an answer")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("wrong localKey") && !msg.contains("camera silent"),
            "expected a distinct wrong-localKey diagnostic, got: {msg}"
        );
    }

    // negotiate_with_trickle(): the camera's host candidate arrives as TRICKLED
    // 302 `candidate` messages (the answer SDP carries none — cap3/cap4). Phase 2
    // must collect the post-answer candidates; retransmitted duplicates are
    // deduped, the empty end-of-candidates sentinel is filtered, and a candidate
    // interleaved BEFORE the answer is collected too.
    #[test]
    fn session_negotiate_with_trickle_collects_post_answer_candidates() {
        let mut t = FakeTransport::default();
        let cand_pre = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            "a=candidate:1 1 UDP 1694498815 192.0.2.7 60862 typ srflx\r\n",
            SignalingPath::Mqtt,
        );
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        // Same host candidate line retransmitted after the answer.
        let host_line = "a=candidate:2 1 UDP 2130706431 10.0.2.15 58363 typ host\r\n";
        let host = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            host_line,
            SignalingPath::Mqtt,
        );
        let host_retransmit = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            host_line,
            SignalingPath::Mqtt,
        );
        let sentinel =
            SignalingEnvelope::candidate("DEV", "USER", "SESS", "trace-1", "", SignalingPath::Mqtt);
        for f in [&cand_pre, &answer, &host, &host_retransmit, &sentinel] {
            t.inbound.push_back(frame_for(f));
        }
        let args = synth_offer_args();
        let outcome = {
            let mut s = new_session(&mut t);
            // `|_| false` keeps the FULL drain (regression guard) so both the
            // pre-answer srflx and the post-answer host candidate are collected.
            s.negotiate_with_trickle(&args, &[], 4, 8, std::time::Duration::ZERO, |_| false)
                .expect("answer negotiated with trickle")
        };
        assert_eq!(outcome.answer.remote_ufrag, "SYN0");
        assert_eq!(outcome.answer.media_key.len(), 16);
        // srflx (pre-answer) + host (post-answer, deduped) = 2.
        assert_eq!(
            outcome.remote_candidates.len(),
            2,
            "srflx + host, the retransmitted host deduped"
        );
        assert!(outcome
            .remote_candidates
            .iter()
            .any(|c| c.contains("typ host")));
        assert!(outcome
            .remote_candidates
            .iter()
            .any(|c| c.contains("typ srflx")));
    }

    // negotiate_with_trickle(): an answer with NO trickled candidates still returns
    // the answer with an empty candidate set (the caller decides how to proceed —
    // it does NOT error here; the no-candidate decision belongs to the media layer).
    #[test]
    fn session_negotiate_with_trickle_answer_without_candidates() {
        let mut t = FakeTransport::default();
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        t.inbound.push_back(frame_for(&answer));
        let args = synth_offer_args();
        let mut s = new_session(&mut t);
        let outcome = s
            .negotiate_with_trickle(&args, &[], 4, 4, std::time::Duration::ZERO, |_| false)
            .unwrap();
        assert_eq!(outcome.answer.remote_ufrag, "SYN0");
        assert!(outcome.remote_candidates.is_empty());
    }

    // negotiate_with_trickle() early-exits phase 2 the instant a usable `typ host`
    // candidate is collected (does NOT drain the full trickle window) — the
    // TASK-0083 time-to-first-frame fix.
    #[test]
    fn session_negotiate_with_trickle_early_exits_on_host_candidate() {
        let mut t = FakeTransport::default();
        let answer = answer_env(
            "v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
        );
        t.inbound.push_back(frame_for(&answer));
        // One post-answer host candidate retransmitted twice, then nothing.
        let host = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            "a=candidate:1 1 UDP 2130706431 10.0.2.15 58363 typ host\r\n",
            SignalingPath::Mqtt,
        );
        t.inbound.push_back(frame_for(&host));
        let args = synth_offer_args();
        // A LARGE trickle budget: if early-exit works, it returns without exhausting
        // it (the FakeTransport has no more frames, so a full drain would still
        // return, but this asserts the host candidate IS collected promptly).
        let mut s = new_session(&mut t);
        let outcome = s
            .negotiate_with_trickle(
                &args,
                &[],
                4,
                10_000,
                std::time::Duration::ZERO,
                super::has_usable_host_candidate,
            )
            .unwrap();
        assert!(super::has_usable_host_candidate(&outcome.remote_candidates));
    }

    // NEGATIVE: no answer within the poll budget is the honest no-answer state
    // (a typed Transport error), NOT a fabricated success.
    #[test]
    fn session_negotiate_times_out_without_answer() {
        let mut t = FakeTransport::default();
        let args = synth_offer_args();
        let mut s = new_session(&mut t);
        assert!(matches!(
            s.negotiate(&args, &[], 3),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a camera disconnect before the answer aborts negotiation loudly.
    #[test]
    fn session_negotiate_errors_on_disconnect() {
        let mut t = FakeTransport::default();
        let disc =
            SignalingEnvelope::from_json(br#"{"header":{"type":"disconnect"},"msg":{}}"#).unwrap();
        t.inbound.push_back(frame_for(&disc));
        let args = synth_offer_args();
        let mut s = new_session(&mut t);
        assert!(matches!(
            s.negotiate(&args, &[], 4),
            Err(Error::Transport(_))
        ));
    }

    #[test]
    fn session_state_frames_flow_only_when_active() {
        assert!(SessionState::Active.frames_flow());
        assert!(!SessionState::Idle.frames_flow());
        assert!(!SessionState::Connecting.frames_flow());
        assert!(!SessionState::Answered.frames_flow());
        assert!(!SessionState::Closed.frames_flow());
    }
}
