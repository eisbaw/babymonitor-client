//! The session state machine + the engine/transport trait seams + the
//! (#[ignore]d) live driver (`re/webrtc_session.md` §5).
//!
//! This ties the Tuya-custom protocol pieces together into a driveable session
//! lifecycle, WITHOUT pulling in the standard-WebRTC media stack (webrtc-rs) or a
//! live MQTT broker. The media engine and the MQTT transport are **trait seams**
//! ([`WebRtcEngine`], [`MqttTransport`]) so:
//! - the offline tests drive the state machine through a fake transport / engine;
//! - the real webrtc-rs engine + rumqttc transport plug in WITHOUT changing the
//!   protocol layer (the webrtc-rs wiring is a filed follow-up, TASK-0037).
//!
//! # The driver is honestly gated (TASK-0034 AC#2)
//! [`LiveSessionDriver::run`] returns [`crate::Error::StreamPending`]: it cannot
//! actually stream because every runtime input is auth-gated (no token / device
//! creds — TASK-0032 + Wave-2 auth) and the media engine is a follow-up. This is
//! the signer's discipline: never a fake stream, never `todo!()`.

use crate::stream::connect::{build_connect_v2, ConnectV2Args, LanMode, CONNECT_SESSION_LEN};
use crate::stream::frame::Frame;
use crate::stream::signaling::{SignalingEnvelope, SignalingType};
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

/// The MQTT transport seam: publish/receive 302 payloads.
///
/// The offline tests implement this with an in-memory fake (no broker); the live
/// path implements it with `rumqttc` against the device's Tuya MQTT channel. The
/// payload bytes here are the ALREADY-localKey-AES-encrypted 302 payload (the AES
/// primitive lives in [`super::mqtt_crypto`] and is recovered; the full envelope
/// variant/framing assembly is the part still live-gated).
pub trait MqttTransport {
    /// Publish an (encrypted) 302 payload to the device's signaling channel.
    ///
    /// # Errors
    /// [`Error::Transport`] on any publish failure.
    fn publish_302(&mut self, dev_id: &str, pv: &str, payload: &[u8]) -> Result<(), Error>;

    /// Try to receive the next inbound (encrypted) 302 payload, if one is ready.
    /// Returns `Ok(None)` when nothing is pending (non-blocking).
    ///
    /// # Errors
    /// [`Error::Transport`] on a receive failure.
    fn try_recv_302(&mut self) -> Result<Option<Vec<u8>>, Error>;
}

/// The standard-WebRTC engine seam (webrtc-rs's job — a filed follow-up).
///
/// The protocol layer hands the engine the negotiated SDP / media key and pulls
/// de-paid frames; the engine owns the PeerConnection / ICE / DTLS-SRTP / SRTP /
/// RTP-depacketize. No implementation ships in this static-only build — see the
/// module-level webrtc-rs decision.
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

    /// Drive the LIVE session to first frame.
    ///
    /// # Honest gating (TASK-0034 AC#2)
    /// This CANNOT run in the current state and returns
    /// [`Error::StreamPending`]: the 302-payload AES primitive is now implemented
    /// (AES-128/ECB/PKCS5, key=localKey — [`super::mqtt_crypto`]), but the 302
    /// envelope assembly is still pending ([`super::mqtt_crypto::encrypt_302_payload`]
    /// returns [`Error::MqttEnvelopePending`]: the pv→output-variant binding +
    /// outer framing need a live capture — TASK-0037), the WebRTC media engine is
    /// a follow-up (no webrtc-rs in this build), and every runtime credential is
    /// auth-gated and absent (TASK-0032 + Wave-2 auth). We surface that honestly
    /// rather than fabricate a stream. The credential validation DOES run first,
    /// so a misconfigured call still fails loud with the precise reason.
    ///
    /// # Errors
    /// - [`Error::StreamConfig`] if credentials are invalid.
    /// - [`Error::StreamPending`] otherwise (the honest not-yet-live state).
    pub fn run<R: RandomSource>(&mut self, rng: &R, trace_id: &str) -> Result<(), Error> {
        self.creds.validate()?;
        self.state = SessionState::Connecting;

        // Build the (offline-valid) connect_v2 control JSON + the local offer,
        // splice the media key into the offer's application section, wrap it in a
        // 302 envelope — all of which is RE-derived and testable. Then ATTEMPT to
        // assemble the full 302 publish payload via the transport seam. The AES
        // PRIMITIVE itself is now recovered + implemented (AES-128/ECB/PKCS5,
        // key=localKey — `mqtt_crypto::aes128_ecb_encrypt`); the honest gate now
        // bites only on the FULL ENVELOPE: the pv→output-variant binding for code
        // 302 + the outer Tuya MQTT framing are unpinned (no live capture), so a
        // publishable payload cannot be assembled yet. We exercise the real seam
        // up to that point rather than short-circuiting (no dead code).
        let connect_json = self.build_connect_message(rng, trace_id)?;

        // The offer SDP comes from the (follow-up) WebRTC engine; building it
        // here proves the engine seam is wired. The Tuya media key would be
        // minted and injected via sdp::inject_aes_key at the integration site.
        let _offer = self.engine.create_offer()?;

        // Assemble the 302 publish payload from the control JSON + device
        // localKey. The AES bytes are produced, but the variant/framing binding
        // is unpinned, so this returns MqttEnvelopePending in this build.
        match crate::stream::mqtt_crypto::encrypt_302_payload(
            connect_json.as_bytes(),
            self.creds.local_key.as_bytes(),
            &self.creds.pv,
        ) {
            Ok(payload) => {
                // Once the pv→variant binding + framing are pinned, we publish
                // here. Unreachable today, but it keeps the transport seam wired.
                self.transport
                    .publish_302(&self.creds.dev_id, &self.creds.pv, &payload)?;
            }
            Err(Error::MqttEnvelopePending) => {
                // Expected: the AES bytes are computed, but the 302 envelope
                // variant/framing is unpinned. Fall through to StreamPending.
            }
            Err(other) => return Err(other),
        }

        // Even if the crypto were available, the live media engine (webrtc-rs)
        // is a follow-up and every runtime credential is auth-gated. Surface the
        // honest not-yet-live state rather than a fabricated stream.
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
                // Extract the Tuya media key (validates the answer carries one),
                // then hand the standard SDP to the engine.
                let _media_key = crate::stream::sdp::extract_aes_key(&env.msg)?;
                self.engine.set_answer(&env.msg)?;
                self.state = SessionState::Answered;
                Ok(())
            }
            SignalingType::Candidate => self.engine.add_remote_candidate(&env.msg),
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
        fn try_recv_302(&mut self) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.inbound.pop_front())
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

    // The LIVE driver MUST report StreamPending — never a fake stream. Prove it.
    #[test]
    fn run_is_stream_pending() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        {
            let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
            let r = driver.run(&FixedRandom(3), "trace-run");
            assert!(
                matches!(r, Err(Error::StreamPending)),
                "the live session cannot stream (auth + media engine gated); must report pending"
            );
        }
        // The transport was wired but never published (the AES bytes compute, but
        // the 302 envelope variant/framing assembly is still pending).
        assert!(
            t.published.is_empty(),
            "no 302 published while the envelope assembly is pending"
        );
    }

    // NEGATIVE: run with invalid credentials fails on validation FIRST (loud),
    // proving we validate before reporting pending.
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
    }

    // Dispatch: an ANSWER feeds the SDP to the engine + extracts the media key,
    // and advances the state.
    #[test]
    fn dispatch_answer_feeds_engine_and_extracts_key() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let answer_sdp = "v=0\r\nm=application 9 x 98\r\na=ice-options:trickle\r\na=aes-key:deadbeef\r\na=mid:2\r\n";
        let env = SignalingEnvelope {
            header: crate::stream::signaling::SignalingHeader {
                r#type: SignalingType::Answer,
                from: None,
                to: None,
                sessionid: None,
                trace_id: Some("t".into()),
                moto_id: None,
            },
            msg: answer_sdp.to_string(),
            token: "tok".into(),
        };
        // Scope the driver so its &mut borrows end before we read the fakes.
        {
            let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
            driver.dispatch_inbound(&env).unwrap();
            assert_eq!(driver.state(), SessionState::Answered);
            assert!(!driver.state().frames_flow());
        }
        // The engine got the answer SDP.
        assert_eq!(e.answer_sdp.as_deref(), Some(answer_sdp));
    }

    // Dispatch: a CANDIDATE is added to the engine.
    #[test]
    fn dispatch_candidate_adds_to_engine() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let env = SignalingEnvelope {
            header: crate::stream::signaling::SignalingHeader {
                r#type: SignalingType::Candidate,
                from: None,
                to: None,
                sessionid: None,
                trace_id: None,
                moto_id: None,
            },
            msg: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host".into(),
            token: "tok".into(),
        };
        {
            let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
            driver.dispatch_inbound(&env).unwrap();
        }
        assert_eq!(e.candidates.len(), 1);
    }

    // NEGATIVE: dispatching an ANSWER with no a=aes-key must error (the media key
    // is mandatory in the answer).
    #[test]
    fn dispatch_answer_without_key_errors() {
        let creds = synth_credentials();
        let mut t = FakeTransport::default();
        let mut e = FakeEngine::default();
        let mut driver = LiveSessionDriver::new(&creds, &mut t, &mut e);
        let env = SignalingEnvelope {
            header: crate::stream::signaling::SignalingHeader {
                r#type: SignalingType::Answer,
                from: None,
                to: None,
                sessionid: None,
                trace_id: None,
                moto_id: None,
            },
            msg: "v=0\r\nm=audio 9 x 0\r\na=mid:0\r\n".into(),
            token: "tok".into(),
        };
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
        let env = SignalingEnvelope::offer("v=0\r\n", "tok", "trace");
        assert!(matches!(
            driver.dispatch_inbound(&env),
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
