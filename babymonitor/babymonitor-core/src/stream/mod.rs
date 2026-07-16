//! Tuya WebRTC-over-MQTT live A/V session client (the RE-derived Tuya-custom
//! protocol layer).
//!
//! This module implements the **Tuya-custom delta** of the live-stream session —
//! the part that standard WebRTC (webrtc-rs) does NOT cover and that the reverse
//! engineering of `libThingP2PSDK.so` + the Java `P2PMQTTServiceManager` actually
//! recovered (`re/webrtc_session.md`, the implementable spec). Concretely:
//!
//! - [`signaling`] — the MQTT **302** inner-envelope `{header, msg}` serde codec
//!   (offer/answer/candidate), matching the cap3 capture: `msg` is an OBJECT
//!   (`{sdp|candidate, token:[ices], tcp_token, log}`), not a string
//!   (`re/webrtc_session.md` §2 + `emulator_captures/cap3/signaling_plaintext.jsonl`).
//! - [`mqtt_crypto`] — the SDP `a=aes-key:<hex>` media-key hex codec (byte-exact,
//!   `re/webrtc_session.md` §3c) + the 302 localKey-AES (AES-128/ECB/PKCS5,
//!   key=localKey, no IV) wrapped in the **binary Tuya message-2.2 frame**
//!   (`pv ++ crc32 ++ s ++ o ++ AES`, cap5-pinned — `re/mqtt_2_2_frame.md`).
//! - [`connect`] — the `connect_v2` control-JSON builder (byte-exact template,
//!   `re/webrtc_session.md` §1).
//! - [`sdp`] — parse/emit the Tuya-custom `m=application` + `a=aes-key` section
//!   (`re/webrtc_session.md` §3c).
//! - [`frame`] — the `imm_p2p_rtc_frame_t` → typed [`frame::Frame`] model + codec
//!   ids (`re/webrtc_session.md` §4).
//! - [`media`] — the cap3 **PATH A** media receive→decode engine
//!   ([`media::MediaEngine`]): UDP → (suite-3) HMAC verify+strip → hand-rolled
//!   ikcp RX with a per-segment AES-128-CBC/GCM decrypt hook → `frg` reassembly →
//!   12-byte RTP parse → [`media::MediaUnit`], plus H.264 STAP-A/FU-A depacketize
//!   and ICE candidate parse/select (`re/media_decode_spec.md`). This is the
//!   AES/KCP transport the cap3 `a=rtpmap:6001 AES/KCP` codec negotiates — fully
//!   offline-unit-tested against synthetic vectors; live UDP/ICE connectivity is
//!   gated (no camera in-sandbox).
//! - [`session`] — the session **state machine** + a [`session::WebRtcEngine`]
//!   trait seam + an [`session::MqttTransport`] seam + the **#[ignore]d live
//!   driver** that is honestly gated on auth + a live device.
//!
//! # The webrtc-rs decision (stated, with rationale)
//!
//! The actual standard-WebRTC engine (PeerConnection / DTLS-SRTP / SRTP /
//! RTP-depacketize) is **webrtc-rs's** job, NOT this module's. We deliberately do
//! **NOT** vendor webrtc-rs into the offline build here, for two reasons:
//!
//! 1. **Offline gate.** webrtc-rs drags in hundreds of transitive crates (tokio,
//!    rustls, ring, sctp, dtls, …). The project's `just assert-offline` gate
//!    requires the test suite to build+enumerate with `--offline`; bloating the
//!    tree risks that discipline. The *valuable, RE-recovered* protocol surface
//!    is the Tuya-custom delta above, which is fully unit-testable with no media
//!    stack at all.
//! 2. **Honest scope.** The live media path cannot run until an authenticated
//!    device session and a real SCD921 returning `p2pType=4` are present. The
//!    device-list / `CameraInfoBean` creds the session needs come from the cloud
//!    auth path or an injected session, while this core module deliberately stays
//!    offline-testable. Wiring webrtc-rs now would be a large dependency that
//!    cannot be exercised end-to-end in the current harness, i.e. an unflagged
//!    half-add. Instead we define the [`session::WebRtcEngine`] trait seam so the
//!    media engine plugs in WITHOUT touching the protocol layer, and FILE the
//!    webrtc-rs wiring as a follow-up (TASK-0037).
//!
//! The MQTT transport (`rumqttc`) IS wired, but behind the
//! [`session::MqttTransport`] seam so the offline tests feed 302 messages through
//! a fake transport with no live broker.
//!
//! # Honest status
//!
//! This layer **builds + unit-tests pass static-only**, and the signaling is now
//! byte-validated against the cap3 capture (offer SDP structure + inner 302
//! plaintext). It still **cannot stream**: the live driver returns
//! [`crate::Error::StreamPending`] because (1) the live MQTT broker needs CONNECT
//! creds whose password is **native-derived** (`doCommandNative(2, ecode)`) and
//! not statically recoverable (`re/mqtt_signaling.md`), (2) the WebRTC media
//! engine (webrtc-rs) is a follow-up, and (3) every runtime input (token, p2pId,
//! p2pKey, ices, session, localKey, pv) rides an authenticated device session this
//! core module does not establish. The 302 envelope framing is **no longer**
//! pending — it is implemented + round-trip-tested. Exactly the signer's
//! TOKEN-PENDING discipline: never a fake stream, never `todo!()`.

pub mod connect;
pub mod frame;
pub mod media;
pub mod mqtt_auth;
pub mod mqtt_crypto;
pub mod rtc_config;
pub mod sdp;
pub mod session;
pub mod signaling;
pub mod topics;
pub mod transport;
pub mod tuya_lan;

use crate::Error;

/// Render an `Option<String>`-shaped secret for `Debug` without leaking its
/// value. Mirrors the redaction helpers in `sign.rs` / `device.rs`.
fn dbg_secret(s: &str) -> String {
    format!("<redacted len={}>", s.len())
}

/// All runtime/auth-gated inputs the live session needs, **injected** as one
/// struct (the key discipline — mirrors [`crate::sign::SigningKeyMaterial`]).
///
/// NONE of these are in the APK; every value comes from ONE authed device-list /
/// `CameraInfoBean` call on the user's own account (`re/webrtc_session.md` §1a,
/// §9). They are injected (not read from `secrets/` inside this module) so the
/// caller owns the secret lifetimes, and the secret-bearing fields are
/// **redacted** from `Debug` so a session never leaks via `{:?}`.
///
/// Tests construct this with SYNTHETIC values only (CLAUDE.md).
#[derive(Clone)]
pub struct StreamCredentials {
    /// Per-session signaling token (`connect_v2` `token`; echoed in 302
    /// `token`). Issued per-session by the cloud — NOT a static constant.
    /// **SECRET**.
    pub token: String,
    /// The P2P device handle = `CameraInfoBean.p2pId` (IOTC UID) → `connect_v2`
    /// `remote_id`. Per-device, account-linked. Sensitive.
    pub p2p_id: String,
    /// The Tuya cloud device id (`devId`) → `connect_v2` `dev_id`; also the MQTT
    /// publish target. Account-linked PII.
    pub dev_id: String,
    /// Capability JSON (`CameraInfoBean.skill`) → `connect_v2` `skill` (emitted
    /// UNQUOTED — must be a valid JSON object/value).
    pub skill: String,
    /// `P2pConfig.p2pKey` — the P2P session key. **SECRET**.
    pub p2p_key: String,
    /// `P2pConfig.ices` — the STUN/TURN server list (NOT static). Carried as the
    /// raw JSON string the cloud returns; fed to the WebRTC ICE engine.
    pub ices: String,
    /// `P2pConfig.session` — the session descriptor. **SECRET**.
    pub session: String,
    /// `P2pConfig.tcpRelay` as a compact JSON string — echoed (with a re-minted
    /// `sessionId`) as the offer `msg.tcp_token` (cap3). `""` if the cloud returned
    /// none, in which case the offer omits it. **SECRET-adjacent** (relay HMAC).
    pub tcp_relay: String,
    /// `P2pConfig.log` as a compact JSON string — passed through verbatim as the
    /// offer `msg.log` (cap3). `""` if absent. **SECRET-adjacent** (log auth key).
    pub log: String,
    /// The device `localKey` — the AES key for the 302 MQTT payload. **SECRET**.
    pub local_key: String,
    /// Protocol version (`DeviceBean.pv`) — the `pv` arg of the MQTT publish.
    pub pv: String,
    /// The camera-info `password` (`rtc.config result.password`) — the password
    /// field of the conv=0 media-start AUTH PDU (`SendAuthorizationInfo`, username
    /// `"admin"`). `""` if the cloud returned none (then no auth PDU is sent).
    /// **SECRET** — never logged.
    pub media_auth_password: String,
}

impl StreamCredentials {
    /// Validate that no load-bearing handle is empty. A live session with an
    /// empty `token`/`p2p_id`/`dev_id`/`local_key` cannot succeed, so we reject
    /// it loudly up front rather than emitting a malformed `connect_v2` / a
    /// broken AES key.
    ///
    /// # Errors
    /// [`Error::StreamConfig`] naming the first empty required field.
    pub fn validate(&self) -> Result<(), Error> {
        for (name, val) in [
            ("token", &self.token),
            ("p2p_id", &self.p2p_id),
            ("dev_id", &self.dev_id),
            ("local_key", &self.local_key),
        ] {
            if val.is_empty() {
                return Err(Error::StreamConfig(format!(
                    "required stream credential `{name}` is empty"
                )));
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for StreamCredentials {
    /// Redacts every secret-bearing field; never leaks values via `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamCredentials")
            .field("token", &dbg_secret(&self.token))
            .field("p2p_id", &dbg_secret(&self.p2p_id))
            .field("dev_id", &dbg_secret(&self.dev_id))
            .field("skill", &self.skill) // capability JSON, not a secret
            .field("p2p_key", &dbg_secret(&self.p2p_key))
            .field("ices", &dbg_secret(&self.ices))
            .field("session", &dbg_secret(&self.session))
            .field("tcp_relay", &dbg_secret(&self.tcp_relay))
            .field("log", &dbg_secret(&self.log))
            .field("local_key", &dbg_secret(&self.local_key))
            .field("pv", &self.pv)
            .field(
                "media_auth_password",
                &dbg_secret(&self.media_auth_password),
            )
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::StreamCredentials;

    /// SYNTHETIC credentials for tests — never a real value (CLAUDE.md).
    #[must_use]
    pub fn synth_credentials() -> StreamCredentials {
        StreamCredentials {
            token: "SYNTH_TOKEN_0000".into(),
            p2p_id: "SYNTH_P2PID_0000".into(),
            dev_id: "SYNTH_DEVID_0000".into(),
            skill: "{}".into(),
            p2p_key: "SYNTH_P2PKEY_0000".into(),
            ices: "[]".into(),
            session: "{}".into(),
            tcp_relay: String::new(),
            log: String::new(),
            // 16 bytes of synthetic key material (AES-128 sized).
            local_key: "0123456789abcdef".into(), // secret-scan:allow (synthetic test value)
            pv: "2.2".into(),
            media_auth_password: "SynthAuthPwd".into(), // secret-scan:allow (synthetic test pwd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_full_credentials() {
        let creds = test_support::synth_credentials();
        assert!(creds.validate().is_ok());
    }

    // NEGATIVE: an empty required handle must be rejected loudly (prove the
    // check bites; a green check that can't go red is not grounding).
    #[test]
    fn validate_rejects_empty_required_field() {
        let mut creds = test_support::synth_credentials();
        creds.token = String::new();
        assert!(matches!(creds.validate(), Err(Error::StreamConfig(_))));

        let mut creds = test_support::synth_credentials();
        creds.local_key = String::new();
        assert!(matches!(creds.validate(), Err(Error::StreamConfig(_))));
    }

    #[test]
    fn debug_redacts_secrets() {
        let creds = test_support::synth_credentials();
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("redacted"));
        // None of the secret VALUES may appear.
        assert!(!dbg.contains("SYNTH_TOKEN_0000"));
        assert!(!dbg.contains("SYNTH_P2PKEY_0000"));
        assert!(!dbg.contains("0123456789abcdef"));
        assert!(
            !dbg.contains("SynthAuthPwd"),
            "auth password must be redacted"
        );
        // Non-secret fields (skill JSON, pv) are fine to show.
        assert!(dbg.contains("pv"));
    }
}
