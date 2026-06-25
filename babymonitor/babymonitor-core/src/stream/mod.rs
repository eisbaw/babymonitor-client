//! Tuya WebRTC-over-MQTT live A/V session client (the RE-derived Tuya-custom
//! protocol layer).
//!
//! This module implements the **Tuya-custom delta** of the live-stream session —
//! the part that standard WebRTC (webrtc-rs) does NOT cover and that the reverse
//! engineering of `libThingP2PSDK.so` + the Java `P2PMQTTServiceManager` actually
//! recovered (`re/webrtc_session.md`, the implementable spec). Concretely:
//!
//! - [`signaling`] — the MQTT **302** signaling envelope `{header,msg,token}`
//!   (offer/answer/candidate/disconnect) serde codec (`re/webrtc_session.md` §2).
//! - [`mqtt_crypto`] — the SDP `a=aes-key:<hex>` media-key hex codec (byte-exact,
//!   `re/webrtc_session.md` §3c) + the 302-payload localKey-AES primitive
//!   (recovered + KAT-pinned: AES-128/ECB/PKCS5, key=localKey, no IV; only the
//!   pv→output-variant binding + outer framing stay live-gated — see the module).
//! - [`connect`] — the `connect_v2` control-JSON builder (byte-exact template,
//!   `re/webrtc_session.md` §1).
//! - [`sdp`] — parse/emit the Tuya-custom `m=application` + `a=aes-key` section
//!   (`re/webrtc_session.md` §3c).
//! - [`frame`] — the `imm_p2p_rtc_frame_t` → typed [`frame::Frame`] model + codec
//!   ids (`re/webrtc_session.md` §4).
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
//! 2. **Honest scope.** The live media path cannot run until login unblocks AND
//!    a real SCD921 returning `p2pType=4` is present. The device-list /
//!    `CameraInfoBean` creds the session needs are unfetchable because there is
//!    no authenticated session: `token.get` is rejected by a server-side identity
//!    gate (`ILLEGAL_CLIENT_ID`, proven sign-insensitive — TASK-0050/0051), so
//!    the cloud never issues a `sid`. (The signer separately still lacks its
//!    un-validated 6th ingredient, the `bmp_token` — TASK-0032 — but that is a
//!    sign ingredient, not the fetch blocker.) Wiring webrtc-rs now would be a
//!    large dependency that cannot be exercised end-to-end, i.e. an unflagged
//!    half-add. Instead we define the [`session::WebRtcEngine`] trait seam so the
//!    media engine plugs in WITHOUT touching the protocol layer, and FILE the
//!    webrtc-rs wiring as a follow-up (TASK-0037).
//!
//! The MQTT transport (`rumqttc`) IS wired, but behind the
//! [`session::MqttTransport`] seam so the offline tests feed 302 messages through
//! a fake transport with no live broker.
//!
//! # Honest status (TASK-0034 AC#2)
//!
//! This layer **builds + unit-tests pass static-only**. It **cannot stream**: the
//! live driver returns [`crate::Error::StreamPending`] because every runtime input
//! (token, p2pId, p2pKey, ices, session, localKey, pv) rides an authenticated
//! session that cannot be obtained — `token.get` is rejected by the server-side
//! identity gate (`ILLEGAL_CLIENT_ID`, TASK-0050/0051) before login ever issues a
//! `sid` — and the WebRTC media engine is a follow-up. Exactly the signer's
//! TOKEN-PENDING discipline: never a fake stream, never `todo!()`.

pub mod connect;
pub mod frame;
pub mod mqtt_crypto;
pub mod sdp;
pub mod session;
pub mod signaling;
pub mod transport;

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
    /// The device `localKey` — the AES key for the 302 MQTT payload. **SECRET**.
    pub local_key: String,
    /// Protocol version (`DeviceBean.pv`) — the `pv` arg of the MQTT publish.
    pub pv: String,
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
            .field("local_key", &dbg_secret(&self.local_key))
            .field("pv", &self.pv)
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
            // 16 bytes of synthetic key material (AES-128 sized).
            local_key: "0123456789abcdef".into(), // secret-scan:allow (synthetic test value)
            pv: "2.2".into(),
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
        // Non-secret fields (skill JSON, pv) are fine to show.
        assert!(dbg.contains("pv"));
    }
}
