//! The MQTT **302** signaling envelope codec (`re/webrtc_session.md` §2).
//!
//! Every WebRTC signaling message rides the device's standard Tuya MQTT channel
//! as message code **302**, AES-encrypted with the device `localKey`. The
//! *plaintext* inside each 302 publish is the JSON envelope modeled here:
//!
//! ```jsonc
//! { "header": { "type": "offer"|"answer"|"candidate"|"disconnect",
//!               "from": "...", "to": "...", "sessionid": "...",
//!               "trace_id": "...", "moto_id": "..." },
//!   "msg":   "<SDP | ICE candidate>",
//!   "token": "<per-session signaling token>" }
//! ```
//!
//! # Grounding (two independent sources, `confirmed` — `re/webrtc_session.md` §2)
//!
//! - The native validators in `libThingP2PSDK.so`:
//!   `invalid signaling: … no header field` / `… no msg field` / `… no token
//!   field` (the three REQUIRED top-level fields), and the type validators
//!   `type: sdp` / `type: candidate` / `type: handle or seq`.
//! - The decompiled Java parser
//!   `com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`
//!   (`handleMqttAnswer` / `send302MessageThroughMqtt`): reads
//!   `header.getString("type")` and compares to `"offer"`/`"answer"`, reads
//!   `header.getString("from")` / `header.getString("trace_id")` (the session
//!   correlation key in `mP2PMqttStateMap`).
//!
//! `moto_id` is present in the public Tuya IPC ref but NOT a `CameraInfoBean`
//! field in THIS app (`re/webrtc_session.md` §2b) — modeled as optional, residual
//! pinned by a live capture.

use serde::{Deserialize, Serialize};

use crate::Error;

/// The `header.type` discriminator (`re/webrtc_session.md` §2b).
///
/// `offer`/`answer` carry an SDP string in `msg`; `candidate` carries an ICE
/// candidate line in `msg`; `disconnect` tears the session down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalingType {
    /// SDP offer (the Rust client emits this first). `msg` = offer SDP.
    Offer,
    /// SDP answer (the device replies). `msg` = answer SDP.
    Answer,
    /// Trickle-ICE candidate. `msg` = ICE candidate line.
    Candidate,
    /// Session teardown.
    Disconnect,
}

/// The 302 envelope `header` object (`re/webrtc_session.md` §2b).
///
/// `type` is the only REQUIRED header field for our codec to be meaningful —
/// without it we cannot dispatch. `trace_id` is the session correlation key (the
/// inbound dispatcher keys state on it). The remaining fields are present
/// per-message but tolerated-absent so a minimal/partial header still parses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingHeader {
    /// Message type — REQUIRED (dispatch discriminator).
    #[serde(rename = "type")]
    pub r#type: SignalingType,
    /// Sender device/user id (`header.from`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Recipient id (`header.to`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Session id (`header.sessionid`; a.k.a. connect_session correlation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessionid: Option<String>,
    /// Session correlation key (`header.trace_id`) — keys `mP2PMqttStateMap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Media-server id (`header.moto_id`) — present in the public Tuya IPC ref,
    /// not a `CameraInfoBean` field in this app; modeled optional (residual,
    /// `re/webrtc_session.md` §2b/§9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moto_id: Option<String>,
}

/// A full 302 signaling envelope (`re/webrtc_session.md` §2b).
///
/// All three top-level fields (`header`, `msg`, `token`) are REQUIRED — the
/// native side rejects a message missing any of them (`no header/msg/token
/// field`). We model them non-`Option` so serde rejects a malformed envelope
/// with a typed error rather than silently parsing a half-empty struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingEnvelope {
    /// The header (type + routing/correlation). REQUIRED.
    pub header: SignalingHeader,
    /// The payload: an SDP (offer/answer) or an ICE candidate line. REQUIRED.
    pub msg: String,
    /// The per-session signaling token. REQUIRED.
    pub token: String,
}

impl SignalingEnvelope {
    /// Parse a 302 envelope from its (decrypted) JSON bytes.
    ///
    /// This is the receive-path codec: feed it the plaintext 302 payload and it
    /// yields the typed envelope, rejecting any message missing `header`/`msg`/
    /// `token` or carrying an unknown `header.type`.
    ///
    /// # Errors
    /// [`Error::SignalingParse`] if the bytes are not valid JSON or do not match
    /// the required envelope shape.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|e| Error::SignalingParse(e.to_string()))
    }

    /// Serialize this envelope to JSON bytes for publishing on 302 (before the
    /// localKey-AES layer is applied by [`super::mqtt_crypto`]).
    ///
    /// # Errors
    /// [`Error::SignalingParse`] if serialization fails (should not happen for a
    /// well-formed struct).
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|e| Error::SignalingParse(e.to_string()))
    }

    /// Build an OFFER envelope carrying an SDP string (the client emits this
    /// first). `trace_id` is the session correlation key the client mints.
    #[must_use]
    pub fn offer(
        sdp: impl Into<String>,
        token: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            header: SignalingHeader {
                r#type: SignalingType::Offer,
                from: None,
                to: None,
                sessionid: None,
                trace_id: Some(trace_id.into()),
                moto_id: None,
            },
            msg: sdp.into(),
            token: token.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // POSITIVE: a full, well-formed answer envelope round-trips through the codec.
    #[test]
    fn parses_full_answer_envelope() {
        let json = br#"{
            "header": {
                "type": "answer",
                "from": "dev-A",
                "to": "client-B",
                "sessionid": "sess-1",
                "trace_id": "trace-xyz",
                "moto_id": "moto-9"
            },
            "msg": "v=0\r\no=- 0 1 IN IP4 127.0.0.1\r\n",
            "token": "SYNTH_SIGNALING_TOKEN"
        }"#;
        let env = SignalingEnvelope::from_json(json).expect("valid envelope parses");
        assert_eq!(env.header.r#type, SignalingType::Answer);
        assert_eq!(env.header.trace_id.as_deref(), Some("trace-xyz"));
        assert_eq!(env.header.from.as_deref(), Some("dev-A"));
        assert_eq!(env.header.moto_id.as_deref(), Some("moto-9"));
        assert!(env.msg.starts_with("v=0"));
        assert_eq!(env.token, "SYNTH_SIGNALING_TOKEN");
    }

    // POSITIVE: a minimal header (only the required `type`) still parses — the
    // other header fields are tolerated-absent.
    #[test]
    fn parses_minimal_candidate_envelope() {
        let json = br#"{
            "header": { "type": "candidate" },
            "msg": "candidate:1 1 UDP 2130706431 192.0.2.1 50000 typ host",
            "token": "t"
        }"#;
        let env = SignalingEnvelope::from_json(json).unwrap();
        assert_eq!(env.header.r#type, SignalingType::Candidate);
        assert!(env.header.trace_id.is_none());
        assert!(env.msg.contains("typ host"));
    }

    // Round-trip: an offer built via the helper serializes and re-parses cleanly,
    // and the serialized form omits the absent optional header fields.
    #[test]
    fn offer_round_trips_and_omits_absent_fields() {
        let env = SignalingEnvelope::offer("v=0\r\n", "tok", "trace-1");
        let bytes = env.to_json().unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        // Absent optionals are skipped, so the JSON has no `from`/`moto_id` keys.
        assert!(!s.contains("\"from\""));
        assert!(!s.contains("\"moto_id\""));
        assert!(s.contains("\"type\":\"offer\""));
        let back = SignalingEnvelope::from_json(&bytes).unwrap();
        assert_eq!(back.header.r#type, SignalingType::Offer);
        assert_eq!(back.header.trace_id.as_deref(), Some("trace-1"));
    }

    // NEGATIVE: a message missing `header` must be REJECTED (native `no header
    // field`). Prove the required-field check bites.
    #[test]
    fn rejects_missing_header() {
        let json = br#"{ "msg": "v=0", "token": "t" }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: a message missing `msg` must be REJECTED (native `no msg field`).
    #[test]
    fn rejects_missing_msg() {
        let json = br#"{ "header": { "type": "offer" }, "token": "t" }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: a message missing `token` must be REJECTED (native `no token
    // field`).
    #[test]
    fn rejects_missing_token() {
        let json = br#"{ "header": { "type": "offer" }, "msg": "v=0" }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: an unknown `header.type` must be REJECTED, not silently mapped to
    // a default — the native validators only accept sdp(offer/answer)/candidate.
    #[test]
    fn rejects_unknown_type() {
        let json = br#"{ "header": { "type": "frobnicate" }, "msg": "x", "token": "t" }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: a header missing the required `type` must be REJECTED.
    #[test]
    fn rejects_header_without_type() {
        let json = br#"{ "header": { "from": "x" }, "msg": "y", "token": "t" }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }
}
