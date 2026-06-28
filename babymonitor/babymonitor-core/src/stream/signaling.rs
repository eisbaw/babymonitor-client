//! The MQTT **302** signaling envelope codec — the *inner* (decrypted) JSON
//! (`re/webrtc_session.md` §2 + the cap3 ground-truth `signaling_plaintext.jsonl`).
//!
//! # cap3 correction (the real wire shape)
//!
//! `re/webrtc_session.md` §2b *inferred* the envelope as `{header, msg:"<sdp>",
//! token:"..."}` from native validator strings. The cap3 plaintext capture
//! (`emulator_captures/cap3/signaling_plaintext.jsonl`, the Frida hook logged it
//! post-decrypt) shows the **actual** shape is different and this module matches
//! the capture, not the inference:
//!
//! ```jsonc
//! { "header": { "from","to","sessionid","moto_id","type",
//!               "trace_id","is_pre","p2p_skill","security_level","path" },
//!   "msg":    { "sdp": "...", "preconnect": true,
//!               "token":     [ <ICE servers> ],     // STUN/TURN
//!               "tcp_token": { ... },               // TCP relay
//!               "log":       { ... } } }            // RTC log sink
//! ```
//!
//! i.e. the top level is **only** `{header, msg}`; `msg` is an **object** (not a
//! string), and the ICE `token`/`tcp_token`/`log` live **inside** `msg` (NOT at the
//! top level). A `candidate` message is `{header, msg:{candidate:"a=candidate:…"}}`.
//!
//! The offer/answer SDP rides in `msg.sdp`; the offerer's gathered ICE candidates
//! ride as separate `candidate` messages over `path:"mqtt"` AND `path:"lan"`.
//!
//! # Grounding
//!
//! - cap3 `signaling_plaintext.jsonl` (11 messages: 1 offer ×2 paths + trickle
//!   candidates + 1 answer) — the byte-exact source these structs are validated
//!   against (`tests/signaling_cap3.rs`, redacted fixture in `tests/fixtures/`).
//! - The native validators in `libThingP2PSDK.so` (`no header field` / `no msg
//!   field` / `type: sdp` / `type: candidate`) + the Java parser
//!   `P2PMQTTServiceManager.handleMqttAnswer` (`re/webrtc_session.md` §2).

use serde::{Deserialize, Serialize};

use crate::stream::sdp;
use crate::Error;

/// The `header.type` discriminator (`re/webrtc_session.md` §2b; cap3 §11).
///
/// `offer`/`answer` carry an SDP in `msg.sdp`; `candidate` carries an ICE
/// candidate line in `msg.candidate`; `disconnect` tears the session down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalingType {
    /// SDP offer (the Rust client emits this first). `msg.sdp` = offer SDP.
    Offer,
    /// SDP answer (the device replies). `msg.sdp` = answer SDP.
    Answer,
    /// Trickle-ICE candidate. `msg.candidate` = ICE candidate line.
    Candidate,
    /// Session teardown.
    Disconnect,
}

/// The signaling path a 302 message rides (`header.path`).
///
/// The offer + each candidate are sent over **both** `mqtt` (cloud relay) and
/// `lan` (local discovery) in cap3; the answer comes back over `mqtt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalingPath {
    /// Cloud MQTT relay path.
    Mqtt,
    /// LAN discovery path.
    Lan,
}

/// The 302 envelope `header` object.
///
/// Field declaration order matches the cap3 **offer** header byte-for-byte
/// (`from,to,sessionid,moto_id,type,trace_id,is_pre,p2p_skill,security_level,
/// path`) so a re-serialized offer reproduces the captured key order. The
/// offer-only numeric fields (`is_pre`/`p2p_skill`/`security_level`) and the
/// answer-only `sub_dev_id` are `Option` + skipped-when-absent, so a `candidate`
/// header (which omits the numerics) and the device `answer` header both parse.
///
/// `type` is the only strictly-REQUIRED field (the dispatch discriminator);
/// everything else is tolerated-absent so a minimal header still parses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingHeader {
    /// Sender device/user id (`header.from`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Recipient id (`header.to`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Session id (`header.sessionid`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessionid: Option<String>,
    /// Media-server id (`header.moto_id`). Empty string in cap3 for this device,
    /// but always present — kept non-skipping so the captured `"moto_id":""` is
    /// reproduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moto_id: Option<String>,
    /// Message type — REQUIRED (dispatch discriminator).
    #[serde(rename = "type")]
    pub r#type: SignalingType,
    /// Session correlation key (`header.trace_id`) — keys `mP2PMqttStateMap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// `is_pre` (preconnect flag) — offer-only in cap3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_pre: Option<i64>,
    /// `p2p_skill` capability bitmask — offer-only in cap3 (=1635).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2p_skill: Option<i64>,
    /// `security_level` — offer-only in cap3 (=3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_level: Option<i64>,
    /// The signaling path (`header.path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<SignalingPath>,
    /// Sub-device id (`header.sub_dev_id`) — present (empty) in the device
    /// `answer` header; modeled optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_dev_id: Option<String>,
}

/// One ICE (STUN/TURN) server entry from `msg.token` (cap3).
///
/// A STUN entry is `{ "urls":"stun:host:port" }`; a TURN entry adds
/// `credential`/`ttl`/`username`. `urls` is a single string in cap3 (the
/// per-server entry), so we model it as `String`.
///
/// Field declaration order matches the cap3 offer's `token` TURN entry
/// byte-for-byte (`credential,ttl,urls,username`) so a re-serialized offer
/// reproduces the captured key order; `urls` is the only always-present field
/// (a STUN entry is just `{"urls":…}`), the rest are TURN-only and skip when
/// absent (TASK-0080).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    /// TURN long-term credential (HMAC), if present. **SECRET-adjacent.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// TURN credential TTL in seconds, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    /// The server URL (`stun:…` / `turn:…`).
    pub urls: String,
    /// TURN long-term credential username (`<expiry>:<devId>`), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// The `msg.tcp_token` object (cap3) — the TCP-relay descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpToken {
    /// Relay credential (HMAC). **SECRET-adjacent.**
    pub credential: String,
    /// Relay domain hint.
    pub domain: String,
    /// Relay session id.
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// IPv4 relay URLs (`tcp4:host:port`).
    pub urls: Vec<String>,
    /// IPv6 relay URLs (`tcp6:[host]:port`).
    #[serde(rename = "urlsEx", default, skip_serializing_if = "Vec::is_empty")]
    pub urls_ex: Vec<String>,
    /// Relay credential username (`<expiry>:<devId>`).
    pub username: String,
}

/// The 302 `msg` object. One struct covers all message types; the field set
/// present selects the meaning, and the declaration order matches the cap3
/// **offer** `msg` (`sdp,preconnect,token,tcp_token,log`) so a re-serialized
/// offer reproduces the captured key order. A `candidate` message carries only
/// `candidate`.
///
/// `log` is kept opaque (`serde_json::Value`) — the Rust client does not need
/// the RTC-log sink config to negotiate, and round-tripping it verbatim avoids
/// over-modeling a field we never consume.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignalingMsg {
    /// The SDP (offer/answer). Absent on a `candidate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    /// `true` on a preconnect-enabled offer (cap3 offer carries `preconnect:true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconnect: Option<bool>,
    /// The STUN/TURN ICE server list (`msg.token`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Vec<IceServer>>,
    /// The TCP-relay descriptor (`msg.tcp_token`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_token: Option<TcpToken>,
    /// The RTC-log sink config — opaque passthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<serde_json::Value>,
    /// The ICE candidate line (`msg.candidate`). Present only on `candidate`
    /// messages; the trickle-end sentinel is an empty string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<String>,
}

/// A full 302 signaling envelope: the top level is exactly `{header, msg}`
/// (cap3). Both fields are REQUIRED; serde rejects a malformed envelope with a
/// typed error rather than parsing a half-empty struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingEnvelope {
    /// The header (routing/correlation + type). REQUIRED.
    pub header: SignalingHeader,
    /// The payload object (`sdp`/`candidate` + ICE creds). REQUIRED.
    pub msg: SignalingMsg,
}

/// The fields the media engine needs out of a parsed `answer`
/// (`re/webrtc_session.md` §2c): the remote ICE creds + media AES key extracted
/// from the answer SDP, plus the ICE/TCP relay descriptors.
#[derive(Debug, Clone)]
pub struct ParsedAnswer {
    /// Remote (device) ICE ufrag from the answer SDP.
    pub remote_ufrag: String,
    /// Remote (device) ICE pwd from the answer SDP.
    pub remote_pwd: String,
    /// The per-session media AES key (raw bytes), from the answer `a=aes-key`.
    pub media_key: Vec<u8>,
    /// The STUN/TURN ICE servers carried in `msg.token` (may be empty).
    pub ice_servers: Vec<IceServer>,
    /// The TCP-relay descriptor carried in `msg.tcp_token`, if any.
    pub tcp_token: Option<TcpToken>,
    /// The raw answer SDP (handed to the WebRTC engine `set_answer`).
    pub sdp: String,
}

impl SignalingEnvelope {
    /// Parse a 302 envelope from its (decrypted) JSON bytes.
    ///
    /// # Errors
    /// [`Error::SignalingParse`] if the bytes are not valid JSON or do not match
    /// the required `{header, msg}` shape / a known `header.type`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|e| Error::SignalingParse(e.to_string()))
    }

    /// Serialize this envelope to JSON bytes for publishing on 302 (before the
    /// localKey-AES layer applied by [`super::mqtt_crypto`]).
    ///
    /// # Errors
    /// [`Error::SignalingParse`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|e| Error::SignalingParse(e.to_string()))
    }

    /// If this is an `answer`, extract everything the media engine needs
    /// ([`ParsedAnswer`]): the remote ICE creds + media key from the SDP, plus
    /// the ICE/TCP relay descriptors from `msg`.
    ///
    /// # Errors
    /// - [`Error::SignalingParse`] if the type is not `answer`, or the answer
    ///   carries no SDP.
    /// - [`Error::SdpAesKey`] (propagated) if the SDP lacks a valid `a=aes-key`
    ///   or ICE creds.
    pub fn parse_answer(&self) -> Result<ParsedAnswer, Error> {
        if self.header.r#type != SignalingType::Answer {
            return Err(Error::SignalingParse(format!(
                "expected an answer envelope, got {:?}",
                self.header.r#type
            )));
        }
        let sdp =
            self.msg.sdp.as_deref().ok_or_else(|| {
                Error::SignalingParse("answer envelope has no msg.sdp".to_string())
            })?;
        let media_key = sdp::extract_aes_key(sdp)?;
        let (remote_ufrag, remote_pwd) = sdp::extract_ice_creds(sdp)?;
        Ok(ParsedAnswer {
            remote_ufrag,
            remote_pwd,
            media_key,
            ice_servers: self.msg.token.clone().unwrap_or_default(),
            tcp_token: self.msg.tcp_token.clone(),
            sdp: sdp.to_string(),
        })
    }
}

/// Inputs to build an `offer`/`candidate` envelope. The routing ids + SDP/ICE
/// come from the session; `path` is set per emit (the offer + each candidate are
/// emitted once per [`SignalingPath`]).
#[derive(Debug, Clone)]
pub struct OfferEnvelopeArgs {
    /// `header.from` — the app/user id.
    pub from: String,
    /// `header.to` — the camera device id.
    pub to: String,
    /// `header.sessionid`.
    pub sessionid: String,
    /// `header.trace_id` — session correlation key.
    pub trace_id: String,
    /// `header.p2p_skill` (cap3 = 1635).
    pub p2p_skill: i64,
    /// `header.security_level` (cap3 = 3).
    pub security_level: i64,
    /// The offer SDP (built by [`super::sdp::build_offer_sdp`]).
    pub sdp: String,
    /// The STUN/TURN ICE servers to echo to the device (`msg.token`).
    pub ice_servers: Vec<IceServer>,
    /// The TCP-relay descriptor (`msg.tcp_token`).
    pub tcp_token: Option<TcpToken>,
    /// The opaque RTC-log sink config (`msg.log`), passed through if present.
    pub log: Option<serde_json::Value>,
}

impl SignalingEnvelope {
    /// Build an `offer` envelope for one [`SignalingPath`], matching the cap3
    /// offer shape (`header` with the offer numerics + `msg` with
    /// `sdp,preconnect:true,token,tcp_token,log`).
    #[must_use]
    pub fn offer(args: &OfferEnvelopeArgs, path: SignalingPath) -> Self {
        Self {
            header: SignalingHeader {
                from: Some(args.from.clone()),
                to: Some(args.to.clone()),
                sessionid: Some(args.sessionid.clone()),
                moto_id: Some(String::new()), // cap3: always present, empty
                r#type: SignalingType::Offer,
                trace_id: Some(args.trace_id.clone()),
                is_pre: Some(0),
                p2p_skill: Some(args.p2p_skill),
                security_level: Some(args.security_level),
                path: Some(path),
                sub_dev_id: None,
            },
            msg: SignalingMsg {
                sdp: Some(args.sdp.clone()),
                preconnect: Some(true),
                token: Some(args.ice_servers.clone()),
                tcp_token: args.tcp_token.clone(),
                log: args.log.clone(),
                candidate: None,
            },
        }
    }

    /// Build a trickle `candidate` envelope for one [`SignalingPath`]. An empty
    /// `candidate` string is the end-of-candidates sentinel (cap3 messages 7/10).
    #[must_use]
    pub fn candidate(
        from: impl Into<String>,
        to: impl Into<String>,
        sessionid: impl Into<String>,
        trace_id: impl Into<String>,
        candidate_line: impl Into<String>,
        path: SignalingPath,
    ) -> Self {
        Self {
            header: SignalingHeader {
                from: Some(from.into()),
                to: Some(to.into()),
                sessionid: Some(sessionid.into()),
                moto_id: Some(String::new()),
                r#type: SignalingType::Candidate,
                trace_id: Some(trace_id.into()),
                is_pre: None,
                p2p_skill: None,
                security_level: None,
                path: Some(path),
                sub_dev_id: None,
            },
            msg: SignalingMsg {
                candidate: Some(candidate_line.into()),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // POSITIVE: a cap3-shaped offer (synthetic ids) parses and exposes the
    // structured fields — msg is an OBJECT with sdp + ICE token, NOT a string.
    #[test]
    fn parses_cap3_shaped_offer() {
        let json = br#"{
            "header": { "from":"USER","to":"DEV","sessionid":"SESS","moto_id":"",
                "type":"offer","trace_id":"TRACE","is_pre":0,"p2p_skill":1635,
                "security_level":3,"path":"mqtt" },
            "msg": { "sdp":"v=0\r\nm=application 9 imm 6001\r\n","preconnect":true,
                "token":[{"urls":"stun:1.2.3.4:3478"},
                    {"credential":"CRED","ttl":36000,"urls":"turn:5.6.7.8:3478","username":"123:DEV"}],
                "tcp_token":{"credential":"TC","domain":"localhost","sessionId":"S2",
                    "urls":["tcp4:9.9.9.9:1443"],"urlsEx":["tcp6:[::1]:1443"],"username":"123:DEV"},
                "log":{"api":"thing.m.rtc.log","topic":"/av/moto/log"} }
        }"#;
        let env = SignalingEnvelope::from_json(json).expect("cap3 offer parses");
        assert_eq!(env.header.r#type, SignalingType::Offer);
        assert_eq!(env.header.path, Some(SignalingPath::Mqtt));
        assert_eq!(env.header.p2p_skill, Some(1635));
        assert_eq!(env.header.security_level, Some(3));
        assert_eq!(env.msg.preconnect, Some(true));
        let token = env.msg.token.as_ref().unwrap();
        assert_eq!(token.len(), 2);
        assert_eq!(token[0].urls, "stun:1.2.3.4:3478");
        assert_eq!(token[1].credential.as_deref(), Some("CRED"));
        assert_eq!(token[1].ttl, Some(36000));
        assert!(env.msg.tcp_token.is_some());
        assert!(env.msg.candidate.is_none());
    }

    // POSITIVE: a candidate parses with only msg.candidate, no SDP/token.
    #[test]
    fn parses_candidate() {
        let json = br#"{
            "header": { "from":"U","to":"D","sessionid":"S","moto_id":"",
                "type":"candidate","trace_id":"T","path":"lan" },
            "msg": { "candidate":"a=candidate:1 1 UDP 2130706431 10.0.2.15 58363 typ host\r\n" }
        }"#;
        let env = SignalingEnvelope::from_json(json).unwrap();
        assert_eq!(env.header.r#type, SignalingType::Candidate);
        assert_eq!(env.header.path, Some(SignalingPath::Lan));
        assert!(env.msg.sdp.is_none());
        assert!(env.msg.candidate.as_deref().unwrap().contains("typ host"));
        // candidate header omits the offer numerics.
        assert!(env.header.p2p_skill.is_none());
    }

    // Round-trip: an offer built via the helper re-serializes with the cap3 key
    // order (header: …type,trace_id,is_pre,p2p_skill,security_level,path; msg:
    // sdp,preconnect,token,tcp_token,log) and re-parses cleanly.
    #[test]
    fn offer_serializes_in_cap3_key_order() {
        let args = OfferEnvelopeArgs {
            from: "USER".into(),
            to: "DEV".into(),
            sessionid: "SESS".into(),
            trace_id: "TRACE".into(),
            p2p_skill: 1635,
            security_level: 3,
            sdp: "v=0\r\n".into(),
            ice_servers: vec![IceServer {
                urls: "stun:1.2.3.4:3478".into(),
                username: None,
                credential: None,
                ttl: None,
            }],
            tcp_token: None,
            log: None,
        };
        let env = SignalingEnvelope::offer(&args, SignalingPath::Mqtt);
        let s = String::from_utf8(env.to_json().unwrap()).unwrap();
        // Header key order (offer): from before type before is_pre before path.
        let i_from = s.find("\"from\"").unwrap();
        let i_type = s.find("\"type\"").unwrap();
        let i_ispre = s.find("\"is_pre\"").unwrap();
        let i_skill = s.find("\"p2p_skill\"").unwrap();
        let i_sec = s.find("\"security_level\"").unwrap();
        let i_path = s.find("\"path\"").unwrap();
        assert!(i_from < i_type && i_type < i_ispre);
        assert!(i_ispre < i_skill && i_skill < i_sec && i_sec < i_path);
        // msg key order: sdp before preconnect before token.
        let i_sdp = s.find("\"sdp\"").unwrap();
        let i_pre = s.find("\"preconnect\"").unwrap();
        let i_tok = s.find("\"token\"").unwrap();
        assert!(i_sdp < i_pre && i_pre < i_tok);
        // moto_id present-but-empty is reproduced.
        assert!(s.contains("\"moto_id\":\"\""));
        // round-trips.
        let back = SignalingEnvelope::from_json(&env.to_json().unwrap()).unwrap();
        assert_eq!(back.header.r#type, SignalingType::Offer);
        assert_eq!(back.msg.preconnect, Some(true));
    }

    // parse_answer extracts the remote ICE creds + media key + ICE servers.
    #[test]
    fn parse_answer_extracts_engine_inputs() {
        let json = br#"{
            "header": { "from":"DEV","to":"USER","path":"mqtt","sessionid":"S",
                "sub_dev_id":"","trace_id":"T","type":"answer" },
            "msg": { "sdp":"v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\na=aes-key:00112233445566778899aabbccddeeff\r\n",
                "token":[{"urls":"stun:1.2.3.4:3478"}],
                "tcp_token":{"credential":"TC","domain":"localhost","sessionId":"S2",
                    "urls":["tcp4:9.9.9.9:1443"],"username":"123:DEV"} }
        }"#;
        let env = SignalingEnvelope::from_json(json).unwrap();
        let ans = env.parse_answer().unwrap();
        assert_eq!(ans.remote_ufrag, "SYN0");
        assert_eq!(ans.remote_pwd, "SYNTHICEPWD0000000000000");
        assert_eq!(ans.media_key.len(), 16);
        assert_eq!(ans.ice_servers.len(), 1);
        assert!(ans.tcp_token.is_some());
    }

    // NEGATIVE: parse_answer on a non-answer is rejected (no silent default).
    #[test]
    fn parse_answer_rejects_non_answer() {
        let json = br#"{ "header": { "type":"candidate" }, "msg": { "candidate":"x" } }"#;
        let env = SignalingEnvelope::from_json(json).unwrap();
        assert!(matches!(env.parse_answer(), Err(Error::SignalingParse(_))));
    }

    // NEGATIVE: a message missing `header` must be REJECTED (native `no header`).
    #[test]
    fn rejects_missing_header() {
        let json = br#"{ "msg": { "candidate":"x" } }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: a message missing `msg` must be REJECTED (native `no msg field`).
    #[test]
    fn rejects_missing_msg() {
        let json = br#"{ "header": { "type":"offer" } }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: an unknown header.type is REJECTED, not silently defaulted.
    #[test]
    fn rejects_unknown_type() {
        let json = br#"{ "header": { "type":"frobnicate" }, "msg": {} }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }

    // NEGATIVE: a header without the required `type` is REJECTED.
    #[test]
    fn rejects_header_without_type() {
        let json = br#"{ "header": { "from":"x" }, "msg": {} }"#;
        assert!(matches!(
            SignalingEnvelope::from_json(json),
            Err(Error::SignalingParse(_))
        ));
    }
}
