//! Parser for the Tuya **`rtc.config.get`** response — the per-camera
//! WebRTC-over-MQTT session config (TASK-0078).
//!
//! The live REST call `smartlife.m.rtc.config.get` (postData `{"devId":"…"}`,
//! ET=3, session-required) returns — after decryption — a `result` object whose
//! `p2pConfig` carries everything the 302 signaling needs that is NOT minted by
//! the client: the ICE (STUN/TURN) server list, the per-session relay/session
//! descriptors, the media-server `motoId`, and the per-session signaling token
//! (`auth`). This module turns that decrypted `result` value into a typed
//! [`RtcConfig`] the CLI assembles a `StreamRuntime` from — so `stream --live`
//! needs only the session, not a hand-written `secrets/stream_runtime.json`.
//!
//! # Ground truth (offline-validated)
//!
//! The field layout is pinned against the decrypted cap1 AND cap3 captures
//! (`secrets/cap1_rtc_decrypted/smartlife.m.rtc.config.get.json` and the cap3
//! flow, decrypted by `re/scripts/decrypt_rtc_flow.py`). `tests/rtc_config_cap.rs`
//! validates this parser against a committed **redacted** fixture (always) and the
//! gitignored real captures (when present, skip-if-absent) — no value is printed.
//!
//! # The media `a=aes-key` is MINTED by us, NOT `session.aesKey`
//!
//! (confidence: confirmed — source: `emulator_captures/cap3` decrypted.) The
//! crucial determination for the offer SDP: in cap3 the offer's `a=aes-key`
//! **equals the answer's** `a=aes-key` (the camera echoes the app's key) but is
//! **different** from that same session's `rtc.config` `p2pConfig.session.aesKey`.
//! So the media key is a fresh per-session 16-byte value the **client mints** and
//! puts into its offer (the camera echoes it back) — it is NOT the
//! `rtc.config session.aesKey`. The CLI therefore continues to mint the media key
//! (`SessionHandles::mint`), and [`RtcConfig::session_aes_key`] is surfaced for
//! completeness/inspection only — never used as the SDP media key. See
//! [`RtcConfig::session_aes_key`] and `tests/rtc_config_cap.rs`.

use serde::Deserialize;

use crate::Error;

/// The typed, RE-relevant subset of a decrypted `rtc.config.get` `result`.
///
/// Every string is carried verbatim from the cloud (no reshaping) except
/// [`ices_json`](Self::ices_json) and [`session_json`](Self::session_json), which
/// are re-serialized to compact JSON strings because the downstream
/// `StreamCredentials.ices` / `.session` are raw-JSON-string fields. NONE of these
/// values is ever logged (several are per-session secrets / account PII).
#[derive(Clone)]
pub struct RtcConfig {
    /// `p2pConfig.ices` re-serialized as a compact JSON array string — the
    /// STUN/TURN server list fed to the ICE engine (and echoed as the offer
    /// `msg.token`, cap3). May be `"[]"` if the cloud returned none.
    pub ices_json: String,
    /// `p2pConfig.session` re-serialized as a compact JSON object string — the
    /// session descriptor (`StreamCredentials.session`). `"{}"` if absent.
    pub session_json: String,
    /// `p2pConfig.session.aesKey` (32-hex). **NOT** the media `a=aes-key** —
    /// the media key is client-minted (see module docs). Surfaced for inspection
    /// only; the CLI never feeds this into the offer SDP. May be empty.
    pub session_aes_key: String,
    /// `p2pConfig.session.icePassword` — the device pre-session ICE pwd. Secret.
    pub ice_password: String,
    /// `p2pConfig.session.iceUfrag` — the device pre-session ICE ufrag.
    pub ice_ufrag: String,
    /// `p2pConfig.session.sessionId` — the per-session id (cap3 offer
    /// `header.sessionid` + SDP `a=msid-semantic: WMS <id>`).
    pub session_id: String,
    /// `p2pConfig.session.uid` — the account/user id. In cap3 this is the offer
    /// `header.from` and the SDP `a=ssrc:0 cname:<uid>`, so the CLI uses it as the
    /// signaling `from`/cname for the WebRTC path (where top-level `p2pId` is ""). PII.
    pub uid: String,
    /// The Tuya device id (`result.id` / `session.devId`) — the 302 addressing
    /// key and the offer `header.to`. Account-linked PII.
    pub dev_id: String,
    /// `result.motoId` (== `p2pConfig.motoId`) — the media-server routing handle
    /// (cap3 offer `header.moto_id`). May be empty on some devices.
    pub moto_id: String,
    /// `result.p2pType` — the transport selector (4 = THING/WebRTC-over-MQTT).
    pub p2p_type: i32,
    /// `result.auth` (== `p2pConfig.auth`) — the per-session signaling token
    /// (base64). Mapped to `StreamCredentials.token`. Secret.
    pub auth: String,
    /// `result.skill` — the camera capability JSON **string** (e.g.
    /// `{"webrtc":3,…}`); fed to `connect_v2 skill`. `"{}"` if absent.
    pub skill: String,
    /// `result.password` — the camera-info auth password the conv=0 media-start
    /// AUTH PDU carries (`SendAuthorizationInfo`, username "admin";
    /// `ghidra_p2p/funcs/00147608`, `re/media_start_handshake.md`). **SECRET** —
    /// never logged (redacted from [`Debug`]). May be empty on a config that
    /// returned none.
    pub password: String,
    /// `p2pConfig.transmission` — the reliable-transport tag (`"kcp"` on the
    /// SCD921). Advisory; the media engine already pins KCP.
    pub transmission: String,
    /// `p2pConfig.tcpRelay` re-serialized as a compact JSON object string — the
    /// TCP-relay descriptor the offer echoes as `msg.tcp_token` (cap3). `""` if the
    /// cloud returned none. Carries a secret credential; never logged. (TASK-0080)
    pub tcp_relay_json: String,
    /// `p2pConfig.log` re-serialized as a compact JSON object string — the RTC-log
    /// sink config passed through verbatim as the offer `msg.log` (cap3). `""` if
    /// absent. Carries a log auth key; never logged. (TASK-0080)
    pub log_json: String,
}

/// Raw serde view of the decrypted `result` object. Only the fields the parser
/// needs are declared; everything else (audioAttributes, portGuess, vedioClarity,
/// …) is ignored. All optional so a partial/older response still parses, with the
/// required-field check enforced by [`RtcConfig::from_rtc_result`].
#[derive(Deserialize)]
struct RawResult {
    #[serde(default)]
    id: String,
    #[serde(rename = "motoId", default)]
    moto_id: String,
    #[serde(rename = "p2pType", default)]
    p2p_type: i32,
    #[serde(default)]
    auth: String,
    /// `skill` is a JSON **string** on the wire.
    #[serde(default)]
    skill: String,
    /// `result.password` — the camera-info auth password (top-level only).
    #[serde(default)]
    password: String,
    #[serde(rename = "p2pConfig", default)]
    p2p_config: Option<RawP2pConfig>,
}

#[derive(Deserialize)]
struct RawP2pConfig {
    #[serde(default)]
    ices: serde_json::Value,
    #[serde(default)]
    session: serde_json::Value,
    #[serde(rename = "motoId", default)]
    moto_id: String,
    #[serde(default)]
    auth: String,
    #[serde(default)]
    transmission: String,
    #[serde(rename = "tcpRelay", default)]
    tcp_relay: serde_json::Value,
    #[serde(default)]
    log: serde_json::Value,
}

#[derive(Deserialize)]
struct RawSession {
    #[serde(rename = "aesKey", default)]
    aes_key: String,
    #[serde(rename = "icePassword", default)]
    ice_password: String,
    #[serde(rename = "iceUfrag", default)]
    ice_ufrag: String,
    #[serde(rename = "sessionId", default)]
    session_id: String,
    #[serde(default)]
    uid: String,
    #[serde(rename = "devId", default)]
    dev_id: String,
}

impl RtcConfig {
    /// Parse a decrypted `rtc.config.get` **`result`** value into [`RtcConfig`].
    ///
    /// Accepts the `result` object directly (what the live REST path yields as
    /// `AtopResponse.result`). The `devId` is taken from `session.devId` when
    /// present, else the top-level `id`.
    ///
    /// # Errors
    /// [`Error::SignalingParse`] if `result` is not a JSON object, has no
    /// `p2pConfig`, or yields no usable `devId` — the load-bearing addressing key.
    pub fn from_rtc_result(result: &serde_json::Value) -> Result<Self, Error> {
        let raw: RawResult = serde_json::from_value(result.clone()).map_err(|e| {
            Error::SignalingParse(format!("rtc.config result is not the expected object: {e}"))
        })?;
        let p2p = raw.p2p_config.ok_or_else(|| {
            Error::SignalingParse("rtc.config result has no p2pConfig".to_string())
        })?;

        // Re-serialize ices/session back to compact JSON strings (the downstream
        // StreamCredentials.ices/.session are raw-JSON-string fields). A null/
        // missing ices becomes "[]"; a null/missing session becomes "{}".
        let ices_json = if p2p.ices.is_null() {
            "[]".to_string()
        } else {
            serde_json::to_string(&p2p.ices)
                .map_err(|e| Error::SignalingParse(format!("rtc.config ices re-serialize: {e}")))?
        };
        let session_json = if p2p.session.is_null() {
            "{}".to_string()
        } else {
            serde_json::to_string(&p2p.session).map_err(|e| {
                Error::SignalingParse(format!("rtc.config session re-serialize: {e}"))
            })?
        };

        // The TCP-relay + log descriptors are re-serialized to compact JSON object
        // strings (the offer echoes them as `msg.tcp_token` / `msg.log`, cap3). A
        // missing/null value becomes "" — the downstream offer builder then omits
        // the field (matching a device whose rtc.config carried none).
        let object_json = |v: &serde_json::Value, what: &str| -> Result<String, Error> {
            if v.is_null() {
                Ok(String::new())
            } else {
                serde_json::to_string(v).map_err(|e| {
                    Error::SignalingParse(format!("rtc.config {what} re-serialize: {e}"))
                })
            }
        };
        let tcp_relay_json = object_json(&p2p.tcp_relay, "tcpRelay")?;
        let log_json = object_json(&p2p.log, "log")?;

        // Parse the nested session object for its scalar fields (best-effort; an
        // absent/odd session leaves them empty rather than failing the whole call).
        let sess: RawSession = if p2p.session.is_null() {
            serde_json::from_str("{}").expect("empty object parses")
        } else {
            serde_json::from_value(p2p.session.clone()).unwrap_or(RawSession {
                aes_key: String::new(),
                ice_password: String::new(),
                ice_ufrag: String::new(),
                session_id: String::new(),
                uid: String::new(),
                dev_id: String::new(),
            })
        };

        // devId: prefer session.devId, fall back to the top-level result id.
        let dev_id = pick(&sess.dev_id, &raw.id);
        if dev_id.is_empty() {
            return Err(Error::SignalingParse(
                "rtc.config result yields no devId (neither session.devId nor result.id)"
                    .to_string(),
            ));
        }

        Ok(Self {
            ices_json,
            session_json,
            session_aes_key: sess.aes_key,
            ice_password: sess.ice_password,
            ice_ufrag: sess.ice_ufrag,
            session_id: sess.session_id,
            uid: sess.uid,
            dev_id,
            // motoId can live at the top level OR inside p2pConfig — prefer the
            // top-level, fall back to p2pConfig.motoId (cap1 has both, equal).
            moto_id: pick(&raw.moto_id, &p2p.moto_id),
            p2p_type: raw.p2p_type,
            auth: pick(&raw.auth, &p2p.auth),
            skill: if raw.skill.is_empty() {
                "{}".to_string()
            } else {
                raw.skill
            },
            password: raw.password,
            transmission: p2p.transmission,
            tcp_relay_json,
            log_json,
        })
    }

    /// Whether this config is the WebRTC-over-MQTT transport (`p2pType == 4`).
    #[must_use]
    pub fn is_webrtc(&self) -> bool {
        self.p2p_type == 4
    }
}

/// First non-empty of two strings (owned copy).
fn pick(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_string()
    } else {
        a.to_string()
    }
}

impl std::fmt::Debug for RtcConfig {
    /// Redacts every per-session secret / PII value — only shapes/lengths and the
    /// non-secret `p2pType`/`transmission`/presence flags are shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtcConfig")
            .field("p2p_type", &self.p2p_type)
            .field("transmission", &self.transmission)
            .field("ices_len", &self.ices_json.len())
            .field("session_present", &(self.session_json != "{}"))
            .field("has_auth", &!self.auth.is_empty())
            .field("has_password", &!self.password.is_empty())
            .field("has_moto_id", &!self.moto_id.is_empty())
            .field("has_tcp_relay", &!self.tcp_relay_json.is_empty())
            .field("has_log", &!self.log_json.is_empty())
            .field("dev_id", &"<redacted>")
            .field("uid", &"<redacted>")
            .field("session_aes_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fully SYNTHETIC rtc.config result — no real device/session/key value.
    fn synthetic_result() -> serde_json::Value {
        serde_json::json!({
            "id": "synthdev0001ufmo",
            "motoId": "signaling00000",
            "p2pType": 4,
            "auth": "U1lOVEhfQVVUSF9CNjQ=",
            "password": "SYNTHpw0", // secret-scan:allow (synthetic test password)
            "skill": "{\"webrtc\":3,\"video_num\":3}",
            "p2pConfig": {
                "ices": [
                    {"urls": "stun:1.2.3.4:3478"},
                    {"urls": "turn:5.6.7.8:3478", "username": "u", "credential": "c", "ttl": 36000}
                ],
                "transmission": "kcp",
                "motoId": "signaling00000",
                "auth": "U1lOVEhfQVVUSF9CNjQ=",
                "tcpRelay": {
                    "credential": "U1lOVEhfVENQPQ==",
                    "domain": "localhost",
                    "sessionId": "synthSID02",
                    "urls": ["tcp4:9.9.9.9:1443"],
                    "urlsEx": ["tcp6:[2a05:dead:beef::2]:1443"],
                    "username": "1700000000:synthdev0001ufmo"
                },
                "log": {
                    "api": "thing.m.rtc.log",
                    "interval": 60,
                    "level": 2,
                    "size": 1024,
                    "tcp": {"address": "3.3.3.3", "domain": "synth.example", "key": "SYNTHLOGKEY01", "port": 9093},
                    "topic": "/av/moto/log"
                },
                "session": {
                    "aesKey": "00112233445566778899aabbccddeeff",
                    "icePassword": "SynthIcePwd0123456789012",
                    "iceUfrag": "SyUf",
                    "sessionId": "synthSID01",
                    "uid": "eu0000000000000synth",
                    "devId": "synthdev0001ufmo"
                }
            }
        })
    }

    #[test]
    fn parses_synthetic_webrtc_config() {
        let rc = RtcConfig::from_rtc_result(&synthetic_result()).unwrap();
        assert!(rc.is_webrtc());
        assert_eq!(rc.p2p_type, 4);
        assert_eq!(rc.dev_id, "synthdev0001ufmo");
        assert_eq!(rc.uid, "eu0000000000000synth");
        assert_eq!(rc.session_id, "synthSID01");
        assert_eq!(rc.ice_ufrag, "SyUf");
        assert_eq!(rc.moto_id, "signaling00000");
        assert_eq!(rc.transmission, "kcp");
        assert!(!rc.auth.is_empty());
        // result.password is surfaced verbatim (the conv=0 media-start AUTH pwd).
        assert_eq!(rc.password, "SYNTHpw0"); // secret-scan:allow (synthetic test password)
                                             // ices re-serialized to a compact JSON array that the signaling IceServer
                                             // list can parse.
        let ices: Vec<crate::stream::signaling::IceServer> =
            serde_json::from_str(&rc.ices_json).unwrap();
        assert_eq!(ices.len(), 2);
        assert_eq!(ices[0].urls, "stun:1.2.3.4:3478");
    }

    #[test]
    fn surfaces_tcp_relay_and_log_as_offer_descriptors() {
        // TASK-0080: the offer echoes p2pConfig.tcpRelay -> msg.tcp_token and
        // p2pConfig.log -> msg.log; the parser surfaces both as compact JSON.
        let rc = RtcConfig::from_rtc_result(&synthetic_result()).unwrap();
        assert!(!rc.tcp_relay_json.is_empty(), "tcpRelay surfaced");
        assert!(!rc.log_json.is_empty(), "log surfaced");
        // tcp_relay parses to the typed TcpToken the offer needs.
        let tcp: crate::stream::signaling::TcpToken =
            serde_json::from_str(&rc.tcp_relay_json).expect("tcpRelay -> TcpToken");
        assert_eq!(tcp.urls, vec!["tcp4:9.9.9.9:1443".to_string()]);
        assert_eq!(tcp.urls_ex.len(), 1, "IPv6 urlsEx carried");
        // log parses to an opaque object with the cap3 keys.
        let log: serde_json::Value = serde_json::from_str(&rc.log_json).expect("log -> value");
        assert_eq!(log["api"], "thing.m.rtc.log");
        assert_eq!(log["tcp"]["port"], 9093);
    }

    #[test]
    fn tcp_relay_and_log_empty_when_absent() {
        // A device whose rtc.config carried neither -> empty strings (offer omits).
        let mut v = synthetic_result();
        let p2p = v["p2pConfig"].as_object_mut().unwrap();
        p2p.remove("tcpRelay");
        p2p.remove("log");
        let rc = RtcConfig::from_rtc_result(&v).unwrap();
        assert!(rc.tcp_relay_json.is_empty());
        assert!(rc.log_json.is_empty());
    }

    #[test]
    fn session_aes_key_is_not_the_media_key_contract() {
        // The session.aesKey is surfaced but is NOT the media key (which the CLI
        // mints). This test documents the contract: the field is populated, and
        // the module guarantees it is never the SDP media key. (The cap3 proof —
        // offer aes-key != session.aesKey — is in tests/rtc_config_cap.rs.)
        let rc = RtcConfig::from_rtc_result(&synthetic_result()).unwrap();
        assert_eq!(rc.session_aes_key, "00112233445566778899aabbccddeeff");
        assert_eq!(rc.session_aes_key.len(), 32, "32-hex = 16 bytes");
    }

    #[test]
    fn falls_back_to_top_level_id_when_session_devid_absent() {
        let mut v = synthetic_result();
        v["p2pConfig"]["session"]
            .as_object_mut()
            .unwrap()
            .remove("devId");
        let rc = RtcConfig::from_rtc_result(&v).unwrap();
        assert_eq!(rc.dev_id, "synthdev0001ufmo"); // from result.id
    }

    #[test]
    fn rejects_result_without_p2pconfig() {
        let v = serde_json::json!({"id": "x", "p2pType": 4});
        let err = RtcConfig::from_rtc_result(&v).unwrap_err();
        assert!(matches!(err, Error::SignalingParse(_)));
    }

    #[test]
    fn rejects_result_without_any_devid() {
        let v = serde_json::json!({"p2pType": 4, "p2pConfig": {"session": {}}});
        let err = RtcConfig::from_rtc_result(&v).unwrap_err();
        assert!(matches!(err, Error::SignalingParse(_)));
    }

    #[test]
    fn debug_redacts_secrets() {
        let rc = RtcConfig::from_rtc_result(&synthetic_result()).unwrap();
        let dbg = format!("{rc:?}");
        assert!(dbg.contains("p2p_type: 4"));
        assert!(
            !dbg.contains("eu0000000000000synth"),
            "uid must be redacted"
        );
        assert!(
            !dbg.contains("00112233445566778899aabbccddeeff"),
            "aesKey must be redacted"
        );
        // The auth password value must never appear in Debug (only a presence flag).
        assert!(
            !dbg.contains("SYNTHpw0"), // secret-scan:allow (synthetic test password)
            "password must be redacted"
        );
        assert!(dbg.contains("has_password: true"));
    }
}
