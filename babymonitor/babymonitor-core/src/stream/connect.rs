//! The `connect_v2` control-JSON builder (`re/webrtc_session.md` §1).
//!
//! The native `imm_p2p_rtc_connect_v2` (`re/ghidra/imm_p2p_rtc_connect_v2.c`)
//! builds, byte-for-byte (format string verified in Ghidra AND r2 at file
//! `0x11759a`):
//!
//! ```text
//! {"cmd":"connect_v2","args":{"remote_id":"%s","dev_id":"%s","skill":%.*s,
//!  "token":%.*s,"trace_id":"%s","timeout_ms":%d,"lan_mode":%d,
//!  "preconnect_enable":1,"connect_session":"%s"}}
//! ```
//!
//! Notes the decompilation pins (so we reproduce them EXACTLY):
//! - `skill` and `token` are emitted **UNQUOTED** (`%.*s` → raw JSON), so each
//!   must already be a valid JSON value (the native side defaults an empty one to
//!   the literal `{}`).
//! - `preconnect_enable` is hard-coded `1`.
//! - `timeout_ms` is clamped to **[1000, 30000]** (native: `< 1001 → 1000`,
//!   `> 29999 → 30000`).
//! - `connect_session` is a **33-byte (0x21) random string** the native lib
//!   generates itself (`imm_p2p_misc_rand_string(&buf, 0x21)`). Since the Rust
//!   client re-implements the native side, it mints its OWN per session.
//! - empty `dev_id` defaults to `remote_id`.

use crate::Error;

/// The lower clamp on `timeout_ms` (native: `< 1001 → 1000`).
pub const TIMEOUT_MS_MIN: i64 = 1000;
/// The upper clamp on `timeout_ms` (native: `> 29999 → 30000`).
pub const TIMEOUT_MS_MAX: i64 = 30000;
/// The exact length of the native-minted `connect_session` random string
/// (`imm_p2p_misc_rand_string(&buf, 0x21)` ⇒ 0x21 = 33 chars).
pub const CONNECT_SESSION_LEN: usize = 0x21;

/// `lan_mode`: 0 = signal via cloud MQTT (remote), 1 = signal via LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanMode {
    /// Cloud MQTT signaling (the remote-view path; `lan_mode=0`).
    Cloud,
    /// LAN signaling (`lan_mode=1`).
    Lan,
}

impl LanMode {
    /// The wire integer for this mode.
    #[must_use]
    pub fn as_int(self) -> i32 {
        match self {
            Self::Cloud => 0,
            Self::Lan => 1,
        }
    }
}

/// Clamp a requested `timeout_ms` to the native-accepted range
/// `[TIMEOUT_MS_MIN, TIMEOUT_MS_MAX]` (`re/webrtc_session.md` §1, step 1).
#[must_use]
pub fn clamp_timeout_ms(requested: i64) -> i64 {
    requested.clamp(TIMEOUT_MS_MIN, TIMEOUT_MS_MAX)
}

/// Inputs to the `connect_v2` builder. The runtime/auth-gated values come from
/// [`super::StreamCredentials`]; `trace_id`/`connect_session` are client-minted.
#[derive(Debug, Clone)]
pub struct ConnectV2Args {
    /// `remote_id` = the P2P device handle (`CameraInfoBean.p2pId`). REQUIRED.
    pub remote_id: String,
    /// `dev_id` = the Tuya cloud device id. Empty → defaults to `remote_id`.
    pub dev_id: String,
    /// `skill` = capability JSON, emitted UNQUOTED. Empty → native default `{}`.
    pub skill: String,
    /// `token` = the per-session signaling token, emitted UNQUOTED. Empty →
    /// native default `{}`.
    pub token: String,
    /// `trace_id` = session correlation id, client-minted (UUID-shaped).
    pub trace_id: String,
    /// `timeout_ms`, clamped to [1000, 30000] by the builder.
    pub timeout_ms: i64,
    /// `lan_mode`.
    pub lan_mode: LanMode,
    /// `connect_session` — client-minted 33-char random (see
    /// [`CONNECT_SESSION_LEN`]).
    pub connect_session: String,
}

/// Build the `connect_v2` control JSON, byte-compatible with the native
/// `imm_p2p_rtc_connect_v2` format string (`re/webrtc_session.md` §1).
///
/// This reproduces the native defaulting (`skill`/`token` empty → `{}`,
/// `dev_id` empty → `remote_id`) and clamping (`timeout_ms`), so the emitted
/// bytes match what the device's own SDK would have produced.
///
/// # Errors
/// - [`Error::StreamConfig`] if `remote_id` is empty (native returns `-5`).
/// - [`Error::StreamConfig`] if `skill`/`token` are non-empty but not valid JSON
///   values (they are emitted UNQUOTED, so an invalid value would corrupt the
///   whole control JSON — we reject loudly rather than emit broken JSON).
/// - [`Error::StreamConfig`] if `connect_session` is not [`CONNECT_SESSION_LEN`]
///   chars.
pub fn build_connect_v2(args: &ConnectV2Args) -> Result<String, Error> {
    if args.remote_id.is_empty() {
        return Err(Error::StreamConfig(
            "connect_v2 remote_id is empty (native returns -5)".into(),
        ));
    }
    if args.connect_session.chars().count() != CONNECT_SESSION_LEN {
        return Err(Error::StreamConfig(format!(
            "connect_session must be {CONNECT_SESSION_LEN} chars (native rand_string 0x21), got {}",
            args.connect_session.chars().count()
        )));
    }

    // Native defaulting.
    let dev_id = if args.dev_id.is_empty() {
        args.remote_id.as_str()
    } else {
        args.dev_id.as_str()
    };
    let skill = default_json_value(&args.skill);
    let token = default_json_value(&args.token);

    // `skill` and `token` are emitted UNQUOTED, so they MUST be valid JSON
    // values; reject loudly otherwise (a bad value would corrupt the control
    // JSON the device parses).
    validate_json_value(skill, "skill")?;
    validate_json_value(token, "token")?;

    let timeout_ms = clamp_timeout_ms(args.timeout_ms);
    let lan_mode = args.lan_mode.as_int();

    // `remote_id`/`dev_id`/`trace_id`/`connect_session` are quoted string fields:
    // JSON-escape them so an embedded quote/backslash cannot break the envelope.
    let remote_id = json_string_escape(&args.remote_id);
    let dev_id_q = json_string_escape(dev_id);
    let trace_id = json_string_escape(&args.trace_id);
    let connect_session = json_string_escape(&args.connect_session);

    Ok(format!(
        "{{\"cmd\":\"connect_v2\",\"args\":{{\"remote_id\":\"{remote_id}\",\"dev_id\":\"{dev_id_q}\",\"skill\":{skill},\"token\":{token},\"trace_id\":\"{trace_id}\",\"timeout_ms\":{timeout_ms},\"lan_mode\":{lan_mode},\"preconnect_enable\":1,\"connect_session\":\"{connect_session}\"}}}}"
    ))
}

/// Native default: an empty `skill`/`token` becomes the literal `{}`.
fn default_json_value(s: &str) -> &str {
    if s.is_empty() {
        "{}"
    } else {
        s
    }
}

/// Validate that a string is a parseable JSON value (used for the UNQUOTED
/// `skill`/`token` fields). We parse with `serde_json` rather than re-emitting,
/// so the caller's exact bytes are preserved (matching the native `%.*s`).
fn validate_json_value(s: &str, field: &str) -> Result<(), Error> {
    serde_json::from_str::<serde_json::Value>(s).map_err(|e| {
        Error::StreamConfig(format!(
            "connect_v2 `{field}` is emitted unquoted but is not valid JSON: {e}"
        ))
    })?;
    Ok(())
}

/// Minimal JSON string-body escape for the quoted fields (escape `"` and `\`,
/// plus control chars that would make the JSON invalid). Kept local + tiny: we
/// only escape the few characters that can appear in an id and break JSON.
fn json_string_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn synth_args() -> ConnectV2Args {
        ConnectV2Args {
            remote_id: "P2PID-AAAA".into(),
            dev_id: "DEVID-BBBB".into(),
            skill: "{\"webrtc\":1}".into(),
            token: "{\"t\":\"sig\"}".into(),
            trace_id: "trace-0001".into(),
            timeout_ms: 5000,
            lan_mode: LanMode::Cloud,
            connect_session: "A".repeat(CONNECT_SESSION_LEN),
        }
    }

    // The built JSON must match the native template SHAPE exactly: the cmd, the
    // arg keys in order, preconnect_enable:1 hard-coded, and the unquoted
    // skill/token. We assert both the raw string AND that it parses back.
    #[test]
    fn builds_connect_v2_matching_template() {
        let json = build_connect_v2(&synth_args()).unwrap();
        assert_eq!(
            json,
            "{\"cmd\":\"connect_v2\",\"args\":{\"remote_id\":\"P2PID-AAAA\",\"dev_id\":\"DEVID-BBBB\",\"skill\":{\"webrtc\":1},\"token\":{\"t\":\"sig\"},\"trace_id\":\"trace-0001\",\"timeout_ms\":5000,\"lan_mode\":0,\"preconnect_enable\":1,\"connect_session\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}"
        );
        // And it must be valid JSON with the expected structure.
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["cmd"], "connect_v2");
        assert_eq!(v["args"]["preconnect_enable"], 1);
        assert_eq!(v["args"]["timeout_ms"], 5000);
        assert_eq!(v["args"]["lan_mode"], 0);
        // skill/token emitted as nested objects (proving they were unquoted).
        assert_eq!(v["args"]["skill"]["webrtc"], 1);
        assert_eq!(v["args"]["token"]["t"], "sig");
    }

    // timeout clamp: below 1000 → 1000, above 30000 → 30000, in-range untouched.
    #[test]
    fn timeout_is_clamped() {
        assert_eq!(clamp_timeout_ms(0), TIMEOUT_MS_MIN);
        assert_eq!(clamp_timeout_ms(999), TIMEOUT_MS_MIN);
        assert_eq!(clamp_timeout_ms(1000), 1000);
        assert_eq!(clamp_timeout_ms(15000), 15000);
        assert_eq!(clamp_timeout_ms(30000), 30000);
        assert_eq!(clamp_timeout_ms(99999), TIMEOUT_MS_MAX);

        let mut a = synth_args();
        a.timeout_ms = 999;
        let json = build_connect_v2(&a).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["args"]["timeout_ms"], 1000);
    }

    // Native defaulting: empty skill/token → {}, empty dev_id → remote_id.
    #[test]
    fn applies_native_defaults() {
        let mut a = synth_args();
        a.skill = String::new();
        a.token = String::new();
        a.dev_id = String::new();
        let json = build_connect_v2(&a).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        // empty skill/token become {}.
        assert!(v["args"]["skill"].is_object());
        assert_eq!(v["args"]["skill"].as_object().unwrap().len(), 0);
        assert!(v["args"]["token"].is_object());
        // empty dev_id defaults to remote_id.
        assert_eq!(v["args"]["dev_id"], "P2PID-AAAA");
    }

    #[test]
    fn lan_mode_one_when_lan() {
        let mut a = synth_args();
        a.lan_mode = LanMode::Lan;
        let v: Value = serde_json::from_str(&build_connect_v2(&a).unwrap()).unwrap();
        assert_eq!(v["args"]["lan_mode"], 1);
    }

    // NEGATIVE: an empty remote_id must be rejected (native -5).
    #[test]
    fn rejects_empty_remote_id() {
        let mut a = synth_args();
        a.remote_id = String::new();
        assert!(matches!(build_connect_v2(&a), Err(Error::StreamConfig(_))));
    }

    // NEGATIVE: a wrong-length connect_session must be rejected (33 chars exact).
    #[test]
    fn rejects_wrong_connect_session_length() {
        let mut a = synth_args();
        a.connect_session = "tooshort".into();
        assert!(matches!(build_connect_v2(&a), Err(Error::StreamConfig(_))));
        a.connect_session = "X".repeat(CONNECT_SESSION_LEN + 1);
        assert!(matches!(build_connect_v2(&a), Err(Error::StreamConfig(_))));
    }

    // NEGATIVE: a non-empty but invalid (unquoted) skill must be rejected — it
    // would corrupt the control JSON the device parses.
    #[test]
    fn rejects_invalid_unquoted_skill() {
        let mut a = synth_args();
        a.skill = "not json at all".into();
        assert!(matches!(build_connect_v2(&a), Err(Error::StreamConfig(_))));
    }

    // A remote_id containing a quote must be escaped, not break the JSON.
    #[test]
    fn escapes_quotes_in_string_fields() {
        let mut a = synth_args();
        a.remote_id = "ev\"il".into();
        let json = build_connect_v2(&a).unwrap();
        // Still valid JSON despite the embedded quote.
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["args"]["remote_id"], "ev\"il");
    }
}
