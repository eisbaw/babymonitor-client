//! Offline validation of the `rtc.config.get` parser ([`RtcConfig`]) and the
//! media-key-origin determination, against captures (TASK-0078).
//!
//! Three layers (mirrors `tests/signaling_cap3.rs`):
//! 1. A **committed, redacted** fixture (`tests/fixtures/rtc_config_redacted.json`,
//!    synthetic ids/keys) — always validated, so CI without the captures still
//!    exercises the full parser.
//! 2. The **real** decrypted cap1 `rtc.config.get` result
//!    (`secrets/cap1_rtc_decrypted/smartlife.m.rtc.config.get.json`, gitignored) —
//!    validated when present; absent → skipped. NO value is printed.
//! 3. The **media-key-MINTED proof** from the cap3 signaling capture
//!    (`emulator_captures/cap3/signaling_plaintext.jsonl`, gitignored): the offer's
//!    `a=aes-key` **equals the answer's** — i.e. the camera echoes the app-minted
//!    key — which (with the separately-proven `offer aes-key != rtc.config
//!    session.aesKey`, see `re/webrtc_session.md`) pins the media key as
//!    client-minted, NOT the `rtc.config session.aesKey`. Absent → skipped.

use std::path::{Path, PathBuf};

use babymonitor_core::stream::rtc_config::RtcConfig;
use babymonitor_core::stream::topics::{publish_topic, subscribe_topic};

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The decrypted cap1/cap3 dump wraps the result under `{"response": {"result": …}}`
/// (the `re/scripts/decrypt_rtc_flow.py` dump shape) OR is the bare `result` object.
/// Return the inner `result` object either way.
fn extract_result(v: &serde_json::Value) -> serde_json::Value {
    if let Some(inner) = v
        .get("response")
        .and_then(|r| r.get("result"))
        .filter(|r| r.is_object())
    {
        return inner.clone();
    }
    if let Some(inner) = v.get("result").filter(|r| r.is_object()) {
        return inner.clone();
    }
    v.clone()
}

#[test]
fn parses_committed_redacted_fixture() {
    let path = repo_path("tests/fixtures/rtc_config_redacted.json");
    let bytes = std::fs::read(&path).expect("redacted fixture present");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture json");
    let rc = RtcConfig::from_rtc_result(&extract_result(&v)).expect("parse fixture");

    assert!(rc.is_webrtc(), "fixture is p2pType=4 WebRTC");
    assert_eq!(rc.dev_id, "synthdev0001ufmo");
    assert_eq!(rc.uid, "eu0000000000000synth");
    assert!(!rc.auth.is_empty(), "per-session signaling token present");
    assert_eq!(rc.transmission, "kcp");
    assert!(!rc.moto_id.is_empty());
    // ices re-serialize to a list the ICE engine parses.
    let ices: Vec<babymonitor_core::stream::signaling::IceServer> =
        serde_json::from_str(&rc.ices_json).expect("ices parse");
    assert_eq!(ices.len(), 3, "2 STUN + 1 TURN");

    // Topic derivation from the (synthetic) devId.
    assert_eq!(publish_topic(&rc.dev_id), "smart/mb/out/synthdev0001ufmo");
    assert_eq!(subscribe_topic(&rc.dev_id), "smart/mb/in/synthdev0001ufmo");
}

#[test]
fn parses_real_cap1_rtc_config_when_present() {
    // The gitignored real decrypted cap1 rtc.config result. Skip if absent (CI).
    let path = repo_path("../../secrets/cap1_rtc_decrypted/smartlife.m.rtc.config.get.json");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skip: {} not present", path.display());
        return;
    };
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("cap1 rtc json");
    let rc = RtcConfig::from_rtc_result(&extract_result(&v)).expect("parse real cap1");

    // Structural assertions only — NEVER print a value.
    assert!(rc.is_webrtc(), "SCD921 rtc.config is p2pType=4");
    assert!(!rc.dev_id.is_empty(), "devId present");
    assert!(!rc.uid.is_empty(), "session.uid present");
    assert!(!rc.session_id.is_empty(), "session.sessionId present");
    assert!(!rc.auth.is_empty(), "per-session auth token present");
    assert_eq!(rc.transmission, "kcp", "SCD921 reliable transport is KCP");
    // session.aesKey is 32 lowercase-hex (16 bytes) — but it is NOT the media key.
    assert_eq!(
        rc.session_aes_key.len(),
        32,
        "session.aesKey is 16 bytes hex"
    );
    assert!(
        rc.session_aes_key.bytes().all(|b| b.is_ascii_hexdigit()),
        "session.aesKey is hex"
    );
    // ices parse into typed ICE servers (>=1 STUN/TURN).
    let ices: Vec<babymonitor_core::stream::signaling::IceServer> =
        serde_json::from_str(&rc.ices_json).expect("real ices parse");
    assert!(
        !ices.is_empty(),
        "rtc.config carries at least one ICE server"
    );

    // The devId that drives the topic template is consistent with the cap3
    // signaling header.to (the camera id) when that capture is present — the
    // INPUT-side validation of the (off-proxy) topic template.
    if let Some(cap3_to) = cap3_header_field("to") {
        assert_eq!(
            rc.dev_id, cap3_to,
            "rtc.config devId == cap3 302 header.to (the camera the topic addresses)"
        );
    }
}

/// The media key is MINTED by the client, NOT `rtc.config session.aesKey`.
///
/// Proof half on-disk in cap3: the offer's `a=aes-key` EQUALS the answer's — the
/// camera echoes the app's key rather than choosing its own. (The complementary
/// half — offer aes-key != that session's `rtc.config session.aesKey` — was proven
/// live during RE and is recorded in `re/webrtc_session.md`; it needs the same
/// session's decrypted rtc.config which is not committed.)
#[test]
fn cap3_offer_aes_key_equals_answer_aes_key_when_present() {
    let Some(offer) = cap3_aes_key("offer") else {
        eprintln!("skip: cap3 signaling capture not present");
        return;
    };
    let answer = cap3_aes_key("answer").expect("cap3 has an answer when it has an offer");
    assert_eq!(
        offer, answer,
        "the camera echoes the app-minted media key (offer a=aes-key == answer a=aes-key)"
    );
    assert_eq!(offer.len(), 32, "media key is 16 bytes hex");
}

// ── cap3 helpers (read the gitignored signaling_plaintext.jsonl, no value print) ──

fn cap3_lines() -> Option<Vec<serde_json::Value>> {
    let path = repo_path("../../emulator_captures/cap3/signaling_plaintext.jsonl");
    let text = std::fs::read_to_string(&path).ok()?;
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .collect(),
    )
}

/// The `a=aes-key:<hex>` of the first cap3 message of `want_type` ("offer"/"answer").
fn cap3_aes_key(want_type: &str) -> Option<String> {
    for outer in cap3_lines()? {
        let text = outer.get("text")?.as_str()?;
        let inner: serde_json::Value = serde_json::from_str(text).ok()?;
        let typ = inner.get("header")?.get("type")?.as_str()?;
        if typ != want_type {
            continue;
        }
        let sdp = inner.get("msg")?.get("sdp")?.as_str()?;
        if let Some(rest) = sdp.split("a=aes-key:").nth(1) {
            let key: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if !key.is_empty() {
                return Some(key);
            }
        }
    }
    None
}

/// A header scalar of the first cap3 `offer` message (e.g. "to" = the camera id).
fn cap3_header_field(field: &str) -> Option<String> {
    for outer in cap3_lines()? {
        let text = outer.get("text")?.as_str()?;
        let inner: serde_json::Value = serde_json::from_str(text).ok()?;
        let hdr = inner.get("header")?;
        if hdr.get("type")?.as_str()? == "offer" {
            return hdr.get(field)?.as_str().map(str::to_string);
        }
    }
    None
}
