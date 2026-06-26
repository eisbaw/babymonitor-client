//! Byte-validation of the WebRTC-over-MQTT 302 signaling codec against the cap3
//! capture (`emulator_captures/cap3/signaling_plaintext.jsonl`).
//!
//! Two layers:
//! 1. A **committed, redacted** fixture (`tests/fixtures/signaling_cap3_redacted.jsonl`,
//!    synthetic ids/keys — no real device/session value) is always validated, so
//!    CI without the capture still exercises the full multi-message file shape.
//! 2. The **real** cap3 file (gitignored) is validated when present — true
//!    byte-validation against the live negotiation. Absent (CI) → skipped.
//!
//! For each offer we re-derive [`OfferSdpParams`] from the captured SDP and assert
//! [`build_offer_sdp`] reproduces the captured offer SDP **byte-for-byte**; for
//! each answer we assert [`SignalingEnvelope::parse_answer`] extracts the ICE
//! creds + media key; and every message round-trips through the localKey-AES 302
//! frame codec.

use babymonitor_core::stream::mqtt_crypto::{build_302_frame, parse_302_frame};
use babymonitor_core::stream::sdp::{build_offer_sdp, OfferSdpParams};
use babymonitor_core::stream::signaling::{SignalingEnvelope, SignalingPath, SignalingType};

// A synthetic 16-byte localKey for the 302-frame round-trip (never a real key).
const SYNTH_LOCAL_KEY: &[u8; 16] = b"0123456789abcdef";

/// Pull the inner 302 JSON out of one capture line. The capture wraps each
/// decrypted message as `{"tag": "...", "text": "<inner json string>"}`.
fn inner_json(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(v.get("text")?.as_str()?.to_string())
}

fn sdp_field<'a>(sdp: &'a str, prefix: &str) -> Option<&'a str> {
    sdp.split("\r\n")
        .find_map(|l| l.strip_prefix(prefix))
        .map(str::trim)
}

/// Re-derive the offer-SDP params from a captured offer SDP and assert our
/// builder reproduces the SAME bytes — the SDP byte-validation.
fn assert_offer_sdp_reproduces(sdp: &str) {
    let o_line = sdp_field(sdp, "o=- ").expect("o= line");
    let o_session: u64 = o_line
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .expect("o_session");
    let stream_id = sdp_field(sdp, "a=msid-semantic: WMS ").expect("msid WMS");
    let ufrag = sdp_field(sdp, "a=ice-ufrag:").expect("ufrag");
    let pwd = sdp_field(sdp, "a=ice-pwd:").expect("pwd");
    let aes_hex = sdp_field(sdp, "a=aes-key:").expect("aes-key");
    let cname = sdp_field(sdp, "a=ssrc:0 cname:").expect("cname");
    let rtpmap = sdp_field(sdp, "a=rtpmap:6001 AES/KCP ").expect("rtpmap");
    let rtpmap_param: u32 = rtpmap.parse().expect("rtpmap param");

    let rebuilt = build_offer_sdp(&OfferSdpParams {
        o_session,
        stream_id: stream_id.to_string(),
        ice_ufrag: ufrag.to_string(),
        ice_pwd: pwd.to_string(),
        media_key: hex::decode(aes_hex).expect("aes-key hex"),
        cname: cname.to_string(),
        rtpmap_param,
    })
    .expect("build_offer_sdp");
    assert_eq!(
        rebuilt, sdp,
        "build_offer_sdp must reproduce the captured offer SDP byte-for-byte"
    );
}

/// Validate one capture file: every message parses to the typed envelope, offers
/// reproduce their SDP, the answer's engine inputs extract, and each round-trips
/// through the 302 frame codec.
fn validate_capture(path: &std::path::Path) {
    let body = std::fs::read_to_string(path).expect("read capture");
    let mut n_offer = 0;
    let mut n_candidate = 0;
    let mut n_answer = 0;

    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let inner = inner_json(line).expect("capture line has text");
        let env = SignalingEnvelope::from_json(inner.as_bytes())
            .unwrap_or_else(|e| panic!("cap3 message must parse: {e}\n{inner}"));

        match env.header.r#type {
            SignalingType::Offer => {
                n_offer += 1;
                // offer carries the structured msg object (NOT a string).
                let sdp = env.msg.sdp.as_deref().expect("offer has msg.sdp");
                assert!(sdp.contains("m=application 9 imm 6001"));
                assert_eq!(env.msg.preconnect, Some(true));
                assert!(env.msg.token.as_ref().is_some_and(|t| !t.is_empty()));
                assert!(env.msg.tcp_token.is_some());
                assert!(matches!(
                    env.header.path,
                    Some(SignalingPath::Mqtt) | Some(SignalingPath::Lan)
                ));
                assert_offer_sdp_reproduces(sdp);
            }
            SignalingType::Candidate => {
                n_candidate += 1;
                // candidate carries only msg.candidate (possibly the empty
                // end-of-candidates sentinel); never an SDP/token.
                assert!(env.msg.sdp.is_none());
                assert!(env.msg.candidate.is_some());
            }
            SignalingType::Answer => {
                n_answer += 1;
                let parsed = env.parse_answer().expect("answer parses");
                assert!(!parsed.remote_ufrag.is_empty());
                assert!(!parsed.remote_pwd.is_empty());
                assert_eq!(parsed.media_key.len(), 16, "media key is 16 bytes");
                assert!(parsed.sdp.contains("m=application 9 tuya 6001"));
            }
            SignalingType::Disconnect => {}
        }

        // Every message round-trips through the localKey-AES 302 frame codec
        // (base64 variant + {data,gwId,protocol,pv,t} frame).
        let frame = build_302_frame(inner.as_bytes(), SYNTH_LOCAL_KEY, "SYNTH_DEV", "2.2", 0)
            .expect("build 302 frame");
        let back = parse_302_frame(&frame, SYNTH_LOCAL_KEY).expect("parse 302 frame");
        assert_eq!(back, inner.as_bytes(), "302 frame round-trip is lossless");
        // And the decrypted plaintext re-parses to the same envelope.
        let env2 = SignalingEnvelope::from_json(&back).unwrap();
        assert_eq!(env2.header.r#type, env.header.r#type);
    }

    assert!(n_offer >= 1, "capture must contain at least one offer");
    assert!(n_answer >= 1, "capture must contain the answer");
    assert!(n_candidate >= 1, "capture must contain trickle candidates");
}

// Always-on: the committed redacted fixture (synthetic ids/keys) validates the
// full file/codec path without committing any real capture value.
#[test]
fn redacted_cap3_fixture_byte_validates() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/signaling_cap3_redacted.jsonl");
    validate_capture(&path);
}

// Gated on the gitignored real capture: true byte-validation when it is present
// locally; cleanly skipped (no failure) in CI where it is absent.
#[test]
fn real_cap3_capture_byte_validates_when_present() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../emulator_captures/cap3/signaling_plaintext.jsonl");
    if !path.exists() {
        eprintln!(
            "skip: real cap3 capture not present ({}); redacted fixture covers CI",
            path.display()
        );
        return;
    }
    validate_capture(&path);
}
