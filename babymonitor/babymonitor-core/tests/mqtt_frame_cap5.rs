//! cap5 KAT — validate the Tuya message-2.2 binary 302 frame codec against the
//! REAL captured publish (`secrets/cap5/offer_302_frame.bin`, gitignored).
//!
//! This is the byte-level ground truth that pins the camera-silent fix: cap3 only
//! had the *decrypted* 302 content; cap5 captured the actual published frame. The
//! test is `#[ignore]`d and present-gated — it needs the local secret fixture
//! (the real `localKey`), so it never runs in CI and leaks nothing.
//!
//! See `re/mqtt_2_2_frame.md` for the wire format.

use babymonitor_core::stream::mqtt_crypto::{
    aes128_ecb_decrypt, aes128_ecb_encrypt, build_302_frame, crc32, parse_302_frame,
};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
#[ignore = "requires local secrets/cap5 capture (gitignored real localKey)"]
fn cap5_real_302_frame_byte_validates() {
    let frame = match std::fs::read(root().join("secrets/cap5/offer_302_frame.bin")) {
        Ok(f) => f,
        Err(_) => return, // fixture absent — skip (present-gated)
    };
    let key_s = std::fs::read_to_string(root().join("secrets/cap5/localkey.txt"))
        .expect("secrets/cap5/localkey.txt must accompany the frame");
    let key = key_s.trim().as_bytes();
    assert_eq!(key.len(), 16, "localKey is the 16-byte AES key");
    let pv = "2.2";

    // ── 1. PARSE the real camera-format frame → a valid 302 offer ────────────
    let inner = parse_302_frame(&frame, key, pv).expect("parse the real published frame");
    let v: serde_json::Value = serde_json::from_slice(&inner).unwrap();
    assert_eq!(v["header"]["type"], "offer", "inner is a 302 offer");
    assert_eq!(v["header"]["security_level"], 3);
    assert!(
        v["msg"]["sdp"].as_str().unwrap().contains("v=0"),
        "msg.sdp is an SDP offer"
    );

    // ── 2. CRYPTO + framing byte-exactness on the REAL bytes ─────────────────
    assert_eq!(&frame[..3], pv.as_bytes(), "pv prefix");
    let crc_field = u32::from_be_bytes(frame[3..7].try_into().unwrap());
    // The camera's 12002 signature gate: crc32 over (s ++ o ++ ciphertext).
    assert_eq!(
        crc32(&frame[7..]),
        crc_field,
        "crc32(frame[7:]) == frame[3:7]"
    );
    let ct = &frame[15..];
    assert_eq!(ct.len() % 16, 0, "ciphertext is whole AES blocks");
    // Re-encrypting the exact decrypted plaintext reproduces the ciphertext —
    // proves our AES-128/ECB/PKCS7 is byte-identical to the device's `AESUtil`.
    let pt = aes128_ecb_decrypt(ct, key).unwrap();
    assert_eq!(
        aes128_ecb_encrypt(&pt, key).unwrap(),
        ct,
        "AES re-encrypt reproduces the captured ciphertext"
    );

    // ── 3. FULL build reproduces the captured frame byte-for-byte ────────────
    // Feed back the captured s/o/t + inner json; the deterministic CRC+AES (and a
    // serde_json re-serialization that matches the device's compact JSON) must
    // yield the exact published bytes.
    let s = u32::from_be_bytes(frame[7..11].try_into().unwrap());
    let o = u32::from_be_bytes(frame[11..15].try_into().unwrap());
    let envelope: serde_json::Value = serde_json::from_slice(&pt).unwrap();
    let t = envelope["t"].as_i64().expect("envelope.t");
    let rebuilt = build_302_frame(&inner, key, pv, s, o, t).expect("rebuild frame");
    assert_eq!(
        rebuilt, frame,
        "rebuilt message-2.2 frame is byte-identical to the captured publish"
    );
}
