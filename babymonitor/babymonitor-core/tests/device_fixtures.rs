//! Fixture-driven tests for `babymonitor_core::device` (TASK-0013).
//!
//! These assert STRUCTURE, not content (TESTING.md Part 2 §3): the synthetic
//! device-list deserializes into the typed models, the camera entry is found,
//! `p2pType` maps to the WebRTC transport, and the load-bearing P2P credential
//! handles are present. A MANDATORY negative test proves the parser REJECTS a
//! malformed record (missing `devId` / missing `p2pId` / wrong type) with a
//! typed error — the models enforce required invariants and are not a permissive
//! serde sponge.
//!
//! The fixtures under `tests/fixtures/` are SYNTHETIC (no real capture exists —
//! this is a static-analysis-only project), so there is no PII/secret concern;
//! every value is obviously-fake.

use std::path::PathBuf;

use babymonitor_core::device::{parse_camera_info, parse_device_list, CameraView, P2pTransport};
use babymonitor_core::Error;

fn fixture(name: &str) -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

// ── POSITIVE: deserialize + structural assertions ──────────────────────────
#[test]
fn device_list_fixture_deserializes_and_finds_camera() {
    let list = parse_device_list(&fixture("device_list.json"))
        .expect("synthetic device-list must deserialize into the typed models");

    // Two owned devices, no shared.
    assert_eq!(list.device_list.len(), 2);
    assert_eq!(list.shared_device_list.len(), 0);
    assert_eq!(list.all_devices().count(), 2);

    // The camera (category `sp`) is found; the plug (`cz`) is not the camera.
    let camera = list
        .find_camera_device()
        .expect("the sp-category camera must be discoverable");
    assert_eq!(camera.dev_id, "synth-dev-0001-camera");
    assert!(camera.is_camera());
    assert!(camera.online(), "isOnline=true -> online");

    // Secret handles are present on the model (we don't assert their values).
    assert!(camera.local_key.is_some());
    assert!(camera.sec_key.is_some());

    // The plug is present but is NOT a camera, and is offline.
    let plug = list
        .all_devices()
        .find(|d| d.dev_id == "synth-dev-0002-plug")
        .expect("plug present");
    assert!(!plug.is_camera());
    assert!(!plug.online());
}

#[test]
fn camera_info_fixture_exposes_webrtc_and_p2p_handles() {
    let info = parse_camera_info(&fixture("camera_info.json"))
        .expect("synthetic camera-info must deserialize");

    // Required load-bearing handles are present (non-empty).
    assert_eq!(info.p2p_id, "synth-p2pid-0001-not-a-real-handle");
    assert_eq!(info.p2p_type, 4);

    // p2pType=4 maps to the WebRTC-over-MQTT transport.
    assert_eq!(info.transport(), P2pTransport::ThingWebRtc);
    assert!(info.transport().is_webrtc());

    // Nested P2P/WebRTC credential handles are present.
    let cfg = info.p2p_config.as_ref().expect("p2pConfig present");
    assert!(cfg.p2p_key.is_some(), "p2pKey handle present");
    assert!(cfg.init_str.is_some(), "initStr handle present");
    assert!(cfg.ices.is_some(), "ices present");
    assert!(cfg.session.is_some(), "session present");
}

#[test]
fn camera_view_pairs_device_and_info() {
    let list = parse_device_list(&fixture("device_list.json")).unwrap();
    let info = parse_camera_info(&fixture("camera_info.json")).unwrap();
    let device = list.find_camera_device().unwrap();

    let view = CameraView::pair(device, &info).expect("camera device + info must pair");
    assert_eq!(view.dev_id(), "synth-dev-0001-camera");
    assert!(view.online());
    assert_eq!(view.transport(), P2pTransport::ThingWebRtc);
    assert_eq!(view.p2p_id(), "synth-p2pid-0001-not-a-real-handle");
    assert!(view.p2p_config().is_some());
}

// ── NEGATIVE (MANDATORY): malformed records are REJECTED with a typed error ─
//
// Each of these proves a REQUIRED invariant bites. A permissive serde sponge
// would silently accept these; our models must not.

#[test]
fn device_missing_dev_id_is_rejected() {
    // A device record with no `devId` — the required addressing key.
    let body = br#"{"deviceList":[{"name":"no id","category":"sp"}]}"#;
    let err = parse_device_list(body).expect_err("missing devId MUST be rejected");
    assert!(matches!(err, Error::DeviceParse(_)));
    // The error should name the missing field for traceability.
    assert!(
        err.to_string().contains("devId") || err.to_string().contains("dev_id"),
        "error must name the missing devId field, got: {err}"
    );
}

#[test]
fn camera_missing_p2p_id_is_rejected() {
    // A camera-info record with no `p2pId` — the load-bearing P2P handle.
    let body = br#"{"id":"x","p2pType":4}"#;
    let err = parse_camera_info(body).expect_err("missing p2pId MUST be rejected");
    assert!(matches!(err, Error::DeviceParse(_)));
    assert!(
        err.to_string().contains("p2pId") || err.to_string().contains("p2p_id"),
        "error must name the missing p2pId field, got: {err}"
    );
}

#[test]
fn camera_missing_p2p_type_is_rejected() {
    // A camera-info record with no `p2pType` — the required transport selector.
    let body = br#"{"id":"x","p2pId":"synth-handle"}"#;
    let err = parse_camera_info(body).expect_err("missing p2pType MUST be rejected");
    assert!(matches!(err, Error::DeviceParse(_)));
}

#[test]
fn camera_wrong_typed_p2p_type_is_rejected() {
    // `p2pType` present but the WRONG type (string, not int) — must not be
    // silently coerced; serde rejects it with a typed error.
    let body = br#"{"p2pId":"synth-handle","p2pType":"four"}"#;
    let err = parse_camera_info(body).expect_err("wrong-typed p2pType MUST be rejected");
    assert!(matches!(err, Error::DeviceParse(_)));
}

#[test]
fn pairing_non_camera_device_is_rejected() {
    // A non-camera device paired with a camera-info must fail loud, not connect
    // with mismatched handles.
    let list = parse_device_list(&fixture("device_list.json")).unwrap();
    let info = parse_camera_info(&fixture("camera_info.json")).unwrap();
    let plug = list
        .all_devices()
        .find(|d| d.dev_id == "synth-dev-0002-plug")
        .unwrap();
    let err = CameraView::pair(plug, &info).expect_err("non-camera device must not pair");
    assert!(matches!(err, Error::DeviceMismatch(_)));
}

// ── Round-trip: serialize -> deserialize is stable ─────────────────────────
#[test]
fn device_list_round_trips_stable() {
    let list = parse_device_list(&fixture("device_list.json")).unwrap();
    let bytes = serde_json::to_vec(&list).expect("serialize");
    let again = parse_device_list(&bytes).expect("re-deserialize");
    assert_eq!(again.device_list.len(), list.device_list.len());
    assert_eq!(again.device_list[0].dev_id, list.device_list[0].dev_id);
    assert_eq!(
        again.device_list[0].local_key,
        list.device_list[0].local_key
    );

    let info = parse_camera_info(&fixture("camera_info.json")).unwrap();
    let ibytes = serde_json::to_vec(&info).expect("serialize info");
    let info2 = parse_camera_info(&ibytes).expect("re-deserialize info");
    assert_eq!(info2.p2p_id, info.p2p_id);
    assert_eq!(info2.p2p_type, info.p2p_type);
    assert_eq!(
        info2.p2p_config.as_ref().unwrap().p2p_key,
        info.p2p_config.as_ref().unwrap().p2p_key
    );
}

// ── Redaction: secrets never appear in Debug ───────────────────────────────
#[test]
fn debug_redacts_all_device_and_camera_secrets() {
    let list = parse_device_list(&fixture("device_list.json")).unwrap();
    let info = parse_camera_info(&fixture("camera_info.json")).unwrap();

    let device_dbg = format!("{:?}", list.device_list[0]);
    // localKey/secKey VALUES must not appear.
    assert!(
        !device_dbg.contains("SYNTH-LOCALKEY"),
        "localKey leaked in Debug"
    );
    assert!(
        !device_dbg.contains("SYNTH-SECKEY"),
        "secKey leaked in Debug"
    );
    assert!(device_dbg.contains("redacted"));
    // Non-secret fields are still visible (Debug remains useful).
    assert!(device_dbg.contains("synth-dev-0001-camera"));

    let info_dbg = format!("{info:?}");
    assert!(!info_dbg.contains("SYNTH-P2P-PASSWORD"), "password leaked");
    assert!(!info_dbg.contains("SYNTH-SESSIONTID"), "sessionTid leaked");
    assert!(!info_dbg.contains("SYNTH-P2PKEY"), "p2pKey leaked");
    assert!(!info_dbg.contains("SYNTH-INITSTR"), "initStr leaked");
    // The session descriptor contents must not leak either.
    assert!(
        !info_dbg.contains("redacted-in-debug"),
        "session contents leaked"
    );
    assert!(info_dbg.contains("redacted"));
    // Non-secret p2pId/p2pType remain visible for diagnostics.
    assert!(info_dbg.contains("synth-p2pid-0001-not-a-real-handle"));
}
