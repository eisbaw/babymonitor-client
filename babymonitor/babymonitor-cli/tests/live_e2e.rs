//! Gold-oracle live end-to-end acceptance harness (TASK-0014 AC#2).
//!
//! This is the STRONGEST acceptance signal we have (TESTING.md Part 2 §1): the
//! Rust client logging into the user's OWN Tuya account, listing devices, and
//! finding the SCD921 camera. It documents the live path that WOULD run against
//! the real device — but it is `#[ignore]`d so it never runs in `just e2e` / CI
//! and never makes a network call there.
//!
//! ## Why it is gated (honest)
//!
//! A from-scratch static client cannot log in: Tuya rejects `token.get` with a
//! server-side identity gate (`ILLEGAL_CLIENT_ID`) *before* it evaluates the
//! request signature — proven sign-insensitive by a corrupted-sign differential
//! (TASK-0050) and host-exhausted across every datacenter gateway (TASK-0048/0051).
//! No further static field clears it. The client is **token-injectable**, so the
//! real unblock is ONE on-device capture of a live session (TASK-0022; top-level
//! README §6). So today this test, when run with `--include-ignored`, asserts the
//! HONEST no-session state end-to-end rather than a fabricated success (the
//! signer's un-validated 6th ingredient trips first, so the concrete probe still
//! surfaces [`Error::BmpTokenPending`] — either way no network call, no fabricated
//! response). When a captured session is injected, the body below is replaced with
//! the real login -> device-list -> find-SCD921 assertions; the manual setup and
//! authorized-scope contract documented here do not change.
//!
//! ## Authorized scope
//!
//! Runs ONLY against the user's own Tuya account and their own SCD921/SCD923
//! device. This is a benign, authorized personal RE project: the user owns the
//! device + account. No third-party account/device is ever targeted.
//!
//! ## Manual setup (once a captured session unblocks login — TASK-0022)
//!
//! 1. Place the app key material at `secrets/tuya_appkey.json` (gitignored):
//!    `{ "app_key": "...", "app_secret": "...", "ttid": "..." }`.
//! 2. The app-cert SHA-256 is computed OFFLINE from the APK
//!    (`extracted/xapk/...apk`, gitignored) — no value is committed.
//! 3. Put the account login (email/password or the chosen flow) where the live
//!    harness reads it from `secrets/` — NEVER in a tracked file.
//! 4. Run a SINGLE-SHOT, rate-limited live pass (see the command in the README).
//!    `--test-threads=1` keeps the live calls serial (no parallel requests that
//!    could trip Tuya rate limiting — AC#4).
//!
//! Nothing here prints a secret: device ids / sid / uid are account-linked PII
//! and are asserted by SHAPE (presence / camera-ness), never echoed.

use babymonitor_core::sign::{PendingBmpToken, SigningKeyMaterial};
use babymonitor_core::stream::frame::Frame;
use babymonitor_core::stream::session::{LiveSessionDriver, MqttTransport, OsRandom, WebRtcEngine};
use babymonitor_core::stream::StreamCredentials;
use babymonitor_core::{device, Error};

/// The gold-oracle live path. `#[ignore]`d: excluded from the offline suite.
///
/// CURRENT (login-blocked) behaviour, asserted honestly when run with
/// `--ignored`: a from-scratch client cannot obtain a session (server-side
/// identity gate, TASK-0050/0051), so no live fetch happens. The live device-list
/// fetch surfaces [`Error::BmpTokenPending`] (the signer's un-validated 6th
/// ingredient is its first stop; not the login blocker). It makes NO network call
/// and fabricates NO response.
///
/// FUTURE (once a captured session is injected — TASK-0022): replace the body with
///   1. `auth login` against `secrets/`-sourced credentials,
///   2. `device::list_devices(...)` returning the real list,
///   3. assert the SCD921 camera is found (`find_camera_device().is_some()` and
///      `is_camera()`), asserting SHAPE only — never printing the devId.
#[test]
#[ignore = "live gold-oracle: a from-scratch login is blocked by the server-side \
            identity gate (ILLEGAL_CLIENT_ID, TASK-0050/0051); needs an injected \
            captured session (TASK-0022) + the user's own Tuya account. Run manually \
            with --ignored --test-threads=1. Today it asserts the honest \
            login-blocked state, not a fabricated login."]
fn live_login_then_device_list_finds_scd921() {
    // SINGLE-SHOT: no retry loop, no parallelism. With the real signer this is
    // the one live request; here the signer probe fails first, so no network is
    // touched at all.
    let material = SigningKeyMaterial {
        // Placeholder-by-construction: never read a real secret here while the
        // login path is blocked. The captured-session harness (TASK-0022) injects
        // a real session into the store and drives the read path from there.
        app_key: String::new(),
        app_secret: String::new(),
        app_cert_sha256_hex: String::new(),
        ttid: String::new(),
    };

    let result = device::list_devices(&material, &PendingBmpToken, "", "");

    // HONEST assertion: a from-scratch login is blocked by the server-side identity
    // gate, so no live fetch happens. We assert the no-session state rather than a
    // login we cannot perform (the signer's un-validated 6th ingredient trips first,
    // so the concrete variant is BmpTokenPending). This test FAILS (goes red) the
    // day someone makes it pretend to succeed without an injected session — which is
    // exactly the negative-feedback property we want.
    match result {
        Err(Error::BmpTokenPending) => {
            // Expected today. When a captured session is injected (TASK-0022), this
            // arm is replaced by the real list-and-find-SCD921 assertions.
        }
        other => panic!(
            "live device-list expected the login-blocked state (no session — identity gate, \
             TASK-0050/0051); got {other:?}. \
             If login now works, update this harness to assert the real SCD921 discovery."
        ),
    }
}

/// The gold-oracle LIVE A/V STREAM path (TASK-0034). `#[ignore]`d: excluded from
/// the offline suite; never opens an MQTT/WebRTC socket in `just e2e`/CI.
///
/// CURRENT (stream-pending) behaviour, asserted honestly when run with
/// `--ignored`: the live session driver surfaces [`Error::StreamPending`] because
/// (a) every runtime credential (token/p2pId/p2pKey/ices/session/localKey/pv)
/// rides an authenticated session that cannot be obtained — `token.get` is
/// rejected by the server-side identity gate (`ILLEGAL_CLIENT_ID`, proven
/// sign-insensitive — TASK-0050/0051), so login never issues a `sid` to fetch the
/// device's `CameraInfoBean`/`P2pConfig` (the signer's un-validated 6th
/// ingredient, the `bmp_token` — TASK-0032 — is a sign input, not this blocker),
/// (b) the 302-payload localKey-AES
/// PRIMITIVE is now implemented (AES-128/ECB/PKCS5, key=localKey), but the full
/// 302 envelope assembly is pending (`Error::MqttEnvelopePending`: the
/// pv→output-variant binding + outer Tuya MQTT framing need a live capture —
/// TASK-0037), and (c) the WebRTC media engine (webrtc-rs) is a follow-up
/// (TASK-0037). It makes NO network call and renders NO fabricated frame.
///
/// FUTURE (once auth unblocks + a real SCD921 returns p2pType=4): replace the
/// engine/transport fakes with the real `RumqttcTransport` (TLS feature on) + the
/// webrtc-rs engine, load `StreamCredentials` from `secrets/`, and assert ≥1
/// decoded video frame is received (`engine.recv_frame()` yields a
/// [`FrameKind::VideoKeyframe`]) — asserting SHAPE only, never echoing payload or
/// the per-session media key.
///
/// ## Authorized scope / manual setup
/// Same contract as the login harness above: ONLY the user's own account + their
/// own SCD921; creds from `secrets/` (gitignored), never a tracked file; single
/// shot, `--test-threads=1`. Nothing here prints a secret.
#[test]
#[ignore = "live A/V stream: needs an authenticated session, which a from-scratch \
            client cannot obtain — token.get is rejected by the server-side identity \
            gate (ILLEGAL_CLIENT_ID, TASK-0050/0051), so the device creds it would \
            fetch are unreachable; needs an injected captured session (TASK-0022). It \
            also needs the 302 envelope variant/framing binding + webrtc-rs engine \
            (TASK-0037) and a live SCD921 returning p2pType=4. Run manually with \
            --ignored --test-threads=1. Today it asserts the honest stream-pending \
            state, not a fabricated stream."]
fn live_webrtc_session_renders_first_frame() {
    // A panicking engine/transport: if the (gated) driver ever reached real I/O
    // these would explode, proving no live path runs while stream-pending.
    struct UnreachableTransport;
    impl MqttTransport for UnreachableTransport {
        fn publish_302(&mut self, _d: &str, _p: &str, _b: &[u8]) -> Result<(), Error> {
            panic!("transport must NOT be driven while the stream is pending");
        }
        fn try_recv_302(&mut self) -> Result<Option<Vec<u8>>, Error> {
            panic!("transport must NOT be driven while the stream is pending");
        }
    }
    struct UnreachableEngine;
    impl WebRtcEngine for UnreachableEngine {
        fn create_offer(&mut self) -> Result<String, Error> {
            // The driver DOES build an offer (proving the seam is wired) before
            // hitting the crypto gate; return a minimal Tuya-shaped offer so the
            // gate (not this fake) is what stops the run.
            Ok("v=0\r\nm=application 9 x 98\r\na=ice-options:trickle\r\na=mid:2\r\n".into())
        }
        fn set_answer(&mut self, _s: &str) -> Result<(), Error> {
            panic!("engine answer must NOT run while the stream is pending");
        }
        fn add_remote_candidate(&mut self, _c: &str) -> Result<(), Error> {
            panic!("engine candidate must NOT run while the stream is pending");
        }
        fn recv_frame(&mut self) -> Result<Option<Frame>, Error> {
            panic!("frame recv must NOT run while the stream is pending");
        }
    }

    // SYNTHETIC creds: the real ones come from secrets/ once auth unblocks. A
    // full set passes validation so the driver reaches the honest pending gate
    // (not a config error). local_key is AES-128-sized synthetic material.
    let creds = StreamCredentials {
        token: "SYNTH_TOKEN".into(),
        p2p_id: "SYNTH_P2PID".into(),
        dev_id: "SYNTH_DEVID".into(),
        skill: "{}".into(),
        p2p_key: "SYNTH_P2PKEY".into(),
        ices: "[]".into(),
        session: "{}".into(),
        local_key: "0123456789abcdef".into(), // secret-scan:allow (synthetic test value)
        pv: "2.2".into(),
    };

    let mut transport = UnreachableTransport;
    let mut engine = UnreachableEngine;
    let mut driver = LiveSessionDriver::new(&creds, &mut transport, &mut engine);

    let result = driver.run(&OsRandom, "live-trace-0001");

    // HONEST assertion: the live stream is blocked. We assert StreamPending
    // rather than a stream we cannot produce. This goes RED the day someone makes
    // it pretend to stream without auth + the media engine — the negative-feedback
    // property we want.
    match result {
        Err(Error::StreamPending) => {
            // Expected today. When auth (TASK-0035) + the media engine (TASK-0037)
            // land, replace the fakes with the real transport/engine and assert
            // ≥1 decoded frame.
        }
        other => panic!(
            "live stream expected stream-pending (auth + webrtc-rs not landed); got {other:?}. \
             If streaming now works, update this harness to assert a real decoded frame."
        ),
    }
}
