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
//! The client cannot actually log in yet: a valid request signature needs the
//! `bmp_token` decoded from `assets/t_s.bmp` by a native white-box table cipher
//! that is not yet ported (TASK-0030). So today this test, when run with
//! `--include-ignored`, asserts the HONEST token-pending state end-to-end rather
//! than a fabricated success. When TASK-0030 lands, the body below is replaced
//! with the real login -> device-list -> find-SCD921 assertions; the manual setup
//! and authorized-scope contract documented here do not change.
//!
//! ## Authorized scope
//!
//! Runs ONLY against the user's own Tuya account and their own SCD921/SCD923
//! device. This is a benign, authorized personal RE project: the user owns the
//! device + account. No third-party account/device is ever targeted.
//!
//! ## Manual setup (once TASK-0030 unblocks login)
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
use babymonitor_core::{device, Error};

/// The gold-oracle live path. `#[ignore]`d: excluded from the offline suite.
///
/// CURRENT (token-pending) behaviour, asserted honestly when run with
/// `--ignored`: the live device-list fetch surfaces [`Error::BmpTokenPending`]
/// because a valid sign is not yet possible (TASK-0030). It makes NO network
/// call and fabricates NO response.
///
/// FUTURE (once TASK-0030 lands): replace the body with
///   1. `auth login` against `secrets/`-sourced credentials,
///   2. `device::list_devices(...)` returning the real list,
///   3. assert the SCD921 camera is found (`find_camera_device().is_some()` and
///      `is_camera()`), asserting SHAPE only — never printing the devId.
#[test]
#[ignore = "live gold-oracle: needs the user's real Tuya account + the bmp_token \
            (TASK-0030); run manually with --ignored --test-threads=1. Today it \
            asserts the honest token-pending state, not a fabricated login."]
fn live_login_then_device_list_finds_scd921() {
    // SINGLE-SHOT: no retry loop, no parallelism. With the real signer this is
    // the one live request; here the signer probe fails first, so no network is
    // touched at all.
    let material = SigningKeyMaterial {
        // Placeholder-by-construction: never read a real secret here while the
        // path is token-pending. TASK-0030's harness will load these from
        // `secrets/` and supply a real BmpTokenProvider.
        app_key: String::new(),
        app_secret: String::new(),
        app_cert_sha256_hex: String::new(),
        ttid: String::new(),
    };

    let result = device::list_devices(&material, &PendingBmpToken, "", "");

    // HONEST assertion: the live path is blocked on the bmp_token. We assert the
    // token-pending state rather than a login we cannot perform. This test FAILS
    // (goes red) the day someone makes it pretend to succeed without TASK-0030 —
    // which is exactly the negative-feedback property we want.
    match result {
        Err(Error::BmpTokenPending) => {
            // Expected today. When TASK-0030 lands, this arm is replaced by the
            // real list-and-find-SCD921 assertions.
        }
        other => panic!(
            "live device-list expected token-pending (TASK-0030 not yet landed); got {other:?}. \
             If login now works, update this harness to assert the real SCD921 discovery."
        ),
    }
}
