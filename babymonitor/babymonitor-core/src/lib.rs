//! `babymonitor-core` — core library for a Rust client to the Philips Avent
//! Baby Monitor+ (a white-labeled Tuya IPC camera, hardware SCD921/SCD923).
//!
//! Real functionality lands incrementally per the backlog. Today this crate
//! carries the Tuya mobile-app ("atop") request **signer** ([`sign`]) and the
//! session **token store** ([`session`]). Cloud login, device-list parsing, and
//! the P2P/WebRTC transport arrive in later tasks. See `re/prd.md`,
//! `re/tuya_sign_static.md`, and `re/tuya_cloud_auth.md`.
//!
//! Design note: this library is built to be *composable* — small functions that
//! the CLI (or any caller) wires together, not a framework. Business logic lives
//! at the integration site, not buried inside helpers. The signer takes all
//! secret key material as an **injected** dependency ([`sign::SigningKeyMaterial`]
//! + [`sign::BmpTokenProvider`]) — no secret value is ever hardcoded here.
//!
//! ## TOKEN-PENDING honesty
//!
//! A *full*, byte-valid signature is blocked on one recovered-but-un-ported
//! input: the `bmp_token` decoded from `assets/t_s.bmp` by an imath-bignum +
//! matrix decode (sign path) (see `re/tuya_sign_static.md` §5 +
//! `re/bmp_token_whitebox.md` §8, filed as **TASK-0032**). Until a
//! [`sign::BmpTokenProvider`] supplies that token, [`sign::Signer::sign`] returns
//! [`Error::BmpTokenPending`] — it NEVER fabricates a signature and NEVER panics.
//! Every *other* ingredient (canonical string, MD5-hex, `_`-join key assembly,
//! offline app-cert SHA-256) is recovered and unit-tested here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

pub mod device;
pub mod session;
pub mod sign;
pub mod stream;

/// The crate version, surfaced so the CLI can print a single source of truth.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors produced by the core library.
///
/// Every fallible operation returns a typed, contextful error — never panic on
/// recoverable conditions (fail fast, fail loud).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A feature exists in the public API surface but is not implemented yet.
    /// Returning this (rather than `todo!()`) keeps the build honest: the
    /// stub-grep gate forbids `todo!`/`unimplemented!` in non-test code, and a
    /// typed error is testable and traceable.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),

    /// The signer has every recovered ingredient EXCEPT the `bmp_token`, which
    /// is decoded by an imath-bignum + matrix decode (sign path) that is not yet
    /// ported (see `re/tuya_sign_static.md` §5 + `re/bmp_token_whitebox.md` §8;
    /// tracked by TASK-0032). This is the honest
    /// TOKEN-PENDING state: a full valid `sign` cannot be produced until a
    /// [`sign::BmpTokenProvider`] supplies the token. We surface this rather
    /// than fabricating a signature, so callers fail fast and loud.
    #[error(
        "tuya sign is token-pending: bmp_token (decoded from assets/t_s.bmp) is \
         not yet available — blocked on TASK-0032 (imath+matrix decode un-ported / live vector)"
    )]
    BmpTokenPending,

    /// A signer input was malformed (e.g. a 32-char MD5-base64 of the wrong
    /// length fed to `swapSignString`, or an empty whitelisted param value).
    /// Carries context so the failure is traceable.
    #[error("invalid sign input: {0}")]
    InvalidSignInput(String),

    /// Reading or hashing the app signing certificate failed (e.g. the APK zip
    /// or its `META-INF/*.RSA` entry is missing or not a PKCS#7 blob).
    #[error("app-cert SHA-256 derivation failed: {0}")]
    CertHash(String),

    /// Reading or writing the on-disk session token store failed.
    #[error("session store I/O error: {0}")]
    SessionStore(String),

    /// A device-list / camera-info response body could not be parsed into the
    /// typed models — invalid JSON, or a missing required invariant (e.g. a
    /// device record without `devId`, or a camera without `p2pId`/`p2pType`).
    /// Carries the underlying serde context so the failure is traceable; the
    /// models enforce required handles rather than being a permissive sponge.
    #[error("device-list parse error: {0}")]
    DeviceParse(String),

    /// A camera view was constructed from mismatched parts (a non-camera
    /// device, or a `CameraInfoBean` that does not correspond to the device).
    /// We fail loud rather than connect with mismatched P2P handles.
    #[error("device/camera mismatch: {0}")]
    DeviceMismatch(String),

    /// A 302 MQTT signaling envelope could not be parsed/serialized — invalid
    /// JSON, a missing required field (`header`/`msg`/`token`), or an unknown
    /// `header.type` (`re/webrtc_session.md` §2). Mirrors the native validators
    /// (`no header/msg/token field`); the models enforce the required shape.
    #[error("302 signaling parse error: {0}")]
    SignalingParse(String),

    /// A `StreamCredentials`/`connect_v2` input was malformed (an empty required
    /// handle, a non-JSON unquoted `skill`/`token`, or a wrong-length
    /// `connect_session`). Carries context so the failure is traceable.
    #[error("stream config error: {0}")]
    StreamConfig(String),

    /// The SDP `a=aes-key:<hex>` media-key codec failed: malformed hex, an
    /// oversized key (native max 23 bytes), or a missing `a=aes-key`/
    /// `m=application` section (`re/webrtc_session.md` §3c).
    #[error("SDP aes-key error: {0}")]
    SdpAesKey(String),

    /// The 302-payload localKey-AES crypto is not yet implementable: the exact
    /// AES mode/IV/padding is NOT statically pinned (the Tuya MQTT `AESUtil.ALGO`
    /// is set at runtime; the obfuscated `Cipher.getInstance` arg is jadx-mangled
    /// — `re/webrtc_session.md` §2a/§7). We surface this typed error rather than
    /// guessing a mode (which would silently produce wrong ciphertext); filed as
    /// a follow-up (TASK-0037). This is the same honesty as `BmpTokenPending`.
    #[error(
        "302-payload localKey-AES is pending: the AES mode/IV is not statically \
         pinned (runtime AESUtil.ALGO) — blocked on TASK-0037 (mode port / live capture)"
    )]
    MqttCryptoPending,

    /// A frame model operation failed: an unrecognized `imm_p2p_rtc_frame_t.type`,
    /// an unsupported rtpmap codec, or an empty payload
    /// (`re/webrtc_session.md` §4).
    #[error("frame model error: {0}")]
    Frame(String),

    /// The MQTT transport seam failed (publish/receive), or an unexpected inbound
    /// message was seen on the receive path.
    #[error("stream transport error: {0}")]
    Transport(String),

    /// The standard-WebRTC engine seam (webrtc-rs) failed.
    #[error("webrtc engine error: {0}")]
    WebRtcEngine(String),

    /// The honest **not-yet-live** state of the live A/V session: the client
    /// cannot actually stream because every runtime input is auth-gated and
    /// absent (token/p2pId/p2pKey/ices/session/localKey/pv — TASK-0032 +
    /// the Wave-2 auth decision TASK-0035), the 302-payload AES mode is unpinned
    /// ([`Error::MqttCryptoPending`]), and the WebRTC media engine is a follow-up
    /// (no webrtc-rs in this build — TASK-0037). The live driver returns THIS
    /// rather than a fabricated stream or `todo!()` — exactly the signer's
    /// TOKEN-PENDING discipline.
    #[error(
        "live A/V stream is pending: cannot stream until auth unblocks (device \
         creds + signing) and the WebRTC media engine lands (TASK-0037)"
    )]
    StreamPending,
}

/// Convenience result alias for the core library.
pub type Result<T> = std::result::Result<T, Error>;

/// Returns a stable identifier for this build, used by the CLI `--version` path
/// and by smoke tests. Single source of truth: derived from Cargo metadata.
#[must_use]
pub fn build_identifier() -> String {
    format!("babymonitor-core {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identifier_reports_crate_version() {
        let id = build_identifier();
        assert!(id.starts_with("babymonitor-core "));
        assert!(id.contains(VERSION));
    }

    #[test]
    fn not_implemented_error_carries_context() {
        let err = Error::NotImplemented("tuya login");
        // The message must name the missing feature so failures are traceable.
        assert!(err.to_string().contains("tuya login"));
    }
}
