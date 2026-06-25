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
//! input: the `bmp_token` decoded from `assets/t_s.bmp` by a native white-box
//! table cipher (see `re/bmp_token_decode.md`, filed as **TASK-0030**). Until a
//! [`sign::BmpTokenProvider`] supplies that token, [`sign::Signer::sign`] returns
//! [`Error::BmpTokenPending`] — it NEVER fabricates a signature and NEVER panics.
//! Every *other* ingredient (canonical string, MD5-hex, `_`-join key assembly,
//! offline app-cert SHA-256) is recovered and unit-tested here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

pub mod session;
pub mod sign;

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
    /// is decoded by a native white-box table cipher that is not yet ported
    /// (see `re/bmp_token_decode.md`; tracked by TASK-0030). This is the honest
    /// TOKEN-PENDING state: a full valid `sign` cannot be produced until a
    /// [`sign::BmpTokenProvider`] supplies the token. We surface this rather
    /// than fabricating a signature, so callers fail fast and loud.
    #[error(
        "tuya sign is token-pending: bmp_token (decoded from assets/t_s.bmp) is \
         not yet available — blocked on TASK-0030 (white-box port / live vector)"
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
