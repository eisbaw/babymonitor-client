//! `babymonitor-core` — core library for a Rust client to the Philips Avent
//! Baby Monitor+ (a white-labeled Tuya IPC camera, hardware SCD921/SCD923).
//!
//! This crate is currently a **scaffold**. Real functionality (Tuya mobile-app
//! sign, cloud login, device-list parsing, P2P/WebRTC transport) is added by
//! later backlog tasks. See `re/prd.md` and `re/review_gate_findings.md`.
//!
//! Design note: this library is built to be *composable* — small functions that
//! the CLI (or any caller) wires together, not a framework. Business logic lives
//! at the integration site, not buried inside helpers.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

/// The crate version, surfaced so the CLI can print a single source of truth.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors produced by the core library.
///
/// Intentionally small for the scaffold. Variants are added as transport, auth,
/// and parsing land. Every fallible operation must return a typed, contextful
/// error — never panic on recoverable conditions (fail fast, fail loud).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A feature exists in the public API surface but is not implemented yet.
    /// Returning this (rather than `todo!()`) keeps the build honest: the
    /// stub-grep gate forbids `todo!`/`unimplemented!` in non-test code, and a
    /// typed error is testable and traceable.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
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
