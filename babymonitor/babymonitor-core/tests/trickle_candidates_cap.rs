//! TASK-0077 — parse the **real** trickle `candidate` 302 messages from the cap3
//! and cap4 captures into typed [`IceCandidate`]s.
//!
//! The camera's answer SDP carries NO `a=candidate:` lines (cap3 + cap4 ground
//! truth — 0 candidates in the answer SDP), so the host/srflx candidates ride as
//! separate 302 `candidate` messages (`{header:{type:candidate}, msg:{candidate:
//! "a=candidate:…"}}`). This test takes each real captured candidate line and
//! asserts [`parse_candidate`] turns it into a well-formed [`IceCandidate`] — the
//! offline validation of the exact wire format the live trickle-collection path
//! ([`MqttSignalingSession::negotiate_with_trickle`]) consumes.
//!
//! Captures are read at RUNTIME from the gitignored/untracked path and never
//! embedded; no candidate value (IP/port) is printed — only structural assertions.
//! cap3's `signaling_plaintext.jsonl` is present in-tree; cap4's `media_meta.jsonl`
//! is local-only, so it is validated when present and cleanly skipped otherwise.

use std::path::Path;

use babymonitor_core::stream::media::transport::{parse_candidate, CandidateKind};
use babymonitor_core::stream::signaling::{SignalingEnvelope, SignalingType};

/// Pull the inner 302 JSON string out of one capture line
/// (`{"tag":"…","text":"<inner json>"}`).
fn inner_json(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(v.get("text")?.as_str()?.to_string())
}

/// Extract every non-empty `candidate` line from one capture, parse each via
/// [`parse_candidate`], and return the parsed kinds. Asserts each candidate line
/// is well-formed (a parse failure panics with context, never silently skipped).
fn parse_capture_candidates(path: &Path) -> Vec<CandidateKind> {
    let body = std::fs::read_to_string(path).expect("read capture");
    let mut kinds = Vec::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let Some(inner) = inner_json(line) else {
            continue;
        };
        let Ok(env) = SignalingEnvelope::from_json(inner.as_bytes()) else {
            continue;
        };
        if env.header.r#type != SignalingType::Candidate {
            continue;
        }
        // A candidate carries its line in msg.candidate; the empty string is the
        // end-of-candidates sentinel (filtered — it is not an ICE candidate).
        let Some(cand) = env.msg.candidate.as_deref() else {
            continue;
        };
        if cand.trim().is_empty() {
            continue;
        }
        let parsed = parse_candidate(cand)
            .unwrap_or_else(|e| panic!("captured candidate line must parse: {e}"));
        // Structural sanity (no values printed): valid component + non-zero port.
        assert!(
            parsed.component >= 1,
            "candidate component is RTP/RTCP (>=1)"
        );
        assert_ne!(parsed.port, 0, "candidate port is non-zero");
        assert_eq!(parsed.transport, "UDP", "captured candidates are UDP");
        kinds.push(parsed.kind);
    }
    kinds
}

/// Assert a capture's candidate set is non-empty and contains at least one host
/// candidate (the LAN-reachable address the host-direct path needs — cap4).
fn assert_candidate_set(kinds: &[CandidateKind], label: &str) {
    assert!(
        !kinds.is_empty(),
        "{label}: capture must contain trickle candidates"
    );
    assert!(
        kinds.contains(&CandidateKind::Host),
        "{label}: capture must contain a `typ host` candidate (host-direct path)"
    );
}

// cap3 is present in-tree: a true byte-validation of the candidate wire format.
#[test]
fn cap3_candidate_messages_parse() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../emulator_captures/cap3/signaling_plaintext.jsonl");
    if !path.exists() {
        eprintln!("skip: cap3 capture not present ({})", path.display());
        return;
    }
    let kinds = parse_capture_candidates(&path);
    assert_candidate_set(&kinds, "cap3");
}

// cap4 media-meta capture is local-only (untracked): validated when present,
// cleanly skipped in CI where it is absent.
#[test]
fn cap4_candidate_messages_parse_when_present() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../emulator_captures/cap4/media_meta.jsonl");
    if !path.exists() {
        eprintln!(
            "skip: cap4 media-meta capture not present ({}); cap3 covers the wire format",
            path.display()
        );
        return;
    }
    let kinds = parse_capture_candidates(&path);
    assert_candidate_set(&kinds, "cap4");
}
