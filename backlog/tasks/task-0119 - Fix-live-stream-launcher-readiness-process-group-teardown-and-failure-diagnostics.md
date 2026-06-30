---
id: TASK-0119
title: >-
  Fix live-stream launcher readiness, process-group teardown, and failure
  diagnostics
status: To Do
assignee: []
created_date: '2026-06-30 10:21'
labels:
  - stream
  - tooling
  - ffmpeg
  - test
dependencies:
  - TASK-0087
references:
  - Justfile
  - babymonitor/babymonitor-cli/src/stream_live.rs
  - babymonitor/babymonitor-cli/src/stream.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The just live-stream launcher currently treats the pump announcement as HTTP readiness, starts VLC after a fixed sleep, ignores its status, kills only part of the Cargo to CLI to ffmpeg tree, and deletes the only diagnostics. Review found a real orphan ffmpeg with PPID 1 still listening on port 8556 after its FIFO and log were deleted. Move non-trivial supervision into a tracked, testable script while retaining just live-stream as the entry point. Own the exact process group and first failure cause; do not use broad process-name killing or rely on Rust destructors after signals.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Build first, run the CLI binary directly in a new session or process group, and declare ready only when the CLI leader is alive and non-zombie and the listening socket is owned by an ffmpeg PID in that exact group; readiness does not connect to or consume the one-client HTTP endpoint.
- [ ] #2 Normal player close, nonzero player exit, stream early exit, readiness timeout, EXIT, HUP, INT, and TERM all perform idempotent TERM then bounded wait then KILL of the exact stream process group, wait the direct child, preserve unrelated processes, and leave the port immediately rebindable.
- [ ] #3 An offline injected fake stream and player harness records PID, process-group, and start-time identity, creates a grandchild listener, and proves every exit path leaves no tagged descendant or listener; checks cannot falsely pass after reparenting or by finding an unrelated listener.
- [ ] #4 The launcher supervises stream and VLC concurrently, returns the first causal nonzero status, and distinguishes port collision, readiness timeout, stream failure, player failure, and normal close rather than reporting every outcome as VLC closed.
- [ ] #5 Failure logs use umask 077, retain the bounded redacted stream and VLC stderr needed for diagnosis, and are deleted only on success; redaction behavior is tested and does not expose runtime credentials or identifiers.
<!-- AC:END -->
