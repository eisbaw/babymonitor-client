---
id: TASK-0121
title: Gate the real live-feature HTTP sink offline in just e2e
status: To Do
assignee: []
created_date: '2026-06-30 10:21'
labels:
  - stream
  - http
  - e2e
  - test
  - ffmpeg
dependencies:
  - TASK-0119
  - TASK-0120
references:
  - Justfile
  - babymonitor/babymonitor-cli/src/stream_live.rs
  - babymonitor/babymonitor-cli/src/stream.rs
  - TESTING.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The normal end-to-end gate intentionally omits the live feature, and stream-validate exercises the blocking replay OutputSink rather than the production LiveAvSink, VideoWriter, and AudioFifo path. Add a deterministic loopback-only regression gate for the exact live HTTP sink and its process lifecycle. It must require no camera, cloud, DNS, credentials, or secrets, and it must not turn timing-sensitive pipe saturation into a flaky false oracle.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A documented Just recipe uses a temporary HOME and Cargo offline mode to build, test all targets, and run clippy with warnings denied for babymonitor-cli with the live feature; tests are non-ignored and perform loopback I/O only.
- [ ] #2 A shared or injected harness exercises the production LiveAvSink behavior with the same ffmpeg arguments, audio policy, bounded access-unit queue, disconnect semantics, and launcher supervision rather than substituting replay OutputSink.
- [ ] #3 A paced multi-GOP synthetic stream covers non-consuming readiness, delayed player attachment, throttled reading that confirms actual queue pressure, continuous decoded-frame progression across multiple GOPs, player disconnect, bounded shutdown, exact ffmpeg PID reaping, and immediate port reuse.
- [ ] #4 Collision-listener and never-reading-client negative cases run under bounded timeouts and make the validator fail for the expected reason; unique-port allocation is serialized or ownership-checked so an ephemeral-port race cannot produce a false result.
- [ ] #5 The gate proves a named live HTTP test actually executed, passes repeated runs without the known TASK-0076-style ffprobe race, and is then wired into just e2e while preserving the existing short default-feature TS stream-validate coverage.
<!-- AC:END -->
