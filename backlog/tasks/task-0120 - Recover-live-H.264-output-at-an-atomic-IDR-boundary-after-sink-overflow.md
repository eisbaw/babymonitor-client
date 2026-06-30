---
id: TASK-0120
title: Recover live H.264 output at an atomic IDR boundary after sink overflow
status: To Do
assignee: []
created_date: '2026-06-30 10:21'
labels:
  - stream
  - media
  - h264
  - test
dependencies: []
references:
  - babymonitor/babymonitor-cli/src/stream_live.rs
  - babymonitor/babymonitor-core/src/stream/media/h264.rs
  - babymonitor/babymonitor-cli/src/gui.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The live video queue currently drops arbitrary newest NAL chunks. That can discard SPS, PPS, IDR, or dependent slices while continuing to emit a partial GOP, so KCP remains healthy but VLC or the GUI becomes undecodable. Replace NAL-level overflow with access-unit-aware atomic queueing and an explicit resynchronization state. This task owns the deterministic slow-sink seam and overflow policy removed from TASK-0114, and it must keep every live video output, including HTTP, GUI, and stdout or their documented alternatives, off the receive and ACK thread.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Queue and drop complete access units using RTP marker or AccessUnitAssembler boundary metadata; after any overflow emit no VCL until an atomic recovery access unit can be enqueued whose first post-gap VCL is IDR with current cached or same-access-unit SPS and PPS prepended.
- [ ] #2 A deterministic fixed-GOP synthetic stream and injected block-then-release sink force overflow with a deliberately small queue, prove receive and ACK-side progress remains nonblocking beyond one receive window, and strict ffmpeg decoding resumes from the first eligible recovery IDR interval.
- [ ] #3 Negative tests separately drop SPS, PPS, IDR, and dependent slices and prove the old arbitrary-NAL policy fails the recovery oracle; tests assert nonzero decoded frames and frame progression, not only bytes, elapsed time, or process success.
- [ ] #4 Overflow diagnostics distinguish dropped NALs, dropped access units, resync entries, and resync completions, are rate-limited, and do not claim recovery until a complete eligible recovery access unit was accepted.
- [ ] #5 HTTP, GUI, and live stdout output either use the same bounded nonblocking access-unit handoff or explicitly reject an unsafe live mode; no live sink performs a potentially blocking write on the media receive and KCP ACK thread.
<!-- AC:END -->
