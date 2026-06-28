---
id: TASK-0085
title: Decouple media/KCP ACK loop from the blocking sink write
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
labels:
  - stream
  - media
  - kcp
  - blocker
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Live stream freezes at ~12 conv=1 segments (camera initial KCP send window). Architecture review root-caused it: the single-threaded media pump (stream_live.rs pump_to_output) does a BLOCKING write into ffmpeg (stream.rs write_annexb / OutputSink), which starves the KCP ACK loop (drain_media_acks), so the camera snd_una never advances and it stops at its window. Decouple the sink from the receive/ACK loop.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Video/audio writes to the sink go through a bounded queue drained by a dedicated writer thread; the receive+ACK loop never blocks on the sink
- [ ] #2 Under a deliberately stalled/slow sink, KCP ACKs keep being emitted and the camera una keeps advancing (observable via media-diag una= log)
- [ ] #3 Explicit overflow policy (e.g. drop-oldest video) documented and tested
<!-- AC:END -->
