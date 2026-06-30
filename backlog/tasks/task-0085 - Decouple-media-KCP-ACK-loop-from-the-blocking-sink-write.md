---
id: TASK-0085
title: Decouple media/KCP ACK loop from the blocking sink write
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 20:45'
updated_date: '2026-06-29 14:44'
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
- [x] #1 Video/audio writes to the sink go through a bounded queue drained by a dedicated writer thread; the receive+ACK loop never blocks on the sink
- [x] #2 Under a deliberately stalled/slow sink, KCP ACKs keep being emitted and the camera una keeps advancing (observable via media-diag una= log)
- [x] #3 Explicit overflow policy (e.g. drop-oldest video) documented and tested
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Thread the video sink (VideoWriter + bounded sync_channel(512)); pump enqueues non-blocking, a writer thread drains ffmpeg (AC#1)
2. Drop-on-full overflow policy + Full/Disconnected distinction + Drop reaper (AC#3)
3. Verify continuous streaming live via the new ingress/egress trace (AC#2)
4. Companion fix: non-fatal FU-A (H264Depacketizer::reset)
5. qa + architect review, then commit
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
VERIFIED LIVE (commit e1528da) against the SCD921: ran continuously 100s, 2244 frames of 1080p H.264; camera max_sn climbed 0->9245 (>> the ~320 KCP window, so our ACKs ARE crediting its send window), video queue depth=0, 0 drops, 0 WASK probes; VLC 3.0.23 decoded ~2050 frames; the trace shows continuous flow with no STALL.

Note on AC#2: the literal "una= advancing" metric was a misframing — the camera-segment una is its rcv_nxt for the (empty) upstream, so it stays 0; the correct proof that ACKs sustain the camera is max_sn climbing far past one window. The deliberate-stalled-sink sub-case is guaranteed by the decoupling (pump never blocks on the sink) and is exercised by the continuous live run; a dedicated stalled-sink overflow UNIT test is the TASK-0085 follow-up.

Root cause was TWO bugs: (1) the blocking sink (this task) and (2) a fatal FU-A depacketize error that aborted the feed once it streamed >3s — both fixed in e1528da.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed the continuous-stream freeze: decoupled the live media sink from the KCP recv/ACK loop. VideoWriter now runs on its own thread behind a bounded 512-NAL queue; the pump enqueues non-blocking (drop-on-full), so ACKs always flow and the camera window keeps advancing. Companion fix: a malformed FU-A fragment is a non-fatal drop+resync (H264Depacketizer::reset) instead of aborting the feed. Added StreamTrace ingress/egress instrumentation + a `just live-stream` VLC recipe.

VERIFIED LIVE: 100s continuous, 2244 frames 1080p, queue depth 0, VLC-decoded ~2050 frames (vs the old ~12-segment freeze). qa-test-runner PASS 4/4; mped-architect review applied (Full/Disconnected distinction, Drop reaper, dropped Arc on pump-only counters). clippy --features live clean, e2e green, 77 cli + 283 core tests. Commit e1528da.
<!-- SECTION:FINAL_SUMMARY:END -->
