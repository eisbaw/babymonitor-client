---
id: TASK-0114
title: >-
  Harden live video sink: FU-A reset + stalled-sink overflow unit tests +
  reviewer cleanups (TASK-0085 follow-up)
status: To Do
assignee: []
created_date: '2026-06-29 14:44'
labels:
  - stream
  - media
  - test
  - hygiene
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Non-blocking items from the TASK-0085 review (qa-test-runner + mped-architect): (1) unit-test H264Depacketizer::reset — a broken FU-A then a clean keyframe must resync; (2) a stalled-sink overflow test proving the drop-newest policy keeps the recv/ACK loop alive (needs VideoWriter testable over an injected slow/never-draining Write sink); (3) collapse the duplicate depay-error counters (pump n_depay_err vs StreamTrace depay_err); (4) doc drift: the video queue is described both as a few-frames cushion and ~5-10s (512 NALs); (5) note the audio channel is unbounded while video is bounded; (6) StreamTrace::line flushes per writeln into a BufWriter (drop one). Low priority hardening; the live behaviour is already verified.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 H264Depacketizer::reset has a unit test (broken FU-A -> reset -> clean NAL resyncs)
- [ ] #2 Video-sink drop-newest overflow policy has a test under a deliberately non-draining sink
- [ ] #3 Reviewer cleanups applied (dup counter, doc drift, per-line flush)
<!-- AC:END -->
