---
id: TASK-0114
title: >-
  Harden live video depacketizer diagnostics and reviewer cleanups (TASK-0085
  follow-up)
status: To Do
assignee: []
created_date: '2026-06-29 14:44'
updated_date: '2026-06-30 10:20'
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
Retain the non-overflow cleanup items from the TASK-0085 reviews: unit-test H264Depacketizer reset after a broken FU-A, collapse duplicate depacketize-error counters, reconcile queue-depth documentation, document that the audio channel is currently unbounded, and remove the synchronous per-line StreamTrace flush from the media pump. The prior criterion that preserved and tested arbitrary drop-newest NAL behavior is intentionally moved to a dedicated access-unit and IDR recovery task because that policy can corrupt the player stream.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 H264Depacketizer reset has a negative-to-positive unit test: broken FU-A fails, reset discards partial state, and a clean NAL or keyframe then decodes without stale bytes.
- [ ] #2 Duplicate depacketize-error counters are collapsed and queue sizing and audio boundedness comments state measured behavior without unsupported seconds-of-buffer claims.
- [ ] #3 StreamTrace no longer synchronously flushes every detailed ingress line on the receive and ACK thread; diagnostics remain available and bounded.
<!-- AC:END -->
