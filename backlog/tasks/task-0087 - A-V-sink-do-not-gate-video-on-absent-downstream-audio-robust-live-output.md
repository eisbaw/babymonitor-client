---
id: TASK-0087
title: 'A/V sink: do not gate video on absent downstream audio; robust live output'
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
labels:
  - stream
  - media
  - ffmpeg
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ffmpeg -shortest + an audio input that may never deliver frames (no conv=2) makes the muxer produce nothing (TS-file mode wrote 0 bytes). HTTP -listen 1 + default port 8554 collided with the QEMU emulator; a player disconnect surfaces as a fatal broken-pipe error. Make live output robust and video-first.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A video-only live session (no conv=2 audio) still produces a continuously-growing, playable stream (drop -shortest or synthesize silence / bind audio lazily)
- [ ] #2 Pre-flight free-port check for --output http with a fail-fast error instead of colliding
- [ ] #3 Player disconnect (broken pipe) is a clean stop, not an error
<!-- AC:END -->
