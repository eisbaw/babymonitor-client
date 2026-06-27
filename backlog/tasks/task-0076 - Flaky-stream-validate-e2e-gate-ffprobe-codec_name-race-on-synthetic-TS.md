---
id: TASK-0076
title: Flaky stream-validate e2e gate (ffprobe codec_name race on synthetic TS)
status: To Do
assignee: []
created_date: '2026-06-27 17:46'
labels:
  - stream
  - test
  - flaky
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just stream-validate is non-deterministic: identical back-to-back runs flip between exit 0 (OK) and exit 1 ("produced TS is not h264") / exit 141 (SIGPIPE). Root cause is the codec-probe step: 'ffprobe -show_entries stream=codec_name ... | grep -qx h264' over the ~1s synthetic libx264 TS sometimes yields empty/partial codec_name (and 'grep -q' closes the pipe early, SIGPIPE-killing ffprobe under 'set -euo pipefail', surfacing as 141). The replay->depacketize->mux Rust path itself is fine ('stream: replayed 18 NAL(s) -> ... 1 keyframe access-unit(s)' prints every run); only the ffprobe assertion flakes. This makes the whole 'just e2e' gate flaky (stream-validate is the last recipe in the e2e chain). Discovered while doing TASK-0074 (live-tls feature wiring) which is unrelated and default-OFF.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 stream-validate passes deterministically across >=20 consecutive runs
- [ ] #2 Root cause fixed (e.g. probe by reading frames/ffprobe -show_streams without 'grep -q' pipe race, or count_frames first; avoid SIGPIPE under pipefail) without weakening the h264-decodes assertion
- [ ] #3 just e2e is green deterministically
<!-- AC:END -->
