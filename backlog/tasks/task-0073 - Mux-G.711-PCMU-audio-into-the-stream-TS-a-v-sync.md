---
id: TASK-0073
title: Mux G.711/PCMU audio into the stream TS (a/v sync)
status: To Do
assignee: []
created_date: '2026-06-26 22:12'
labels:
  - stream
  - decoder
  - media
  - audio
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0070 decodes G.711 mu-law (core media::g711) and serves a VIDEO-ONLY MPEG-TS. Wire the decoded PCM as a second track into the ffmpeg muxer (second pipe/fd or named FIFO: -f s16le -ar 8000 -ac 1) so the stream carries A/V, with PTS aligned to the video clock (audio pts = rtp_ts >> 3 ms per imm_p2p_rtc_recv_frame.c:91-99). Offline-validate that ffprobe reports both a video(h264) and audio stream.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 stream serves a TS with both an h264 video and a pcm/aac audio stream (ffprobe shows both)
- [ ] #2 audio PTS aligned to video so playback is in sync (no large drift)
- [ ] #3 offline-validated via ffprobe on a synthetic A/V replay; no secrets
<!-- AC:END -->
