---
id: TASK-0073
title: Mux G.711/PCMU audio into the stream TS (a/v sync)
status: To Do
assignee: []
created_date: '2026-06-26 22:12'
updated_date: '2026-06-27 19:47'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Downstream A/V mux implemented + AUDIO CORRECTION

Title is stale: the DOWNSTREAM camera audio is NOT G.711/PCMU - it is raw 16 kHz mono S16LE PCM (cap4 ground truth; G.711 µ-law @8k is the TALK-BACK/upstream direction only). Implemented the downstream-audio mux:
- core stream/media/audio.rs (S16LE@16k constants + identity decode); MediaUnit.conv routes video(1)/audio(2).
- CLI: babymonitor-cli stream --replay-audio <s16le> muxes audio alongside H.264 via ffmpeg (2nd input -f s16le -ar 16000 -ac 1 -> AAC track). Live pump feeds audio over a FIFO.
- just stream-validate (in e2e) now asserts the produced MPEG-TS carries BOTH an h264 video AND an audio track.
- VALIDATED byte-exact vs REAL cap4: audio 1,532,800 B S16LE reconstructed identically (tests/cap4_replay.rs cap4_unified_pump_routes_av_to_truth).
Gates GREEN (just e2e exit 0; live clippy clean). Not committed. Suggest retitling this task to reflect S16LE (not G.711).
<!-- SECTION:NOTES:END -->
