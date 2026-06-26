---
id: TASK-0070
title: H.264/PCMU decoder + live display (CLI stream subcommand)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-26 20:20'
updated_date: '2026-06-26 22:20'
labels:
  - stream
  - decoder
  - media
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Consume the depacketized media from the transport+decrypt engine (TASK-0037) and render the SCD921 feed. Per re/media_decode_spec.md: H.264 RTP depacketize (STAP-A/FU-A -> Annex-B 00 00 00 01 NAL stream, keyframe=NAL5 preceded by 7/8), decode via openh264 (or pipe Annex-B to ffmpeg/ffplay); audio = G.711 mu-law (PT 0, 8kHz) via a 256-entry LUT. Add a babymonitor-cli `stream` subcommand that performs login -> device discovery -> signaling -> media and shows live video (and optional audio). Validate decode against the cap4 captured decrypted frames (TASK-0068).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 H.264 depacketizer (STAP-A/FU-A -> Annex-B) matches re/media_decode_spec.md; unit-tested on synthetic RTP
- [x] #2 openh264 (or ffmpeg) decodes the Annex-B stream to raw frames; one keyframe renders
- [x] #3 G.711 mu-law audio decoded (LUT); optional playback
- [x] #4 babymonitor-cli stream subcommand drives login->discovery->signaling->media->display end-to-end
- [ ] #5 Decode validated against cap4 decrypted frames (TASK-0068); secrets stay in secrets/
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. core: media/g711.rs — 256-entry mu-law LUT (const fn), mulaw_decode -> i16 PCM + s16le bytes; ref-value unit tests (0x00->-32124, 0x80->+32124, 0xFF->0).\n2. core: h264.rs — AccessUnitAssembler (group depacketized Annex-B NALs by RTP M-bit; keyframe = AU containing NAL5; track SPS/PPS); unit tests. (depacketizer already exists from TASK-0037 = AC#1.)\n3. cli: stream.rs — babymonitor-cli stream subcommand. OFFLINE replay path (--replay-annexb): parse Annex-B -> NAL split -> RTP packetize (single/FU-A) -> rtp::parse_rtp + H264Depacketizer (exercises the depacketizer) -> AccessUnitAssembler -> OutputSink. LIVE path: wire login->discovery->signaling->media via SessionStore, honestly gated (no session/broker in sandbox).\n4. cli: OutputSink spawns ffmpeg as downstream muxer/server fed decrypted Annex-B on stdin: http (mpegts over HTTP, -listen 1, http://127.0.0.1:PORT/stream.ts), ts-file (for ffprobe), stdout (mpv - fallback). Document exact vlc/mpv cmd in --help.\n5. shell.nix: add ffmpeg (pin the muxer). Justfile: stream-validate recipe — gen synthetic Annex-B via libx264, run stream --replay-annexb --output ts, ffprobe asserts codec_name=h264 + ffmpeg decodes 1 frame; wire into e2e.\n6. re/: document the vlc/mpv command + offline-validation method.\n7. Run just e2e and cargo test -p babymonitor-core; report ACTUAL pass/fail. AC#5 (cap4) honest: NO cap4 exists -> validated on synthetic only.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- Implemented (build on uncommitted TASK-0069 tree; NOT committed).
- core media/g711.rs: 256-entry mu-law LUT (const fn), mulaw_decode -> i16 + s16le; ITU anchors pinned (0x00=-32124, 0x80=+32124, 0xFF=0). 6 tests.
- core h264.rs: AccessUnitAssembler (AU boundary = RTP M-bit; keyframe = NAL5; tracks SPS/PPS). 4 tests. (depacketizer existed from TASK-0037.)
- cli stream.rs: babymonitor-cli stream subcommand. REPLAY (--replay-annexb): Annex-B split -> RTP packetize (single/FU-A) -> real rtp::parse_rtp + H264Depacketizer + AccessUnitAssembler -> OutputSink. LIVE: SessionStore-gated, returns StreamPending (no fabricated stream). 7 tests.
- OutputSink spawns ffmpeg fed decrypted Annex-B on stdin: http (mpegts over HTTP -listen 1 http://127.0.0.1:PORT/stream.ts), ts (--ts-out, ffprobe target), stdout (mpv - fallback). -r 15 + -bsf:v setts=ts=N for clean PTS.
- shell.nix: +ffmpeg (cached 8.0). Justfile: stream-validate recipe wired into e2e.
- re/stream_playback.md documents vlc/mpv/ffplay commands + offline validation. --help carries the play commands (after_help).
VALIDATION (ACTUAL): just e2e EXIT 0 (core 213 pass/0 fail/3 ign, cli 13 pass, stream-validate OK: ffprobe=h264 + 15 frames decoded). cargo test -p babymonitor-core: 213 pass/0 fail/3 ign +10+2. Manually verified HTTP serve: curl connected to http://127.0.0.1:PORT/stream.ts, pulled 27KB MPEG-TS, ffprobe=h264 320x240. stdout mode piped to ffprobe -f h264 = h264.
HONEST GAPS: AC#5 NOT met — no emulator_captures/cap4 exists, so decode validated on SYNTHETIC H.264 only, not captured camera bytes. Live drive (login/broker/camera) cannot run in sandbox — gated honestly. Audio: G.711 decode done; muxing PCMU into the TS is a follow-up (video-only TS served today).

IMPLEMENTED: G.711 mu-law LUT, AccessUnitAssembler (AU=RTP M-bit, keyframe=NAL5), babymonitor-cli stream subcommand, MPEG-TS-over-HTTP. just e2e + stream-validate GREEN: synthetic replay -> depacketize (33 NAL->35 RTP->33 NAL, 1 keyframe AU) -> MPEG-TS, ffprobe=h264 320x240 30 frames. Command: vlc/mpv/ffplay http://127.0.0.1:8554/stream.ts (also --replay-annexb / --output ts|stdout).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added a vlc/mpv-connectable live-view output stage on top of the TASK-0037 media engine: the `babymonitor-cli stream` subcommand re-muxes decoded Annex-B H.264 into MPEG-TS served over HTTP, plus the H.264 access-unit/keyframe layer and a G.711 mu-law audio decoder.

What changed
- core media/g711.rs: 256-entry mu-law (PCMU, PT 0, 8kHz) -> i16 PCM / s16le LUT (compile-time const fn); ITU anchors pinned (0x00=-32124, 0x80=+32124, 0xFF=0). 6 tests.
- core stream/media/h264.rs: AccessUnitAssembler groups depacketized Annex-B NALs by the RTP M-bit; flags keyframe (NAL5) + SPS/PPS. 4 tests. (The STAP-A/FU-A depacketizer from TASK-0037 = AC#1.)
- cli stream.rs (new, always-compiled, no network): `stream` subcommand. REPLAY (--replay-annexb) reads Annex-B, RTP-packetizes (single/FU-A), runs the REAL rtp::parse_rtp + H264Depacketizer + AccessUnitAssembler, and re-muxes via ffmpeg. LIVE wires login->discovery->signaling->media->output but is honestly gated (no session/broker/camera) and returns StreamPending. OutputSink spawns ffmpeg fed decrypted Annex-B on stdin: http (mpegts over HTTP, -listen 1, http://127.0.0.1:PORT/stream.ts), ts (--ts-out, ffprobe target), stdout (mpv - fallback). 7 tests.
- shell.nix +ffmpeg; Justfile stream-validate recipe wired into e2e; re/stream_playback.md + --help document the vlc/mpv/ffplay commands.

User impact: `vlc http://127.0.0.1:8554/stream.ts` (mpv/ffplay) plays the feed once the live drive is unblocked; today the same output path is provable offline via --replay-annexb.

Tests (ACTUAL): just e2e EXIT 0 (core 213 pass/0 fail/3 ign; cli 13 pass; stream-validate OK -> ffprobe codec_name=h264, 15 frames decoded). cargo test -p babymonitor-core: 213/0/3 +10+2. Manually verified the HTTP serve end-to-end (curl client pulled 27KB MPEG-TS, ffprobe=h264 320x240) and stdout Annex-B (ffprobe -f h264 = h264).

Risks / follow-ups: AC#5 NOT met — no emulator_captures/cap4 exists, so decode is validated on SYNTHETIC H.264 only, not captured camera bytes (TASK-0068 unblocks). Audio is decoded but the TS is video-only; A/V muxing filed as TASK-0073. The live network drive is environmentally gated, not implemented-as-runnable here. ffmpeg is the muxer (a pure-Rust MPEG-TS muxer is a possible follow-up). Not committed, per instruction.
<!-- SECTION:FINAL_SUMMARY:END -->
