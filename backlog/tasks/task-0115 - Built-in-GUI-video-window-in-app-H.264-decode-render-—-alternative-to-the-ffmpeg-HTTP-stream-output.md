---
id: TASK-0115
title: >-
  Built-in GUI video window (in-app H.264 decode + render) — alternative to the
  ffmpeg/HTTP stream output
status: Done
assignee:
  - '@claude'
created_date: '2026-06-29 21:14'
updated_date: '2026-06-29 22:38'
labels:
  - stream
  - media
  - gui
  - feature
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Today the live path muxes decoded H.264 to MPEG-TS via ffmpeg and serves it over HTTP for an EXTERNAL player (vlc/mpv/ffplay) — see stream --output http + the just live-stream recipe. Add a self-contained ALTERNATIVE that decodes and renders the live feed in a NATIVE GUI window inside the Rust app: no external player, no ffmpeg mux + HTTP hop, lower latency, one process. Reuse the existing media pump + depacketizer (babymonitor-core stream/media, H264Depacketizer): a new output mode (e.g. stream --output window) feeds decoded Annex-B NALs to an in-app H.264 decoder -> frames -> a windowed presenter, and the downstream 16 kHz S16LE audio to an audio output. Gate it behind a gui cargo feature (like the existing live feature) so the headless/offline build, just e2e, and the live-only path are unaffected and the windowing/decoder deps do not bloat the default build. Decisions to make + record: decoder crate (recommend ffmpeg-next/libavcodec since ffmpeg is already a dep, vs the H.264-only openh264 crate); window + present (recommend winit + pixels/softbuffer/wgpu, vs minifb or egui/eframe); audio out (cpal); YUV420->RGB conversion (swscale or a shader). This is client-implementation work (not RE), so the static-analysis-only constraint does not apply; live rendering still needs the camera + a display, but the decode path is offline-testable via --replay-annexb.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A new gated output mode (e.g. --output window behind feature gui) renders the live H.264 feed in a native GUI window with NO external player and NO ffmpeg/HTTP hop
- [x] #2 Reuses the existing MediaEngine + H264Depacketizer — the decode+present is a new sink alongside LiveAvSink, fed by the same pump
- [x] #3 Offline-validatable: the decode->window path renders a synthetic/replay Annex-B stream (--replay-annexb) without a camera (window itself may need a display)
- [x] #4 Downstream 16 kHz S16LE audio plays via an in-app audio output (cpal), or the A/V-sync gap is documented + tracked
- [x] #5 GUI/decoder/window/audio deps are behind the gui cargo feature; default build + just e2e are unchanged and green (no new deps in the offline path)
- [x] #6 A short decision record (decoder + windowing + audio crate choices, with rationale) is captured in re/ or the task notes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Finished + verified the in-app SDL2 window.

- Fixed the E0597 Texture/TextureCreator lifetime: moved the per-frame upload+present out of a closure into a free present_frames<'r>(...) whose 'r ties &TextureCreator to the stored Texture<'r> (a closure cannot relate two captures). gui.rs.
- Wired --output window: added OutputMode::Window (stream.rs) + VideoOut::Window(GuiSink) in the live LiveAvSink (stream_live.rs, pump_to_output UNTOUCHED) + OutputSink::Window(GuiSink) for the offline --replay-annexb path (camera-free). All gui-gated; honest error when gui is off; live window needs --features live,gui.
- Silenced libav logging to Quiet (per-NAL feeding logs [h264] no frame! at ERROR level on most receive_frame calls).
- Removed dead title field; cfg(not(live)) allow(dead_code) on GuiSink so --features gui-only stays clippy-clean.

Build/lint: cargo build + clippy -D warnings clean for gui, live, live+gui, and default. just e2e GREEN. just secret-scan OK.

VERIFIED OFFLINE (--features gui, no camera): replayed a synthetic 30s/450-frame testsrc Annex-B via --replay-annexb --output window -> window opened, presented 450 frames, 0 dropped.

VERIFIED LIVE (--features live,gui, real camera, valid session): controlled ~110s run of stream --output window. First cold attempt got a silent camera (no answer within 600 polls) and exited honestly; retry connected (302 nomination VALIDATED). Trace BABYMONITOR_STREAM_TRACE sustained 114s of continuous SUMMARY lines, max_sn 61->5755 monotonic, vq(enq/wr/drop)=2974/2858/0 -> the in-app window decoded+rendered 2858 frames, 0 drops. Privacy: verified by counters only, no frame saved/viewed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added an in-app SDL2 video window as an alternative to the ffmpeg/HTTP stream output: stream --output window renders the live H.264 feed in OUR OWN window via an IN-PROCESS libavcodec decoder (ffmpeg-the-third) -> YUV420 -> SDL2 IYUV texture. No subprocess, no MPEG-TS, no HTTP, no external player.

What changed:
- gui.rs: GuiSink (bounded sync_channel(512), drop-on-full -> never stalls the KCP recv/ACK loop, reusing the TASK-0085 discipline) + a presenter thread that owns SDL + the decoder. Fixed the Texture/TextureCreator lifetime with a free present_frames<'r> fn (explicit 'r) instead of a closure.
- stream.rs: new OutputMode::Window + an OutputSink::Window(GuiSink) so the OFFLINE --replay-annexb path renders with NO camera.
- stream_live.rs: VideoOut::Window(GuiSink) in LiveAvSink; write_video->gui.send, video_stats->gui.stats, finish->gui.finish. pump_to_output untouched.
- shell.nix already pins ffmpeg_7 (ffmpeg-sys-the-third 3.0.1 still references avfft.h, removed in ffmpeg 8) + SDL2 + libclang/bindgen env.
- All deps behind the gui feature; the live camera window also needs live (cargo build --features live,gui). Honest error if gui is absent.
- Decision record: re/gui_window.md (in-process libav decode, ffmpeg_7 pin, SDL IYUV present, sdl2-compat pump_events workaround = no X-close handling, libav Quiet logging, bounded-queue reuse, audio-not-wired gap).

User impact: a one-process, lower-latency live viewer. Limitations: video-only (no audio yet -> follow-up TASK-0116); no window-close-button handling (sdl2-compat event-enum panic worked around with pump_events).

Tests / verification:
- just e2e GREEN; clippy -D warnings clean across gui / live / live+gui / default; secret-scan OK.
- Offline (no camera): synthetic 450-frame replay -> presented 450 frames, 0 dropped.
- LIVE (real camera, valid session): controlled ~110s run sustained 114s of climbing trace counters (max_sn 61->5755), in-app window decoded+rendered 2858 frames, 0 drops. Verified by counters only (privacy). One transient silent-camera cold start, succeeded on retry.

Risks/follow-ups: audio not wired (TASK-0116); no X-close handling; libav errors silenced (health = frame counters).
<!-- SECTION:FINAL_SUMMARY:END -->
