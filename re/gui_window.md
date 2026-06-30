# In-app SDL2 video window (`--output window`, `gui` feature) — decision record

**Task:** TASK-0115. **Status:** implemented + live-verified (see "Verification" below).
**Confidence:** high — this is *our own* client code, not an RE claim, and was run live
end-to-end against the real camera.

## What it is

An alternative to the existing `stream` output modes (`http` / `ts` / `stdout`, all of which
hand decoded Annex-B to an **ffmpeg subprocess** that muxes MPEG-TS for an external player). The
new `--output window` mode renders the live decoded H.264 feed in **our own window** with:

- an **in-process libavcodec** H.264 decoder (the `ffmpeg-the-third` crate's `codec` binding) —
  NOT a subprocess, NOT an MPEG-TS/HTTP hop, no external player; and
- **SDL2** for the native window + a streaming **IYUV** texture (the GPU does YUV→RGB).

Code: `babymonitor/babymonitor-cli/src/gui.rs` (the `GuiSink` + `present_loop`/`present_frames`
presenter), wired into the live A/V driver (`stream_live.rs`, `VideoOut::Window`) and the offline
replay sink (`stream.rs`, `OutputSink::Window`). Both are feature-gated: `--output window` needs
`gui`, and for the live camera path also `live` (so: `cargo build --features live,gui`). The
offline `--replay-annexb … --output window` path needs only `gui` (camera-free).

## Key decisions / rationale

### In-process libav decode (not a subprocess)
The whole point of this mode is to own the pixels. We pull YUV420P planes directly out of the
libavcodec frame and upload them straight into an SDL IYUV streaming texture — no swscale, no
re-encode, no muxer, no localhost socket. This is lower-latency and simpler to reason about than
spawning `ffmpeg | player`.

### ffmpeg pinned to ffmpeg_7 in `shell.nix` (avfft.h)
`ffmpeg-sys-the-third 3.0.1` (pulled by `ffmpeg-the-third 3`) generates bindings that still
reference `libavutil/avfft.h`. **ffmpeg 8.0 removed that header**, so the `-sys` crate fails to
build against ffmpeg 8. `shell.nix` therefore pins `ffmpeg_7` (≤ 7.1 is the supported range) and
exports `LIBCLANG_PATH` + `BINDGEN_EXTRA_CLANG_ARGS` (glibc dev headers + the clang resource dir
+ the ffmpeg_7 include dir) so bindgen finds `<stdlib.h>` and the ffmpeg headers. The existing
`stream` mux path (which calls the `ffmpeg` *binary*) is unaffected by the pin.

### `TextureCreator`/`Texture<'r>` lifetime — free fn, not a closure
sdl2's default (no `unsafe_textures`) `Texture<'r>` borrows its `TextureCreator`. The per-frame
upload/present logic lives in a free `present_frames<'r>(…)` whose `'r` explicitly ties the
`&TextureCreator` argument to the `Texture<'r>` stored in the reused `Option`. A closure could not
express this (it cannot relate two of its own captures), which is the E0597
`texture_creator does not live long enough` the first cut hit. The creator is declared before the
texture so it always outlives it.

### sdl2-compat event-enum panic — raw event-type polling (`close_requested`)
nix's SDL2 is **sdl2-compat** (an SDL3-backed shim). It emits some event type values that the
`sdl2 0.37` crate's safe `Event` enum conversion panics on (e.g. `0x207`), so `poll_iter()` is
unusable. We instead read the **raw event `type_` integer** via a small `unsafe` FFI
(`gui::close_requested`: `SDL_PumpEvents` + `SDL_PollEvent`), acting only on `SDL_QUIT` /
`SDL_WINDOWEVENT_CLOSE` and discarding everything else — no Rust enum conversion, no panic. This is
the one spot the CLI crate needs `unsafe`, so its root is `deny(unsafe_code)` (not `forbid`); the
core crate stays `forbid` (TASK-0117).

Consequence: **the X close button now works** — clicking it (a `WM_DELETE_WINDOW`) stops the
window. And because this sdl2-compat build turns **SIGINT/SIGTERM/SIGQUIT into an `SDL_QUIT`** that
`close_requested` now honors, **Ctrl-C and a plain `kill`/`timeout --signal=TERM` stop it too** —
all verified empirically (`xdotool windowclose` and `SIGTERM` each exit the process ~1 s later;
`SIGKILL` of course also works). In the live/replay presenter the close calls
`std::process::exit(0)` (the window IS the app); the selftest loop simply breaks. The `just
gui-stream` recipe keeps its foreground-shell trap as a belt-and-suspenders SIGKILL backstop.

### libav logging silenced to `Quiet`
We feed the decoder one NAL per packet and drain after each, so libavcodec logs
`[h264 @ …] no frame!` on every `receive_frame` that doesn't yet have a complete access unit
(most calls). In this build that message is at libav's **ERROR** level, so it can't be filtered by
severity without also dropping genuine decode complaints. The window's health signal is the
**presented / dropped frame counters** (visible in the `BABYMONITOR_STREAM_TRACE` SUMMARY as
`vq(enq/wr/drop)`), not decoder chatter, so libav logging is set to `Quiet`. Trade-off: real
decode-error *text* is suppressed too; corruption instead shows as a stalled count / garbled
picture.

### Bounded queue / ACK-loop reuse (TASK-0085)
`GuiSink::send` enqueues each Annex-B NAL onto a **bounded** `sync_channel(512)` with
**drop-on-full** (it never blocks). This is the same discipline as the ffmpeg `VideoWriter`: the
KCP recv/ACK loop must never stall on a slow consumer, or the camera's send window stops advancing
and the stream freezes after its first window. A dedicated presenter thread owns SDL + the decoder
and drains the queue. Dropped NALs are counted and surface in the trace.

## Known gaps / limitations (v1)

- **Audio is not wired** into the window sink. `--output window` is **video-only**; the downstream
  16 kHz audio track is decoded by the engine but not played (the ffmpeg `http`/`ts` modes still
  mux it to AAC). A follow-up task should add an SDL audio device fed from the same engine.
- **Window close is abrupt** — the X button / Ctrl-C / SIGTERM now stop the window
  (`gui::close_requested`), but the live presenter does so via `std::process::exit(0)`, which skips
  graceful teardown (no `GuiSink::finish` summary, no MQTT session teardown — the camera times its
  own session out rather than being told). TASK-0117 tracks signalling the media pump to unwind
  cleanly instead.
- **No on-screen error text** — health is judged by counters (libav logging is `Quiet`).

## Verification

- **Offline (camera-free), `--features gui`:** replayed a synthetic 30 s / 450-frame
  testsrc Annex-B sample through `--replay-annexb … --output window`. Result: window opened,
  **presented 450 frames, 0 dropped** — proving the GuiSink → libavcodec decode → SDL IYUV present
  path with no camera.
- **Live (real camera), `--features live,gui`:** a controlled ~110 s run of
  `stream --output window` on a valid session. Camera answered (302 nomination VALIDATED, media
  pumping); the run sustained **114 s** of continuous `BABYMONITOR_STREAM_TRACE` SUMMARY lines with
  monotonically climbing `max_sn` (61 → 5755) and `vq(enq/wr/drop) = 2974 / 2858 / 0` — i.e. the
  in-app window **decoded + rendered 2858 frames, 0 drops**, well past the 100 s bar. (One earlier
  cold-start attempt got a silent camera — "no answer within 600 polls" — and exited honestly; a
  retry connected. This is the camera's known transient signaling behaviour, upstream of the GUI.)
- No decoded frame was ever saved or viewed (owner's real home) — verification is by counter only.

No secret values appear in this file.
