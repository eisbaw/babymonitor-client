---
id: TASK-0117
title: >-
  GUI window hardening: fail-fast presenter init, accurate queue-depth stat,
  window-close/event handling, DRY
status: To Do
assignee: []
created_date: '2026-06-30 05:36'
updated_date: '2026-06-30 10:46'
labels:
  - gui
  - tech-debt
  - task-0115-followup
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-ups from the mped-architect review of the TASK-0115 in-app GUI video window (gui.rs). All NON-BLOCKING; the core stream is correct and the TASK-0085 ACK-loop decoupling is preserved. These harden diagnostics, fail-fast, and UX of the window sink.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 GuiSink::spawn rendezvous on presenter init (SDL/decoder open) so an init failure (e.g. no DISPLAY) fails fast at construction like VideoWriter, instead of only surfacing at finish(); add a one-shot log on the send() TrySendError::Disconnected arm so a dead presenter is not silent (mirror stream_live writer_gone)
- [ ] #2 Fix the window-mode queue-depth diagnostic: GuiSink::stats() second slot reports decoded FRAMES while StreamTrace treats it as written NALs and computes depth=enq-wr, so non-VCL NALs (SPS/PPS/SEI) inflate the reported depth; count NALs dequeued from the channel as 'written' (parity with VideoWriter) and expose presented-frames separately, or document the window-mode semantics in the trace
- [x] #3 Window close / event handling: the pump_events() mitigation for the sdl2-compat (SDL3) event-enum panic means there is no working window close button; provide a real close path (handle quit without the panicking enum, or upstream/pin a non-compat SDL2) so the window can be closed without killing the process
- [ ] #4 DRY: factor the duplicated SDL window+pump boilerplate shared by selftest() and present_loop() into one helper (e.g. open_window(title,w,h,resizable))
- [ ] #5 Graceful window-close shutdown: replace the live presenter's process::exit(0) with a shared shutdown signal the media pump polls, so main unwinds through GuiSink::finish (summary) and sends an MQTT session teardown to the camera instead of letting it time out
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Window-close (AC#3) done: gui::close_requested() reads raw SDL event types via a localized unsafe FFI (crate root relaxed forbid->deny(unsafe_code); core stays forbid) and acts on SDL_QUIT/SDL_WINDOWEVENT_CLOSE. Verified with xdotool windowclose (WM_DELETE) on both selftest and live windows (~1s exit), and SIGTERM also stops it (sdl2-compat maps INT/TERM/QUIT->SDL_QUIT). Committed with the title em-dash->ASCII fix. Remaining: AC1 fail-fast init, AC2 depth stat, AC4 DRY, AC5 graceful shutdown.
<!-- SECTION:NOTES:END -->
