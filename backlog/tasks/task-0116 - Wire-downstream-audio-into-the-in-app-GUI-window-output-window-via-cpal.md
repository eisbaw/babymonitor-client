---
id: TASK-0116
title: Wire downstream audio into the in-app GUI window (--output window) via cpal
status: To Do
assignee: []
created_date: '2026-06-29 22:37'
labels:
  - stream
  - media
  - gui
  - audio
  - feature
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0115 shipped the in-app SDL2 video window (stream --output window, gui feature) as VIDEO-ONLY: the downstream 16 kHz mono S16LE audio is decoded by the engine but not played. The ffmpeg http/ts modes still mux it to AAC. Add an in-app audio output (e.g. cpal, or SDL audio since SDL2 is already linked) fed from the same MediaEngine audio path, with basic A/V sync, so the window plays sound. See re/gui_window.md (Known gaps).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 stream --output window plays the downstream 16 kHz S16LE audio in-app (no external player), fed from the same engine that feeds the video sink
- [ ] #2 Audio stays roughly in sync with video; the bounded/drop-on-full discipline (TASK-0085) is preserved so the recv/ACK loop never stalls
- [ ] #3 Audio deps stay behind the gui feature; default build + just e2e remain green
<!-- AC:END -->
