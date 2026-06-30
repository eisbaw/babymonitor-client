---
id: TASK-0087
title: 'A/V sink: do not gate video on absent downstream audio; robust live output'
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
updated_date: '2026-06-30 10:20'
labels:
  - stream
  - media
  - ffmpeg
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Make the live ffmpeg sink video-first and bounded across startup, playback, and teardown. Today an always-present audio FIFO plus shortest can gate video, port conflicts are detected too late, player disconnects are ambiguous, AudioFifo can block forever opening its FIFO, VideoWriter can join a blocked write before killing ffmpeg, and the audio channel is unbounded. Define the one-client HTTP contract and make every failure path terminate without leaked processes, FIFOs, ports, or unbounded memory.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A video-only live session with no conv=2 audio produces a continuously growing, playable stream; audio absence cannot block ffmpeg startup or mux progress.
- [ ] #2 HTTP port ownership is checked before any live session, cloud, broker, or camera work; an occupied port fails fast with the listener identity and no media pipeline side effects.
- [ ] #3 The one-client contract is explicit and tested: player disconnect ends the session cleanly, and the next invocation can immediately bind the same port; reconnect or multi-client support is not implied unless implemented.
- [ ] #4 ffmpeg spawn failure, early ffmpeg exit, absent audio, and a never-reading HTTP client all reach a bounded teardown that terminates or unblocks the child and FIFO before joining writer threads, removes the FIFO, and leaves no listener.
- [ ] #5 Video and audio buffering have explicit bounded policies and metrics; a blocked audio FIFO cannot grow an unbounded channel or stall video.
<!-- AC:END -->
