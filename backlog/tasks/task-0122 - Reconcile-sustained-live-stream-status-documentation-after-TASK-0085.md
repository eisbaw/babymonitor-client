---
id: TASK-0122
title: Reconcile sustained live-stream status documentation after TASK-0085
status: To Do
assignee: []
created_date: '2026-06-30 10:22'
labels:
  - stream
  - docs
  - honesty
  - hygiene
dependencies:
  - TASK-0121
references:
  - re/prd.md
  - re/live_stream_run.md
  - re/stream_playback.md
  - TESTING.md
  - Justfile
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Current-status prose in the PRD, live run guide, playback guide, and Justfile still describes the pre-e1528da twelve-segment freeze as an active blocker. Reconcile those statements after the launcher, sink, overflow, and offline HTTP gate tasks land. Preserve explicitly dated historical root-cause records, but make every current claim distinguish manual live-camera evidence from automated loopback evidence and from still-open protocol work.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The PRD, re/live_stream_run.md, re/stream_playback.md, relevant READMEs, TESTING.md, and Justfile comments agree that blocking sink ACK starvation and fatal FU-A propagation were fixed by TASK-0085, and no current instructions claim prompt VLC attachment is required to keep KCP advancing.
- [ ] #2 Documentation records the existing manual approximately 100-second HTTP and VLC observation as manual evidence, records the offline production-HTTP coverage delivered by TASK-0121 as automated loopback evidence, and does not upgrade either into fully proven continuous live A/V.
- [ ] #3 Remaining limitations point to their owning tasks: KCP response correctness TASK-0086, sink and audio lifecycle TASK-0087, capture-grounded sustained replay TASK-0089, reviewer cleanups TASK-0114, and access-unit overflow recovery TASK-0120.
- [ ] #4 A scoped stale-status tripwire rejects unframed current claims that the old twelve-segment freeze is still active while allowing clearly historical or superseded passages; it is demonstrated red on a planted stale fragment and green on the repository.
- [ ] #5 just check-evidence passes, citations remain artifact- or symbol-grounded, and TASK-0085 historical notes are not rewritten as if their original failure never occurred.
<!-- AC:END -->
