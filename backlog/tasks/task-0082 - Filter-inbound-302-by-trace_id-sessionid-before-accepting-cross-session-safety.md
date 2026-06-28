---
id: TASK-0082
title: >-
  Filter inbound 302 by trace_id/sessionid before accepting (cross-session
  safety)
status: To Do
assignee: []
created_date: '2026-06-28 11:24'
labels:
  - stream
  - signaling
  - robustness
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
poll_inbound -> flow.ingest switches purely on header.type; it does not check header.trace_id/sessionid against this session. Topics are per-devId (smart/mb/in/<devId>), so only same-device frames arrive, but a concurrent/retried session for the SAME device could interleave a foreign well-formed answer that would be accepted as ours and feed wrong ICE creds/media key to the engine. Pre-existing (not introduced by the cap5 frame fix); surfaced by mped-architect review of TASK-0081.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 poll_inbound rejects/ignores a 302 whose header.trace_id (or sessionid) does not match the active session
- [ ] #2 a unit test interleaves a foreign-trace answer and asserts it is not accepted as the session answer
<!-- AC:END -->
