---
id: TASK-0036
title: 'Wave-2 DEEP RE-PLAN: run phase2-backlog-snowball for Wave-2 in a fresh session'
status: To Do
assignee: []
created_date: '2026-06-25 07:14'
labels:
  - phase-gate
  - replan
  - wave2
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Terminal re-plan for Wave-1 (snowball discipline). Wave-1 (static RE) is COMPLETE; the deep Wave-2 plan should be authored at the START of a fresh session (full context), NOT at the tail of the exhausted Wave-1 session. In that fresh session, re-invoke phase2-backlog-snowball with re/prd.md, TESTING.md, and the Wave-1 lessons: the auth dead-end (runtime-config bmp_token), the WebRTC-over-MQTT stream as the video deliverable, the deferred pairing (TASK-0008) + P2P framing (TASK-0010), and the gate nits (20/21/28/31 + the verdict-overturn guard). Sequence the Wave-2 auth DECISION first (it gates everything). Write no feature code in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 phase2-backlog-snowball run for Wave-2 in a fresh session; Wave-2 tasks dependency-ordered with the auth decision first
<!-- AC:END -->
