---
id: TASK-0126
title: Live-validate SCD921 LAN-only streaming with Tuya cloud unavailable
status: To Do
assignee: []
created_date: '2026-07-16 13:49'
labels:
  - live-test
  - lan
  - streaming
dependencies:
  - TASK-0125
references:
  - re/ghidra/imm_p2p_rtc_connect_v2.c
  - re/prd.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Prove the owner camera can negotiate and stream through IPC_LAN_302 without Tuya MQTT, then test a cold start without any WAN dependency. Capture only redacted diagnostics under secrets and correct code or claims based on observed behavior.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Runtime discovery records the actual SCD921 Hgw LAN version and address without exposing identifiers or localKey
- [ ] #2 A fresh stream starts and produces validated H.264 while the Tuya MQTT path is unavailable
- [ ] #3 Connection tracing demonstrates LAN mode contacts only the camera LAN address during signaling and media startup
- [ ] #4 Camera and client restart test is performed with WAN unavailable; result is recorded honestly as pass or with the exact remaining cloud dependency
- [ ] #5 LocalKey rotation/re-pair behavior and cached metadata lifetime are tested or explicitly bounded
- [ ] #6 README and RE findings distinguish LAN signaling on TCP 6668 from ICE/KCP UDP media and remove the datapoint-only overclaim
- [ ] #7 No live credentials, identifiers, IPs, or media enter tracked files
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Discover the camera LAN metadata and confirm protocol version. 2. Run LAN signaling with cloud broker unusable and validate media. 3. Trace outbound connections. 4. Repeat after camera/client restart with WAN unavailable. 5. Fix observed defects, update evidence/docs, run gates, and commit.
<!-- SECTION:PLAN:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just e2e passes
- [ ] #2 qa-test-runner and mped-architect report no unresolved blockers
<!-- DOD:END -->
