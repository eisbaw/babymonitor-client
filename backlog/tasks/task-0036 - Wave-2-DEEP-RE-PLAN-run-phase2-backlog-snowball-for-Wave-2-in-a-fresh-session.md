---
id: TASK-0036
title: 'Wave-2 DEEP RE-PLAN: run phase2-backlog-snowball for Wave-2 in a fresh session'
status: To Do
assignee: []
created_date: '2026-06-25 07:14'
updated_date: '2026-06-25 08:38'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0008 (pairing flow mapped): A Rust PAIRING module is LOW PRIORITY for Wave-2. The user's camera is ALREADY PAIRED -> pairing is NOT on the critical path: an already-bound device appears in HomeBean.deviceList as a normal DeviceBean (carrying localKey/p2pId for the stream) and the device-list + CameraInfoBean fetch require only the login sid — NO pairing token, NO SmartLink. The critical path is the SAME auth+device-list spine the stream already depends on (TASK-0032 bmp_token + TASK-0035 auth decision + TASK-0012/0013). 

IF a future 'add a new camera' feature is wanted, the pairing protocol is mapped to implementable depth in re/pairing_flow.md (EZ packet-length scheme Ghidra-confirmed under re/ghidra/smartlink_*.c; AP {ssid,passwd,token,ccode}; QR {p,s,t}; token thing.m.device.token.create v2.0; bind-confirm poll thing.m.device.list.token v5.0). Only a few constants are live-gated (exact AP UDP port ~6669, on-wire action spelling, poll cadence). Recommendation: do NOT schedule a pairing crate in Wave-2 unless 'pair a new device' becomes an explicit goal; it adds UDP-broadcast/multicast-socket + soft-AP-join complexity for zero benefit to the already-paired view path.
<!-- SECTION:NOTES:END -->
