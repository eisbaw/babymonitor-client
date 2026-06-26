---
id: TASK-0075
title: >-
  ICE STUN(srflx)/TURN(relay) for NAT-traversed cameras (host-candidate-only
  today)
status: To Do
assignee: []
created_date: '2026-06-26 22:20'
labels:
  - stream
  - ice
  - media
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
UdpMediaTransport does plain UDP host candidates only; STUN binding (srflx) + TURN Allocate (relay) are not implemented, so only directly-routable cameras are reachable. cap3 provided STUN/TURN servers + ephemeral creds in the SDP token. Implement minimal ICE: STUN binding to discover srflx, TURN Allocate/CreatePermission/Send for relay, and connectivity checks, to reach a camera behind NAT.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 STUN binding request to the SDP stun: server yields a srflx candidate
- [ ] #2 TURN Allocate+permission+relay path works against the SDP turn: server (ephemeral creds)
- [ ] #3 Media connects to the camera via the best candidate (host/srflx/relay)
<!-- AC:END -->
