---
id: TASK-0125
title: Wire IPC_LAN_302 signaling into the Rust stream engine
status: To Do
assignee: []
created_date: '2026-07-16 13:48'
labels:
  - rust
  - lan
  - streaming
dependencies:
  - TASK-0124
references:
  - >-
    decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java
  - decompiled/jadx/sources/com/thingclips/smart/p2p/qqpddqd.java
  - babymonitor/babymonitor-core/src/stream/session.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the fake LAN signaling path, which currently publishes through MQTT, with a genuine authenticated local Tuya transport carrying IPC_LAN_302 frame type 32. Reuse the existing SDP, ICE, KCP, and media engine and provide explicit cloud, LAN, and auto routing.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A transport-neutral signaling interface routes MQTT envelopes only to MQTT and LAN envelopes only to the local frame-32 carrier
- [ ] #2 LAN mode connects using camera IP, device ID, localKey, and Hgw LAN version without opening a broker socket
- [ ] #3 Inbound frame-32 answer and candidate JSON feeds the existing trace/session filtering and media negotiation
- [ ] #4 CLI exposes explicit cloud, lan, and auto signaling modes with honest diagnostics and no silent cloud fallback in lan mode
- [ ] #5 Durable LAN metadata is loaded from secure per-user configuration; ephemeral ICE, media keys, trace IDs, and session IDs remain per-run
- [ ] #6 Offline integration tests prove LAN mode opens no REST or MQTT connections and exercises answer plus candidate negotiation
- [ ] #7 Existing cloud-MQTT mode remains covered and behavior-compatible
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Generalize the signaling seam. 2. Implement Lan302Transport over TASK-0124. 3. Wire runtime configuration and CLI routing. 4. Add socket-fake integration and regression tests. 5. Run gates and commit.
<!-- SECTION:PLAN:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just e2e passes
- [ ] #2 qa-test-runner and mped-architect report no unresolved blockers
<!-- DOD:END -->
