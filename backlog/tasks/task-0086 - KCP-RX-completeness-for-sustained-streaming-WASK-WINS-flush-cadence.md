---
id: TASK-0086
title: 'KCP RX completeness for sustained streaming (WASK->WINS, flush cadence)'
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
labels:
  - stream
  - media
  - kcp
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
media/kcp.rs is receive-only: IKCP_CMD_WASK/WINS is a no-op and there is no standalone ACK flush cadence (ACKs only piggyback on inbound datagrams). For sustained conv=1/conv=2 the camera may probe our window or our ACKs may be lost. Add window-tell + a minimal flush tick; advance media-start retransmit una/ts to current values.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Inbound WASK is answered with a WINS window-tell
- [ ] #2 An ikcp_update-style tick re-flushes ACKs so lost ACKs recover when the camera goes quiet
- [ ] #3 media-start retransmits carry the current conv0 una/ts, not stale 0
<!-- AC:END -->
