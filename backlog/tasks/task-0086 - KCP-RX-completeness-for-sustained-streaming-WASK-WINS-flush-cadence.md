---
id: TASK-0086
title: 'KCP RX completeness for sustained streaming (WASK->WINS, flush cadence)'
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
updated_date: '2026-06-30 10:20'
labels:
  - stream
  - media
  - kcp
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
KCP receive-side control responses are incomplete. WASK is ignored, already-consumed duplicate PUSH segments are not re-ACKed, and drain_media_acks clears responses before the nonblocking UDP send confirms acceptance. Implement bounded ACK and WINS queuing plus a timed flush so transient send failures and lost ACK recovery follow KCP behavior without busy-spinning. Refresh media-start retransmit headers from current state.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Inbound WASK queues a WINS for the same conv with the current receive window and una, valid suite-3 HMAC, and bounded timed flush.
- [ ] #2 After rcv_nxt advances and its first ACK is drained, a retransmitted stale PUSH with sn below rcv_nxt emits a fresh ACK with echoed ts and current una without decrypting or delivering the media twice.
- [ ] #3 Injected UDP send outcomes transient then success prove ACK and WINS datagrams remain queued after Ok(None), including WouldBlock and ConnectionRefused, and are removed only after a full datagram send succeeds.
- [ ] #4 Pending responses are bounded and deduplicated, retry on a timer without further inbound media or busy-spinning, and a permanently transient transport reaches a tested bound or timeout.
- [ ] #5 A successfully submitted but network-lost ACK recovers when the peer retransmits its PUSH and the stale duplicate is re-ACKed; the client does not blindly replay all historical ACKs.
- [ ] #6 Media-start retransmits preserve sequence and payload but regenerate current ts, una, and HMAC.
<!-- AC:END -->
