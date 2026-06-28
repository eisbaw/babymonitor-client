---
id: TASK-0089
title: >-
  Verify conv=1/conv=2 KCP ACK byte-shape vs cap4 and add a sustained-A/V
  harness
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
labels:
  - stream
  - media
  - test
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The conv=1/conv=2 ACK datagram framing (cmd=0x52, una, wnd, HMAC) is inferred, not ground-truthed. Pin it against the apps ~785 return packets in cap4, then add an honest end-to-end harness that injects a recorded conv=1+conv=2 byte stream into the live pump so smooth continuous A/V becomes regression-tested, not a one-off manual observation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 conv=1/conv=2 ACK framing is byte-validated against cap4 (header fields, coalescing, wnd)
- [ ] #2 A replay harness feeds a recorded conv=1+conv=2 stream through pump_to_output and asserts sustained decoded frames + advancing ACKs
<!-- AC:END -->
