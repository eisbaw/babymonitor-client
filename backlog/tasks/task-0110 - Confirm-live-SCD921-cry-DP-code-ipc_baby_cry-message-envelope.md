---
id: TASK-0110
title: Confirm live SCD921 cry DP code + ipc_baby_cry message envelope
status: To Do
assignee: []
created_date: '2026-06-28 21:56'
labels:
  - re
  - ai-detection
  - dp
  - baby-monitor
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from TASK-0091. Static RE found two cry-detection DP code strings (cry_detection_switch in the Tuya SDK func vs cry_det_switch dpId 12 in the product DpCode table) and a message-center detection key ipc_baby_cry, but could not statically determine which DP the SCD921 firmware actually carries nor the exact JSON envelope of the cry alarm message. Resolve using the device schema + a captured type-212 message from the emulator/live capture pipeline. Anonymize devId/uid; keep raw samples under secrets/.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Live SCD921 device schema confirms whether cry_detection_switch or cry_det_switch (dpId 12) is the on-device DP, with value type
- [ ] #2 A captured ipc_baby_cry message-center alarm payload shape is documented (msgType, fields), anonymized
- [ ] #3 re/cry_detection.md residual-unknowns section updated with the findings
<!-- AC:END -->
