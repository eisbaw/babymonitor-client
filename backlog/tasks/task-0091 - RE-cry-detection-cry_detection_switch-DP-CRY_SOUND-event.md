---
id: TASK-0091
title: RE cry detection (cry_detection_switch DP + CRY_SOUND event)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:56'
labels:
  - re
  - ai-detection
  - dp
  - baby-monitor
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the on/off AI cry-detection feature distinct from Zoundream translation. Identify the Tuya DP (cry_detection_switch), the CameraNotifyModel.ACTION.CRY_SOUND event surface, the func/UI wiring, and how detected-cry events reach the app (MQTT DP report vs message-center event). Static-RE only: map the DP code, value semantics, and event payload shape into an re/ writeup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The cry_detection_switch DP code and value semantics are documented from DpCrySoundSwitch.java with file:line evidence
- [x] #2 The cry-event reporting path (ACTION.CRY_SOUND / message-center type) is identified with evidence and confidence noted
- [x] #3 re/cry_detection.md writeup exists; the boundary with Cry Translation is stated
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read DpCrySoundSwitch.java / FuncCrySoundSwitch.java + BaseDpOperator + CameraNotifyModel
2. Trace ACTION.CRY_SOUND producers/consumers
3. Find detection-event path (message center ipc_baby_cry)
4. Resolve strings/layouts + Cry Translation boundary
5. Write re/cry_detection.md; run secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DP code cry_detection_switch (bool) from DpCrySoundSwitch.f():68; maps to ACTION.CRY_SOUND g():107. BaseDpOperator wraps bool schema -> BoolDpOperateBean (:105). Func reads/writes Boolean (FuncCrySoundSwitch :96/:285), label "Detect Baby Crying" (R.string.G2=0x7f130fbb=ipc_cry_sound_detected_switch_settings). CRY_SOUND notify carries switch STATE via SUB_ACTION.SET_STATUS (BaseDpOperator d():256-258) - only producer is the DP, no event consumer. Detection EVENT travels via message center: SoundClassifyKeys.Cry_detected="ipc_baby_cry" (:12), type-212 filter soundKeys (Message212TypeFilterUtils :59). Second product DP cry_det_switch dpId 12 (DeviceDpUtil :72). Boundary: Cry Translation = cry_trans_switch dpId 2 + 5 reasons (CryTranslationClassifyKeys). secret-scan OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the on/off AI cry-detection feature in re/cry_detection.md (static RE only).

Findings:
- DP cry_detection_switch is boolean (TRUE=on); evidence DpCrySoundSwitch.java:68/:107, BoolDpOperateBean wrap BaseDpOperator.java:105-106, Func read/write FuncCrySoundSwitch.java:96/:285. UI = single switch row labelled "Detect Baby Crying" (R.string.G2 -> 0x7f130fbb -> ipc_cry_sound_detected_switch_settings).
- ACTION.CRY_SOUND is STATE-only: emitted via CameraEventSender with SUB_ACTION.SET_STATUS on DP report (BaseDpOperator.java:256-258); grep shows the DP operator is the sole producer and there is no event consumer.
- Detected-cry EVENTS arrive via the Tuya message center, sound-classify key ipc_baby_cry (SoundClassifyKeys.java:12; Message212TypeFilterUtils.java:59/:221) - NOT a DP report. (type-212 label inferred from class name = medium confidence.)
- Surfaced a second product DP cry_det_switch dpId 12 (DeviceDpUtil.java:72); which code the SCD921 firmware actually carries needs the device schema (residual unknown).
- Boundary with Cry Translation (Zoundream) stated explicitly: cry_trans_switch dpId 2 + 5-reason CryTranslationClassifyKeys + subscription; fragment_cry_definition.xml belongs to Translation not Detection.

Gate: nix-shell just secret-scan = OK. No secret/PII values written.
<!-- SECTION:FINAL_SUMMARY:END -->
