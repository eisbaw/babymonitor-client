---
id: TASK-0096
title: >-
  RE motion detection: sensitivity DPs, recording trigger, IVA tracking, PIR,
  object outline
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:54'
labels:
  - re
  - ai-detection
  - sensors
  - dp
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the motion-detection stack as a recording/notification trigger. Map the video motion sensitivity DP (MotionMonitorSensitivityMode HIGH(2)/MIDDLE(1)/LOW(0), DpMotionMonitorSensitivity), the motion on/off switch, object-outline overlay DP, motion tracking / IVA auto-follow (native enableIVA), and the PIR sensor DP (PIRMode 0-4). Static-RE: document each DP code, value mapping, and the ACTION.MOTION_SIGNAL event path into one re/ writeup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Motion sensitivity DP code + value mapping and the motion on/off switch DP are documented with file:line evidence
- [x] #2 The IVA/motion-tracking native call (enableIVA) and PIR DP are identified with confidence; relation to the recording trigger is stated
- [x] #3 re/motion_detection.md writeup exists covering sensitivity, outline, tracking, PIR and the MOTION_SIGNAL event
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep DP/mode/func sources for motion_sensitivity, motion_switch, ipc_object_outline, motion_tracking, pir DPs\n2. Map enableIVA native chain + gating DP\n3. Confirm MOTION_SIGNAL absence; document real ACTION path\n4. Write re/motion_detection.md\n5. Run just secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Java-tree static RE only. Found: motion_sensitivity(0/1/2 via MotionMonitorSensitivityMode), master motion_switch(bool), motion_record(RECORD_NATIVE recording trigger), ipc_auto_siren, ipc_object_outline drives native enableIVA(long,bool)@ThingCameraNative:57 via getEnableIVA()@ThingSmartCameraP2PSync:2483. enableIVA is client-side overlay drawing (object outline + cross-line out_off_bounds), NOT PTZ auto-follow; the real auto-follow is motion_tracking PTZ DP via FuncMotionTracking. PIRMode(0-4 CLOSE/LOW/MID/HIGH/OPEN) consumed by DpPIR(pir_switch); plus ipc_pir_switch(bool) and ipc_pir_sensitivity. NOTE: ACTION.MOTION_SIGNAL does NOT exist in the tree (0 hits) - real event vehicle is CameraNotifyModel.ACTION.MOTION_MONITOR + SUB_ACTIONs.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the SCD921 motion-detection control plane in re/motion_detection.md (static, Java-tree only).

DP map (all under devicecontrol/operate/dp/, registered in DpCamera.java):
- motion_switch (DpMotionMonitorSwitch, MOTION_MONITOR/SWITCH) master on/off.
- motion_sensitivity (DpMotionMonitorSensitivity, MOTION_MONITOR/SENSITIVITY) -> MotionMonitorSensitivityMode LOW=0/MIDDLE=1/HIGH=2 string values.
- motion_record (DpMotionMonitorRecordSwitch, RECORD_NATIVE) = the record-on-motion trigger; ipc_auto_siren (TRIGGER_SIREN); motion_interval/timer DPs gate cadence/schedule.
- ipc_object_outline (DpMotionMonitorObjectOutline, OBJECT_OUTLINE) gates native enableIVA(long,bool) [ThingCameraNative:57] via getEnableIVA()->setSdkEnableIVA->IPCThingP2PCamera.enableIVA. enableIVA draws the object-outline/cross-line (out_off_bounds) overlay client-side (SmartRectFeature width/color/fps/style) - it is NOT PTZ auto-follow.
- PTZ auto-follow is the separate motion_tracking boolean DP (PTZDPModel.DP_MOTION_TRACKING) via FuncMotionTracking.publishDps.
- PIR: PIRMode 0-4 (CLOSE/LOW/MID/HIGH/OPEN) consumed by DpPIR(pir_switch, ACTION.PIR); plus ipc_pir_switch (bool, IPC_PIR) and ipc_pir_sensitivity (IPC_PIR_SENSITIVITY).

Honesty corrections: (1) ACTION.MOTION_SIGNAL does not exist anywhere in the jadx tree (0 grep hits); the real event vehicle is CameraNotifyModel.ACTION.MOTION_MONITOR + SUB_ACTIONs, documented instead. (2) The native enableIVA is overlay rendering, not auto-follow - corrected the task framing.

Residual unknowns flagged: inbound motion-alarm push/MQTT wire shape (not captured), firmware detection/PIR-fusion algorithm, enableIVA native handle (needs Ghidra). secret-scan: OK (no secrets/PII inlined; DP codes are Tuya schema identifiers).
<!-- SECTION:FINAL_SUMMARY:END -->
