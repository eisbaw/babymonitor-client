---
id: TASK-0094
title: RE PTZ pan/tilt control (PTZDirection enum + publishDps command path)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:55'
labels:
  - re
  - camera-control
  - dp
  - ptz
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the pan/tilt motor control. Map the 8-direction PTZDirection enum (UP(0)..LEFT_UP(7), ROTATE, CALIBRATING), the IThingIPCPTZ API and PTZControlView/NewUIPTZControlView UI wiring, and the exact DP code + payload published via publishDps() to move the camera, plus the stop semantics. Static-RE into an re/ writeup; verify whether the SCD921/923 actually exposes a motor (string evidence suggests yes).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The PTZ direction enum values and the DP code/payload published via publishDps() are documented with file:line evidence
- [x] #2 Start/continuous/stop movement semantics are captured and whether SCD921/923 supports motorized PTZ is assessed with confidence
- [x] #3 re/ptz_control.md writeup exists with the command encoding for each direction
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep decompiled sources for PTZDirection enum + ThingIPCConstant + PTZDPModel\n2. Trace publishDps move/stop call sites (RN bridge, DpHelperExtendKt, panel models)\n3. Read PTZControlView/NewUIPTZControlView touch semantics\n4. Assess SCD921 motor support from captured device DP schema\n5. Write re/ptz_control.md; run secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Findings:\n- Enum com/thingclips/camera/devicecontrol/model/PTZDirection.java:9-20 UP(0)..LEFT_UP(7),ROTATE(8),CALIBRATING(9); mirror at smart.camera.devicecontrol.mode.PTZDirection adds UNKNOW(-1). Smali corroborated (smali_classes8 PTZDirection.smali:216-409).\n- DP codes PTZDPModel.java:16-17: ptz_control (enum/string DP, payload direction string 0..9), ptz_stop (bool DP, payload Boolean.TRUE).\n- Publish API IThingIPCPTZ.java:29 publishDps(code,value,cb); gate querySupportByDPCode :31.\n- Move: DpHelperExtendKt.java:138, RNThingCameraManager.java:659; per-direction cameramanager/TRCTCameraManager.java:14665/14698/14763/14807. Stop: DpHelperExtendKt.java:213, RNThingCameraManager.java:829 etc.\n- Press-and-hold semantics: PTZControlView.java:1078-1101 ACTION_DOWN->onUp/Down/Left/Right, ACTION_UP->onTouchEventUp; NewUIPTZControlView.java:1185.. RN bridge startPtz*/stopPtz at trctcameramanager TRCTCameraManager.java:5446-6027. Move guard allows only 4 cardinals (switchmap LEFT/UP/RIGHT/DOWN->1-4).\n- Motor assessment: captured device schema (secrets/cap1_rtc_decrypted) has motion/decibel/temp/floodlight/ipc_flip DPs but NO ptz_control/cruise/zoom/preset -> querySupportByDPCode false -> SCD921 has no motor (MEDIUM, absence-based). PTZ APK assets are generic skin, not device evidence.\nsecret-scan: OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the Tuya PTZ pan/tilt motor-control path the Baby Monitor+ app reskins, in re/ptz_control.md.\n\nWhat changed:\n- Mapped the PTZDirection enum (UP="0"..LEFT_UP="7", ROTATE="8", CALIBRATING="9"; mirror enum adds UNKNOW="-1") with file:line + smali corroboration.\n- Documented DP codes PTZDPModel.ptz_control (enum DP, payload = direction string) and ptz_stop (bool DP, payload = Boolean.TRUE), and the IThingIPCPTZ.publishDps()/querySupportByDPCode() API.\n- Captured the full per-direction command encoding table and all move/stop publish call sites (RN bridge, DpHelperExtendKt, panel models).\n- Documented press-and-hold start/continuous/stop semantics from PTZControlView/NewUIPTZControlView onTouchEvent (DOWN=move, UP=stop) and the RN startPtz*/stopPtz bridge; noted move path is gated to the 4 cardinal directions.\n\nMotor verdict: SCD921/SCD923 most likely has NO motorized PTZ (MEDIUM). The captured device cloud DP schema lists only sound/motion/temperature/floodlight/ipc_flip DPs and no ptz_control, so querySupportByDPCode("ptz_control") is false and the pad is hidden. The PTZ assets in the APK are generic Tuya skin, not device-specific evidence. Confidence is MEDIUM because it rests on absence in one schema capture.\n\nNo secrets/PII in the doc; just secret-scan passes.
<!-- SECTION:FINAL_SUMMARY:END -->
