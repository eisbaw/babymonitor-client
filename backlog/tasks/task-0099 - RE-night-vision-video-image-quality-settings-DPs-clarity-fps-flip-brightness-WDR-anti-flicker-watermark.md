---
id: TASK-0099
title: >-
  RE night vision + video image/quality settings DPs (clarity, fps, flip,
  brightness, WDR, anti-flicker, watermark)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:55'
labels:
  - re
  - camera-control
  - dp
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the camera image/quality DP family as a group. Cover NightVisionMode (auto/ir/color/true_color/black_color, DpNightVisionMode), video clarity/resolution (getVideoClarity/setVideoClarity, DeviceAbilityBean.vedioClaritys, UHD/HD/SD/LD), FPSMode (60/45/30), CameraFlipMode (mirror/rotate), display brightness/contrast/sharpness DPs, WDR, AntiFlickerMode (50/60Hz), and watermark. Static-RE each DP code + enum mapping into one consolidated re/ writeup. Night vision is a baby-monitor essential — call it out explicitly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Night vision mode enum + DP and the clarity/resolution get/set path are documented with file:line evidence
- [x] #2 FPS, flip/mirror/rotate, brightness/contrast/sharpness, WDR, anti-flicker and watermark DP codes are tabulated with value mappings
- [x] #3 re/camera_image_settings.md writeup exists with one table mapping DP code -> values -> meaning; confidence per row
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static-RE of the Tuya camera image/quality DP family. DP code = f() in each Dp*.java (proven via BaseDpOperator.java:31 schemaMap.get(f)); enum value strings from mode/*.java. Findings: nightvision_mode enum (auto/ir_mode/color_mode/true_color_mode/black_color_mode); basic_nightvision legacy 0/1/2; clarity is native int via ThingCameraNative.getVideoClarity/setVideoClarity (ICameraP2P SD=2/HD=4/UHD=8, no LD constant); ipc_flip rotate/mirror enum; basic_anti_flicker 0/1/2 (off/50/60Hz); ipc_bright/ipc_contrast/ipc_sharp int DPs; basic_wdr + basic_osd boolean. CAVEAT: DpFPS is @Deprecated, f() returns placeholder "DpFPS" not a real DP code, so live FPS DP unresolved (FPSMode enum 0/1/2=60/45/30 still mapped). Boolean/int value-types are schema-driven (medium conf). secret-scan passes.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the camera image/quality DP family in re/camera_image_settings.md (consolidated single-table writeup with per-row confidence + file:line evidence + residual-unknowns).

What: night vision (nightvision_mode enum, basic_nightvision legacy, basic_shimmer full-colour), clarity get/set path (native getVideoClarity/setVideoClarity int SD=2/HD=4/UHD=8 + DeviceAbilityBean.vedioClaritys), ipc_flip rotate/mirror enum + legacy basic_flip, basic_anti_flicker 50/60Hz, ipc_bright/ipc_contrast/ipc_sharp, basic_wdr, basic_osd watermark, FPSMode 60/45/30.

Honesty: DpFPS is @Deprecated with placeholder DP code so the live FPS DP code is not statically resolvable; no LD clarity constant exists; boolean/int DP value-types are runtime-schema-driven (medium confidence). secret-scan OK.
<!-- SECTION:FINAL_SUMMARY:END -->
