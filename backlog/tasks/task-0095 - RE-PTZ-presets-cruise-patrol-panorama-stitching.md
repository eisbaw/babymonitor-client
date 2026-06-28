---
id: TASK-0095
title: 'RE PTZ presets, cruise/patrol & panorama stitching'
status: Done
assignee:
  - '@myself'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:13'
labels:
  - re
  - camera-control
  - ptz
  - native
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the higher-level PTZ automation: preset/collection points (add/modify/delete/view via IThingIPCPTZ), auto-cruise/patrol (setCruiseMode/setCruiseTiming, ipc_panel_button_cruise), and PTZ-driven panorama stitching (startStitchingPTZPanorama + native libIPCStitch.so). Static-RE the DP/native entrypoints and the stitch JNI surface into an re/ writeup. Medium priority — depends on motorized PTZ being present.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Preset-point and cruise/patrol DP/API entrypoints are documented with file:line evidence and their parameters described
- [x] #2 The panorama stitching path (RN startStitchingPTZPanorama + libIPCStitch.so JNI) is identified with confidence and unknowns noted
- [x] #3 re/ptz_presets_cruise.md writeup exists
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Static-RE per ACs: grep decompiled/jadx + decompiled/apktool; write re/ptz_presets_cruise.md with per-claim confidence + file:line evidence; verify just secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Evidence grepped under decompiled/jadx/sources and decompiled/apktool; native symbols via nm -D on decompiled/nativelibs/libIPCStitch.so (gitignored, symbol-name-anchored per project convention). Key findings: (1) preset CRUD is a HYBRID transport - add/delete/recall over device DP memory_point_set (type-multiplexed JSON 1/2/3), but rename/list over Tuya mobile cloud API thing.m.ipc.memory.point.*; a Rust client needs both. (2) memory_point_set delete fills "devId" from bean.getId() not getDevId() - a Tuya quirk, reproduce as-is. (3) Panorama is camera-side sweep + P2P album download + LOCAL native stitch (imm_pano_stitch, OpenCV-style) + cloud upload - not a single DP, lowest priority for a baby cot cam. (4) Honesty: whole PTZ surface is gated on the camera having a motorized head; SCD921 is fixed-lens, and the app is generic Tuya white-label so it ships the full PTZ UI regardless - applicability to this device is unconfirmed and only a device DP schema capture can close it. No secrets/PII written; no DP values inlined. Did not touch backlog CLI (orchestrator-managed); returned per AC reporting only.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wrote re/ptz_presets_cruise.md, a static-RE writeup of the Tuya IPC PTZ automation surface reskinned by the Philips Avent Baby Monitor+.

What it documents (all with file:line / symbol evidence + per-claim confidence):
- DP model: PTZDPModel.java:8-19 canonical codes (ptz_control, memory_point_set, ipc_preset_set, cruise_switch/mode/status/time/time_mode, motion_tracking).
- Preset/collection points: IThingIPCPTZ interface + concrete bqdbdbd impl. Exact wire payloads for add/delete/view (memory_point_set, type 1/2/3 JSON) and the cloud-API path for rename/list (thing.m.ipc.memory.point.rename v1.0 / .list v2.0). CollectionPointBean fields (mpId/pos/encryption) described.
- Cruise/patrol: setCruiseMode (full=0 / memory=1, >=2-preset guard, error -1432), setCruiseTiming (cruise_time_mode=1 + cruise_time={t_start,t_end}), enums, and the blackpanel MVP UI glue. ipc_panel_button_cruise mapped to the cruise DPs (button->DP binding noted as medium-confidence).
- Panorama stitching: RN startStitchingPTZPanorama (ICameraManager:211 / smali:27069 / ka TRCTCameraManager:18429) -> DeviceAlbumManager (queryAlbumFileIndex + P2P startDownloadAlbumFile of ipc_panorama_tmp) -> ThingIPCStitchManager -> libIPCStitch.so JNI. Full JNI export table with offsets, the C++ imm_pano_stitch engine identity (feature-match/focal/rotation/bundle-adjust, IMM lineage), and the key honesty flag that isSupportStitchingPanorama is only a storage-permission check, not a PTZ-capability gate.

Residual unknowns section lists 6 gaps (device-schema applicability, sweep trigger, StitchProc arg semantics, pos/encryption format, memory_point_set type completeness, panel-button->DP binding) each with what evidence would unblock it. A parity checklist closes the doc.

Verification: just secret-scan passes; no secrets/PII/DP values inlined (secrets referenced by secrets/ location only).
<!-- SECTION:FINAL_SUMMARY:END -->
