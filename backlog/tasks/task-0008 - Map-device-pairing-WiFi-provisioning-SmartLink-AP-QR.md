---
id: TASK-0008
title: Map device pairing + WiFi provisioning (SmartLink/AP/QR)
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 00:23'
labels:
  - phase5
  - re
  - wave1
  - pairing
dependencies:
  - TASK-0001
  - TASK-0003
  - TASK-0005
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY: to add a camera the app provisions WiFi (Tuya EZ/AP SmartLink via libThingSmartLink) and binds via a pairing token from cloud; QR via ML Kit. Model the full pairing handshake. Delegate to general-purpose subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/pairing_flow.md documents: pairing-token request, EZ vs AP SmartLink packet/UDP scheme, the QR payload format, and the bind-confirm polling — evidence+confidence; honestly flags any part only in native code
- [ ] #2 Identifies which steps are mandatory for an already-paired camera (our case) vs first-time setup, so the Rust client can target the minimal path first
- [ ] #3 SCOPE NARROWING (already-paired camera): Wave-1 only confirms how an already-bound device appears in device-list and whether re-binding needs anything; defer full EZ/AP SmartLink packet + QR-payload reconstruction to a later wave as its own task
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from TASK-0001/0003/0004: Pairing code = com/thingclips/smart/activator/ (648 files). Native: libThingSmartLink.so JNI Java_com_thingclips_smart_android_device_ThingSmartLink_smartLink. JS contract = TUNIActivationManager.startDeviceActivate, full param model: scanType/token/ssid/password/cipher/gwId/uuid/mac/pid/devId + hgwBean(ip/gwId/productKey/encrypt/version/token/wf_cfg/ssid/apConfigType) + currentMeshBean(localKey/meshId/password). Also TUNIBLEPairingManager (BLE) + libbarhopper_v3.so (QR). EZ/AP/SmartLink/Matter all supported.
<!-- SECTION:NOTES:END -->
