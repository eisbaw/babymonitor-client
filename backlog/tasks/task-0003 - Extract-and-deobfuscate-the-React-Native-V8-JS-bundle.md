---
id: TASK-0003
title: Extract and deobfuscate the React Native / V8 JS bundle
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:35'
updated_date: '2026-06-24 23:42'
labels:
  - phase2
  - re
  - wave1
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY: app runs React Native on V8; assets (kit_js, mini_app_js, thing_uni_plugins=101 plugins, mini_app_js) hold much of the auth/pairing orchestration in far-more-readable JS than native/Java. Delegate to Explore subagent (large output).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All JS bundles located under assets/ extracted to decompiled/js (beautified); re/js_bundle_map.md indexes the bundles, the Tuya RN bridge module names, and where login/pairing/streaming flows live
- [x] #2 Notes whether bundle is plain JS, Hermes bytecode, or V8 cache; if bytecode, records the tool needed to decompile and files a follow-up task
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. unzip assets/{kit_js,mini_app_js,thing_uni_plugins} -> decompiled/js.
2. Determine format: head bytes (plain JS vs Hermes HBC magic 0x1F1903C1 vs V8 cache). file/xxd.
3. Beautify plain-JS kit_js bundles (js-beautify if available, else note minified).
4. Index bundles + Tuya RN bridge module names (TUNI* managers) + locate login/pairing/streaming flows via rg over IPCKit/P2PKit/PlayNetKit/Activation.
5. Write re/js_bundle_map.md; secret-scan must stay green (do NOT commit raw bundle content with secrets).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Extracted assets to decompiled/js (gitignored): kit_js (12 plain-JS UMD bundles), mini_app_js (8), thing_uni_plugins (101 TUNI bridge manifests, 74 non-trivial). re/scripts/reflow_js.py beautifies kit_js/mini_app_js to *.pretty.
FORMAT VERDICT: plain minified JS, NOT Hermes (no 0x1F1903C1) / NOT V8 snapshot -> NO bytecode follow-up task filed (none needed).
Bridge: JS calls native via window.gzlServiceNativeBridge.serviceInvoke; each native module described by a TUNI*Manager.json (method->param schema) = the API contract.
KEY surfaces: TUNIIPCCameraManager.connect/createMediaDevice/talk/playback (live view); TUNIP2pFileManager (P2P stream); TUNIMQTTManager (signaling); TUNIAPIRequestManager.apiRequestByAtop (mobile-app cloud-sign path, F1) + apiRequestByHighwayRestful; TUNIActivationManager.startDeviceActivate (pairing model: ssid/token/pid/hgwBean/localKey); TUNILoginManager (ticket-based, real auth is NATIVE).
GOTCHA: cloud hostnames/endpoints are NOT in JS (native thing_domains_v1 + login response, F5); login credential handling is native (-> task 7). No secret VALUE literals in bundles (only field NAMES); secret-scan green.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Mapped the React Native (V8) JS layer into re/js_bundle_map.md. Verdict: assets kit_js (12)/mini_app_js (8) are plain minified JavaScript (NOT Hermes bytecode / NOT a V8 snapshot), so no bytecode-decompiler follow-up is needed; thing_uni_plugins is 101 JSON bridge-API descriptor manifests.

What: documented the gzlServiceNativeBridge JS->native bridge mechanism and the full TUNI*Manager API contract — streaming (TUNIIPCCameraManager connect/createMediaDevice/talk/playback, 47 methods), P2P transport (TUNIP2pFileManager), MQTT signaling (TUNIMQTTManager), the Tuya atop mobile-app cloud-API+sign path (apiRequestByAtop, ties to review-gate F1), the device-pairing model (startDeviceActivate: ssid/token/pid/hgwBean/localKey), and the ticket-based login (real credential handling is native, deferred to task 7).

Tooling: added re/scripts/reflow_js.py (string-aware beautifier, no node dependency) producing *.pretty siblings. Security: no secret VALUE literals in bundles (only schema field names like password/localKey/sk); secret-scan + check-evidence green. Raw bundle content stays in the gitignored decompiled/js/.
<!-- SECTION:FINAL_SUMMARY:END -->
