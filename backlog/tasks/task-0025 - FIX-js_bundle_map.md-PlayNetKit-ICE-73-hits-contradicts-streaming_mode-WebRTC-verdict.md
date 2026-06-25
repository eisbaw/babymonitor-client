---
id: TASK-0025
title: >-
  FIX: js_bundle_map.md PlayNetKit 'ICE 73 hits' contradicts streaming_mode
  WebRTC verdict
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 02:38'
updated_date: '2026-06-25 02:56'
labels:
  - review-followup
  - wave1
  - docs
  - grounding
dependencies:
  - TASK-0003
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AUDIT FINDING F1 (TASK-0006), severity P0/blocking. re/js_bundle_map.md ~:45 describes miniapp_PlayNetKit.js as 'streaming play-mode + ICE (73 ice hits)' inside a confidence:confirmed section, implying WebRTC ICE primitives live in the JS. re/streaming_mode.md ~:54-62 (TASK-0017, later) explicitly CORRECTS this as a false positive and WINS. Re-verified for the audit: rg -io '[a-z]*ice[a-z]*' decompiled/js/assets/kit_js/miniapp_PlayNetKit.js.pretty yields only onScanDeviceInfo/slice/connectMatterDevice substrings (no webrtc ICE); rg -lc 'RTCPeerConnection|createOffer|ice-ufrag' decompiled/js/assets/kit_js/*.pretty returns ZERO. The real WebRTC SDP/ICE/DTLS-SRTP machinery is native (re/symbols/libThingP2PSDK.dynsym.txt), surfaced in Java by P2PMQTTServiceManager.send302MessageThroughMqtt. FIX: (1) correct the PlayNetKit row to drop the '73 ice hits' claim and add a forward-pointer to streaming_mode.md's FP-correction; (2) fold in finding F2 - PlayNetKit role text 'streaming play-mode' overstates capability (the JS bridge only names connect/createMediaDevice with {deviceId}-only params per TUNIIPCCameraManager.json). NOTE: this is a CONTENT defect the SHAPE-only lint cannot catch (structural root cause = open TASK-0021). VERIFY: re-grep shows the corrected text; just check-evidence + just secret-scan GREEN. Do NOT edit any other doc.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 js_bundle_map.md PlayNetKit row corrected: '73 ice hits' claim dropped and forward-pointed to streaming_mode.md FP-correction; F2 folded in (role text 'streaming play-mode' softened - JS bridge only names connect/createMediaDevice with {deviceId}-only params)
- [x] #2 re-grep confirms corrected text (no surviving 'ICE 73 hits' / WebRTC-in-JS implication); just check-evidence + just secret-scan GREEN; no other re/*.md doc edited
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Re-verify PlayNetKit ice-substring grep + zero-WebRTC grep (DONE).
2. Correct js_bundle_map.md PlayNetKit row: drop 73-ice claim, soften role to bridge connect/createMediaDevice {deviceId}-only, add native+streaming_mode forward-pointer with grep command.
3. Keep ## kit_js section confirmed with >=2 non-.md cites (libThingP2PSDK.so + P2PMQTTServiceManager.java) or it already has bundle .js cites.
4. Run check-evidence + secret-scan GREEN; confirm no other re/*.md edited for this AC.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GOTCHA: the false claim sat in the `## kit_js bundles (confidence: confirmed)` section. The shape-only check-evidence lint could not catch it (TASK-0021). Fix drops the "73 ice hits" claim from the PlayNetKit table row + adds a confirmed CORRECTION block with >=2 non-.md sources (JS .pretty greps AND libThingP2PSDK.so + P2PMQTTServiceManager.java native/Java WebRTC evidence). F2 folded in: role text softened to "play-mode UI/orchestration only; transport-agnostic" and the correction states the JS bridge only names connect/createMediaDevice with {deviceId}-only params.
GOTCHA: the new block uses libThingP2PSDK.so (matches lib*.so) + a .java path as the two confirmed sources; re/symbols/*.dynsym.txt is .txt and does NOT count as a citation token under check-evidence, so it is decoration not a source.
Re-verified on the live decompile tree: rg -lc RTCPeerConnection|createOffer|ice-ufrag over kit_js/*.pretty = ZERO (exit 1); rg -io for ice-substrings yields only slice/connectMatterDevice/onScanDeviceInfo etc.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Corrected the stale PlayNetKit "ICE (73 ice hits)" claim in re/js_bundle_map.md (audit F1, P0).

What changed:
- PlayNetKit table row no longer claims ICE/WebRTC-in-JS; role softened to "play-mode UI/orchestration only; transport-agnostic" (folds in F2: JS bridge only names connect/createMediaDevice with {deviceId}-only params).
- Added a confidence:confirmed CORRECTION block (>=2 non-.md sources: the two JS greps over decompiled/js/assets/kit_js/*.pretty AND native+Java WebRTC evidence in libThingP2PSDK.so + P2PMQTTServiceManager.send302MessageThroughMqtt) documenting the ice substring false-positive and forward-pointing to re/streaming_mode.md.
- The reproducing grep commands are embedded in the doc.

Verification: re-grep confirms zero WebRTC primitives in kit_js; check-evidence + secret-scan + e2e GREEN. No other re/*.md doc edited.
<!-- SECTION:FINAL_SUMMARY:END -->
