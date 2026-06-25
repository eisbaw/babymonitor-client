---
id: TASK-0025
title: >-
  FIX: js_bundle_map.md PlayNetKit 'ICE 73 hits' contradicts streaming_mode
  WebRTC verdict
status: To Do
assignee: []
created_date: '2026-06-25 02:38'
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
