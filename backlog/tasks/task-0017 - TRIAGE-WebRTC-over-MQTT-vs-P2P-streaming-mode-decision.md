---
id: TASK-0017
title: 'TRIAGE: WebRTC-over-MQTT vs P2P streaming-mode decision'
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:46'
updated_date: '2026-06-26 15:20'
labels:
  - phase3
  - re
  - wave1
  - stream
  - triage
dependencies:
  - TASK-0003
  - TASK-0004
  - TASK-0011
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md, re/review_gate_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology. Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) + confidence. NEVER write a recovered secret/token/real account ID into a task field, re/*.md, or your returned summary — reference its secrets/ location only. File new backlog tasks for tangents.

WHY (re/review_gate_findings.md F2): modern Tuya cameras can stream via WebRTC signaled over MQTT + cloud (seydx/tuya-ipc-terminal), bypassing libThingP2PSDK entirely - potentially far cheaper than static native P2P RE. Decide which transport(s) the SCD921 actually uses BEFORE deep P2P effort. JS-FIRST: assets/mini_app_js, thing_uni_plugins, kit_js; search webrtc/sdp/ice/stun/mqtt/signaling strings; then confirm in native if needed. Delegate to Explore subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 re/streaming_mode.md states whether the app prefers WebRTC-over-MQTT, Tuya P2P, or both, with evidence+confidence and the MQTT signaling topic shape if present; cross-ref seydx/tuya-ipc-terminal
- [x] #2 A recommendation for which transport Wave 2 should implement first, with the cheaper path called out
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
JS-first: grep kit_js/mini_app_js/thing_uni_plugins for webrtc/sdp/ice/mqtt/connect_v2/skill/lan_mode -> establish JS layer is transport-agnostic (connect(deviceId) only). Corroborate in native libThingP2PSDK.so strings (connect_v2/skill/lan_mode, sdp/candidate signaling types, SendMessageThroughMQTT) + libThingCameraSDK.so (PPCS). Decode capability negotiation from ThingCameraConstants.P2PType enum + CameraInfoBean sample (p2pType 2=PPCS/4=THING-WebRTC, skill.webrtc). Pin MQTT 302 signaling shape from P2PMQTTServiceManager (send302MessageThroughMqtt/handleMqttAnswer header.type). Cross-check seydx/tuya-ipc-terminal + tuya/webrtc-demo-go. Write re/streaming_mode.md with per-claim confidence+citation; recommend WebRTC-over-MQTT first. Gates: check-evidence/secret-scan/e2e green. Feed forward to 0009/0010/0016.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from TASK-0001/0003/0004: TRIAGE LEANS WebRTC-over-MQTT. Native libThingP2PSDK.so carries SDP/ICE/DTLS-SRTP(mbedTLS)+MQTT-signaling(connect_v2, send302) AND legacy PPCS. JS: TUNIMQTTManager (createMQTTClient/publish/subscribe/onMessage) + TUNIIPCCameraManager.connect/createMediaDevice; PlayNetKit has 73 ice refs. Java: IThingP2P.resendOffer + IMqttServiceUtils.send302MessageThroughMqtt/registerMqtt302. Recommend webrtc-rs + MQTT signaling client over PPCS AV-framing reconstruction. Confirm which the SCD921 firmware negotiates via the connect_v2 skill field. Public ref: tuya/tuya-rtc-camera-sdk-android (WebRTC+MQTT, <300ms).

GOTCHAS / corrections from this triage:
- The forward-carried 'PlayNetKit has 73 ice refs' was a FALSE POSITIVE: 'ice' = substrings of onScanDeviceInfo/connectMatterDevice/slice; 'turn' = the keyword 'return' in minified code. The JS kit layer contains ZERO real WebRTC/SDP/ICE primitives. JS connect() only passes {deviceId}; the transport is decided entirely in native. Do NOT treat JS as evidence of transport.
- Capability negotiation is DATA-DRIVEN per device, not firmware-version-gated in the app. ThingCameraConstants.P2PType enum: P2P_TYPE_PPCS(2), P2P_TYPE_THING(4=WebRTC). Device cloud record carries p2pType + a skill JSON with a 'webrtc' bitmask. connect_v2 passes skill to native.
- MQTT signaling = Tuya device channel msg code 302 (P2PMQTTServiceManager.publish(devId,pv,localKey,json,302) cloud / lan302Publish LAN). Envelope: {header:{type:offer|answer|candidate,from,to,sessionid,trace_id}, msg, token}. 302 payload AES-encrypted with device localKey at protocol version pv.
- Do NOT conflate the P2P 'skill' (capability bitmask) with the VAS 'skill' (security service subscription, com/thingclips/security/vas/skill) - different concept, same word.
- The populated CameraInfoBean in qpppdqb.java:423 is a hard-coded Tuya DEMO record (demo password/p2pId/device-id 6c3a4212...). NOT a real user secret; referenced by path only, never copied. secret-scan green.
- THE ONE HYPOTHESIS THAT CAN BE WRONG: whether the real SCD921 firmware returns p2pType=4 (WebRTC) vs 2 (PPCS). Statically we only see the SDK demo bean. Needs one live obtainCameraConfig/device-list call. If it returns 2, the recommendation flips to PPCS.

Cycle-4 review: both GO. Orchestrator fixed P1 (mis-attributed nin/nout topic citation -> now attributed to public ref + corrected) and 2 P2 prose overstatements (layer-independence framing, webrtc 'bitmask' softened). Gate-coverage gap (shape-not-content) -> TASK-0021.

SUPERSEDE (2026-06-26, live-confirmed via TASK-0065): the one flippable hypothesis in this triage (does the real SCD921 advertise p2pType=4 WebRTC vs 2 PPCS) is RESOLVED. Live device discovery (m.life.my.group.device.list v2.2) returned skills.p2pType=4 for the genuine device (Philips Avent Baby Monitor, productId kzm54lhabeeucq5a). Transport = Tuya WebRTC-over-MQTT, CONFIRMED on real hardware. The WebRTC-over-MQTT-first recommendation stands; the needs-one-live-obtainCameraConfig gap is closed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
VERDICT: SCD921 stack PREFERS Tuya WebRTC signaled over MQTT (msg code 302) + a parallel LAN channel; legacy PPCS (TUTK/IOTC) is a fallback. Choice is data-driven per device from cloud p2pType (2=PPCS, 4=THING/WebRTC, ThingCameraConstants.P2PType) + a skill JSON 'webrtc' bitmask; not firmware-version-gated in app. Deliverable re/streaming_mode.md. RECOMMENDATION: Wave-2 implements WebRTC-over-MQTT FIRST (cheaper: JSON signaling over existing MQTT + standard webrtc-rs SDP/ICE/DTLS-SRTP, vs reconstructing proprietary PPCS AV framing). Crates: webrtc(-rs) + rumqttc/paho-mqtt + openh264/opus; 302 payload AES-localKey at proto ver pv (port from com/thingclips/sdk/mqtt). Evidence: native libThingP2PSDK.so (connect_v2/skill/lan_mode, sdp/candidate signaling, SendMessageThroughMQTT) + Java IThingP2P.resendOffer/setSignaling + P2PMQTTServiceManager.send302MessageThroughMqtt/handleMqttAnswer; cross-checked seydx/tuya-ipc-terminal (302/header.type/offer-answer-candidate match) + tuya/webrtc-demo-go. Gates: check-evidence OK, secret-scan OK, e2e OK. LIVE-DEVICE GAP: whether THIS firmware advertises webrtc (p2pType 4 vs 2) needs one live obtainCameraConfig call - the only claim that can flip the recommendation. Corrected the JS '73 ice refs' note (false positive).
<!-- SECTION:FINAL_SUMMARY:END -->
