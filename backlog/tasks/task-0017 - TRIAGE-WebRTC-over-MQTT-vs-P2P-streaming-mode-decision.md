---
id: TASK-0017
title: 'TRIAGE: WebRTC-over-MQTT vs P2P streaming-mode decision'
status: To Do
assignee: []
created_date: '2026-06-24 22:46'
updated_date: '2026-06-25 00:23'
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
- [ ] #1 re/streaming_mode.md states whether the app prefers WebRTC-over-MQTT, Tuya P2P, or both, with evidence+confidence and the MQTT signaling topic shape if present; cross-ref seydx/tuya-ipc-terminal
- [ ] #2 A recommendation for which transport Wave 2 should implement first, with the cheaper path called out
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from TASK-0001/0003/0004: TRIAGE LEANS WebRTC-over-MQTT. Native libThingP2PSDK.so carries SDP/ICE/DTLS-SRTP(mbedTLS)+MQTT-signaling(connect_v2, send302) AND legacy PPCS. JS: TUNIMQTTManager (createMQTTClient/publish/subscribe/onMessage) + TUNIIPCCameraManager.connect/createMediaDevice; PlayNetKit has 73 ice refs. Java: IThingP2P.resendOffer + IMqttServiceUtils.send302MessageThroughMqtt/registerMqtt302. Recommend webrtc-rs + MQTT signaling client over PPCS AV-framing reconstruction. Confirm which the SCD921 firmware negotiates via the connect_v2 skill field. Public ref: tuya/tuya-rtc-camera-sdk-android (WebRTC+MQTT, <300ms).
<!-- SECTION:NOTES:END -->
