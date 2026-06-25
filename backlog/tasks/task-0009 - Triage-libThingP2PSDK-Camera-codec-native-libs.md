---
id: TASK-0009
title: Triage libThingP2PSDK/Camera/codec native libs
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 00:23'
labels:
  - phase3
  - re
  - wave1
  - p2p
dependencies:
  - TASK-0004
  - TASK-0011
  - TASK-0017
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 3): before deep diving, map the P2P/camera/codec libs - exported API surface, key strings, magic constants, and cross-reference public Tuya-P2P RE (tinytuya, tuya P2P projects, IOTC/PPCS lineage). Delegate to Explore subagent with radare2/ghidra-headless.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/p2p_triage.md: exported functions of libThingP2PSDK/CameraSDK, candidate session-init + send/recv entry points, protocol magic strings, and a mapping to any known public Tuya/IOTC P2P documentation with confidence
- [ ] #2 Lists the concrete next-dive targets (function offsets) for the deep spike task
- [ ] #3 JS-FIRST: pass the JS bundle (bridge method names, P2P channel orchestration, signaling) BEFORE native decompilation; only dive into .so for what JS does not reveal
- [ ] #4 Cross-reference named public sources: tuya/tuya-iotos-android-iot-p2p-demo (channel API surface) and WyzeCam tutk.py (IOTC/TUTK AV framing) — raises confidence toward 'confirmed'
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from TASK-0004: Symbol dumps already saved under re/symbols/ (libThingP2PSDK/Camera/VideoCodec/AudioEngine/SmartLink/P2PFileTrans .dynsym.txt + .dynamic.txt). KEY: libThingP2PSDK.so = WebRTC-over-MQTT (SDP a=ice-ufrag/rtcp-mux, STUN/TURN, DTLS-SRTP via STATICALLY-BUNDLED mbedTLS /Users/Pan/GitHub/mbedtls; MQTT signaling create signaling mqtt worker thread + SendMessageThroughMqtt; connect_v2 cmd with remote_id/dev_id/skill/token/lan_mode) AND legacy PPCS (ERROR_PPCS_* in CameraSDK). VideoCodec=OpenH264(Cisco). AudioEngine=Google WebRTC audio_processing (AEC/AGC/NS/VAD), build path leak ipc-tymedia-sdk. P2P version 3.10.0, Camera 1.2.x. P2P SDK does NOT link app OpenSSL (own mbedTLS).
<!-- SECTION:NOTES:END -->
