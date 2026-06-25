---
id: TASK-0010
title: 'SPIKE: libThingP2PSDK session + AV framing feasibility'
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 01:04'
labels:
  - phase4
  - re
  - wave1
  - p2p
  - spike
  - risk
dependencies:
  - TASK-0009
  - TASK-0017
  - TASK-0019
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

RISK SPIKE (skill phase 4). Deepest static dive: reconstruct P2P session establishment (signaling, NAT-traversal/broker vs LAN), the AV stream framing (headers, codec markers for H.264/H.265 + Opus/SBC), and any per-session crypto. Ghidra decompilation of libThingP2PSDK + cross-ref public work. Delegate to general-purpose subagent. Time-box; depth over breadth on the session+framing path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/p2p_protocol.md documents session setup + AV framing to the depth statically achievable, every claim with confidence+evidence (lib@offset)
- [ ] #2 MANDATORY verdict, exactly one of {recoverable-statically | partially | needs-live-capture}, with the precise evidence that a single pcap (if ever available) would unblock — this verdict drives Wave-2 planning
- [ ] #3 TIME-BOXED probe (depth on session+framing path only). The verdict must also CHOOSE which transport Wave 2 pursues (P2P vs the WebRTC path from task 17), and name SPECIFICALLY which bytes a single pcap would unblock (e.g. handshake nonce / key-agreement)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from TASK-0001/0004: Strong static evidence the SCD921 stream is WebRTC-over-MQTT (review-gate F2 CONFIRMED at lib level). Java side: com/thingclips/smart/p2p/api/IThingP2P.java (connect/recvData/resendOffer=SDP) + utils/IMqttServiceUtils.java (send302MessageThroughMqtt, registerMqtt302 - "302" is Tuya camera signaling code over MQTT). Native libThingP2PSDK has full SDP/ICE/STUN/TURN/DTLS-SRTP + MQTT signaling strings. PPCS legacy path also present. connect_v2 skill field likely encodes capability negotiation. Likely task-10 verdict: partially (framing recoverable; per-session DTLS key exchange needs live pcap). Public ref: tuya/tuya-rtc-camera-sdk-android.

Forward-carried from TASK-0017 (streaming triage): if WebRTC is the live path (likely - p2pType=4 default, 302 MQTT signaling confirmed in libThingP2PSDK.so + Java P2PMQTTServiceManager, matches seydx/tuya-ipc-terminal), the PPCS AV-framing reconstruction this spike targets is LOWER priority. Recommend gating this spike behind a live check: only dive into PPCS framing if the real SCD921 device record returns p2pType=2. Otherwise Wave-2 should spike WebRTC-over-MQTT (webrtc-rs + rumqttc) instead. See re/streaming_mode.md.
<!-- SECTION:NOTES:END -->
