---
id: TASK-0010
title: 'SPIKE: libThingP2PSDK session + AV framing feasibility'
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 03:08'
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
FORWARD from TASK-0009 (re/p2p_triage.md) - PRIORITIZED next-dive targets (symbols, no offsets yet - the .dynsym addresses are the r2/Ghidra entry points):

PRIORITY 1 (WebRTC, the CHOSEN transport per re/streaming_mode.md):
1. ThingSmartP2PSDK::thing_p2p_rtc_connect_v2 (imm_p2p_rtc_connect_v2) - session-init; how skill/token/connect_session/lan_mode are consumed + how the SDP offer is kicked off. Demangled sig: (char* remote_id, char* dev_id, char* skill, uint, char* token, uint, char* trace_id, int timeout_ms, int lan_mode).
2. imm_p2p_rtc_sdp_encode/_decode/_negotiate + _add_*_codec - offer/answer construction, codec list (OpenH264 H264 + 'imm' codec), trickle-ICE.
3. imm_p2p_rtc_sdp_get_aes_key/_set_aes_key + imm_p2p_hmac_sha1/aes_decrypt_with_raw_key - MEDIA/SESSION KEY DERIVATION (review-gate F3's expected hard blocker; AES key appears CARRIED IN SDP - verify if statically recoverable or needs live DTLS pcap). THIS is the prime 'which bytes a pcap unblocks' candidate for AC#2/#3.
4. ThingSmartP2PSDK::SendMessageThroughMQTT + set_signaling + the 302 {header,msg,token} envelope - pin byte shape vs P2PMQTTServiceManager.handleMqttAnswer + seydx/tuya-ipc-terminal.
5. imm_p2p_rtc_frame_t + thing_p2p_rtc_recv_frame + imm_p2p_rtc_frame_list_* (ARQ) + imm_p2p_h264_packetize_nal_fua/_stapa - AV frame container + RTP/H264 framing the Rust depacketizer reads after SRTP.
6. ThingSmartP2PSDK::Initialize 3-callback contract (on_msg/on_https/on_state) + enums rtc_state/rtc_active_state_e/rtc_connection_mode_e - the session state machine.

PRIORITY 2 (PPCS fallback - LOW prio, gate behind a LIVE p2pType==2; statically only the demo bean shows p2pType=4):
7. ThingCameraNative_connect4ppcs + the inner_p2p_type selector in libThingCameraSDK.so (PPCS_Write vs thing_p2p_rtc_send_data) - the runtime tie-break site.
8. PPCS_Write/PPCS_Read call sites + RTP de-framer ('invalid RTP packet','Cannot write a 0 size RTP packet.') - proprietary AV framing over IOTC, templated by WyzeCam tutk.py.

Structs/enums to recover: imm_p2p_rtc_frame_t, imm_p2p_rtc_options, imm_p2p_rtc_session_info_t, rtc_state, rtc_active_state_e, rtc_connection_mode_e.
NOTE: since WebRTC won, the PPCS AV-framing reconstruction is now LOW priority; the verdict (AC#2) should likely steer Wave-2 to WebRTC-over-MQTT and name the SDP-carried AES key / DTLS handshake as the pcap-unblockable bytes.
<!-- SECTION:NOTES:END -->
