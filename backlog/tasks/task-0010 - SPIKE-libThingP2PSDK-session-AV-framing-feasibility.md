---
id: TASK-0010
title: 'SPIKE: libThingP2PSDK session + AV framing feasibility'
status: In Progress
assignee:
  - '@reverser'
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 07:34'
labels:
  - wave2
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
- [x] #1 re/p2p_protocol.md documents session setup + AV framing to the depth statically achievable, every claim with confidence+evidence (lib@offset)
- [x] #2 MANDATORY verdict, exactly one of {recoverable-statically | partially | needs-live-capture}, with the precise evidence that a single pcap (if ever available) would unblock — this verdict drives Wave-2 planning
- [x] #3 TIME-BOXED probe (depth on session+framing path only). The verdict must also CHOOSE which transport Wave 2 pursues (P2P vs the WebRTC path from task 17), and name SPECIFICALLY which bytes a single pcap would unblock (e.g. handshake nonce / key-agreement)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
--- TASK-0010 WebRTC-PRIMARY dive (Ghidra primary, r2 cross-check) ---
DELIVERABLE: re/webrtc_session.md (the implementable WebRTC-over-MQTT session spec for TASK-0034). Committed Ghidra C under re/ghidra/imm_p2p_rtc_*.c + ThingSmartP2PSDK_*.c.

GHIDRA INVOCATION (reuse): ghidra-analyzeHeadless analysis/ghidra p2psdk -import decompiled/nativelibs/libThingP2PSDK.so -scriptPath analysis/ghidra -postScript DumpDecomp.py re/ghidra <name@0xADDR ...>. Image base 0x100000, so dynsym file-offset 0xX -> pass 0x10X (e.g. imm_p2p_rtc_connect_v2 dynsym 0x60c10 -> 0x160c10). r2 uses the raw file offset (0x60c10) with no image base; that mismatch is the only Ghidra-vs-r2 'divergence' (cosmetic, not semantic) - af @ 0x60c10 then matches.

KEY FINDINGS:
- connect_v2 (imm_p2p_rtc_connect_v2 @0x160c10) emits, byte-exact (Ghidra+r2): {"cmd":"connect_v2","args":{"remote_id","dev_id","skill","token","trace_id","timeout_ms","lan_mode","preconnect_enable":1,"connect_session"}}. timeout clamped [1000,30000]. connect_session is GENERATED INSIDE the lib (imm_p2p_misc_rand_string, 33 bytes) - NOT a caller arg. skill/token emitted UNQUOTED (%.*s).
- AES MEDIA KEY IS CARRIED IN SDP (F3 hard-blocker RESOLVED via decompile): imm_p2p_rtc_sdp_encode emits an 'imm' m=application section with `a=aes-key:<hex>`; imm_p2p_rtc_sdp_set_aes_key/_get_aes_key hex-en/decode a <=23-byte key at sdp_ctx+0x86. So a SINGLE capture of the offer/answer 302 yields the media key directly - no DTLS-exporter RE needed. THIS is the pcap-unblockable artifact (AC#2/#3).
- imm_p2p_rtc_frame_t (from send_frame/recv_frame): off0x00 payload*, 0x08 capacity(in), 0x0c length(out), 0x10 pts, 0x18 dts, 0x20 type{0=audio,1=video,2=video-keyframe}. Audio + video are separate frame lists behind one recv_frame call; payload is RTP-de-paid (past 0x48 hdr).
- 302 envelope {header{type:offer|answer|candidate|disconnect, from, to, sessionid, trace_id[, moto_id]}, msg:<sdp|candidate>, token}. trace_id is the session key (Java mP2PMqttStateMap). Required fields header/msg/token confirmed by native validators. Carrier: homeCamera.publish(devId,pv,localKey,jsonMsg,302,cb), AES-localKey. Native->Java handoff: SendMessageThroughMQTT CallStaticVoidMethod(target,json).
- Codecs: video H264 (openh264, build 1.5.0-Philips620.3); audio PCMU/G.711 at SDP layer + Opus for talk. STUN/TURN from runtime P2pConfig.ices (string IMM_P2P_ESTUNINSERVER = not static). KCP+ARQ on the imm data path (Tuya-custom).
- State enum (switch @ session+0x1a): 3=connected/active (only state that passes data); 4/0xb/0xc/0x10/0x11=errors.

VERDICT (AC#2): partially recoverable-statically -> Wave-2 pursues WebRTC-over-MQTT (confirmed). The one pcap-unblockable artifact: the per-session a=aes-key value + the negotiated offer/answer SDP bytes (codecs/SSRCs/fingerprints). Plus needs-live: whether SCD921 returns p2pType=4 (vs 2->PPCS) and whether moto_id appears in its 302 header.

IMPLEMENTABILITY (for TASK-0034): IMPLEMENTABLE given runtime-gated inputs (token, p2pId=remote_id, dev_id, skill, P2pConfig.p2pKey/ices/session, device localKey, pv - all from one authed device-list call; client mints trace_id+connect_session). webrtc-rs handles SDP/ICE/DTLS-SRTP/RTP; rumqttc handles the 302 transport; Tuya-custom = the 302 envelope + the m=application/a=aes-key/imm extension + KCP. GATES GREEN: check-evidence, secret-scan, e2e.

GOTCHA: re/ghidra/*.c are NOT counted as citation tokens by check-evidence (SOURCE_EXT excludes 'c'); cite libThingP2PSDK.so + the .java path for token-counting. recv_frame branch dumped is the audio path; video path is symmetric via imm_p2p_rtc_frame_list_*.
<!-- SECTION:NOTES:END -->
