---
id: TASK-0034
title: >-
  Wave-2: WebRTC-over-MQTT signaling client + live A/V stream (webrtc-rs +
  rumqttc)
status: To Do
assignee: []
created_date: '2026-06-25 07:14'
updated_date: '2026-06-25 07:34'
labels:
  - phase3
  - rust
  - wave2
  - stream
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-2 core deliverable (the actual video). Per re/streaming_mode.md + re/p2p_triage.md: implement the Tuya WebRTC path — an MQTT signaling client (rumqttc) exchanging the 302 offer/answer/candidate envelope, a webrtc-rs PeerConnection (DTLS-SRTP), H.264 (openh264) + Opus/audiopus decode, rendering a frame. The signaling/MQTT/webrtc scaffolding + unit tests are buildable STATIC-ONLY now; the LIVE stream is gated on (a) auth working (blocked — see the Wave-2 auth decision task) to fetch the device p2pId/p2pConfig, and (b) the real SCD921 returning p2pType=4. Keep the #[ignore] live-gold-oracle discipline.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 MQTT 302 signaling envelope + webrtc-rs session scaffolding implemented with unit tests (offline); the live path is #[ignore]d, honestly gated on auth + a live device
- [ ] #2 Honest status: builds + unit-tests pass static-only; cannot stream until auth unblocks (Wave-2 auth decision) and a real device is present
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
--- SPEC POINTERS from TASK-0010 (re/webrtc_session.md) ---
PRIMARY SPEC: re/webrtc_session.md - the implementable WebRTC-over-MQTT session spec. Committed Ghidra C: re/ghidra/imm_p2p_rtc_connect_v2.c, _sdp_encode.c, _set/get_aes_key.c, _recv_frame.c, _send_frame.c, _set_signaling.c, ThingSmartP2PSDK_SendMessageThroughMQTT.c.

IMPLEMENT (Tuya-custom, webrtc-rs does NOT cover):
1. MQTT 302 signaling client (rumqttc): envelope {header{type:offer|answer|candidate|disconnect, from, to, sessionid, trace_id}, msg:<sdp|candidate>, token}. Carrier = device Tuya MQTT, message code 302, payload AES-encrypted with device localKey at protocol ver pv. trace_id = session correlation key. (spec re/webrtc_session.md s2)
2. SDP: webrtc-rs builds the standard v=0/o=/m=audio(PCMU)/m=video(H264) sections + ICE/DTLS-SRTP. BUT add the Tuya-custom 3rd section: m=application with `a=aes-key:<hex>` + an 'imm' rtpmap. The media AES key is CARRIED IN THE SDP (parse from peer answer's application section; emit your own in the offer). (spec s3c)
3. recv_frame -> imm_p2p_rtc_frame_t: off 0x00 payload, 0x0c length, 0x10 pts, 0x20 type{0=audio,1=video,2=keyframe}. webrtc-rs gives you RTP on the SRTP tracks - depacketize H264 NAL (std) yourself; the native imm_p2p_h264_packetize_* is the send-side mirror. (spec s4)
4. Codecs: H264 (openh264 crate) + PCMU/G711 + Opus (audiopus). (spec s4d)

RUNTIME-GATED INPUTS to make INJECTABLE (none in APK; all from ONE authed device-list/CameraInfoBean call on the user's account):
 - token (per-session signaling token)
 - p2pId  -> connect_v2 remote_id
 - dev_id (Tuya devId)
 - skill  (capability JSON)
 - P2pConfig.p2pKey  (SECRET)
 - P2pConfig.ices    (STUN/TURN servers - NOT static)
 - P2pConfig.session (SECRET), tcpRelay/udpRelay
 - device localKey   (302 payload AES) + pv
 - client MINTS its own trace_id + connect_session (33-byte rand)

RESIDUAL (live-only, gate the #[ignore] live test): the actual a=aes-key value + negotiated SDP bytes come only from a capture of the offer/answer 302; and confirm SCD921 returns p2pType=4 (else PPCS fallback). The offline scaffolding (302 envelope codec + webrtc-rs session + decoders + unit tests) is fully buildable now from re/webrtc_session.md.
<!-- SECTION:NOTES:END -->
