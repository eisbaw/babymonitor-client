---
id: TASK-0068
title: >-
  Capture live MQTT 302 signaling + media transport via emulator Frida hooks
  (extend cap1)
status: To Do
assignee: []
created_date: '2026-06-26 15:22'
updated_date: '2026-06-26 17:38'
labels:
  - stream
  - capture
  - wave2
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First live frame is blocked NOT by auth (solved) but by never having observed the WebRTC-over-MQTT signaling or the media bytes — cap1 captured HTTPS/atop REST only. The decrypted live rtc.config (secrets/cap1_rtc_decrypted/) shows transmission=kcp, p2pType=4, supportsWebrtc=true, and the cloud mints session.{aesKey,icePassword,iceUfrag} directly (Tuya SRTP-like keying, maybe NOT standard DTLS-SRTP). This forks the media engine (webrtc-rs vs native KCP/moto port from libThingP2PSDK.so) and is the dominant remaining unknown — only a media capture settles it. cap1 creds are also expired (~10h TTL), so a fresh capture is required regardless. Separate from TASK-0042 (blocked our-Rust-client login); this is the emulator-MITM route via ../android_emulator_re.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 In-app live view initiated against the real online SCD921 on the emulator; session captured
- [ ] #2 Plaintext 302 offer/answer/candidate sequence + exact MQTT publish/subscribe topic string(s) recorded to secrets/ only
- [ ] #3 Media transport CLASSIFIED: DTLS-SRTP handshake OR KCP/moto framing (UDP media pcap) — settles the webrtc-rs vs native-KCP fork for TASK-0037
- [ ] #4 pv->variant binding + outer 302 framing pinned from a real 302 blob (resolves MqttEnvelopePending)
- [ ] #5 Findings (topic shape, framing, transport verdict, SDP shape) written to re/webrtc_session.md; no secret values in tracked files; secret-scan green
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PARTIALLY DONE via cap3 (deep Frida agent at Tuya P2P signaling seams): the MQTT-302 signaling is captured PLAINTEXT (cap3/signaling_plaintext.jsonl: 1 offer + 9 candidates + 1 answer; full SDP, ICE creds, per-session media key a=aes-key, STUN/TURN/tcp_token). 302 envelope = AES-ECB(deviceLocalKey). REMAINING from this task: (a) the media UDP RTP bytes (still off-proxy, native) via UDP pcap/recvfrom hook, and (b) the media AES MODE — fastest via a Frida hook on the AES primitive filtered by the SDP key (its out = decrypted frame; cap3/DECRYPT.md §3). Signaling topic/format ACs effectively met; media-bytes AC remains.
<!-- SECTION:NOTES:END -->
