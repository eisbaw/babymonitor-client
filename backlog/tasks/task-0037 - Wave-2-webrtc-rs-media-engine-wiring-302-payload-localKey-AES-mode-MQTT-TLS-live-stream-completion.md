---
id: TASK-0037
title: >-
  Wave-2: webrtc-rs media engine wiring + 302-payload localKey-AES mode + MQTT
  TLS (live stream completion)
status: In Progress
assignee:
  - '@architect'
created_date: '2026-06-25 07:59'
updated_date: '2026-06-25 08:08'
labels:
  - phase3
  - rust
  - wave2
  - stream
  - followup
dependencies:
  - TASK-0034
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from TASK-0034 (the Tuya-custom protocol layer landed offline-complete). Wire the live media + the un-pinned crypto:
1. webrtc-rs PeerConnection engine implementing babymonitor_core::stream::session::WebRtcEngine (create_offer/set_answer/add_remote_candidate/recv_frame): standard SDP + ICE (from injected P2pConfig.ices) + DTLS-SRTP + SRTP, H.264 (openh264) + PCMU/Opus de-packetize -> stream::frame::Frame. Deliberately deferred in TASK-0034 to protect the just assert-offline gate from webrtc-rs's large dep tree.
2. 302-payload localKey-AES: pin the exact AES mode/IV/padding (currently stream::mqtt_crypto::{encrypt,decrypt}_302_payload return Error::MqttCryptoPending). NOT statically pinned: Tuya MQTT AESUtil.ALGO is set at runtime (setALGO(i)); the obfuscated Cipher.getInstance arg is jadx-mangled (Cipher.il). Needs a port of com/thingclips/sdk/mqtt/ crypto OR one live 302 capture.
3. MQTT TLS: re-enable rumqttc use-rustls feature for the real (TLS) Tuya broker; stream::transport::RumqttcTransport currently builds with default-features=false (no TLS) to keep the offline gate green. Pin the exact Tuya 302 topic string + the Tuya MQTT protocol-version binary envelope framing (also unpinned).
Gated on the auth decision (TASK-0035) + a live SCD921 returning p2pType=4. The #[ignore]d live test babymonitor-cli/tests/live_e2e.rs::live_webrtc_session_renders_first_frame asserts the honest stream-pending state today; replace its fakes with the real engine/transport when this lands.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RE-SCOPED per TASK-0034 cycle-22 review: the localKey-AES mode IS statically pinned (AES-128/ECB/PKCS5Padding, key=localKey.getBytes() 16 ASCII bytes, NO IV; output hex via byte2hex or base64/raw by pv variant — evidence: decompiled/jadx/sources/com/thingclips/sdk/mqtt/qpqddqd.java setALGO("AES")/encrypt|encryptWithBase64|encryptWithBytes + com/thingclips/smart/android/common/utils/AESUtil.java getInstance(this.ALGO)/encrypt). FIRST deliverable of this task = correct the false 'not statically pinnable' claim (lib.rs MqttCryptoPending msg, stream/mqtt_crypto.rs docs, re/webrtc_session.md §2a/§7) AND implement the AES primitive with a known-answer test; the gate then narrows to ONLY the pv->variant binding for code 302 + the outer Tuya MQTT envelope framing (genuine live-capture residual). webrtc-rs media engine + TLS remain the larger live-gated pieces.
<!-- SECTION:NOTES:END -->
