---
id: TASK-0037
title: >-
  Wave-2: webrtc-rs media engine wiring + 302-payload localKey-AES mode + MQTT
  TLS (live stream completion)
status: To Do
assignee: []
created_date: '2026-06-25 07:59'
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
