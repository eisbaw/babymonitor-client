---
id: TASK-0034
title: >-
  Wave-2: WebRTC-over-MQTT signaling client + live A/V stream (webrtc-rs +
  rumqttc)
status: To Do
assignee: []
created_date: '2026-06-25 07:14'
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
