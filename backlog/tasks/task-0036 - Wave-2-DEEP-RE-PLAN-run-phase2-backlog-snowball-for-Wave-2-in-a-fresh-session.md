---
id: TASK-0036
title: 'Wave-2 DEEP RE-PLAN: run phase2-backlog-snowball for Wave-2 in a fresh session'
status: To Do
assignee: []
created_date: '2026-06-25 07:14'
updated_date: '2026-06-25 08:25'
labels:
  - phase-gate
  - replan
  - wave2
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Terminal re-plan for Wave-1 (snowball discipline). Wave-1 (static RE) is COMPLETE; the deep Wave-2 plan should be authored at the START of a fresh session (full context), NOT at the tail of the exhausted Wave-1 session. In that fresh session, re-invoke phase2-backlog-snowball with re/prd.md, TESTING.md, and the Wave-1 lessons: the auth dead-end (runtime-config bmp_token), the WebRTC-over-MQTT stream as the video deliverable, the deferred pairing (TASK-0008) + P2P framing (TASK-0010), and the gate nits (20/21/28/31 + the verdict-overturn guard). Sequence the Wave-2 auth DECISION first (it gates everything). Write no feature code in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 phase2-backlog-snowball run for Wave-2 in a fresh session; Wave-2 tasks dependency-ordered with the auth decision first
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0034 (stream client state for the Wave-2 re-plan):

WHAT'S BUILT (offline-complete, in babymonitor-core src/stream/): the full Tuya-custom WebRTC-over-MQTT protocol layer — 302 signaling envelope codec, SDP a=aes-key hex codec (byte-exact), connect_v2 builder (byte-exact template), SDP application-section parse/inject, imm_p2p_rtc_frame_t->Frame model + codec ids (H264/PCMU/Opus), session state machine, RandomSource+33-char connect_session minter, and a StreamCredentials injectable seam (Debug-redacted). rumqttc wired (default-features=false) behind a MqttTransport seam. 90 unit tests incl prove-the-check-bites negatives. just e2e/check-evidence/secret-scan/showcase all green; assert-offline still passes after rumqttc cached.

WHAT'S LIVE-GATED (cannot run today):
- Auth: every stream credential (token/p2pId/p2pKey/ices/session/localKey/pv) comes from ONE authed device-list/CameraInfoBean call -> blocked on TASK-0032 (bmp_token) + the Wave-2 auth DECISION (TASK-0035). The stream is downstream of auth, exactly as Wave-1 lesson #1 said.
- 302-payload localKey-AES mode: NOT statically pinnable (runtime AESUtil.ALGO + jadx-mangled Cipher.il). stream::mqtt_crypto returns MqttCryptoPending. Needs a port of com/thingclips/sdk/mqtt/ crypto OR one live 302 capture.
- Live device: must confirm the real SCD921 returns p2pType=4 (else PPCS fallback).

WHAT MEDIA-DECODE/RENDER WORK REMAINS (FILED as TASK-0037, dep on TASK-0034):
1. webrtc-rs PeerConnection engine implementing stream::session::WebRtcEngine (standard SDP/ICE/DTLS-SRTP/SRTP + H264(openh264)/PCMU/Opus de-packetize -> Frame). Deliberately deferred to protect the assert-offline gate from webrtc-rs's large dep tree; the WebRtcEngine trait seam is the clean plug-in point.
2. 302-payload AES mode pinning (see above).
3. MQTT TLS (rumqttc use-rustls) + the exact Tuya 302 topic + protocol-version binary framing.
4. Actual frame RENDER/PLAYBACK (a video sink + audio out) — not yet scoped; Wave-2 re-plan should add a render/CLI-view task after TASK-0037.

RE-PLAN IMPLICATION: the stream protocol layer is done and unblocked-by-design; the remaining stream work (TASK-0037 + render) is strictly downstream of the auth decision (TASK-0035). Sequence: TASK-0035 (auth) -> capture device creds + one 302 -> TASK-0037 (media engine + AES mode + TLS) -> render task.

CORRECTION (cycle-23): line ~36's '302-payload AES NOT statically pinnable (runtime AESUtil.ALGO + Cipher.il) -> MqttCryptoPending' is FALSE/STALE. The AES is pinned (AES-128/ECB/PKCS5, key=localKey, no IV) and implemented; the residual is only the pv->variant binding + framing (MqttEnvelopePending). Wave-2 re-plan should carry the corrected scope.
<!-- SECTION:NOTES:END -->
