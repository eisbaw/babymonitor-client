---
id: TASK-0126
title: Live-validate SCD921 LAN-only streaming with Tuya cloud unavailable
status: In Progress
assignee:
  - '@task-0126-impl'
created_date: '2026-07-16 13:49'
updated_date: '2026-07-16 18:16'
labels:
  - live-test
  - lan
  - streaming
dependencies:
  - TASK-0125
references:
  - re/ghidra/imm_p2p_rtc_connect_v2.c
  - re/prd.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Prove the owner camera can negotiate and stream through IPC_LAN_302 without Tuya MQTT, then test a cold start without any WAN dependency. Capture only redacted diagnostics under secrets and correct code or claims based on observed behavior.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Runtime discovery records the actual SCD921 Hgw LAN version and address without exposing identifiers or localKey
- [x] #2 A fresh stream starts and produces validated H.264 while the Tuya MQTT path is unavailable
- [x] #3 Connection tracing demonstrates LAN mode contacts only the camera LAN address during signaling and media startup
- [ ] #4 Camera and client restart test is performed with WAN unavailable; result is recorded honestly as pass or with the exact remaining cloud dependency
- [x] #5 LocalKey rotation/re-pair behavior and cached metadata lifetime are tested or explicitly bounded
- [x] #6 README and RE findings distinguish LAN signaling on TCP 6668 from ICE/KCP UDP media and remove the datapoint-only overclaim
- [x] #7 No live credentials, identifiers, IPs, or media enter tracked files
- [x] #8 Protocol 3.3 IPC_LAN_302 framing is implemented from APK/native evidence with independent known-answer tests, and a scanned endpoint is not labeled as the camera until localKey decryption yields a valid expected signaling envelope.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Discover the camera LAN metadata and confirm protocol version. 2. Run LAN signaling with cloud broker unusable and validate media. 3. Trace outbound connections. 4. Repeat after camera/client restart with WAN unavailable. 5. Fix observed defects, update evidence/docs, run gates, and commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Protocol correction (2026-07-16): the first port-6668 scan candidate failed the cached localKey under protocol 3.4 HMAC and was not identified as the camera. APK/Ghidra evidence showed the legacy 3.3 IPC_LAN_302 path: Java AES-128-ECB/PKCS7 encrypts command-32 JSON, native ThingFrame wraps it in 0x55aa framing with CRC32 and 0xaa55, and inbound Java decrypts only after CRC validation. The implementation now requires a fresh correlated, key-confirming decrypted signaling answer before an endpoint/config is accepted.

Live explicit-endpoint proof (2026-07-16): a bounded port-6668 scan found the camera; a fresh correlated IPC_LAN_302 answer decrypted under the cached localKey and proved Hgw 3.3 before the owner-only 0600 config was saved. The first stream returned Answer -> empty candidate -> Disconnect. Ghidra pinned the cause: msg.token=[] creates no camera ICE socket. The client now advertises a numeric LAN-local RFC 5389 responder in msg.token; the next run received a nonempty camera host candidate over frame 32, validated ICE, completed media auth, and captured 7,340,032 bytes. ffprobe reports H.264 1920x1080 at 15 fps plus AAC, 103.464 s; the trace reports zero media drops and zero depacketization errors. The local STUN responder served zero camera Binding queries: numeric token -> socket creation -> host-candidate trickle is camera-live-proven, while Binding/XOR-MAPPED response and srflx selection remain loopback/unit-proven.

WAN-denied fresh-client proof (2026-07-16): ran --signaling lan inside a systemd user unit with IPAddressDeny=any and IPAddressAllow limited to loopback plus the single cached camera LAN address. The client still received a frame-32 answer/candidate, validated ICE, and produced a 3,407,872-byte MPEG-TS capture. ffprobe reports H.264 1920x1080 at 15 fps plus AAC with 47.264 s duration. Public DNS, Tuya REST/MQTT, public STUN/TURN, and every non-camera destination were kernel-denied. Media host selection is pinned to the key-proven camera IPv4 address and LAN signaling accepts only the reverse-correlated device/sender/path route. This was a fresh client against an already-running paired camera; camera cold-power restart remains untested, so AC #4 remains open.

Discovery/lifetime boundary (2026-07-16): the camera did not advertise on the implemented UDP 6666/6667/7000 discovery probes, so discovery interoperability is only APK-derived/offline-tested; explicit endpoint plus mandatory TCP/localKey proof is live-proven. camera_ip is DHCP/lease-bound, Hgw version firmware-bound, IDs account-bound, localKey reset/re-pair-bound, and media password rtc.config-bound. ICE/session/STUN/TCP/media values are per-run. Reset/re-pair rotation and local credential reacquisition are not implemented; long-session heartbeat, renegotiation, and reconnect behavior beyond the measured 47-103 seconds is not claimed.

Release-gate update (2026-07-16): README/RE docs separate TCP 6668 IPC_LAN_302 signaling from UDP ICE/KCP media and retain the lifecycle limitations above. just e2e passes, including the live-feature test/clippy recipe. The project secret scanner reports no tracked credentials, identifiers, private IPs, or media; the generic diff scanner reports only crates.io checksum warnings in Cargo.lock. AC #2, #3, and #5 are evidenced as checked; only the physical camera restart portion of AC #4 remains outstanding.

Review gate (2026-07-16): qa-test-runner and mped-architect found no unresolved implementation, security, evidence, test, or documentation blockers and approved this incremental commit. Both explicitly withheld TASK-0126 completion because AC #4 (physical camera cold restart under WAN denial) remains unperformed.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just e2e passes
- [x] #2 qa-test-runner and mped-architect report no unresolved blockers
<!-- DOD:END -->
