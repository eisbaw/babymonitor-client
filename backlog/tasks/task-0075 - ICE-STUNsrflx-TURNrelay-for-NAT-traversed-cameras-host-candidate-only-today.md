---
id: TASK-0075
title: >-
  ICE STUN(srflx)/TURN(relay) for NAT-traversed cameras (host-candidate-only
  today)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-26 22:20'
updated_date: '2026-06-27 18:46'
labels:
  - stream
  - ice
  - media
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
UdpMediaTransport does plain UDP host candidates only; STUN binding (srflx) + TURN Allocate (relay) are not implemented, so only directly-routable cameras are reachable. cap3 provided STUN/TURN servers + ephemeral creds in the SDP token. Implement minimal ICE: STUN binding to discover srflx, TURN Allocate/CreatePermission/Send for relay, and connectivity checks, to reach a camera behind NAT.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 STUN binding request to the SDP stun: server yields a srflx candidate
- [ ] #2 TURN Allocate+permission+relay path works against the SDP turn: server (ephemeral creds)
- [ ] #3 Media connects to the camera via the best candidate (host/srflx/relay)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SCOPE NOTE from cap4: the camera was reached via a HOST candidate (LAN-direct, 192.0.2.184) — NO STUN/TURN needed when the client shares the camera LAN. So host-direct is the fast path to a first self-contained live frame; STUN(srflx)/TURN(relay) here are for REMOTE/NAT-d access. cap4 has ~559 real STUN binding packets (media.pcap, payload[4:8]==0x2112a442) usable to KAT a STUN encoder.

## ICE/STUN media-path layer implemented (offline-validated; live socket I/O is owner-only)

Implemented the minimal ICE connectivity layer per the cap4-proven scope: HOST-direct as the primary media path, the STUN Binding codec as the connectivity-check + srflx primitive, and a documented TURN stub.

### New/changed code
- babymonitor-core/src/stream/media/stun.rs (NEW): minimal STUN (RFC 5389/8445) Binding codec — StunMessage::decode (header+cookie validation, TLV walk), BindingRequest::encode (PRIORITY / ICE-CONTROLLING|CONTROLLED / USE-CANDIDATE / SOFTWARE / USERNAME), message_integrity (HMAC-SHA1 over msg-up-to-MI with patched length, key = peer ICE pwd), fingerprint (inline IEEE CRC-32 ^ 0x5354554e, no new crate), verify_message_integrity (constant-time), StunMessage::xor_mapped_address (srflx decode, IPv4+IPv6), encode_server_query.
- babymonitor-core/src/stream/media/transport.rs: IceCredentials (local/remote ufrag+pwd; secret pwds redacted in Debug; outbound_username = remote:local; build_check), connect_host_direct + select_host_candidate (PRIMARY cap4 path: highest-prio typ host, RTP component preferred), UdpMediaTransport::send_datagram/local_addr/send_connectivity_check, discover_srflx (live STUN round-trip -> XOR-MAPPED-ADDRESS), allocate_turn_relay (loud documented stub).
- babymonitor-core/src/stream/media/mod.rs: MediaEngine::pump(transport, buf) — the seam exposing the selected UDP transport to the media engine (TASK-0037).

### cap4 KAT vs ground truth (offline-validated, #[ignore]d, reads gitignored cap4 at runtime; NO inlined secrets)
- tests/cap4_stun_kat.rs (NEW): finds a REAL camera-bound ICE connectivity-check Binding Request in emulator_captures/cap4/media.pcap (linktype 276 SLL2; STUN = payload[4:8]==2112a442), recovers the camera (answer) ICE pwd at runtime from media_meta.jsonl, and proves: (a) our decoder parses it (type/txid/attrs); (b) our message_integrity (HMAC-SHA1, camera pwd) + fingerprint reproduce that real packet's MESSAGE-INTEGRITY + FINGERPRINT bytes EXACTLY; (c) BindingRequest::encode reproduces the whole real 100-byte packet byte-for-byte (including the camera's non-standard SOFTWARE attr that declares its padding as part of the value). A second test decodes a real Binding Success XOR-MAPPED-ADDRESS to a valid PUBLIC srflx, asserted structurally only — the public IP is never printed/committed (PII).
- transport.rs srflx_loopback_round_trip (#[ignore]d): drives discover_srflx end-to-end over a localhost UDP responder (no camera).

### Gates (ACTUAL results)
- just e2e -> exit 0 (build/test/lint/fmt-check/stub-grep/assert-offline/stream-validate all green; new offline unit tests for stun/transport/pump pass).
- cargo clippy -p babymonitor-cli --features live --all-targets -- -D warnings -> clean (live feature compiles+lints).
- Ignored suite: cap4_stun_kat (2) + srflx_loopback (1) + cap4_replay (2) all pass.

### Honest scope: offline-validated vs LIVE-gated
- OFFLINE-VALIDATED: the STUN encode/decode + MI/FINGERPRINT/XMA primitives (byte-exact vs real cap4), host-candidate selection, the check-bytes builder, the srflx round-trip logic (loopback), and the transport->engine pump seam.
- LIVE-gated (owner-only; no broker/camera in sandbox; NOT run here): the actual UDP socket I/O — connect_host_direct to the camera, sending the consent check so the camera starts streaming, and discover_srflx against the SDP stun: server. No live network calls were made.

### AC status (honest)
- AC#1 (srflx via SDP stun server): mechanism implemented + offline-validated (loopback round-trip + real cap4 XMA decode); a live round-trip to the SDP stun server is the owner's confirmation. NOT checked.
- AC#2 (TURN Allocate/permission/relay): intentionally a documented stub (allocate_turn_relay) — cap4 reached the camera with NO relay, so TURN is non-blocking and left for remote/NAT. NOT checked.
- AC#3 (media connects via best candidate): host-direct selection + connect + the engine pump seam are implemented + offline-tested; the live connect+stream is owner-only. NOT checked.

### Note (unrelated, pre-existing)
just secret-scan is RED only on pre-existing emulator_captures/*/flows.full.txt + pcaps (known, tracked by TASK-0066; emulator_captures is not gitignored). ZERO hits reference the new source/test files. No git commit made (per instruction).
<!-- SECTION:NOTES:END -->
