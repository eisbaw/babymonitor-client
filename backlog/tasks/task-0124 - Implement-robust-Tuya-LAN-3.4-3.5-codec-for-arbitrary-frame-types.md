---
id: TASK-0124
title: Implement robust Tuya LAN 3.4/3.5 codec for arbitrary frame types
status: Done
assignee:
  - '@task-0124-impl'
created_date: '2026-07-16 13:48'
updated_date: '2026-07-16 14:30'
labels:
  - rust
  - lan
  - reverse-engineering
dependencies: []
references:
  - 'https://github.com/FruitieX/rust-async-tuyapi/pull/21'
  - decompiled/jadx/sources/com/thingclips/sdk/hardware/enums/FrameTypeEnum.java
  - analysis/ghidra/network_dump/frame35_builder.c
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Recover the exact authenticated Tuya LAN framing used by this APK and implement a production-quality incremental TCP codec in babymonitor-core. Use rust-async-tuyapi PR #21 only as an MIT-licensed reference. The immediate consumer is IPC_LAN_302 frame type 32; this task must not wire the stream CLI yet.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Protocol-version selection is driven by discovered/cached Hgw LAN version, never inferred from MQTT pv
- [x] #2 Codec supports Tuya 3.4 and 3.5 session-key negotiation and arbitrary u32 frame types including 32
- [x] #3 Frame type 32 carries raw JSON without a DP protocol header
- [x] #4 Incremental decoder handles fragmented, coalesced, and partial TCP frames using declared lengths rather than suffix scanning
- [x] #5 Response status and outer sequence are preserved
- [x] #6 Deterministic unit/KAT tests cover handshake derivation, encode/decode, fragmentation, coalescing, malformed lengths, and command 32
- [x] #7 No credentials, device IDs, IPs, localKeys, or captures enter tracked files
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Pin APK/native wire evidence and inspect the linked PR. 2. Design transport-neutral frame/message types. 3. Implement v3.4/v3.5 crypto, handshake, and incremental framing. 4. Add deterministic fixtures and negative tests. 5. Run review gates and commit.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented an authenticated, transport-neutral Tuya LAN codec for Hgw protocol 3.4 and 3.5. It supports arbitrary u32 commands including raw IPC_LAN_302 type 32, strict declared-length TCP reassembly, explicit response status/sequence, fail-closed commands 3/4/5 session negotiation, fresh GCM nonces, bounded frames, and zeroized/redacted keys. Added 15 deterministic tests with independent OpenSSL-backed request, response-status, and session-key vectors plus fragmentation, coalescing, malformed/authentication failure, reserved-header, nonce, redaction, and failed-finish-write coverage. Final just e2e, secret scan, QA, and architecture gates are green.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just e2e passes
- [x] #2 qa-test-runner and mped-architect report no unresolved blockers
<!-- DOD:END -->
