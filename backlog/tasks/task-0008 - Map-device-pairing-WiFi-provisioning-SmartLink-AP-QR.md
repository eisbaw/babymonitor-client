---
id: TASK-0008
title: Map device pairing + WiFi provisioning (SmartLink/AP/QR)
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 08:38'
labels:
  - wave2
dependencies:
  - TASK-0001
  - TASK-0003
  - TASK-0005
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY: to add a camera the app provisions WiFi (Tuya EZ/AP SmartLink via libThingSmartLink) and binds via a pairing token from cloud; QR via ML Kit. Model the full pairing handshake. Delegate to general-purpose subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/pairing_flow.md documents: pairing-token request, EZ vs AP SmartLink packet/UDP scheme, the QR payload format, and the bind-confirm polling — evidence+confidence; honestly flags any part only in native code
- [ ] #2 Identifies which steps are mandatory for an already-paired camera (our case) vs first-time setup, so the Rust client can target the minimal path first
- [ ] #3 SCOPE NARROWING (already-paired camera): Wave-1 only confirms how an already-bound device appears in device-list and whether re-binding needs anything; defer full EZ/AP SmartLink packet + QR-payload reconstruction to a later wave as its own task
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Ghidra headless on libThingSmartLink.so -> decompile thing_smart_link, broadcast_encode/body/head, multicast_encode/body/head, xmitState, pkt_delay, send_data, crc8/crc32, encode_data, Thing_Native_SmartLink. Commit key C under re/ghidra/.
2. r2 cross-check the EZ packet-length encoding (broadcast vs multicast) -> record divergence.
3. jadx: activator/ ThingSmartLink Java wrapper + smartLink() param order (ssid/pwd/token...); AP-mode endpoint; token.create cloud action; bind/active polling action; QR payload (barhopper).
4. Build on re/tuya_cloud_auth.md for token-create + bind-confirm cloud APIs.
5. Write re/pairing_flow.md: token, EZ packet scheme, AP, QR, bind-confirm; each symbol-anchored + confidence; explicit ALREADY-PAIRED -> NO pairing, only auth+device-list (re/tuya_cloud_auth.md §5).
6. Gates: just check-evidence / secret-scan / e2e GREEN. Commit (no AI trailer). Feed-forward TASK-0036.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (TASK-0008). Wrote re/pairing_flow.md + 8 Ghidra C files under re/ghidra/smartlink_*.c.

FINDINGS:
- Pairing token: thing.m.device.token.create v2.0 (session-required) -> ActiveTokenBean{token,secret,key}; QR variant m.thing.device.qrcode.token.create v2.0 (+gid). renewal: m.thing.device.active.token.renewal.
- EZ/SmartConfig (libThingSmartLink.so, Ghidra): smartLink(ssid,pwd,token,5,2,1000,1,1). broadcast_body_encode builds [len(pwd)][pwd][len(token)][token][ssid], CRC8 head nibbles tagged 0x10/0x20/0x30/0x40, data bytes |0x100, seq |0x80; data carried in UDP DATAGRAM LENGTH (content is a zero buffer). multicast_body_encode AES-128-CBC-encrypts the password (fixed SDK key in .data, NOT per-device) + CRC32(0xedb88320), encodes ssid/pwd/token into multicast group-IP low bytes (base flags 0x40/0x00/0x20). send_data_thread: sendto(255.255.255.255) + multicast groups, paced by select(), stop via sendStatusStop->thing_quit_flag.
- AP mode: APConfigBeanUDP{ssid,passwd,token,ccode} JSON sent over the device soft-AP via ThingNetworkInterface.sendBroadcast(255.255.255.255, <port>, ...). Exact port = obfuscated const pdqdqbd.pppbppp (Tuya default 6669/UDP) = NEEDS-LIVE.
- QR payload: literal JSON {"p":pwd,"s":ssid,"t":token} (ppqdbbq.java ~1719). App GENERATES it; camera scans (its ML Kit libbarhopper). thing.m.qrcode.parse decodes a device label-QR.
- Bind-confirm: poll thing.m.device.list.token v5.0 (postData token, bizDM device_config_add) -> ConfigDevResp; then active thing.m.device.local.device.active / m.thing.device.local.device.active / thing.m.dm.device.active.

ALREADY-PAIRED (user's case): NO pairing needed. Already-bound device appears in HomeBean.deviceList as a normal DeviceBean (localKey/p2pId for stream); device-list + camera-config require only sid, no token, no SmartLink. PAIRING IS NOT ON THE CRITICAL PATH for viewing the existing camera.

GHIDRA-vs-r2: agree on broadcast encoder structure (strlen x3, malloc, length-prefix strb, memcpy, |0x80/|0x30 flags). Divergence is representation-only: r2 needed -m 0 (lib laddr 0 vs Ghidra base 0x100000); 16-bit |0x100/|0x10/|0x20/|0x40 flags appear as movz+orr in r2 (not orr-immediate), folded into ushort|0xNN by Ghidra. No semantic disagreement.

GOTCHAS:
- check-evidence: lib*.so@0xHEX does NOT count as a distinct citation token (the regex matches bare lib*.so before the @0x suffix), and re/ghidra/*.c paths are NOT recognized (.c not in SOURCE_EXT). So §3 native subsections (Ghidra+r2 reading the SAME bytes) are honestly single-source -> labelled 'likely', not 'confirmed'. §0/§1/§2/§6/§7 are 'confirmed' (native + Java, two real sources).
- AES key for the EZ multicast password is a FIXED SDK constant in libThingSmartLink.so .data (_DAT_0012b0c0/_UNK_0012b0c8), recoverable but not committed (not a per-device secret). Ghidra C uses _DAT_ refs, no inlined key bytes -> secret-scan clean.
- STATIC-COMPLETE: EZ packet scheme, smartLink arg order, QR payload, token/AP/bind SHAPES. NEEDS-LIVE: exact AP UDP port, on-wire a= after thing->smartlife rewrite, poll cadence/timeout, byte-exact multicast group derivation.

GATES: just check-evidence GREEN (17 docs, 0 waived); just secret-scan GREEN; just e2e GREEN.
<!-- SECTION:NOTES:END -->
