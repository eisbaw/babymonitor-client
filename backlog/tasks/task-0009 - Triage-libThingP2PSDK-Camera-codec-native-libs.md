---
id: TASK-0009
title: Triage libThingP2PSDK/Camera/codec native libs
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 03:08'
labels:
  - phase3
  - re
  - wave1
  - p2p
dependencies:
  - TASK-0004
  - TASK-0011
  - TASK-0017
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 3): before deep diving, map the P2P/camera/codec libs - exported API surface, key strings, magic constants, and cross-reference public Tuya-P2P RE (tinytuya, tuya P2P projects, IOTC/PPCS lineage). Delegate to Explore subagent with radare2/ghidra-headless.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/p2p_triage.md: exported functions of libThingP2PSDK/CameraSDK, candidate session-init + send/recv entry points, protocol magic strings, and a mapping to any known public Tuya/IOTC P2P documentation with confidence
- [ ] #2 Lists the concrete next-dive targets (function offsets) for the deep spike task
- [ ] #3 JS-FIRST: pass the JS bundle (bridge method names, P2P channel orchestration, signaling) BEFORE native decompilation; only dive into .so for what JS does not reveal
- [ ] #4 Cross-reference named public sources: tuya/tuya-iotos-android-iot-p2p-demo (channel API surface) and WyzeCam tutk.py (IOTC/TUTK AV framing) — raises confidence toward 'confirmed'
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read symbol dumps (re/symbols/*.dynsym.txt) + demangle via c++filt; group exports by purpose (WebRTC signaling vs PPCS/IOTC) for libThingP2PSDK + CameraSDK + codec/audio libs.
2. JS-FIRST (AC#3): confirm the JS bridge surface already mapped in streaming_mode.md/js_bundle_map.md gates the native dive; cite TUNIIPCCameraManager.connect(deviceId) -> native.
3. String-grep .so for protocol magic/version/connect_v2/PPCS already cited; do not re-dump.
4. Map each entry-point group to public lineage (tuya-rtc-camera-sdk-android WebRTC; tuya-iotos-android-iot-p2p-demo; WyzeCam tutk.py PPCS).
5. Write re/p2p_triage.md: exported API surface (WebRTC vs PPCS), session-init+send/recv candidates labeled by transport, protocol magic, public-ref mapping, PRIORITIZED next-dive targets (WebRTC first, PPCS fallback low-prio).
6. Gates: just check-evidence GREEN, just secret-scan GREEN, just e2e GREEN.
7. Feed forward notes to TASK-0010 (prioritized targets) + TASK-0016 if WebRTC-Rust relevant. One commit, no AI trailer.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GOTCHAS / findings:
- check-evidence lint: re/symbols/*.dynsym.txt is NOT a citation token (.txt not in SOURCE_EXT; only java/kt/so/json/js/ts/bmp/xml/cfg/properties). Cite the lib*.so form (e.g. libThingP2PSDK.so) instead; the dump path is decoration. Also 'cross-confirmed' in prose trips the CONFIDENCE_RE as a stray 'confirmed' label - reworded to 'corroborated'.
- Demangled full C++ signatures of class ThingSmartP2PSDK via c++filt (51 syms) - recovers ARG TYPES for connect_v2/v3, send/recv_data, send/recv_frame(imm_p2p_rtc_frame_t*), Initialize(3 callbacks). This is the richest surface for the Rust client; written into re/p2p_triage.md S1b.
- NEW string finding: libThingVideoCodecSDK.so carries '1.5.0-Philips620.3' = OpenH264 fork with a Philips-specific build tag (confirmed literal). Logged in S3.
- The inner_p2p_type selector JSON in libThingCameraSDK.so ('PPCS_Write' vs 'thing_p2p_rtc_send_data') is the concrete runtime tie-break artifact for p2pType 2-vs-4.
- HONEST LIMIT: no disassembly done. This is the API-surface + entry-point map only; arg SEMANTICS, skill bitmask, token/key derivation need Ghidra/r2 (TASK-0010) or a live device.
ACs: #1 done (exported fns, session-init+send/recv, magic, public-ref map w/ confidence). #2 done (prioritized next-dive symbols, S5). #3 done (JS-first gate S0). #4 done (tuya p2p-demo + WyzeCam tutk.py mapped, S4). Gates check-evidence/secret-scan/e2e all GREEN.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Produced re/p2p_triage.md: the exported API surface of libThingP2PSDK.so (26 JNI ThingP2PSDK_* exports + the full demangled C++ ThingSmartP2PSDK class with arg types + the imm_p2p_rtc_sdp_*/ice_*/frame_list ARQ families), grouped WebRTC-session vs legacy-PPCS; the session-init (thing_p2p_rtc_connect_v2/v3) and send/recv (send_data/recv_data, send_frame/recv_frame) entry points labeled per transport; the protocol magic (connect_v2 JSON envelope, signaling type validators, 302 {header,msg,token}, ERROR_PPCS_* family, inner_p2p_type selector); a confidence-graded mapping to public lineage (tuya-rtc-camera-sdk-android + seydx/tuya-ipc-terminal for WebRTC; tuya-iotos-android-iot-p2p-demo + WyzeCam tutk.py for PPCS); and a PRIORITIZED next-dive list (WebRTC first, PPCS fallback low-prio). JS-first gate confirmed the JS layer is transport-agnostic ({deviceId}-only) so the native dive is the correct next step. New finding: video codec is an OpenH264 fork tagged 1.5.0-Philips620.3. All 4 ACs met. Gates GREEN: check-evidence, secret-scan, e2e. Next-dive targets fed forward to TASK-0010; WebRTC-Rust-relevant surface fed to TASK-0016. LIMIT: no disassembly - arg semantics/skill bitmask/key derivation need Ghidra/r2 (TASK-0010) or a live device.
<!-- SECTION:FINAL_SUMMARY:END -->
