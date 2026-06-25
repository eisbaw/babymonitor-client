---
id: TASK-0028
title: Citation-precision nits in js_bundle_map.md WebRTC correction block
status: Done
assignee:
  - '@architect'
created_date: '2026-06-25 03:00'
updated_date: '2026-06-25 09:02'
labels:
  - re
  - citation-hygiene
  - review-followup
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-10 review (both GO, P2). Two tiny accuracy fixes in re/js_bundle_map.md WebRTC CORRECTION block: (1) ~:70-71 the runtime strings a=ice-ufrag / "invalid signaling: type: candidate" are attributed to re/symbols/libThingP2PSDK.dynsym.txt but live in the .so binary (the dynsym has the SYMBOLS like imm_p2p_ice_session_add_remote_candidate, not those strings) — cite decompiled/nativelibs/libThingP2PSDK.so for the strings, or quote a dynsym symbol instead. (2) ~:75-78 the "two greps … AND native+Java" independence wording invites the misreading that two greps of the same JS artifact are two sources — borrow streaming_mode.md:68 candor ("native lib + Java bridge — not fully independent"). Non-blocking; confirmed verdict stands.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Both citation nits fixed; check-evidence stays green; the confirmed block still has >=2 genuinely independent sources
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. js_bundle_map.md WebRTC block: fix citation — strings a=ice-ufrag/'invalid signaling: type: candidate' live in the .so binary, not the dynsym (which has imm_p2p_ice_* SYMBOLS). Cite decompiled/nativelibs/libThingP2PSDK.so for the strings; cite a dynsym symbol where appropriate. 2. Soften the 'two greps AND native+Java' independence wording, borrowing streaming_mode.md candor (native lib + Java bridge not fully independent).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE. js_bundle_map.md WebRTC CORRECTION block: (1) the runtime strings a=ice-ufrag / 'invalid signaling: type: candidate' are now cited to the .so BINARY (verified: strings -n5 decompiled/nativelibs/libThingP2PSDK.so yields 3 hits), with an explicit note that the dynsym is the symbol TABLE carrying imm_p2p_ice_session_* SYMBOLS (not those strings) — so strings->. so, symbols->dynsym. (2) Softened the independence wording borrowing streaming_mode.md:68 candor: the .so native strings/symbols and the Java P2PMQTTServiceManager bridge are NOT fully independent (both the same Tuya P2P SDK); the genuinely-independent pair is JS-kit layer vs native lib (+ public Tuya impls). check-evidence stays GREEN; the confirmed block still has >=2 genuinely independent sources (JS *.pretty greps AND the native .so).

Cycle-25 review: both GO. Verdict-overturn guard proven REAL (both reviewers reconstructed all 4 historical recurrences -> guard FLAGS them); same-artifact dedup breaks no legit claim + forced an honest bmp_token_whitebox §9 confirmed->likely; redaction leak-safe; js_bundle_map citation correct. P1 frame-word looseness (latent, tree unaffected) -> TASK-0038.
<!-- SECTION:NOTES:END -->
