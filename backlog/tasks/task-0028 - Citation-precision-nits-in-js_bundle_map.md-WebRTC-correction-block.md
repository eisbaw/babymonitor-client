---
id: TASK-0028
title: Citation-precision nits in js_bundle_map.md WebRTC correction block
status: To Do
assignee: []
created_date: '2026-06-25 03:00'
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
- [ ] #1 Both citation nits fixed; check-evidence stays green; the confirmed block still has >=2 genuinely independent sources
<!-- AC:END -->
