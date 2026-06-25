---
id: TASK-0006
title: 'REVIEW: honesty+architecture audit of Wave-1 analysis docs'
status: Done
assignee:
  - '@me'
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 02:39'
labels:
  - phase-gate
  - review
  - wave1
dependencies:
  - TASK-0001
  - TASK-0002
  - TASK-0003
  - TASK-0004
  - TASK-0005
  - TASK-0011
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

REVIEW TASK (read-only). Run mped-architect over re/*.md produced so far. Check: every protocol/auth claim has confidence+evidence per TESTING.md; cross-source contradictions (JS vs Java vs native) are recorded not hidden; no adjective-only claims; scope still matches PRD. Output findings as NEW backlog tasks. Write no production code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/review_wave1_analysis.md written with findings; each ungrounded/contradictory claim filed as a fix task
- [ ] #2 just check-evidence (once it exists) passes over committed re/*.md, or gaps are filed as tasks
- [ ] #3 just secret-scan passes over all committed files + backlog/tasks/*.md (no recovered secret/real account ID committed)
- [ ] #4 Fix-tasks filed by this review are triaged (closed or consciously deferred with reason); the wave does not silently advance past open P0/P1 findings
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read all Wave-1 docs (milestone2, decompile_dex, manifest, js_bundle_map, native_libs, streaming_mode, tuya_sign, tuya_cloud_auth, tuya_cloud_config, review_gate_findings).
2. Read check_evidence.py to know the lint contract my review doc must satisfy.
3. Build cross-doc consistency matrix: transport, p2pType, static-vs-live boundary, sign verdict, datacenter selection.
4. Spot-check ~10 load-bearing symbol citations against decompiled tree via rg.
5. Identify findings: cross-doc contradictions, overclaims (<2 indep sources / adjective-only / wrong verdict), citation rot, coverage/honesty gaps, architecture coherence gaps.
6. Write re/review_wave1_analysis.md: per-doc verdict + consistency matrix + findings(severity+doc:section+fix) + overall soundness verdict. Doc itself passes check-evidence.
7. File each substantive finding as a backlog task --dep, triage blocking vs deferrable.
8. Verify: just check-evidence GREEN, just secret-scan GREEN, just e2e GREEN. One commit, no AI trailer.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FINAL SUMMARY (TASK-0006 audit complete):
OVERALL VERDICT: Wave-1 static foundation is SOUND for the Rust slice (auth->device->stream), with ONE P0 cross-doc contradiction + lower-severity nits. Deliverable: re/review_wave1_analysis.md (passes check-evidence on its own merits, 11 docs GREEN).
CROSS-DOC CONTRADICTION (F1, P0): js_bundle_map.md:45 asserts PlayNetKit 'ICE 73 hits' (confirmed section) -> streaming_mode.md:54-62 (TASK-0017) refutes it as a false positive; independently re-verified (zero RTCPeerConnection/ice-ufrag in kit_js; PlayNetKit 'ice' hits are onScanDevice/slice substrings). streaming_mode.md WINS. Filed TASK-0025 --dep TASK-0003 (BLOCKING).
F2 (P2): PlayNetKit role text overstated -> folded into TASK-0025.
F3 (P1, DEFERRABLE): milestone2_findings.md streaming framing stale vs TASK-0017 verdict (labelled likely, not a grounding violation; entry-doc navigational steer). Filed TASK-0026 --dep TASK-0017.
F4 (P1): lint validates citation SHAPE not CONTENT -> F1 is its concrete instance; already owned by open TASK-0021, NOT re-filed.
CITATION-ROT SPOT-CHECK: 12 load-bearing symbols across 6 docs resolved at EXACT cited paths = ZERO rot. (rg -l|head gave false misses only via obfuscated-name collisions; FQ paths are accurate.)
NON-FINDINGS (avoided FPs): tuya_sign 'needs-runtime-hook' is contract-correct per TASK-0005 AC#3 (lint canonical-verdict gate only keys on p2p_protocol.md); streaming_mode confirmed leans honestly on independent public ref; cloud_auth DeviceBean correctly likely (single source).
GATES: just check-evidence GREEN (11 docs), just secret-scan GREEN (no secret in any tracked file/task/doc), just e2e GREEN. Findings filed+triaged: F1 blocking, F3 deferrable. Wave does not advance past open P0.
<!-- SECTION:NOTES:END -->
