---
id: TASK-0006
title: 'REVIEW: honesty+architecture audit of Wave-1 analysis docs'
status: Done
assignee:
  - '@me'
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 02:52'
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
META-REVIEW NO-GO (post-completion): the audit MISSED a second cross-doc contradiction and overclaimed 'ONE contradiction'. Missed finding = F5: re/milestone2_findings.md 'What this means' point #3 (~:84) frames appKey/appSecret as SUFFICIENT to sign Tuya requests ('Tuya cloud signs every API request (HMAC) with these'), refuted by the later TASK-0005 spike re/tuya_sign.md (Verdict: needs-runtime-hook) and review_gate_findings.md F1 (sign key = [app_cert_SHA256]_[decoded t_s.bmp token]_[appSecret], native+runtime-cert-dependent). Same staleness class as the streaming F3 - milestone2 is the stale entry doc. FIX APPLIED: (1) filed TASK-0027 (FIX milestone2 sign-key staleness, P1, --dep TASK-0005/TASK-0007, with 2 structured ACs); (2) edited re/review_wave1_analysis.md - added F5 finding (confidence: confirmed, grounded in pbddddb.java doCommandNative cmd=1 + libthing_security.so + nalajcie/tuya-sign-hacking), fixed the matrix 'Sign scheme' row to 'milestone2 STALE (sign-sufficiency)' -> tuya_sign WINS, softened the 'ONE contradiction'/'everywhere else converges'/'ONE place internally INCONSISTENT' headlines to TWO recorded contradictions (F1+F5) bounded-by-spot-check, kept the SOUND-foundation verdict; (3) added structured ACs to TASK-0025 and TASK-0026 (they had only inline FIX/VERIFY prose). Gates GREEN after edit: check-evidence (11 docs, 0 active), secret-scan, e2e. The overall SOUND-for-Rust-slice verdict stands; only the completeness/ONE-contradiction claim was wrong.

Cycle-9 review: initial GO from qa but NO-GO from 2nd architect (audit missed the milestone2 sign-sufficiency contradiction F5, overclaimed 'ONE contradiction'). Fixed in cffc1e7: F5 recorded, matrix Sign-scheme row corrected, headline softened, SOUND verdict retained, TASK-0027 filed. Re-review GO. Residual nit: 'F5' label overloaded with datacenter-F5 in the matrix -> note on TASK-0027.
<!-- SECTION:NOTES:END -->
