---
id: TASK-0021
title: check-evidence validates citation SHAPE not CONTENT (false-attribution passes)
status: To Do
assignee: []
created_date: '2026-06-25 01:11'
updated_date: '2026-06-25 07:09'
labels:
  - phase5
  - gates
  - review-followup
dependencies:
  - TASK-0019
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-4 review (mped-architect, P1): check_evidence.py validates that a citation MATCHES a path:line shape but never that the cited file/line actually contains the claimed content. A wrong attribution (e.g. citing dpdqppp.java for nin/nout topic prefixes it does not contain) passes the gate. This is an inherent limit of a static doc-linter; full content-validation needs the gitignored decompile present. Options: (a) opportunistic check — when the cited path exists locally, grep that line region for a token from the claim; (b) accept the limit and lean on the human/mped-architect review gate for attribution accuracy (document it). Not blocking; the review gate caught this one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Either an opportunistic content-check is added (when cited file exists, verify a claim token near the cited line) with a self-test, OR the limitation is documented in check_evidence.py header + TESTING.md and accepted with rationale
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SYSTEMIC FOLLOW-UP (recurring, 2x): when a spike OVERTURNS a prior verdict, the entry/sibling docs that authoritatively assert the OLD verdict are not automatically reconciled, producing a cross-doc contradiction (NO-GO under TESTING.md 'record which won and why'). Recurrences: (1) TASK-0006/F5 (milestone2 sign-sufficiency staleness vs the TASK-0005 spike); (2) TASK-0023 (three docs — tuya_sign.md, review_wave1_analysis.md, milestone2_findings.md, plus tuya_cloud_auth.md found during verification — still asserted needs-runtime-hook after partially-recoverable superseded it). Proposed cheap guard, in scope of this gate's content-vs-shape gap: a checklist/grep step run whenever a verdict changes — e.g. after a spike sets a new verdict token, grep re/ for the OLD token and require each remaining hit to be either in the winning doc as history or to carry a SUPERSEDED pointer. This is a coherence/lint affordance (could be a soft check-evidence advisory), not a P0 wire gate. Keep low priority; do not over-engineer into a full content validator.

STRENGTHENED (TASK-0033, 4th recurrence). The overturn-lag pattern recurred AGAIN: TASK-0033 (Ghidra port) REFUTED the 'bmp_token decode is deterministic / no runtime input / statically-recoverable-in-principle' model (the decode keys off a RUNTIME JNI byte[] SDK-config, doCommandNative param_6) -- but THREE docs still asserted the refuted model as current and a review NO-GO'd: (3a) tuya_sign_static.md §5+§6, (3b) bmp_token_whitebox.md §6/§7 verdict-skim sections, (3c) bmp_token_decode.md + tuya_sign.md banner. Now reconciled manually (TASK-0033 doc-reconciliation commit). This is recurrence #4 (after #1 TASK-0006/F5, #2/#3 TASK-0023's doc set). A grep-guard would have caught ALL FOUR mechanically. WAVE-2 SHOULD IMPLEMENT the verdict-overturn grep-guard: after a spike sets a NEW verdict token, a check greps re/ for the OLD verdict token(s) and FAILS unless each hit is in history/SUPERSEDED/REFUTED context with a forward-pointer to the authoritative section. Make it a real gate step (e.g. an advisory in check-evidence or a dedicated just recipe run in e2e), not just a checklist -- the manual checklist has now failed to prevent 4 recurrences. Per scope this is NOT implemented now (Wave-2).
<!-- SECTION:NOTES:END -->
