---
id: TASK-0039
title: >-
  Verdict-guard SOFT+pointer: require pointer to resolve to the row's
  superseded_by target
status: To Do
assignee: []
created_date: '2026-06-25 09:31'
labels:
  - gates
  - review-followup
  - wave2
dependencies:
  - TASK-0038
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-27 review of TASK-0038 (GO, P2 accept-consciously). The verdict-guard SOFT+forward-pointer and SOFT-word-in-heading branches are cheaper to game than the notes imply: in this densely cross-referenced corpus every hit already has a .md/§/TASK pointer within ±3 lines, so SOFT+PTR reduces to "any soft word within 7 lines"; and a heading like "Notes on history" exempts a whole sections live verdicts. Reproducible bypasses: soft+any-.md, soft+bare-see, soft-heading-over-live-prose. Tighten: require the SOFT+PTR forward-pointer to resolve to the SUPERSEDED_VERDICTS row superseded_by TARGET (the actual replacing doc/TASK), not any .md/see; require SOFT-heading to co-occur with a strong banner or a row-specific pointer. NON-BLOCKING — the specific bare-soft-word P1 is fixed + mutation-proven; the human/mped-architect gate is the documented shape-not-content backstop. Diminishing returns: do not over-engineer; this is the last reasonable tightening before accepting the human gate as final.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 SOFT+PTR requires the pointer to match the row superseded_by target; the 3 documented bypasses now FLAG; real tree still green; self-tests added
<!-- AC:END -->
