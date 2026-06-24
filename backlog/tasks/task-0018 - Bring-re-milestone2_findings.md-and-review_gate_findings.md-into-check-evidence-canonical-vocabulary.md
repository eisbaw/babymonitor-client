---
id: TASK-0018
title: >-
  Bring re/milestone2_findings.md and review_gate_findings.md into
  check-evidence canonical vocabulary
status: To Do
assignee: []
created_date: '2026-06-24 22:59'
labels:
  - grounding
  - docs
  - wave1
dependencies:
  - TASK-0011
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
check-evidence (TASK-0011) flags 6 pre-existing grounding gaps: milestone2_findings.md sections use non-canonical confidence words (very high/high/uncertain) instead of the pinned {confirmed|likely|speculative}, and the confidence is not co-located with each claim subsection; review_gate_findings.md 'Grounding/security defects' meta-section lacks a co-located confidence label + citation. These are waived in check_evidence.py BASELINE_WAIVERS keyed to this task. Remediate by re-spelling confidence to the canonical set (faithfully, no meaning change) and co-locating a confidence label + evidence citation in each flagged section, then remove the waiver entries so the gate goes fully green with no baseline.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 milestone2_findings.md: each claim section carries a co-located confidence token {confirmed|likely|speculative} mapping faithfully from the existing very-high/high/uncertain judgments
- [ ] #2 review_gate_findings.md 'Grounding/security defects' section carries a confidence label + evidence citation, or is restructured so it is not a protocol-claim section
- [ ] #3 BASELINE_WAIVERS in re/scripts/check_evidence.py is emptied and just check-evidence is green with zero waivers
<!-- AC:END -->
