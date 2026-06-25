---
id: TASK-0018
title: >-
  Bring re/milestone2_findings.md and review_gate_findings.md into
  check-evidence canonical vocabulary
status: Done
assignee:
  - '@claude'
created_date: '2026-06-24 22:59'
updated_date: '2026-06-25 00:49'
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
- [x] #1 milestone2_findings.md: each claim section carries a co-located confidence token {confirmed|likely|speculative} mapping faithfully from the existing very-high/high/uncertain judgments
- [x] #2 review_gate_findings.md 'Grounding/security defects' section carries a confidence label + evidence citation, or is restructured so it is not a protocol-claim section
- [x] #3 BASELINE_WAIVERS in re/scripts/check_evidence.py is emptied and just check-evidence is green with zero waivers
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Rewrite milestone2_findings.md confidence vocab to {confirmed|likely|speculative}, co-located per claim section + citation.
2. review_gate_findings.md Grounding/security section: add confidence+citation or restructure as non-claim.
3. Empty BASELINE_WAIVERS in check_evidence.py; ensure stale-waiver detection passes.
4. just check-evidence GREEN 0 waivers. Do NOT weaken lint.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPLEMENTED (commit 3f4b623, atomic with TASK-0019).

Mapping applied (faithful, no meaning change): very high -> confirmed; high -> likely; uncertain -> speculative.

milestone2_findings.md: each claim section (Headline, Streaming/device stack, Cloud config, What-this-means, Confidence summary) now carries a co-located canonical label + citation. "confirmed" used only where >=2 independent sources genuinely exist (native re/symbols/ dumps AND decompiled com/thingclips tree). The bottom "Confidence" summary respelled to canonical tokens.

review_gate_findings.md "Grounding/security defects" section: relabelled as a PROCESS/decision record (confidence: confirmed — not a protocol claim) with citations to re/scripts/check_evidence.py:1, secret_scan.sh:1, stub_grep.sh:1.

BASELINE_WAIVERS emptied to set(). check-evidence GREEN with 0 waivers. Lint NOT weakened — docs fixed on their own merits.

GOTCHA: the stale-waiver detector in check_evidence.py would FAIL if a waiver entry is left after its doc is fixed, so the waiver set MUST be emptied in the same change that fixes the docs (cannot lag). This forced the atomic commit with TASK-0019.

GOTCHA: the section-subtree parser keys waivers on the heading TITLE. Because I changed several headings to append "(confidence: ...)", the OLD waiver titles would have gone stale anyway — another reason the waiver had to be emptied, not edited.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Brought the two pre-existing baseline docs into the canonical confidence vocabulary and emptied the lint waiver.

What changed:
- milestone2_findings.md + review_gate_findings.md: very-high/high/uncertain respelled to {confirmed|likely|speculative}, co-located per claim section with citations. `confirmed` kept only where >=2 independent sources exist.
- review_gate "Grounding/security defects" section relabelled as a process record (not a protocol claim) with script citations.
- check_evidence.py BASELINE_WAIVERS emptied; the ratchet mechanism is retained.

Result: just check-evidence GREEN with ZERO waivers, on the docs own merits — the lint was made STRICTER (TASK-0019), not weaker.

Note: committed atomically with TASK-0019 because emptying the waiver requires the stricter lint and the rewritten docs together (stale-waiver detection forbids a lagging waiver).
<!-- SECTION:FINAL_SUMMARY:END -->
