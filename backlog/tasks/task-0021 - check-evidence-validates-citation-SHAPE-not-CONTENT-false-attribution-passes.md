---
id: TASK-0021
title: check-evidence validates citation SHAPE not CONTENT (false-attribution passes)
status: Done
assignee:
  - '@architect'
created_date: '2026-06-25 01:11'
updated_date: '2026-06-25 09:02'
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
- [x] #1 Either an opportunistic content-check is added (when cited file exists, verify a claim token near the cited line) with a self-test, OR the limitation is documented in check_evidence.py header + TESTING.md and accepted with rationale
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add data-driven verdict-overturn guard to check_evidence.py: list of {old_token, superseded_by} pairs. Grep re/*.md for each old token; a hit FAILS unless the surrounding context carries a SUPERSEDED/REFUTED/CORRECTED/HISTORICAL/erratum forward-pointer frame. 2. Self-test: planted doc asserting old token as current FAILS; framed doc PASSES. 3. Wire into run() so 'just check-evidence' runs it. 4. For content-vs-shape: document the limitation in check_evidence.py header + TESTING.md (cheaper than opportunistic check, gitignored decompile not always present). 5. Run guard over real re/ tree; fix any genuinely un-framed stale token doc.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE. Verdict-overturn guard implemented in check_evidence.py (lint_verdicts), wired into run() so 'just check-evidence' and 'just e2e' enforce it. Data-driven SUPERSEDED_VERDICTS table of (old, superseded_by, pattern): needs-runtime-hook, 'white-box table cipher', 'no runtime input', 'statically-recoverable-in-principle'. Every hit must be framed: FRAME_WORDS (SUPERSEDED/REFUTED/CORRECTED/RETRACTED/HISTORICAL/OVERTURNED/erratum/conservative/pre-disassembly/stale/...) within +-3 lines, OR a frame word in the ENCLOSING SECTION HEADING (section-anchored, catches the '## [HISTORICAL — WRONG]' case 18 lines above the hit), OR a ~~strikethrough~~, OR an option-set {a|token|b} menu (window-joined so it works across wrapped lines). Self-tests prove RED on un-framed stale token + GREEN on banner/heading/strike/option-set framing. RAN OVER REAL re/ TREE: GREEN — all 24 superseded-token hits are genuinely framed (audited each: SUPERSEDED/REFUTED/RETRACTED/OVERTURNED/conservative/option-set; none rely on incidental matches). NO un-framed stale token found in the live tree (the manual reconciliations from TASK-0023/0033 already framed them; the guard now makes it mechanical). GOTCHA: line-window alone missed the [HISTORICAL] heading at distance>window — section-anchored heading check is essential; and option-set braces can wrap lines so OPTION_SET_RE must run on window text not the single line. CONTENT-VS-SHAPE (AC part 2): chose DOCUMENTED-ACCEPTANCE (cheaper than opportunistic check, which would be GREEN-when-decompile-absent=false confidence, and jadx line drift rots a content grep). Documented limitation in check_evidence.py header + TESTING.md 'Shape vs content'; attribution accuracy owned by the review gate.

Cycle-25 review: both GO. Verdict-overturn guard proven REAL (both reviewers reconstructed all 4 historical recurrences -> guard FLAGS them); same-artifact dedup breaks no legit claim + forced an honest bmp_token_whitebox §9 confirmed->likely; redaction leak-safe; js_bundle_map citation correct. P1 frame-word looseness (latent, tree unaffected) -> TASK-0038.
<!-- SECTION:NOTES:END -->
