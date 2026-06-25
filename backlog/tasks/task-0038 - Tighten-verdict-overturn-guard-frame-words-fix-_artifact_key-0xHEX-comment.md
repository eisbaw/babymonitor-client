---
id: TASK-0038
title: Tighten verdict-overturn guard frame-words + fix _artifact_key @0xHEX comment
status: To Do
assignee: []
created_date: '2026-06-25 09:02'
labels:
  - gates
  - review-followup
  - wave2
dependencies:
  - TASK-0021
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-25 review of TASK-0021 (both GO, P1+P2). (P1) check_evidence.py lint_verdicts FRAME_WORDS includes broad soft words (history/stale/conservative/deprecated/obsolete) matched by ±3-line proximity with NO requirement the frame refer to the verdict token — both reviewers built adversarial docs where an unrelated nearby "history"/"stale" let a genuine current stale verdict PASS (false negative). Current re/ tree unaffected (all 24 hits have strong SUPERSEDED/strikethrough/section frames). Fix: require the frame word adjacent to a forward-pointer (SUPERSEDED/per/→/see or the superseded_by target doc name), OR drop the weakest soft words and force banner/strikethrough. (P2) _artifact_key comment claims @0xHEX is stripped before keying — it is NOT (LINE_HINT_RE only strips ~?:NN); it works by CITATION_RE alternation accident — add @0x[0-9A-Fa-f]+$ to the hint-strip or fix the comment so a future regex edit cannot silently break the .so-collapse.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Frame-word match requires a forward-pointer (not a free-floating soft word); adversarial 'history/stale near a current stale verdict' is FLAGGED; self-test added; real re/ tree still passes
- [ ] #2 _artifact_key @0xHEX handling made explicit (strip or documented); same-.so-with-offset citations still collapse to one source
<!-- AC:END -->
