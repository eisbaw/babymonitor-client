---
id: TASK-0038
title: Tighten verdict-overturn guard frame-words + fix _artifact_key @0xHEX comment
status: Done
assignee:
  - '@architect'
created_date: '2026-06-25 09:02'
updated_date: '2026-06-25 09:25'
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
- [x] #1 Frame-word match requires a forward-pointer (not a free-floating soft word); adversarial 'history/stale near a current stale verdict' is FLAGGED; self-test added; real re/ tree still passes
- [x] #2 _artifact_key @0xHEX handling made explicit (strip or documented); same-.so-with-offset citations still collapse to one source
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
P1 (frame tightening):
1. Audited all 24 real-tree superseded-token hits: 23 carry a STRONG frame (banner/strike/optset), exactly 1 (bmp_token_decode.md:136) is anchored by a [HISTORICAL — WRONG] section heading. NONE rely on a free-floating soft word.
2. Split FRAME_WORDS into STRONG_BANNER (superseded/refuted/corrected/retracted/overturned/erratum) and SOFT_HISTORY (historical/history/deprecated/obsolete/stale/outdated/pre-disassembly/conservative/no-longer/was-wrong/now-wrong).
3. New _is_framed: framed iff STRONG banner (window OR heading) | strikethrough | option-set | soft word IN A HEADING | (soft word AND a forward-pointer →/->/see/per/superseded-by/.md/TASK-/§ in window). A bare free-floating soft word no longer frames.
4. Verified: real tree 0 would-flag; 3 adversarial soft-word docs (history/stale/conservative near a CURRENT stale verdict) now FLAG.
5. Add self-tests: 2 adversarial FLAG cases + strong-frame PASS cases + re-prove 4 un-framed recurrence forms FLAG.
P2 (_artifact_key): add @0x[0-9A-Fa-f]+$ to a hint-strip applied before _artifact_key keying so lib.so@0xHEX collapses to lib.so explicitly (not by CITATION_RE accident); fix the brittle comment; add self-test that lib.so@0x1234, lib.so, and its dump collapse to one key.
Verify: just check-evidence / gates-selftest / secret-scan / e2e all GREEN; run guard over re/ → 0 findings. One commit, no AI trailer.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GOTCHAS / decisions (TASK-0038):
- All 24 real-tree superseded-token hits were audited: 23 carry a STRONG frame (banner/strikethrough/option-set); exactly ONE (bmp_token_decode.md:136) relies on a soft word, but it is in the [HISTORICAL — WRONG] SECTION HEADING, not free-floating body prose. So the soft-word-in-heading clause is load-bearing for the real tree — do NOT drop it. No real doc needed editing.
- The false-negative vector was specifically free-floating soft words in BODY prose within ±3 lines. Fix: bare soft word no longer frames; it must be (a) in the enclosing heading, or (b) paired with a forward-pointer (→/->/see/per/superseded by/.md/TASK-NNNN/§N) in the window. STRONG banners (SUPERSEDED/REFUTED/CORRECTED/RETRACTED/OVERTURNED/erratum), strikethrough, and option-sets frame alone.
- Deliberately EXCLUDED bare `now` from the forward-pointer set for the soft+pointer clause — `now` is too weak and would re-open the hole. (`now` still appears incidentally in many real hits but those all pass on a strong banner, not soft+now.)
- Limitation: the soft+forward-pointer clause is still theoretically gameable by an adversary who writes BOTH an unrelated soft word AND a `see`/`.md` pointer within ±3 lines of a current stale verdict. That is a much more deliberate, review-visible construct than a bare soft word; the human/mped-architect gate remains the backstop (documented limitation, consistent with the shape-not-content stance).
- P2: _artifact_key previously collapsed `.so@0xHEX` only by a CITATION_RE alternation accident (the `.so\\b` source-path alternative matched first and dropped the offset). Now LINE_HINT_RE also strips `@0x[0-9A-Fa-f]+$`, and _artifact_key + _SO_BIN_RE strip/tolerate the offset themselves (defence in depth) so the collapse is deterministic regardless of future CITATION_RE edits. Self-test asserts `.so@0xHEX`, bare `.so`, and the readelf dump collapse to one key, and that a confirmed claim citing one .so at two offsets flags as one source.
- Mutation-tested the new self-tests: re-enabling bare soft-word framing turns the 3 adversarial cases RED, proving they bite.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Tightened the verdict-overturn guard's frame matching and made _artifact_key's @0xHEX handling explicit.

P1 — frame tightening (check_evidence.py):
- Split FRAME_WORDS into STRONG_BANNER_WORDS (superseded/refuted/corrected/retracted/overturned/erratum) and SOFT_HISTORY_WORDS (historical/stale/obsolete/deprecated/conservative/…).
- New _is_framed: a hit is framed iff a STRONG banner is in the window or enclosing heading; OR a ~~strikethrough~~ on the hit line; OR a {a|token|b} option-set in the window; OR a SOFT word in the enclosing SECTION HEADING; OR a SOFT word paired with a FORWARD-POINTER (→/->/see/per/superseded by/.md/TASK-NNNN/§N). A bare free-floating soft word in body prose no longer frames — that was the exploitable false negative.
- Verified all 24 real-tree hits still pass (23 on strong banner/strike/option-set, 1 on a [HISTORICAL — WRONG] section heading); 0 findings over re/. No doc needed editing.

P2 — _artifact_key @0xHEX (check_evidence.py):
- The brittle comment claimed @0xHEX was already stripped; it was not — collapse worked only by a CITATION_RE alternation accident. LINE_HINT_RE now also strips @0x[0-9A-Fa-f]+$, and _artifact_key + _SO_BIN_RE strip/tolerate the offset themselves, so lib.so@0xHEX / lib.so / its readelf dump collapse to one artifact key deterministically. Comment corrected.

Self-tests added: 3 adversarial soft-word cases (history/stale/conservative near a CURRENT stale verdict) now FLAG; strong-banner/strikethrough/option-set/soft-in-heading/soft+pointer frames PASS; the 4 historical recurrence forms re-proven to FLAG un-framed; @0xHEX collapse asserted directly and end-to-end. Mutation-tested: re-enabling bare soft-word framing turns the adversarial tests RED.

Gates: just check-evidence, gates-selftest, secret-scan, e2e all GREEN.
<!-- SECTION:FINAL_SUMMARY:END -->
