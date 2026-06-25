---
id: TASK-0020
title: 'Gate polish: redaction offset-safety + same-artifact citation independence'
status: Done
assignee:
  - '@architect'
created_date: '2026-06-25 00:55'
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
From cycle-3 review (both GO, P2 nits). Non-blocking gate hardening: (1) secret_scan.sh redaction keeps first 5 chars of the LINE not the value region — safe only because path:/line: prefixes are prepended; make it offset-based (mask from the value) and add a self-test for a value-leading JWT/email/GPS line. (2) check_evidence distinct_citations(): two readelf views of the SAME .so (dynamic.txt + dynsym.txt) currently count as 2 independent sources for a confirmed label — tighten to treat dumps of the same source artifact as one source. (3) line-anchored citation drift (e.g. milestone2:61 -> js_bundle_map.md:185 points at the wrong block) — consider section-anchored citations. None block claim tasks.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Redaction is offset-based; self-test proves a value-leading line is masked
- [x] #2 Same-source dumps no longer satisfy the >=2-source confirmed rule on their own; self-test added
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. secret_scan.sh: make redaction OFFSET-based — extract the matched VALUE via grep -oiE, locate its index in the line, mask from the value start (keep small line-prefix context only up to the value). Add self-test: a value-leading line (JWT/email at col 0) is masked. 2. check_evidence.py distinct_citations(): treat two dumps of the SAME .so artifact (lib.dynamic.txt + lib.dynsym.txt, or .so + its symbol dump) as ONE source for the >=2-source confirmed rule. Add self-test.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE. (1) Redaction is now OFFSET-based in scan_stream(): the matched VALUE is re-extracted with grep -oiE -m1 using the same pattern, its index in the line is computed, and masking starts at the value (the line prefix — path:/field-name — is kept, capped at 32 chars). Self-test 1c plants a JWT and email at column 0 (value-leading) and asserts neither 'eyJhbGci' nor 'victimleaduser' appears in output. GOTCHA: grep -oiE -m1 must use the SAME pattern as the detection grep or the offset is wrong; fail-safe redacts the WHOLE line if the value can't be isolated. (2) distinct_citations() now canonicalises .so views via _artifact_key(): a .so binary and its readelf/nm dumps (lib*.dynsym.txt / lib*.dynamic.txt / .symbols/.syms/.rodata/.strings.txt) collapse to one 'so:<libbase>' key, so two dumps of the SAME .so no longer satisfy the >=2-source confirmed rule. ALSO widened CITATION_RE to recognise the dump .txt paths as citation tokens (they weren't matched before). Self-tests (d2): two dumps of same .so FLAG, dump+.so binary FLAG, two DIFFERENT .so PASS. GOTCHA/REAL CATCH: the tightening flagged a genuine over-claim — bmp_token_whitebox.md §9 claimed 'two independent sources' but Ghidra + radare2 are two TOOLS decompiling the SAME libthing_security_algorithm.so; downgraded §9 confidence:confirmed -> likely with candor (no independent oracle exists for the matrix decode; the doc itself admits the only oracle is a live sign-accept).

Cycle-25 review: both GO. Verdict-overturn guard proven REAL (both reviewers reconstructed all 4 historical recurrences -> guard FLAGS them); same-artifact dedup breaks no legit claim + forced an honest bmp_token_whitebox §9 confirmed->likely; redaction leak-safe; js_bundle_map citation correct. P1 frame-word looseness (latent, tree unaffected) -> TASK-0038.
<!-- SECTION:NOTES:END -->
