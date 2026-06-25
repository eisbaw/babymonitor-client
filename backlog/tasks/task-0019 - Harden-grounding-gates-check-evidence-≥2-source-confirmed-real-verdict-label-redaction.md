---
id: TASK-0019
title: >-
  Harden grounding gates (check-evidence ≥2-source confirmed, real verdict
  label, redaction)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-24 23:16'
updated_date: '2026-06-25 00:55'
labels:
  - phase5
  - rust
  - wave1
  - gates
  - review-followup
dependencies:
  - TASK-0011
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, TESTING.md, re/review_gate_findings.md; invoke Skill android-app-reverser. Use nix-shell --run for tools. Never write a secret into a doc/task/summary.

FROM cycle-1 review of TASK-0011 (re/review_gate_findings has context). Three precise gate-correctness fixes, each WITH a self-test that proves the new rule bites:
- P1-1 check_evidence.py (~:199-205): when a section confidence label is `confirmed`, require >=2 distinct citation tokens (path AND/OR >=2 named refs); TESTING.md:28-29 says single-source confirmed is BAD. Add self-test: confirmed+single-citation MUST flag.
- P1-2 check_evidence.py (~:127-128,240-258): VERDICT_RE must anchor to a LABEL form (e.g. ^\s*(\*\*)?Verdict(\*\*)?\s*[:=]\s*(recoverable-statically|partially|needs-live-capture)), not bare-word prose; add negative self-test that prose "partially" does NOT count.
- P1-3 secret_scan.sh (~:96-99): redaction prints up to 72 chars (comment says 6) -> echoes real secrets into hook/CI logs. Redact to a true short prefix + [REDACTED N chars]; never print the value region.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 P2P verdict gate requires a labelled Verdict: <token> line; prose 'partially' does NOT satisfy it; zero/one/many self-tests updated
- [x] #2 secret-scan redaction never prints more than a short prefix of a matched secret; self-test asserts the full value is not echoed
- [x] #3 just e2e + just gates-selftest green after changes; no regression to existing self-tests
- [x] #4 check-evidence flags a section whose confidence label is confirmed but which has only ONE citation; self-test proves it (confirmed+1 citation -> FLAG, confirmed+2 distinct citations -> PASS)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. P1-1: check_evidence.py confirmed=>require >=2 distinct citation tokens (path-citation counts; named-refs count; need 2 distinct). Add count_citations(). Self-test confirmed+1=>FLAG, confirmed+2=>PASS.
2. P1-2: replace VERDICT_RE with labelled-form anchored multiline regex. Update zero/one/many selftests + negative prose test.
3. P1-3: secret_scan.sh redact to short prefix (first 5 chars)+[REDACTED N chars]; selftest asserts full planted value not in output.
4. Cycle-2 doc nits in decompile_dex.md: scope confirmed headers to presence; footnote resendOffer=>WebRTC to native dynsym; downgrade 302 to likely; add just-decompile note in each re/ analysis doc.
5. Run gates-selftest (show RED-on-bad), e2e.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CYCLE-2 REVIEW add-ons (fold into this pass, both reviewers GO on tasks 1-4): (a) re/decompile_dex.md:76/:85 — split the blanket 'confidence: confirmed' header so it covers symbol/method PRESENCE only; the inline 'resendOffer => confirms WebRTC' inference should footnote the native dynsym cross-ref (it IS >=2-source) rather than ride the confirmed label. (b) re/decompile_dex.md:88 — '302 = Tuya camera-signaling code' is single-source (Java method names only); downgrade to 'likely' or cite where 302 is decoded. (c) one-line note in each re/ doc that Java :line citations require a local 'just decompile' (jadx tree is gitignored). (d) publish-scrub later: re/native_libs.md:18/:86 leak upstream devs' build paths (not our PII) — note for task-5 AC#5 scope.

IMPLEMENTED (commit 3f4b623, single atomic commit with TASK-0018 — see below for why).

P1-1 (confirmed>=2 sources): added distinct_citations()/is_confirmed() in check_evidence.py; confirmed label now needs >=2 DISTINCT citation tokens (case-folded dedup so one source written twice does NOT count). Self-test added: confirmed+1->FLAG, confirmed+2->PASS. Proven RED-on-bad live.

P1-2 (labelled verdict): VERDICT_RE rewritten to ^\s*(\*\*)?Verdict(\*\*)?\s*[:=]\s*(token), MULTILINE. Bare prose "partially" no longer counts. Added negative prose self-test + updated zero/one/many.

P1-3 (redaction): secret_scan.sh redaction was cut -c1-72 (could leak whole secret). Now 5-char prefix + [REDACTED N chars]. Self-test asserts full planted value absent from output.

GOTCHA 1 (root-cause fix, not a workaround): scan_worktree had a LATENT bug — when an untracked binary file (e.g. __pycache__/*.pyc created by running the python lint) was concatenated into the scan stream, a NUL byte flipped GNU grep into "binary file matches" mode and SUPPRESSED per-line output, so a real secret next to a binary file went UNREPORTED. Fixed with grep -a (text mode) + skip *.pyc/__pycache__. This is why the worktree self-test was failing intermittently. Added __pycache__/ + *.pyc to .gitignore.

GOTCHA 2: outside nix-shell the system grep is ugrep 7.5.0, NOT GNU grep — flags differ. ALWAYS run via nix-shell (just secret-scan). Direct bash runs of secret_scan.sh will misbehave.

GOTCHA 3: the secret pattern requires >=16 CONTIGUOUS [A-Za-z0-9] after the field separator. A demo fixture with underscores breaking the run (e.g. FAKEDEMOvalue_DEAD...) will NOT match — use a contiguous alnum value when demoing.

CYCLE-2 doc nits: decompile_dex.md confirmed headers scoped to PRESENCE; resendOffer=>WebRTC footnoted to native dynsym (>=2-source); 302 downgraded to likely. Added "Java :line needs local just decompile" note to decompile_dex/native_libs/js_bundle_map/manifest_analysis. Added a REAL `just decompile` recipe (the cited command must exist — APK present at extracted/xapk/).

GOTCHA 4 (scope creep, honest): the new >=2-source rule surfaced PRE-EXISTING single-citation `confirmed` sections in 3 OTHER docs (decompile_dex, js_bundle_map, native_libs). I added genuine second sources rather than weaken the lint. This is correct but means TASK-0019 touched more docs than its title implies.

WHY ONE COMMIT: emptying BASELINE_WAIVERS (0018) requires the baseline docs already rewritten AND the stricter lint present; splitting would leave an intermediate commit with stale waivers / failing check-evidence. Atomic commit keeps every gate green per-commit.

Cycle-3 review: both GO. Gates verified genuinely stronger (live-proven bites), relabels honest, NUL-byte grep -a fix increases detection. P2 nits -> TASK-0020 (low).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Hardened the three grounding gates so each can demonstrably go RED, and folded the cycle-2 doc nits.

What changed:
- check_evidence.py: `confirmed` now requires >=2 distinct citations (rule 4b); P2P verdict gate requires a labelled `Verdict: <token>` line (bare prose rejected). New self-tests: confirmed+1->FLAG/confirmed+2->PASS, and a negative bare-prose verdict test.
- secret_scan.sh: redaction reduced from cut -c1-72 to 5-char prefix + [REDACTED N chars] (never prints the value); self-test asserts the full planted value is absent. Root-caused and fixed a latent miss where a NUL byte from an adjacent binary file silenced grep (now grep -a + skip *.pyc/__pycache__).
- Justfile: added a reproducible `just decompile` recipe so the new citation note is true.
- decompile_dex.md: confirmed headers scoped to symbol PRESENCE; resendOffer=>WebRTC footnoted to the native dynsym cross-ref; 302 claim downgraded to `likely`. Added a local-`just decompile` note to all 4 analysis docs.

Tests: just gates-selftest GREEN; new rules proven RED-on-bad live; just e2e GREEN.

Risk/follow-up: the >=2-source rule surfaced single-citation `confirmed` sections in 3 other docs — fixed in the same commit with genuine second sources. No lint weakening.
<!-- SECTION:FINAL_SUMMARY:END -->
