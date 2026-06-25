---
id: TASK-0019
title: >-
  Harden grounding gates (check-evidence ≥2-source confirmed, real verdict
  label, redaction)
status: To Do
assignee: []
created_date: '2026-06-24 23:16'
updated_date: '2026-06-25 00:30'
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
- [ ] #1 P2P verdict gate requires a labelled Verdict: <token> line; prose 'partially' does NOT satisfy it; zero/one/many self-tests updated
- [ ] #2 secret-scan redaction never prints more than a short prefix of a matched secret; self-test asserts the full value is not echoed
- [ ] #3 just e2e + just gates-selftest green after changes; no regression to existing self-tests
- [ ] #4 check-evidence flags a section whose confidence label is confirmed but which has only ONE citation; self-test proves it (confirmed+1 citation -> FLAG, confirmed+2 distinct citations -> PASS)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CYCLE-2 REVIEW add-ons (fold into this pass, both reviewers GO on tasks 1-4): (a) re/decompile_dex.md:76/:85 — split the blanket 'confidence: confirmed' header so it covers symbol/method PRESENCE only; the inline 'resendOffer => confirms WebRTC' inference should footnote the native dynsym cross-ref (it IS >=2-source) rather than ride the confirmed label. (b) re/decompile_dex.md:88 — '302 = Tuya camera-signaling code' is single-source (Java method names only); downgrade to 'likely' or cite where 302 is decoded. (c) one-line note in each re/ doc that Java :line citations require a local 'just decompile' (jadx tree is gitignored). (d) publish-scrub later: re/native_libs.md:18/:86 leak upstream devs' build paths (not our PII) — note for task-5 AC#5 scope.
<!-- SECTION:NOTES:END -->
