---
id: TASK-0011
title: 'Scaffold Rust workspace, Justfile, and grounding gates'
status: In Progress
assignee:
  - '@orchestrator'
created_date: '2026-06-24 22:37'
updated_date: '2026-06-24 23:09'
labels:
  - phase5
  - rust
  - wave1
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 5/6): create the babymonitor/ cargo workspace (babymonitor-core + babymonitor-cli) plus the Justfile gates TESTING.md depends on. Implement with mped-architect. Keep deps minimal (reqwest, serde, tokio, hmac/sha2, aes, thiserror, clap).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 babymonitor/ workspace builds; Justfile has build/test/lint/fmt/fmt-check/e2e/run/showcase; just e2e is green on the empty skeleton
- [ ] #2 just check-evidence implemented (lint over re/*.md: fails a section with a protocol claim lacking a confidence label or evidence citation) and is green or filing gaps
- [ ] #3 just showcase runs the (currently trivial) CLI without panic
- [ ] #4 just secret-scan exists, scans tracked files + git diff + backlog/tasks/*.md for Tuya appKey/appSecret/token/email/GPS/known IDs, and FAILS on a planted fake secret (prove the check bites); wired into a pre-commit/pre-push path
- [ ] #5 check-evidence ships WITH a fixtures test: a planted bad re/ fragment (adjective claim, no citation) it MUST flag, and a good fragment it MUST pass; claim lexicon pinned (endpoint|HMAC|sign|token|magic|offset|packet|frame|handshake|port|AES|key)
- [ ] #6 check-evidence also asserts re/p2p_protocol.md (when present) contains exactly one literal verdict token {recoverable-statically|partially|needs-live-capture}
- [ ] #7 just e2e includes a stub-grep gate failing on todo!(/unimplemented!(/unreachable!( outside #[cfg(test)]; and just e2e runs green with no network access (proving live tests are #[ignore]d)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Create babymonitor/ cargo workspace: babymonitor-core (lib) + babymonitor-cli (bin, clap). Minimal deps; trivial CLI with --version + no-op subcommand.
2. Add re/scripts/check_evidence.py: lint re/*.md by heading-section. Section body matching claim lexicon (endpoint|HMAC|sign|token|magic|offset|packet|frame|handshake|port|AES|key) MUST have a confidence token (confirmed|likely|speculative) AND an evidence citation (path:NN, lib*.so@0x, JS path, URL/named ref). Assert re/p2p_protocol.md (when present) has exactly one verdict {recoverable-statically|partially|needs-live-capture}. Ship fixtures self-test (planted GOOD passes, BAD flagged).
3. Add re/scripts/secret_scan.sh: grep tracked files + git diff (staged+unstaged) + backlog/tasks/*.md for Tuya appKey/appSecret/bearer/JWT/email/GPS. Self-test proves it bites on planted fake secret.
4. Justfile at root: build/test/lint/fmt/fmt-check/e2e/run/showcase/check-evidence/check-evidence-selftest/secret-scan/secret-scan-selftest. e2e = build+test+lint+fmt-check + stub-grep gate (todo!/unimplemented!/unreachable! outside cfg(test)) + offline assertion. Tools via nix-shell.
5. Run existing re/*.md through check-evidence; if flagged, fix doc or lint correctness (file follow-up if real gap).
6. Verify all gates green; prove each bites (red on bad, green on clean).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- Workspace builds (cargo 1.91); 2 crates: babymonitor-core (lib, thiserror) + babymonitor-cli (bin, clap). Trivial info subcommand + --json + --version for showcase.
- GOTCHA (offline AC#7): cargo build/test do touch the registry on a COLD cache; the nix shell pre-caches, so e2e is offline in steady state. Proven via CARGO_NET_OFFLINE=true just e2e (green) and an assert-offline recipe (cargo test --offline --list). A truly cold checkout would need cargo vendor; out of scope, noted honestly.
- GOTCHA (check-evidence section model): a section is the heading SUBTREE (until next equal/higher heading); confidence/citation may live in a child. Heading TITLE is searched too (docs carry (confidence: likely) in headings). prd.md is EXCLUDED (it is a requirements doc, not a protocol-claims doc per TESTING.md Part1).
- GOTCHA (confidence false-pass): canonical tokens only count as LABELS (confidence:/bold/paren/trailing), NOT prose like "most likely" — else milestone2 would false-pass.
- DECISION: named public refs (tinytuya/localtuya/...) count as citations per TESTING.md. Pinned list in NAMED_REFS.
- BASELINE WAIVER RATCHET: 6 pre-existing gaps in milestone2_findings.md (non-canonical confidence words) + review_gate_findings.md meta-section are WAIVED (reported, not failing) and tracked in TASK-0018. New ungrounded sections still FAIL (ratchet self-test proves it). check-evidence is GREEN with 6 waived.
- GOTCHA (secret-scan untracked files): scanning only tracked files + git diff MISSED brand-new untracked files (all of babymonitor/). Fixed scan_worktree to include git ls-files --others --exclude-standard. Self-test now plants an untracked file and asserts it is flagged.
- GOTCHA (self-scanning): worktree scan flags the scanners OWN fixture literals. Solved with inline # secret-scan:allow marker (greppable, auditable; only marked lines exempt). Markers are shell COMMENTS so runtime fixture files lack them and are still flagged.
- FIX: untracked .claude/scheduled_tasks.lock contained a harness sessionId — git rm --cached + gitignored (.claude/*.lock).
- ERE bug fixed: [:space:] mis-nested; correct is [[:space:]]. grep -i needed for camelCase appKey/appSecret. Guarded by self-test.
- pre-push hook (re/scripts/pre-push) runs secret-scan + e2e; install via just install-hooks (symlink).
<!-- SECTION:NOTES:END -->
