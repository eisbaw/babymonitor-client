---
id: TASK-0011
title: 'Scaffold Rust workspace, Justfile, and grounding gates'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-24 22:45'
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
