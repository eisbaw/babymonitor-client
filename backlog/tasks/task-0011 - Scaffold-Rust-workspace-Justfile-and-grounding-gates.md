---
id: TASK-0011
title: 'Scaffold Rust workspace, Justfile, and grounding gates'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
labels:
  - phase5
  - rust
  - wave1
  - foundation
dependencies:
  - TASK-0006
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
<!-- AC:END -->
