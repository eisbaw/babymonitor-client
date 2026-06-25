---
id: TASK-0015
title: 'REVIEW GATE: Wave-1 code + analysis (mped-architect + qa-test-runner)'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 06:22'
labels:
  - phase-gate
  - review
  - wave1
dependencies:
  - TASK-0012
  - TASK-0013
  - TASK-0014
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WAVE-1 GATE (read-only). Run mped-architect (architecture/honesty) and qa-test-runner (just e2e + just showcase) in PARALLEL over everything Wave-1 landed. Verify TESTING.md gates actually bite (corrupt-input tests exist), no unflagged stubs, claims grounded. File findings as fix tasks. No production code here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/review_wave1_gate.md records both reviews; just e2e and just showcase results pasted; every issue filed as a task
- [ ] #2 Go/No-go for Wave 2 stated, keyed off the task-10 P2P feasibility verdict
- [ ] #3 just secret-scan green over committed files + backlog/tasks/*.md; just e2e run with network disabled stays green (live tests are #[ignore]d)
- [ ] #4 All P0/P1 fix-tasks from task 6 and this gate are closed or consciously deferred with reason before Go for Wave 2
<!-- AC:END -->
