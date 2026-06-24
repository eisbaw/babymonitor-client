---
id: TASK-0016
title: 'RE-PLAN: plan Wave 2 from Wave-1 knowledge (not feature code)'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
labels:
  - phase-gate
  - replan
  - wave1
dependencies:
  - TASK-0015
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

Re-plan task - NOT feature code. Re-invoke Skill phase2-backlog-snowball with: re/prd.md, TESTING.md, and the Wave-1 lessons/notes - ESPECIALLY the task-10 P2P feasibility verdict {recoverable-statically | partially | needs-live-capture} and the cloud-auth/pairing docs. Plan Wave 2 to the depth the new knowledge now supports (e.g. Rust P2P transport + media decode/display + two-way audio if P2P is feasible; otherwise a narrowed scope + the exact evidence needed). Write no implementation in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wave-2 tasks exist in the tracker, dependency-ordered and test-grounded
- [ ] #2 Wave 2 again ends with its own re-plan task UNLESS the project is now firm enough for a full breakdown
- [ ] #3 TESTING.md updated with what Wave 1 taught (especially the real P2P verdict and any new oracles)
<!-- AC:END -->
