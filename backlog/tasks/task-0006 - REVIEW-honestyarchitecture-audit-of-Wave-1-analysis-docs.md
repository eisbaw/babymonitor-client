---
id: TASK-0006
title: 'REVIEW: honesty+architecture audit of Wave-1 analysis docs'
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
labels:
  - phase-gate
  - review
  - wave1
dependencies:
  - TASK-0001
  - TASK-0002
  - TASK-0003
  - TASK-0004
  - TASK-0005
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

REVIEW TASK (read-only). Run mped-architect over re/*.md produced so far. Check: every protocol/auth claim has confidence+evidence per TESTING.md; cross-source contradictions (JS vs Java vs native) are recorded not hidden; no adjective-only claims; scope still matches PRD. Output findings as NEW backlog tasks. Write no production code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/review_wave1_analysis.md written with findings; each ungrounded/contradictory claim filed as a fix task
- [ ] #2 just check-evidence (once it exists) passes over committed re/*.md, or gaps are filed as tasks
<!-- AC:END -->
