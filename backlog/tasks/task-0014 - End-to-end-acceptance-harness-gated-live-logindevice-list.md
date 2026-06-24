---
id: TASK-0014
title: 'End-to-end acceptance harness: gated live login+device-list'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-24 22:47'
labels:
  - phase7
  - test
  - wave1
  - e2e
dependencies:
  - TASK-0013
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

UX/E2E TASK (skill phase 7). Wire the gold-oracle acceptance signal from TESTING.md: a #[ignore] live test + a CLI path (babymonitor-cli auth login; devices list) that runs against the user real Tuya account/SCD921. Document the manual auth setup. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 babymonitor-cli supports auth login + devices list with human and --json output; showcase includes the read-only commands
- [ ] #2 An #[ignore]d live e2e test exists with documented setup (creds from secrets/); README snippet explains how the user runs it against the real camera
- [ ] #3 Live calls rate-limited/single-shot; just e2e (offline) excludes the live test; README documents authorized scope = user's own account + device only
<!-- AC:END -->
