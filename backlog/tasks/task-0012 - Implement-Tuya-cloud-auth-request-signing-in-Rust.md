---
id: TASK-0012
title: Implement Tuya cloud auth + request signing in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
labels:
  - phase5
  - rust
  - wave1
  - auth
dependencies:
  - TASK-0011
  - TASK-0007
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: the first genuinely buildable+testable slice. Implement Tuya HMAC request signing, account login, token issue/refresh, datacenter base-URL selection in babymonitor-core, per re/tuya_cloud_auth.md. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::auth signs requests; a differential unit test reproduces the captured signing vector from task 7 byte-for-byte (this gate bites with no network)
- [ ] #2 Token store persists to ~/.local/share/babymonitor/; refresh-before-expiry covered by a unit test; no unflagged stubs
<!-- AC:END -->
