---
id: TASK-0002
title: 'Decode manifest, permissions, and app components (apktool)'
status: To Do
assignee: []
created_date: '2026-06-24 22:35'
labels:
  - phase2
  - re
  - wave1
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 2): AndroidManifest + resources reveal services/activities/receivers, the permission set (camera/mic/location/local-network), exported components, deep links and any custom URI schemes used for pairing/login. Delegate to Explore subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decompiled/apktool produced from base APK; re/manifest_analysis.md lists permissions, all services/activities/receivers, intent-filters, deep-link schemes, and flags anything network/pairing-relevant
- [ ] #2 Tuya/RN service entry points (push, P2P, camera foreground service) identified with class names
<!-- AC:END -->
