---
id: TASK-0001
title: Decompile all DEX with jadx into searchable Java
status: To Do
assignee: []
created_date: '2026-06-24 22:34'
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

WHY: 14 multidex files (~190MB) hold the Java/Kotlin half of this Tuya-reskin app. A clean jadx decompile under decompiled/jadx is the substrate every later static-analysis task searches. Delegate to an Explore/general-purpose subagent (large output).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All classes*.dex from extracted/xapk base APK decompiled to decompiled/jadx (jadx -Xmx4g), with a short re/decompile_dex.md noting jadx failures/obfuscation coverage
- [ ] #2 Package-level map produced: com.tuya/com.thingclips namespaces, Philips packages, React Native bridge packages — counts + where the Tuya camera/P2P/auth code lives
- [ ] #3 decompiled/ stays gitignored; only the summary md is committed
<!-- AC:END -->
