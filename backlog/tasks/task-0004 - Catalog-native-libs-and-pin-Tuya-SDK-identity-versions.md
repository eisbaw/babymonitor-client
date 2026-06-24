---
id: TASK-0004
title: Catalog native libs and pin Tuya SDK identity/versions
status: To Do
assignee: []
created_date: '2026-06-24 22:35'
labels:
  - phase3
  - re
  - wave1
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 2/3): the .so set is the ground truth of the stack. Need each Tuya lib version, exported symbols, and embedded strings to cross-reference public Tuya RE. Delegate to Explore subagent; use nm/readelf/strings/radare2.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/native_libs.md tables every lib/arm64-v8a/*.so with size, SONAME, detected version strings, and role; Tuya libThingP2PSDK/CameraSDK/VideoCodec/AudioEngine/SmartLink versions pinned where present
- [ ] #2 Exported-symbol dumps saved to analysis/ for the P2P/camera/codec libs; obvious crypto (OpenSSL 1.1, libthing_security) and their algorithms noted
<!-- AC:END -->
