---
id: TASK-0008
title: Map device pairing + WiFi provisioning (SmartLink/AP/QR)
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
labels:
  - phase5
  - re
  - wave1
  - pairing
dependencies:
  - TASK-0001
  - TASK-0003
  - TASK-0005
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY: to add a camera the app provisions WiFi (Tuya EZ/AP SmartLink via libThingSmartLink) and binds via a pairing token from cloud; QR via ML Kit. Model the full pairing handshake. Delegate to general-purpose subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/pairing_flow.md documents: pairing-token request, EZ vs AP SmartLink packet/UDP scheme, the QR payload format, and the bind-confirm polling — evidence+confidence; honestly flags any part only in native code
- [ ] #2 Identifies which steps are mandatory for an already-paired camera (our case) vs first-time setup, so the Rust client can target the minimal path first
<!-- AC:END -->
