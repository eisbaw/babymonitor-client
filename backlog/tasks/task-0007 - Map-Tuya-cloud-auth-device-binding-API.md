---
id: TASK-0007
title: Map Tuya cloud auth + device-binding API
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
labels:
  - phase4
  - re
  - wave1
  - auth
dependencies:
  - TASK-0001
  - TASK-0003
  - TASK-0005
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 3/4): model the request/response contract for account login, token issuance/refresh, datacenter selection, and device list/binding. Source = decompiled Tuya SDK (com.thingclips.*) + JS bridge calls + recovered appKey. Produce a protocol doc the Rust auth crate implements against. Delegate to general-purpose subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/tuya_cloud_auth.md: endpoints, the HMAC request-signing scheme (param canonicalization, headers, nonce/time), token model, refresh, and the device-list/binding response shape — each with evidence+confidence
- [ ] #2 A signing test vector (fixed inputs -> expected signature) is captured for the later Rust differential test; PII-free
<!-- AC:END -->
