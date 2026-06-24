---
id: TASK-0013
title: Implement device list/binding models + service in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
labels:
  - phase5
  - rust
  - wave1
  - device
dependencies:
  - TASK-0012
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: lets the client discover the SCD921 under the Tuya account - prerequisite for any streaming. Implement typed models + service from re/tuya_cloud_auth.md, serde camelCase, liberal Option/default. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::device lists devices and exposes the camera entry (id, p2p creds handles, online state); fixture test deserializes a real/representative device-list JSON (stored in secrets/) without error
- [ ] #2 Model mismatches found vs real shape are fixed; honest notes on any field whose meaning is still unknown
<!-- AC:END -->
