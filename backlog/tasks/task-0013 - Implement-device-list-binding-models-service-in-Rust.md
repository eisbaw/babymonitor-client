---
id: TASK-0013
title: Implement device list/binding models + service in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 00:23'
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
- [ ] #3 PROVE THE CHECK BITES: a negative test asserts the parser REJECTS/surfaces an error on a malformed device entry (missing camera P2P-credential handle / wrong type); the camera entry asserts required (non-Option) invariants (device id, p2p creds handle) so it is not a permissive serde sponge
- [ ] #4 ANONYMIZE: any device-list JSON quoted in re/*.md, notes, or summaries has uid/homeId/localKey/gwId/email/GPS/IP replaced with synthetic placeholders; a sanitized committable fixture is produced and tests run against it; localKey + P2P creds treated as secrets
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from TASK-0003/0004: Device-list/binding model field names seen in JS bridge schemas (decompiled/js/assets/thing_uni_plugins): startDeviceActivate carries devId/pid/uuid/mac/localKey (currentMeshBean.localKey); CloudStorageSignatureManager.generateSignedUrl uses sk/ak/bucket/region/endpoint/token. Camera connect uses deviceId. localKey + P2P creds are SECRETS - anonymize fixtures before any committed file (CLAUDE.md rule). P2P session beans: com/thingclips/smart/camera/ipccamerasdk/bean/ (CameraInfoBean, DeviceAbilityBean, AudioParams).
<!-- SECTION:NOTES:END -->
