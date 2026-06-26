---
id: TASK-0067
title: >-
  Unify+sharpen camera detection: core parse_device_array + SCD921
  disambiguation
status: To Do
assignee: []
created_date: '2026-06-26 13:53'
labels:
  - device
  - streaming
  - refactor
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Architect review of the device-discovery wiring: (1) live inspect_device_list scans raw JSON while core DeviceBean::is_camera/skills_p2p_type is unused on the live path -> two impls of one rule will drift. Teach core a parse_device_array for the bare v2.2 array and have inspect_device_list reuse the typed is_camera. (2) Detection picks the FIRST camera by category/p2pType with no SCD921 disambiguation; a multi-camera account could pick the wrong device. For the streaming phase, match the right camera by productId (kzm54lhabeeucq5a) / name and pull ITS devId/localKey/p2pKey.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Core parses the bare v2.2 device array; live inspect_device_list reuses the single typed is_camera/skills_p2p_type (no duplicate rule)
- [ ] #2 Camera selection disambiguates the SCD921 by productId/name, not first-match
- [ ] #3 Returns the chosen camera devId (shape) for the streaming phase; secrets stay in secrets/
<!-- AC:END -->
