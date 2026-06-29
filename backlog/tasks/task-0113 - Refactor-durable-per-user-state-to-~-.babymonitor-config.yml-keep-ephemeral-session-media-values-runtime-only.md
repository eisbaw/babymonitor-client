---
id: TASK-0113
title: >-
  Refactor durable per-user state to ~/.babymonitor/config.yml; keep ephemeral
  session/media values runtime-only
status: To Do
assignee: []
created_date: '2026-06-29 10:47'
updated_date: '2026-06-29 10:55'
labels:
  - re
  - config
  - hygiene
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Per the KEEP-vs-scrub classification (secrets/pii_secret_consolidated_inventory.md, TASK-0112): APK-recoverable app constants stay public; DURABLE per-user state (account email + password-or-token, uid, devId, localKey, homeId, region selector) should load from a gitignored ~/.babymonitor/config.yml instead of ad-hoc secrets/*.json. EPHEMERAL per-session/per-network values (sid, session/media keys, ICE creds, srflx) stay runtime-derived and are NEVER persisted. These values are already gitignored (not a commit risk), so this is a design/UX refactor, not a leak fix. Locations/field-names only; no VALUE in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Client loads account creds + device selection (devId/localKey/homeId/uid/region) from ~/.babymonitor/config.yml
- [ ] #2 Ephemeral session/media/ICE/srflx values are runtime-derived and never written to disk or committed
- [ ] #3 Home GPS is not persisted (client does not need it to stream)
- [ ] #4 just secret-scan + just e2e remain GREEN
<!-- AC:END -->
