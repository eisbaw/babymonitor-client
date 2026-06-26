---
id: TASK-0066
title: 'secret-scan RED: tracked emulator_captures dumps leak real tokens/emails/JWTs'
status: To Do
assignee: []
created_date: '2026-06-26 11:28'
updated_date: '2026-06-26 15:20'
labels:
  - auth
  - secrets
  - hygiene
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just secret-scan fails with ~215 findings, ALL from the TRACKED emulator_captures/cap0+cap1 mitm dumps (flows.full.txt/.mitm/.json): real authToken JWTs + email-shaped hex byte-sequences. These wire dumps carry live account secrets and PII and must not stay in tracked files. Pre-existing condition discovered during TASK-0065 (not introduced by it). Options: gitignore + remove from tracking the raw dumps and keep only a redacted/anonymized extract under re/, or move the raw dumps under secrets/. The cap1 flows.json is needed for offline validation (decrypt_capture_login.py), so any move must preserve a gitignored working copy. secret-scan must go GREEN after.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 secret-scan passes (exit 0) with no findings from tracked capture files
- [ ] #2 cap1 flows.json still available (gitignored/secrets) for re/scripts/decrypt_capture_login.py offline validation
- [ ] #3 No real token/email/JWT remains in any git-tracked file
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
cap0 = clean pre-login capture (hits US node a1-us.iotbing.com); cap1 = full login+sync (token.get on a1.tuyaeu.com, DC switches to EU after password.login), 76 flows. Both carry real PII (authToken JWTs, email-shaped sequences) and must be gitignored/quarantined before any push.
<!-- SECTION:NOTES:END -->
