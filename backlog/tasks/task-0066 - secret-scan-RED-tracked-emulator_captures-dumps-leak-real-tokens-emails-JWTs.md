---
id: TASK-0066
title: 'secret-scan RED: tracked emulator_captures dumps leak real tokens/emails/JWTs'
status: Done
assignee: []
created_date: '2026-06-26 11:28'
updated_date: '2026-06-29 10:48'
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
- [x] #1 secret-scan passes (exit 0) with no findings from tracked capture files
- [x] #2 cap1 flows.json still available (gitignored/secrets) for re/scripts/decrypt_capture_login.py offline validation
- [x] #3 No real token/email/JWT remains in any git-tracked file
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RESOLVED in the worktree: emulator_captures/ is fully gitignored + UNTRACKED (git ls-files emulator_captures = 0) and just secret-scan is GREEN (exit 0) — no real token/email/JWT remains in any TRACKED file. cap1/flows.json remains on disk under emulator_captures/ (gitignored) for offline validation (decrypt_capture_login.py). The ~215-finding RED condition this task described no longer exists in the worktree. RESIDUAL exposure is git HISTORY only (5 commits) -> handled by TASK-0084 / TASK-0111 (combined git-filter-repo rewrite).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Resolved: the tracked cap0/cap1 mitm dumps were gitignored + removed from tracking; just secret-scan is GREEN and no real token/email/JWT sits in any tracked file. cap1 flows.json stays available (gitignored) for offline validation. Remaining git-HISTORY residue is tracked by TASK-0084/TASK-0111. No values reproduced.
<!-- SECTION:FINAL_SUMMARY:END -->
