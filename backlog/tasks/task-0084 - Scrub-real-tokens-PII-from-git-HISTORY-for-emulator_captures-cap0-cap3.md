---
id: TASK-0084
title: Scrub real tokens/PII from git HISTORY for emulator_captures/cap0-cap3
status: To Do
assignee: []
created_date: '2026-06-28 12:52'
updated_date: '2026-06-29 10:48'
labels:
  - security
  - hygiene
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cap0-cap3 were committed (tracked) in an earlier commit and contain real Tuya JWTs/tokens and many email-shaped lines (flows.json/flows.full.txt/flows.mitm). They are now untracked + gitignored (local-only, like cap4/cap5 + secrets/) so they will not appear in NEW commits, but the values REMAIN in git history. Before this repo is ever pushed to any non-private remote, scrub history (git filter-repo / BFG to drop emulator_captures/ from all past commits) and force-update. Until then: do NOT push. Flagged by mped-architect + qa-test-runner during the TASK-0081 commit review.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 emulator_captures/ paths are absent from all git history (git log --all -- emulator_captures returns nothing)
- [ ] #2 just secret-scan + a history scan confirm no real token/PII remains reachable from any ref
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Executed as part of TASK-0111: a single git-filter-repo run removes emulator_captures/ from all history (this task AC#1) AND redacts the 3 worktree-scrubbed values (media key / srflx / owner email) in the same pass. A blind history content scan (TASK-0111) confirmed the full personal-secret scope (only emulator_captures + those 3). Track execution + verification in TASK-0111; close both together after the rewrite. Kept To Do until the rewrite runs.
<!-- SECTION:NOTES:END -->
