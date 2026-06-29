---
id: TASK-0111
title: >-
  Run git-filter-repo to purge scrubbed secrets/PII from git HISTORY — gated on
  post-refactor validation
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-29 09:55'
updated_date: '2026-06-29 10:48'
labels:
  - security
  - hygiene
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After the worktree scrub (TASK-0109 follow-up), three real values were removed from tracked source but REMAIN in git history: (1) the cap3 per-session media AES key formerly inlined in babymonitor-core/src/stream/sdp.rs; (2) the cap4 srflx public IP formerly inlined in babymonitor-core/src/stream/media/stun.rs; (3) the owner email in the secret-scan allowlist, formerly tracked at re/scripts/secret_scan.sh (now relocated under secrets/, gitignored). HEAD no longer exposes these (media key + srflx are now runtime-resolved; test values are synthetic/RFC5737), but the old commits still do. Once the refactored client is validated to still log in and stream end-to-end, run git-filter-repo (or BFG) to purge these values from ALL history and force-update. Combine in ONE rewrite with TASK-0084 (emulator_captures/cap0-cap3 raw flow blobs already in history). HARD GATE: do NOT push to any non-private remote until done. No secret VALUE appears in this task — locations only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Precondition met BEFORE any rewrite: refactored client validated working end-to-end (login + live A/V stream + just e2e green); evidence captured in notes
- [ ] #2 git-filter-repo removes from ALL history the former sdp.rs cap3 media key, the former stun.rs cap4 srflx IP, and the owner email in the old re/scripts/secret_scan.sh path (referenced by location, never reproduced here)
- [ ] #3 The emulator_captures/cap0-cap3 history scrub (TASK-0084 scope) is performed in the SAME rewrite: git log --all -- emulator_captures returns nothing
- [ ] #4 A history CONTENT scan (git log -p --all through the secret patterns, or gitleaks/trufflehog history mode) confirms none of the scrubbed values remain reachable from any ref
- [ ] #5 just secret-scan green + history scan green; repo safe to push; force-update coordinated
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Blind history content scan to lock scope (DONE)
2. Add git-filter-repo to shell.nix (DONE)
3. Build secrets/scan/replace_spec.txt from the 3 history values (DONE)
4. PREREQ: commit TASK-0112 worktree scrub after qa+architect review
5. Backup .git, then: git filter-repo --force --invert-paths --path emulator_captures/ --replace-text secrets/scan/replace_spec.txt
6. Verify: git log --all -- emulator_captures empty; re-run blind scan -> 0 hits; secret-scan GREEN
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope LOCKED via blind scan of all 132 commits: personal secrets in history = emulator_captures/cap1-3 (flows/signaling/DECRYPT.md/TRAFFIC.md, 5 commits) + owner email (re/scripts/secret_scan.sh, full history) + C1 media key (sdp.rs history) + C2 srflx (stun.rs history). NOTHING outside emulator_captures otherwise — no token/localKey/devId/uid/GPS ever entered a tracked doc or task field. Prepped: git-filter-repo in shell.nix (verified); gitignored secrets/scan/{personal_secrets,app_secrets,replace_spec}.txt built (replace_spec = the 3 redactions). Absorbs TASK-0084. Ready command in plan step 5; awaiting go (irreversible: rewrites all 132 commit hashes).
<!-- SECTION:NOTES:END -->
