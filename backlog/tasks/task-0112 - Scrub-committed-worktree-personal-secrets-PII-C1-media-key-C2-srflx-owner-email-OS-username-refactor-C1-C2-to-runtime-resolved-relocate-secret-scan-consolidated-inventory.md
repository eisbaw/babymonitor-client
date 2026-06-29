---
id: TASK-0112
title: >-
  Scrub committed-worktree personal secrets/PII (C1 media key, C2 srflx, owner
  email, OS username) + refactor C1/C2 to runtime-resolved; relocate
  secret-scan; consolidated inventory
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-29 10:47'
updated_date: '2026-06-29 10:47'
labels:
  - re
  - security
  - pii
  - hygiene
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Remediation of the COMMITTABLE-surface findings from TASK-0109 (worktree only; the git-history rewrite is TASK-0111). Removes the only real personal values that were in TRACKED source: (C1) the cap3 per-session media AES key inlined in babymonitor-core/src/stream/sdp.rs — now a synthetic test vector, production resolves it at runtime via extract_aes_key; (C2) the cap4 srflx public IP inlined in babymonitor-core/src/stream/media/stun.rs — now an RFC5737 doc address, production decodes it at runtime from XOR-MAPPED-ADDRESS. Also relocate re/scripts/secret_scan.sh (owner-email allowlist) under secrets/ (gitignored) and repoint the Justfile; scrub the OS username from re/media_decode_spec.md; produce secrets/pii_secret_consolidated_inventory.md (location-only map + KEEP-vs-scrub classification: APK-recoverable app constants are public and KEPT; per-account/session/device values are scrubbed/refactored). Locations only; no secret VALUE in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 C1 cap3 media key removed from src/stream/sdp.rs; test uses a synthetic key annotated as synthetic; production resolves the key at runtime (extract_aes_key)
- [x] #2 C2 cap4 srflx public IP removed from src/stream/media/stun.rs; test uses an RFC5737 doc address annotated as such; production decodes srflx at runtime
- [x] #3 secret_scan.sh relocated under secrets/ (owner-email allowlist no longer a tracked file); Justfile secret-scan/-selftest repointed; gate still GREEN from new location and selftest still bites
- [x] #4 OS username path removed from all tracked files (re/media_decode_spec.md)
- [x] #5 secrets/pii_secret_consolidated_inventory.md produced (location-only) with KEEP (public app constants) vs SCRUB/refactor (personal) classification
- [x] #6 just e2e and just secret-scan both GREEN after the changes
- [ ] #7 Changes committed after the mandated qa-test-runner + mped-architect review gate
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Scrub C1 (sdp.rs) + C2 (stun.rs) -> synthetic/runtime, annotate as synthetic
2. Move secret_scan.sh under secrets/, repoint Justfile, verify gate+selftest
3. Scrub OS username from re/media_decode_spec.md
4. Write secrets/pii_secret_consolidated_inventory.md (location-only + KEEP/SCRUB)
5. Validate: just e2e + just secret-scan GREEN
6. Commit after qa-test-runner + mped-architect review (AC#7)
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented + validated (NOT yet committed):
- C1/C2 scrubbed; both edited tests pass; full babymonitor-core suite + just e2e GREEN (exit 0, 283+ passed, 0 failed). Faux literals annotated as synthetic with runtime-resolution comments.
- secret_scan.sh -> secrets/secret_scan.sh (untracked); Justfile repointed; secret-scan GREEN + selftest bites from new location. GOTCHA: gate is now local-only (absent on fresh clone) since secrets/ is gitignored.
- OS username removed from re/media_decode_spec.md (only 1 tracked occurrence; ground-truth grep, not the scan critic's ~25).
- secrets/pii_secret_consolidated_inventory.md written (gitignored, location-only).
Pending (AC#7): qa-test-runner + mped-architect review, then commit. 6 pending tracked changes (sdp.rs, stun.rs, Justfile, media_decode_spec.md, shell.nix +git-filter-repo, secret_scan.sh deletion).
<!-- SECTION:NOTES:END -->
