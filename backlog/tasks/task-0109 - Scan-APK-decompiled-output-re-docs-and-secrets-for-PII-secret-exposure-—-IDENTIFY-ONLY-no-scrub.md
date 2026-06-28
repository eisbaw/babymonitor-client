---
id: TASK-0109
title: >-
  Scan APK, decompiled output, re/ docs and secrets/ for PII/secret exposure —
  IDENTIFY ONLY (no scrub)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:10'
labels:
  - re
  - security
  - pii
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Produce an INVENTORY (map) of where PII and secrets appear across the project — identification only, NO remediation. Cover: (a) hardcoded values in the APK / decompiled sources (appKey/appSecret/sign-keys/endpoints/sample creds), (b) committed re/*.md docs and backlog tasks (highest risk for accidental commit), (c) gitignored secrets/ and emulator_captures/, (d) test fixtures/logs. Classify each by type and severity and whether it is TRACKED/committed vs gitignored. IDENTIFY ONLY — do NOT scrub, redact, move, or modify anything (a separate remediation task will act on this). The report itself must reference LOCATIONS only and reproduce NO secret/PII value.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An inventory of PII/secret occurrences exists (type + file:location + tracked-vs-gitignored + severity), reproducing NO secret value (location-only references)
- [x] #2 Hardcoded credentials/keys/endpoints in the APK/decompiled output are catalogued with evidence paths
- [x] #3 Exposure in committed re/*.md docs and backlog task fields is catalogued (the highest-risk accidental-commit surface)
- [x] #4 re/pii_inventory.md is produced (locations only); just secret-scan still passes; nothing is scrubbed or modified
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Enumerate tracked vs gitignored surfaces (git ls-files / check-ignore / log)
2. Grep decompiled smali/xml/js for hardcoded creds/keys/endpoints
3. Scan committed re/*.md + backlog tasks for value/partial-value leaks
4. Classify secrets/ + emulator_captures/ by type; check git history
5. Write re/pii_inventory.md (locations only, no values); confirm just secret-scan green
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Inventory written to re/pii_inventory.md (locations only, NO values). Key results:
- Live committed source is value-clean: just secret-scan passes.
- APK/decompiled (all GITIGNORED): Tuya appKey/appSecret/ttid (BuildConfig.smali:25/29/33), two encryptImage keys (ThingNGConfig.smali:64/68), Firebase/Google keys + OAuth client id (strings.xml:2857-2859/2193/2813/7170); endpoints are NOT plaintext (AES asset thing_domains_v1); push-vendor slots empty.
- Committed/committable text leaks: real productId (16-char model id) in 3 TRACKED backlog tasks (0017/0065/0067) + 2 UNTRACKED-committable re docs (motion_detection.md, video_diary.md); 4-char appKey/secret fingerprints in re/identity_enumeration.md; owner self-email in secret_scan.sh. Per-unit devId/uid/homeId/localKey VALUES were kept out (good discipline).
- HIGHEST severity = git HISTORY: cap0-cap3 raw mitm flows + cap3 signaling_plaintext.jsonl committed in 5 past commits (20a6d67/5603d96/1a69576/d13317e/ac5ba55), removed from HEAD, still retrievable as blobs; secret-scan does not scan history (blind spot).
- secrets/ + emulator_captures/ fully GITIGNORED; nothing under them tracked; classified by filename type.
IDENTIFY-ONLY: nothing scrubbed/moved/modified. secret-scan re-run GREEN after writing the doc.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Produced re/pii_inventory.md — a location-only map of PII/secret exposure across the project (IDENTIFY-ONLY; nothing scrubbed/modified). No secret or PII value is reproduced in the doc or any task field.

Scope covered:
- Hardcoded APK/decompiled credentials catalogued with file:line evidence (Tuya appKey/appSecret/ttid, two encryptImage keys, Firebase/Google API+app+OAuth keys, FCM/project ids, vdevo test id, BMP sign-token assets); confirmed endpoints are AES-encrypted assets not plaintext, push-vendor slots empty, native libs identity-free, JS bundle is schema-only. All under GITIGNORED decompiled/.
- Committed re/*.md + backlog task fields audited: real productId (model id) in 5 files (3 tracked tasks + 2 untracked-committable docs), 4-char key fingerprints in identity_enumeration.md, owner self-email in secret_scan.sh; structural sweep confirms per-unit devId/uid/homeId/localKey VALUES are NOT in committed text.
- secrets/ and emulator_captures/ classified by type (GITIGNORED, none tracked).
- Identified the highest-severity item: cap0-cap3 raw capture blobs persist in GIT HISTORY (5 commits, removed from HEAD, still retrievable); secret-scan does not scan history.
- Added tracked-state legend (TRACKED / UNTRACKED-committable / GITIGNORED / HISTORY), a P0-P2 severity roll-up, residual-unknowns, and out-of-scope remediation recommendations.

Verification: just secret-scan GREEN both before and after writing the doc; direct pattern self-check on the doc is clean.

Risk/follow-ups (out of scope, recommended as separate tasks): (1) git history purge of cap0-cap3 before any public push; (2) scrub real productId from the 5 files; (3) drop the 4-char fingerprints; (4) extend secret-scan with productId/devId shapes + a history mode.
<!-- SECTION:FINAL_SUMMARY:END -->
