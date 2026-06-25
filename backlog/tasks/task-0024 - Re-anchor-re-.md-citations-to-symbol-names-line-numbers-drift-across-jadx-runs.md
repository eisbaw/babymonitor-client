---
id: TASK-0024
title: >-
  Re-anchor re/*.md citations to symbol names (line numbers drift across jadx
  runs)
status: To Do
assignee: []
created_date: '2026-06-25 01:50'
labels:
  - phase3
  - re
  - review-followup
  - citation-hygiene
dependencies:
  - TASK-0021
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-7 review of TASK-0007 (both reviewers, P1). The analysis docs cite decompiled paths as path:LINE, but jadx line numbers shift between runs/configs (e.g. -Xmx12g --no-debug-info vs default), so several load-bearing cites in re/tuya_cloud_auth.md (checkAPIName cited :185-191 but actually :236-239; User.java :34-57 vs :241-259; CameraInfoBean P2pConfig :140-175 vs :1459-1465) point into obfuscation noise. Symbolic anchors (class/field/method/string-constant names) are ALL correct. Fix: adopt a citation convention of SYMBOL-anchored cites (e.g. ThingApiParams.checkAPIName / User.sid) with line as an optional hint, and sweep existing re/*.md to match. Relates to TASK-0021 (check-evidence validates shape not content). Consider pinning the jadx invocation in just decompile so lines are reproducible. Affects all analysis docs, not just tuya_cloud_auth.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A symbol-anchored citation convention is documented (TESTING.md / check_evidence header) and the existing re/*.md load-bearing cites are swept to it (or verified symbol+line accurate against the current just decompile tree)
- [ ] #2 check-evidence still green; ideally a spot-check that a sampled cited symbol resolves in the current decompile
<!-- AC:END -->
