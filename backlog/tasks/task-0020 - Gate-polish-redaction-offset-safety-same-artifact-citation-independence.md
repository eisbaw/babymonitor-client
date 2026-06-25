---
id: TASK-0020
title: 'Gate polish: redaction offset-safety + same-artifact citation independence'
status: To Do
assignee: []
created_date: '2026-06-25 00:55'
labels:
  - phase5
  - gates
  - review-followup
dependencies:
  - TASK-0019
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-3 review (both GO, P2 nits). Non-blocking gate hardening: (1) secret_scan.sh redaction keeps first 5 chars of the LINE not the value region — safe only because path:/line: prefixes are prepended; make it offset-based (mask from the value) and add a self-test for a value-leading JWT/email/GPS line. (2) check_evidence distinct_citations(): two readelf views of the SAME .so (dynamic.txt + dynsym.txt) currently count as 2 independent sources for a confirmed label — tighten to treat dumps of the same source artifact as one source. (3) line-anchored citation drift (e.g. milestone2:61 -> js_bundle_map.md:185 points at the wrong block) — consider section-anchored citations. None block claim tasks.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Redaction is offset-based; self-test proves a value-leading line is masked
- [ ] #2 Same-source dumps no longer satisfy the >=2-source confirmed rule on their own; self-test added
<!-- AC:END -->
