---
id: TASK-0021
title: check-evidence validates citation SHAPE not CONTENT (false-attribution passes)
status: To Do
assignee: []
created_date: '2026-06-25 01:11'
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
From cycle-4 review (mped-architect, P1): check_evidence.py validates that a citation MATCHES a path:line shape but never that the cited file/line actually contains the claimed content. A wrong attribution (e.g. citing dpdqppp.java for nin/nout topic prefixes it does not contain) passes the gate. This is an inherent limit of a static doc-linter; full content-validation needs the gitignored decompile present. Options: (a) opportunistic check — when the cited path exists locally, grep that line region for a token from the claim; (b) accept the limit and lean on the human/mped-architect review gate for attribution accuracy (document it). Not blocking; the review gate caught this one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Either an opportunistic content-check is added (when cited file exists, verify a claim token near the cited line) with a self-test, OR the limitation is documented in check_evidence.py header + TESTING.md and accepted with rationale
<!-- AC:END -->
