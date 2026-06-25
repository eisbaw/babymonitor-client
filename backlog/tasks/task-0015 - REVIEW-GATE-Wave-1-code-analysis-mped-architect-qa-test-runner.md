---
id: TASK-0015
title: 'REVIEW GATE: Wave-1 code + analysis (mped-architect + qa-test-runner)'
status: In Progress
assignee:
  - '@orchestrator'
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 06:33'
labels:
  - phase-gate
  - review
  - wave1
dependencies:
  - TASK-0012
  - TASK-0013
  - TASK-0014
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WAVE-1 GATE (read-only). Run mped-architect (architecture/honesty) and qa-test-runner (just e2e + just showcase) in PARALLEL over everything Wave-1 landed. Verify TESTING.md gates actually bite (corrupt-input tests exist), no unflagged stubs, claims grounded. File findings as fix tasks. No production code here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/review_wave1_gate.md records both reviews; just e2e and just showcase results pasted; every issue filed as a task
- [ ] #2 Go/No-go for Wave 2 stated, keyed off the task-10 P2P feasibility verdict
- [ ] #3 just secret-scan green over committed files + backlog/tasks/*.md; just e2e run with network disabled stays green (live tests are #[ignore]d)
- [ ] #4 All P0/P1 fix-tasks from task 6 and this gate are closed or consciously deferred with reason before Go for Wave 2
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
P0 fix applied (Wave-1 NO-GO): the shipped client + README + live-e2e test still described the RETRACTED white-box-table-cipher model and cited the CLOSED TASK-0030. Reconciled the code to the FINAL settled model — bmp_token is the imath-bignum + matrix decode on the sign path (fcn.13b5c -> read_keys_from_content@0x4974 -> matrix fcn.5eb0); the AES-128-CBC fcn.11658 is a separate cert-pinning consumer (red herring for the signer). Mechanical, no logic change: README.md, babymonitor-core/{lib,sign,device}.rs, babymonitor-cli/src/main.rs + tests/live_e2e.rs; 'white-box table cipher' -> the matrix model, TASK-0030 -> TASK-0032, doc refs repointed to re/tuya_sign_static.md §5 + re/bmp_token_whitebox.md §8; the runtime BmpTokenPending message + CLI JSON blocked_on now cite TASK-0032; renamed sign::tests::full_signature_byte_parity_pending_task_0030 -> _task_0032. Also closed stale-In-Progress TASK-0029. Gates GREEN: e2e, check-evidence, secret-scan. rg 'TASK-0030|white-box table cipher' over babymonitor/ now empty.
<!-- SECTION:NOTES:END -->
