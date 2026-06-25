---
id: TASK-0054
title: >-
  Reframe core stream/device doc-comments that frame TASK-0032/bmp_token as the
  auth/stream-credential blocker
status: To Do
assignee: []
created_date: '2026-06-25 17:56'
labels:
  - phase3
  - docs
  - cleanup
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0053 corrected the user-facing LOGIN-wall messaging (CLI + babymonitor/README) to the proven sign-insensitive server-side identity gate (ILLEGAL_CLIENT_ID, TASK-0050/0051). Residual internal doc-comments in the core stream/device layer still frame TASK-0032/bmp_token as the auth blocker for STREAM credentials (e.g. babymonitor-core/src/stream/session.rs ~:15,:233; src/stream/mod.rs ~:38; src/device.rs auth-gate comments; live_e2e.rs stream test ~:113,:134). These are not the user-facing login reason (so out of TASK-0053 scope) but conflate the same disproven cause: the real reason stream creds are unfetchable is the absent authenticated session (identity gate), with bmp_token only the signer's un-validated 6th ingredient. Reframe these internal comments consistently; keep control flow + the BmpTokenPending/StreamPending variant names unchanged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Core stream/device doc-comments + the live_e2e stream test reframe TASK-0032/bmp_token from 'the auth/stream blocker' to 'the absent authenticated session (server-side identity gate, TASK-0050/0051); bmp_token is only the signer un-validated 6th ingredient'; no control-flow or type-name change
- [ ] #2 just e2e + just secret-scan + just check-evidence all green
<!-- AC:END -->
