---
id: TASK-0047
title: >-
  Confirm exact wire ttid value the SDK sends (philipsclnightowl vs
  sdk_<ver>@appKey rewrite)
status: To Do
assignee: []
created_date: '2026-06-25 14:21'
labels:
  - auth
  - static-analysis
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0046 found AppInitializer.d rewrites the channel arg to 'sdk_<ver>@<appKey>' when mSdk==true, while BuildConfig.THING_SMART_TTID and the app_scheme string resource are both 'philipsclnightowl'. The exact str3 reaching ThingSdk.init -> ThingSmartNetWork.mTtid (wire 'ttid') is single-source-traced (likely). Resolve which value rides the wire as ttid. Secondary: ILLEGAL_CLIENT_ID is a clientId-identity rejection, not a ttid one, so this is not the gate. Unblock: Frida hook on the wire ttid or one app request capture (depends on TASK-0022). See re/identity_enumeration.md section 2a.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wire 'ttid' value is determined (philipsclnightowl OR sdk_<ver>@appKey OR other), with >=2 sources or one live capture
- [ ] #2 secrets/tuya_appkey_candidates.json ttid field updated if it differs from secrets/tuya_appkey.json
- [ ] #3 re/identity_enumeration.md section 2a downgraded/promoted accordingly
<!-- AC:END -->
