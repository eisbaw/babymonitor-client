---
id: TASK-0045
title: >-
  OWNER-DECISION: on-device capture of the app's real token.get (confirm
  appKey/ttid; resolve ILLEGAL_CLIENT_ID) — broader than cloud-login auth
status: Done
assignee: []
created_date: '2026-06-25 13:36'
updated_date: '2026-06-25 17:42'
labels:
  - wave3
  - auth
  - live
  - blocked-human
  - owner-decision
dependencies:
  - TASK-0042
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
BLOCKED ON OWNER DECISION. After matching every STATIC request element (host, clientId/time, chKey[confirmed HMAC-SHA256], all signed params, all 3 SDK headers; no attestation gate exists), the live token.get STILL returns ILLEGAL_CLIENT_ID — a server-side, identity-layer, pre-sign rejection pointing at appKey/ttid PROVISIONING. The static surface is exhausted (architect + qa confirmed). The decisive unblock is an ON-DEVICE capture of the running app: a Frida hook on ThingApiParams.getUrlParams/getRequestBody OR an mitmproxy TLS-unpinning capture of one real token.get, to read the EXACT clientId/ttid/channel/User-Agent the live app sends and confirm whether our extracted appKey/ttid match. This is BROADER than the cloud-login the owner authorized (it runs the app on a device + instruments it). If the captured values MATCH ours and it still fails, the appKey is server-bound to the official app and NO standalone client can authenticate (hard wall — owner needs a provisioned key). NOTE: even fully blocked, the bmp_token candidate is integral-solve-consistent + the entire signer/stream protocol layer is built+tested — only the live appKey-provisioning gate stands between the client and a working login.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Owner decides: authorize the on-device capture (then a follow-up cycle diffs the app real request vs ours + fixes/refutes the appKey/ttid), OR accept the provisioning hard-wall endpoint
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OWNER DECISION (2026-06-25): STOP static, SHIP the RE writeup. On-device capture / any dynamic unblock NOT authorized. Static cloud-login is airtight-exhausted (TASK-0046/0048/0050/0051): appKey confirmed-real, reject proven SIGN-INSENSITIVE (identity-layer), all gateways + last wire fields matched -> server-side appKey<->app binding a static client cannot satisfy. Closing as decided; the one-capture unblock path remains documented (TASK-0022) if ever revisited.
<!-- SECTION:NOTES:END -->
