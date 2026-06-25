---
id: TASK-0049
title: >-
  DECISION (gated): cloud-login blocker — only after the corrupted-sign
  differential rules sign-failure out
status: Done
assignee: []
created_date: '2026-06-25 15:01'
updated_date: '2026-06-25 17:42'
labels:
  - auth
  - identity
  - blocked
  - decision
dependencies:
  - TASK-0050
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
GATED — do not action until TASK-0050 (corrupted-sign differential) completes. TASK-0048 closed the static HOST avenue (all reachable EU/AZ atop gateways incl. iotbing return ILLEGAL_CLIENT_ID with the fully app-faithful, correctly-ttid/channel/appRnVersion envelope and the confirmed-real appKey). BUT the architect review (post-0048) showed the "ILLEGAL_CLIENT_ID = app-attestation/provisioning gate" conclusion is SPECULATIVE and UNEARNED: (1) our own docs (re/live_login.md) say whether the code is returned before sign-evaluation is server-opaque/unproven; (2) a whole-tree grep for SafetyNet|PlayIntegrity|attest|integrity finds ZERO evidence of any attestation in the app; (3) every probe sent the SAME un-validated candidate sign (bmp_token is an integral-solve candidate never server-confirmed; the MD5 fold was never disambiguated). So ILLEGAL_CLIENT_ID is equally consistent with a WRONG SIGN as with an identity gate. TASK-0050 disambiguates this statically. Only if TASK-0050 proves the reject is identity-layer (sign-insensitive) does this decision (on-device capture vs LAN-pairing pivot) become live. If TASK-0050 shows the reject is sign-sensitive, the blocker is the bmp_token/fold = still static work, and this task is moot.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Owner decides between on-device capture (a) and local-pairing pivot (b); decision recorded
- [ ] #2 If (a): the exact missing provisioning surface (header/param/attestation) is identified from ONE capture and the static client updated; if (b): a backlog task for the LAN pairing/stream avenue is created
- [ ] #3 re/live_login.md verdict promoted from likely to confirmed once a second source (capture or a definitive provisioning-doc) corroborates the app-attestation-gate conclusion
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
UNBLOCKED by TASK-0050 (2026-06-25): the corrupted-sign differential ran against a1.tuyaeu.com — candidate sign and a one-nibble-corrupted sign BOTH returned byte-identical ILLEGAL_CLIENT_ID (HTTP 200, "Invalid client;No access"). The reject is therefore SIGN-INSENSITIVE: the gateway rejects on client identity BEFORE evaluating the sign. This is the controlled second source AC#3 asked for (the corrupted variant is the negative control), promoting the identity/provisioning-gate claim likely->confirmed (re/live_login.md). The "wrong sign" alternative is ruled OUT for this error. TASK-0050 Stage B also confirmed (re/tuya_cloud_auth.md §8) that captcha/verifyToken is a separate code-send service, NOT an atop token.get header — so there is no statically-missing request decoration either. Owner decision (on-device capture vs LAN-pairing pivot) is now live; the static client cannot clear this gate from recovered material alone.

OWNER DECISION (2026-06-25): STOP static, SHIP the RE writeup. On-device capture / any dynamic unblock NOT authorized. Static cloud-login is airtight-exhausted (TASK-0046/0048/0050/0051): appKey confirmed-real, reject proven SIGN-INSENSITIVE (identity-layer), all gateways + last wire fields matched -> server-side appKey<->app binding a static client cannot satisfy. Closing as decided; the one-capture unblock path remains documented (TASK-0022) if ever revisited.
<!-- SECTION:NOTES:END -->
