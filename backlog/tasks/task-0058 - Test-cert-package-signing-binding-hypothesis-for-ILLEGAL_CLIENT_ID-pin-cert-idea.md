---
id: TASK-0058
title: >-
  Test cert/package signing-binding hypothesis for ILLEGAL_CLIENT_ID (pin-cert
  idea)
status: Done
assignee: []
created_date: '2026-06-25 22:50'
updated_date: '2026-06-25 23:26'
labels:
  - auth
  - illegal-client-id
  - crypto
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner hypothesis: maybe the gateway binds the appKey/clientId to packageName + signing-cert SHA256, and we fail that binding. Determine statically whether ILLEGAL_CLIENT_ID can be cert/package bound: where the signing-cert SHA256 + packageName enter the request (sign key vs a verifiable field), and whether the corrupt-sign differential already rules cert-binding out (cert only enters via the ignored sign key => cannot be the cause). Give a definitive yes/no with evidence; if not ruled out, define the one probe that would confirm.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Documented path of packageName + cert-SHA256 into the request (which fields), with citations
- [ ] #2 Reasoned verdict: is ILLEGAL_CLIENT_ID cert/package bound? consistent with sign-insensitivity evidence?
- [ ] #3 If not ruled out, the single confirming probe is specified; else clearly marked refuted with evidence
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REFUTED by native ground truth (round-2 libthing_security analysis). Signing cert SHA-256 (DAT_00139088) + packageName (DAT_001390a0) have exactly two fates: (1) LOCAL anti-tamper memcmp vs securityOpen whitelist from t_s.bmp -> checkStatus(int) + 7s kill-switch exit thread (passes only an int, never leaves device); (2) folded into the HMAC master key G. Never a standalone server-visible field. A wrong cert can only cause a signature-class error, never identity-class ILLEGAL_CLIENT_ID (server cannot see the cert without already holding G). Pin-cert hypothesis is dead.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Verdict: NO. ILLEGAL_CLIENT_ID is not cert/package bound. Evidence: 00116528 (cert reader returns void, no JNI return of fingerprint); 00113ed8:289-311 (anti-tamper int callback); cert only feeds the HMAC key. Refuted with high confidence.
<!-- SECTION:FINAL_SUMMARY:END -->
