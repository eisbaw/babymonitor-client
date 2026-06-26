---
id: TASK-0062
title: >-
  chKey correctness: verify getChKey derivation order + gated chKey-corruption
  differential
status: Done
assignee: []
created_date: '2026-06-25 23:20'
updated_date: '2026-06-26 10:31'
labels:
  - auth
  - illegal-client-id
  - native
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
chKey is a standalone wire param AND signed; encodes appId<->package<->cert binding; its key/msg ordering is single-source likely (chkey_static.md 3a) and was held CONSTANT in the TASK-0050 differential, so never exercised. If the gateway validates standalone chKey at the identity stage, a wrong chKey -> ILLEGAL_CLIENT_ID before sign-verify. Verify the derivation against native getChKey@0x116000, and design a chKey-corruption differential (note both-wrong trap).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 getChKey key/msg ordering confirmed against native getChKey@0x116000 (not just one reading)
- [ ] #2 Determined whether any code path shows the server reading standalone chKey (or stated: no static evidence)
- [ ] #3 chKey-corruption differential designed with both-wrong-trap caveat; gated on owner approval for any live fire
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SOLVED ILLEGAL_CLIENT_ID. Capture-verified chKey = hex(HMAC-SHA256(appKey, pkg+_+certColonUpper))[8..16] = 8 chars (genuine 071d81fa in emulator_captures/cap1). Our derivation used [8..24]=16 chars. The server validates this standalone client-binding param and rejected the wrong-length value with ILLEGAL_CLIENT_ID before sign-verify (which is why the corrupt-sign A/B looked sign-insensitive: both arms carried the wrong chKey). Fixed sign.rs::ch_key [8..24]->[8..16]; e2e + live tests green; re-probe returns success {t,sign,result}.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Root cause of ILLEGAL_CLIENT_ID: chKey wrong length (16 vs 8 chars). Fixed slice [8..24]->[8..16], capture-verified against the genuine app chKey 071d81fa. token.get now succeeds.
<!-- SECTION:FINAL_SUMMARY:END -->
