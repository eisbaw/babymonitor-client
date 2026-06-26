---
id: TASK-0062
title: >-
  chKey correctness: verify getChKey derivation order + gated chKey-corruption
  differential
status: To Do
assignee: []
created_date: '2026-06-25 23:20'
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
