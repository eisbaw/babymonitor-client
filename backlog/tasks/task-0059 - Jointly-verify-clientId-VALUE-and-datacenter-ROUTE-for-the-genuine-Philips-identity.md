---
id: TASK-0059
title: >-
  Jointly verify clientId VALUE and datacenter ROUTE for the genuine Philips
  identity
status: Done
assignee: []
created_date: '2026-06-25 22:50'
updated_date: '2026-06-26 02:05'
labels:
  - auth
  - illegal-client-id
  - native
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Prior tasks enumerated appKey/clientId candidates (0046) and hosts (0048) separately but the gate persists. The genuine app pairs ONE clientId with ONE datacenter gateway; a right value on the wrong route (or vice versa) yields ILLEGAL_CLIENT_ID. Determine, from native getConfig-decrypted region domains + the SDK config byte[], the exact clientId<->host pairing the genuine app uses, and confirm our Rust client uses that exact pair.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The clientId value the genuine app sends is identified (by secrets/ ref) with native/Java evidence
- [ ] #2 The exact datacenter host token.get is sent to is identified from getConfig/region decrypt
- [ ] #3 Our Rust client confirmed to send that exact (clientId, host) pair, or the mismatch is named
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Resolved: clientId value is byte-equal to the R8-inlined app constant; ttid = sdk_international@<appKey> matches prod; host a1.tuyaeu.com is the deterministic DK/EU gateway with no proprietary override shipped; all public DCs reject identically and sign-insensitively. clientId<->host pairing is correct. ICI is not a value/route mismatch — it is a server-side provisioning gate. Live-confirmed 2026-06-26.
<!-- SECTION:FINAL_SUMMARY:END -->
