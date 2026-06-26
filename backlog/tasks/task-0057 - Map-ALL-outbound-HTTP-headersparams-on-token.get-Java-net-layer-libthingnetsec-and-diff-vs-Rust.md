---
id: TASK-0057
title: >-
  Map ALL outbound HTTP headers+params on token.get (Java net layer +
  libthingnetsec) and diff vs Rust
status: Done
assignee: []
created_date: '2026-06-25 22:50'
updated_date: '2026-06-26 02:05'
labels:
  - auth
  - illegal-client-id
  - network
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ILLEGAL_CLIENT_ID is returned before sign-check (proven sign-insensitive), so it is keyed on an identity-bearing param/header/route we send wrong or omit. Trace the full OkHttp interceptor chain and BusinessResponse/ApiBuilder header+param assembly that the genuine app attaches to the login token.get, corroborated by libthingnetsec.so native ground truth, and diff field-by-field against babymonitor-core/src/sign.rs + babymonitor-cli/src/live.rs to find the missing/wrong field.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Complete list of HTTP headers the SDK attaches to token.get, each with its source (constant/native/interceptor) + citation
- [ ] #2 Complete outbound param set (query + body) with value-or-shape and origin
- [ ] #3 Field-by-field diff vs our Rust request; every mismatch flagged with likelihood of causing ILLEGAL_CLIENT_ID
- [ ] #4 Written to re/illegal_client_id_diff.md; no literal secrets, secrets/ paths only
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Round-4 net-layer trace enumerated the complete token.get HTTP request (POST /api.json, 4 headers, full signed param set) from the Java net layer (libthingnetsec.so is crypto-only). Diff vs Rust: every identity-class field matches the genuine app (clientId value, ttid, host, headers, nd, chKey shape). Only divergence was omitted deviceId (fixed in 0064). No identity-class field we send wrong/omit; static surface exhausted. Findings in re/live_login.md 2026-06-26.
<!-- SECTION:FINAL_SUMMARY:END -->
