---
id: TASK-0048
title: >-
  Fix host false-exhaustion: enumerate ALL regionConfig hosts + probe un-tried
  iotbing/px datacenter gateways for token.get
status: To Do
assignee: []
created_date: '2026-06-25 14:42'
labels:
  - phase3
  - wave3
  - auth
  - identity
  - live
dependencies:
  - TASK-0046
  - TASK-0047
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Review gate (TASK-0046) caught a false-exhaustion: the ILLEGAL_CLIENT_ID host hypothesis was declared REFUTED on only 2 of ~22 decrypted EU regionConfig host fields. A confirmed-correct appKey can still draw ILLEGAL_CLIENT_ID from the WRONG datacenter gateway. ROOT-CAUSE FIX + PROBE: (A) STATIC: make re/scripts/regions_decrypt.py emit EVERY regionConfig host field (not just mobileApiUrl/gwApiUrl) so the full host list is authoritative; correct the over-claimed docs (re/live_login.md "do not re-sweep hosts" + re/regions_decrypt.md "REFUTED by ground truth") -> downgrade to likely, scope to mobileApiUrl-only. Reconcile the live.rs token.get envelope to the full ThingApiParams.initUrlParams shape (appRnVersion if the app sets it, bizData getCommonParams) so the probe request is app-faithful. Resolve TASK-0047 (static-trace wire ttid via AppInitializer.d mSdk path). (B) LIVE (guardrails: read-only token.get only, NOT password.login, no retry-spam, secrets only in gitignored secrets/, stop at 2FA, stop on success): probe the un-tried hosts in ranked order with ONE token.get each: 1) https://apigw-eu.iotbing.com (fusionUrl), 2) https://a1-us.iotbing.com, 3) px.tuyaeu.com, 4) a3.tuyaeu.com. If any clears ILLEGAL_CLIENT_ID, the sign oracle is finally reachable. If all return ILLEGAL_CLIENT_ID, the static host avenue is genuinely exhausted -> report which hosts tried.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 regions_decrypt.py emits all regionConfig host fields; the authoritative full EU host list is recorded (hosts are public, non-secret); over-claimed host docs corrected to likely/scoped
- [ ] #2 token.get envelope reconciled to the full initUrlParams shape; TASK-0047 wire-ttid resolved statically
- [ ] #3 Each un-tried host (apigw-eu.iotbing.com, a1-us.iotbing.com, px.tuyaeu.com, a3.tuyaeu.com) probed with exactly one token.get under guardrails; outcome per host recorded in re/live_login.md (method/outcome, no values); if any clears ILLEGAL_CLIENT_ID it is reported, else host avenue declared genuinely exhausted
<!-- AC:END -->
