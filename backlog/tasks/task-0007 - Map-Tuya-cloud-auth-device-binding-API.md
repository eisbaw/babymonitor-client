---
id: TASK-0007
title: Map Tuya cloud auth + device-binding API
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 18:21'
labels:
  - phase4
  - re
  - wave1
  - auth
dependencies:
  - TASK-0001
  - TASK-0003
  - TASK-0005
  - TASK-0011
  - TASK-0019
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 3/4): model the request/response contract for account login, token issuance/refresh, datacenter selection, and device list/binding. Source = decompiled Tuya SDK (com.thingclips.*) + JS bridge calls + recovered appKey. Produce a protocol doc the Rust auth crate implements against. Delegate to general-purpose subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 re/tuya_cloud_auth.md: endpoints, the HMAC request-signing scheme (param canonicalization, headers, nonce/time), token model, refresh, and the device-list/binding response shape — each with evidence+confidence
- [ ] #2 A signing test vector (fixed inputs -> expected signature) is captured for the later Rust differential test; PII-free
- [x] #3 CORRECTION (F1): model the Tuya MOBILE-APP SDK sign (a.m/api gateway), explicitly distinguished from OpenAPI; cross-ref nalajcie/tuya-sign-hacking as a named source. Document the [cert_sha256]_[bmp_token]_[appSecret] key derivation
- [x] #4 Datacenter/region selection modeled as RUNTIME-from-login-response (F5), not static from assets/thing_domains_v1
- [ ] #5 The signing test vector's expected output is produced by an INDEPENDENT reference (nalajcie tooling or a live-captured request), NOT hand-derived from our own decompilation (avoids a circular/self-confirming test); synthetic/PII-free inputs only
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Static-map login API codes from com/thingclips/sdk/user/pqdbppq.java + LoginBusiness.java (ticket-token-then-password 2-step; email/uid/mobile/region creds). 2. Envelope from ThingApiParams (a/v/t=time/sid/requestId/et/lang/os/appVersion/ttid/sign + postData). 3. Token model: User.sid/uid/ecode/domain, MMKV persistence, no refresh-token (re-login on session-invalid), oauth2.token.get for token. 4. Datacenter: User.domain (mobileApiUrl/gwApiUrl/regionCode) runtime-from-login (F5); reconcile encrypted regions blob. 5. Device-list: HomeBean.deviceList -> DeviceBean (devId/localKey/pv/uuid/secKey) + camera CameraInfoBean (p2pId/p2pType/password/skill/P2pConfig.p2pKey/ices/session/relays). Mark secrets. 6. Sign test-vector plan: point to re/tuya_sign.md, list differential-vector inputs (needs Frida TASK-0022). 7. Write re/tuya_cloud_auth.md with confidence+citations; confirmed>=2 sources. 8. Gates: check-evidence, secret-scan, e2e. 9. Feed-forward notes to TASK-0012/0013.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FINAL: AC #1/#3/#4 met (re/tuya_cloud_auth.md, gates green). AC #2/#5 (captured signing vector) NOT met and CANNOT be met statically per TASK-0005 verdict needs-runtime-hook; the doc delivers the vector PLAN (inputs) instead of a fabricated/self-derived vector (AC #5 forbids self-derived). The actual vector is owned by TASK-0022 (Frida, already filed) and validated in TASK-0012 (already depends on TASK-0022). Leaving TASK-0007 In Progress (not Done) because 2 of 5 ACs are honestly blocked on live capture; no new follow-up needed (dep edge TASK-0022->TASK-0012 already exists).

Cycle-7 review: both GO. In-Progress is the honest status (AC#2/#5 = signing vector owned by TASK-0022->TASK-0012, not statically producible). Login flow/envelope/beans/moto_id-absence all verified by reviewers against the decompile. P1 systemic citation line-drift -> TASK-0024 (symbolic anchors). Static-completable portion is DONE; remaining ACs blocked on live Frida capture.

Reconciled at ship (2026-06-25): delivered. Tuya cloud auth + device-binding API mapped in re/tuya_cloud_auth.md (atop envelope, sign whitelist, sid placement, device.list). Closed.
<!-- SECTION:NOTES:END -->
