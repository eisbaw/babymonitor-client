---
id: TASK-0012
title: Implement Tuya cloud auth + request signing in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 01:44'
labels:
  - phase5
  - rust
  - wave1
  - auth
dependencies:
  - TASK-0022
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: the first genuinely buildable+testable slice. Implement Tuya HMAC request signing, account login, token issue/refresh, datacenter base-URL selection in babymonitor-core, per re/tuya_cloud_auth.md. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::auth signs requests; a differential unit test reproduces the captured signing vector from task 7 byte-for-byte (this gate bites with no network)
- [ ] #2 Token store persists to ~/.local/share/babymonitor/; refresh-before-expiry covered by a unit test; no unflagged stubs
- [ ] #3 If task 5 verdict is not 'recoverable-statically', the byte-for-byte differential (AC#1) may be unsatisfiable purely statically: implement+unit-test the sign ALGORITHM, and obtain the expected vector from the user's gated live run instead; record the blocker, do NOT fake a vector
- [ ] #4 Any live auth calls are rate-limited and single-shot; no retry loops against Tuya auth (no account lockout / infra hammering)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
[from TASK-0007: re/tuya_cloud_auth.md is the auth contract]
EXACT ENDPOINTS (atop mobile gateway, NOT OpenAPI):
- Login is 2-step ticket flow:
  1) thing.m.user.username.token.get v2.0 (sessionRequire=false) -> TokenBean{token(ticket), publicKey, exponent, pExponent}. publicKey+exponent = RSA pubkey; RSA-encrypt the password with it (ifencrypt=1).
  2) thing.m.user.email.password.login (email) / thing.m.user.mobile.passwd.login v4.0 (mobile) / uid variants. postData: countryCode, email|mobile, passwd(RSA-enc), token(ticket), ifencrypt(0/1), mfa blob {"group":1,"mfaCode":"..."}. Returns User{sid, uid, ecode, domain, timezoneId, ...}.
- Other creds available: email.code.login, mobile.code.login, uid.password.login, uid.token.create, sso.ticket.user.get, qr.token.login. Primary path for this app = email/uid + region.
ENVELOPE (signed URL/GET params): a(action), v(version), t/time(server epoch), sid(session, empty pre-login), requestId(UUID per req), et=3, lang, os=Android, appVersion, ttid(secrets/), clientId(appKey, secrets/), deviceId, sign. Body = postData (JSON). Defaults: sessionRequire/locationRequire true, apiVersion='*'. checkAPIName() rewrites thing.*->smartlife.* before sign.
SIGN: see re/tuya_sign.md (NOT here). String-to-sign reproducible (sort whitelist, join with '||', postData->swap(md5b64)); keyed sign is NATIVE -> needs the TASK-0022 Frida vector to validate (this task depends on TASK-0022). Do NOT self-derive the vector.
TOKEN MODEL: session=User.sid. No refresh-token; on session-invalid RE-LOGIN. Persist sid+uid to ~/.local/share/babymonitor/ (both SECRET).
DATACENTER: do NOT hardcode base URL. Use User.domain.mobileApiUrl (+ gwApiUrl, gwMqttUrl, regionCode) from the login response (F5). Bootstrap login against the region candidate, then switch to domain.mobileApiUrl. Pre-login helpers: thing.m.user.region.list, thing.m.app.domain.query.
LIMITATION: exact on-wire a= spelling + obfuscated device-list action need a live/Frida confirm.
<!-- SECTION:NOTES:END -->
