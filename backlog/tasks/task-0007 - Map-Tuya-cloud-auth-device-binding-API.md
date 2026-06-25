---
id: TASK-0007
title: Map Tuya cloud auth + device-binding API
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
updated_date: '2026-06-25 01:22'
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
- [ ] #1 re/tuya_cloud_auth.md: endpoints, the HMAC request-signing scheme (param canonicalization, headers, nonce/time), token model, refresh, and the device-list/binding response shape — each with evidence+confidence
- [ ] #2 A signing test vector (fixed inputs -> expected signature) is captured for the later Rust differential test; PII-free
- [ ] #3 CORRECTION (F1): model the Tuya MOBILE-APP SDK sign (a.m/api gateway), explicitly distinguished from OpenAPI; cross-ref nalajcie/tuya-sign-hacking as a named source. Document the [cert_sha256]_[bmp_token]_[appSecret] key derivation
- [ ] #4 Datacenter/region selection modeled as RUNTIME-from-login-response (F5), not static from assets/thing_domains_v1
- [ ] #5 The signing test vector's expected output is produced by an INDEPENDENT reference (nalajcie tooling or a live-captured request), NOT hand-derived from our own decompilation (avoids a circular/self-confirming test); synthetic/PII-free inputs only
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
[from TASK-0005 SPIKE] Cloud-auth signing map (see re/tuya_sign.md, re/tuya_cloud_config.md):
- Request signer = Tuya mobile-app gateway ("atop"), NOT OpenAPI. Entry TUNIAPIRequestManager.apiRequestByAtop -> ThingApiSignManager.
- String-to-sign: sort params asc, keep whitelist (a,v,t,sid,appVersion,os,deviceId,lang,requestId,et,sp,...), join key=value with literal "||" (not "&"); postData value replaced by swapSignString(md5AsBase64(body)) first; swapSignString permutes a 32-char md5-b64 as B[0:8]+s[0:8]+s[24:32]+B[8:16].
- Keyed sign is NATIVE: pbddddb.bdpdqbp -> ThingNetworkSecurity.doCommandNative(ctx, cmd=1, stringToSign). Key derivation = f(app_cert_SHA256, token from t_s.bmp, appSecret) inside libthing_security.so (F1 confirmed via native strings: t_s.bmp, SignFileDecoder, X509Certificate, SHA256). Likely HMAC-SHA256.
- appKey/appSecret/TTID: STATIC in DEX BuildConfig -> secrets/tuya_appkey.json (values NOT in any committed file).
- Datacenter domains: NOT static plaintext; encrypted in assets/thing_domains_v1/regions, decrypted at runtime by native getConfig; datacenter chosen by region post-login (F5). Plan datacenter selection as runtime-from-login.
- VERDICT for the sign key: needs-runtime-hook. The differential test vector for the signer is NOT statically derivable; it must come from the Frida hook (TASK-0022) or a live capture.
<!-- SECTION:NOTES:END -->
