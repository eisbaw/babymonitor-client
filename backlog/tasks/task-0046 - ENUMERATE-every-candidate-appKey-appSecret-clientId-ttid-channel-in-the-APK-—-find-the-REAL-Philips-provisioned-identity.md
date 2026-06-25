---
id: TASK-0046
title: >-
  ENUMERATE every candidate appKey/appSecret/clientId/ttid/channel in the APK —
  find the REAL Philips-provisioned identity
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 13:49'
updated_date: '2026-06-25 14:42'
labels:
  - phase3
  - wave3
  - auth
  - identity
  - static
dependencies:
  - TASK-0045
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner declined on-device capture; stay STATIC. The app authenticates fine, so the REAL provisioned identity is baked into the APK — we likely used the WRONG one. PRIME SUSPECT: secrets/tuya_appkey.json appKey/appSecret came from com/thingclips/sample/BuildConfig.java (TASK-0005) = the Tuya SDK SAMPLE app config, NOT the real Philips key -> would explain ILLEGAL_CLIENT_ID + a wrong chKey (chKey keys on appId). DEEP STATIC ENUM (Ghidra/r2/jadx + grep): (1) find ALL appKey-shaped (~16-24 alnum) / appSecret-shaped (~32) / ttid / clientId values across the WHOLE APK — assets (thing_domains_v1, ThingUIConfig.json, thing_uni_plugins RN/JS incl. PlayNetKit, mini_app_js), res/values strings.xml, AndroidManifest meta-data (Tuya often declares TUYA_SMART_APPKEY/SECRET there), ALL BuildConfig + smali constants, native lib strings. There may be multiple (sample vs real). (2) Check for an ENCRYPTED/OBFUSCATED appKey/ttid decrypted at init like the regions blob (pure-Java AES-256-CTR, key+IV in asset header) — apply that + sibling decryptors. (3) TRACE which appKey/ttid/channel the SDK ACTUALLY uses for token.get: ThingSdk.init/initThingData -> ThingSmartNetWork.mAppId/mAppSecret, ThingApiParams ttid/channel, getConfig/init. (4) Rank candidates by likelihood of being the real provisioned key. Write the top candidate identity VALUES to secrets/ ONLY (gitignored); a re/ methods doc records WHERE each candidate lives + the trace, NEVER values.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Every candidate appKey/appSecret/ttid/clientId/channel in the APK enumerated with its source location; the SAMPLE-vs-REAL distinction resolved by tracing what ThingSdk.init/token.get actually uses; encrypted-identity check done
- [x] #2 The most-likely REAL Philips identity tuple (appKey/appSecret/ttid/channel) written to secrets/ (values withheld from all tracked files); re/ doc records method+locations; ranked candidate list for the live re-attempt
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Review gate: appKey-is-real finding GO (R8-inlined at SmartApplication.e(); com.thingclips.sample = Philips own module carrying APPLICATION_ID=com.philips.ph.babymonitorplus). No encrypted/alternate appKey. chKey derived from correct appId.

Architect NO-GO on the downstream "needs Frida" conclusion: FALSE-EXHAUSTION caught. Host enumeration covered only 2 of ~22 regionConfig host fields. Un-probed EU hosts: fusionUrl=apigw-eu.iotbing.com (iotbing cloud, never tried), a1-us.iotbing.com, px.tuyaeu.com, a3.tuyaeu.com. token.get routing params largely refuted (region resolves EU correctly for DK code 45; countryCode is postData not envelope) EXCEPT appRnVersion/bizData shape gap. ttid wire value still single-source (TASK-0047). Root cause of false-exhaustion: regions_decrypt.py emits only 2 host fields.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Static identity enumeration: REFUTED the wrong-appKey hypothesis. The appKey in secrets/tuya_appkey.json is the REAL Philips-provisioned key (R8-inlined into production SmartApplication.e(); the com.thingclips.sample module is Philips own app module, not a Tuya demo). No encrypted/obfuscated appKey exists; the SDK sends this exact tuple. chKey was derived from the correct appId.

Consequence: ILLEGAL_CLIENT_ID is NOT a wrong-key problem. Review gate caught a false-exhaustion in the sibling host claim (only 2 of ~22 regionConfig hosts were ever tried) -> follow-up TASK-0048 to fix the host enumeration and probe the un-tried iotbing/px datacenter gateways before any on-device option. Deliverables: re/identity_enumeration.md (no values), secrets/tuya_appkey_candidates.json (gitignored). Gates: secret-scan + check-evidence + e2e all green.
<!-- SECTION:FINAL_SUMMARY:END -->
