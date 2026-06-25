---
id: TASK-0048
title: >-
  Fix host false-exhaustion: enumerate ALL regionConfig hosts + probe un-tried
  iotbing/px datacenter gateways for token.get
status: In Progress
assignee:
  - '@implementer'
created_date: '2026-06-25 14:42'
updated_date: '2026-06-25 14:55'
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
- [x] #1 regions_decrypt.py emits all regionConfig host fields; the authoritative full EU host list is recorded (hosts are public, non-secret); over-claimed host docs corrected to likely/scoped
- [x] #2 token.get envelope reconciled to the full initUrlParams shape; TASK-0047 wire-ttid resolved statically
- [ ] #3 Each un-tried host (apigw-eu.iotbing.com, a1-us.iotbing.com, px.tuyaeu.com, a3.tuyaeu.com) probed with exactly one token.get under guardrails; outcome per host recorded in re/live_login.md (method/outcome, no values); if any clears ILLEGAL_CLIENT_ID it is reported, else host avenue declared genuinely exhausted
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
STAGE A (static, no network; gates: e2e + secret-scan + check-evidence):
1. regions_decrypt.py: emit EVERY regionConfig host field per region (not just mobileApiUrl/gwApiUrl). Add a test asserting >2 host fields emitted. Record authoritative full EU host list in re/regions_decrypt.md (public hosts ok).
2. Downgrade over-claimed docs: live_login.md "do not re-sweep hosts" + regions_decrypt.md "REFUTED by ground truth" from confirmed->likely, scoped to mobileApiUrl-only; iotbing/px/fusion hosts UN-probed. Keep verdict-overturn guard green.
3. token.get envelope: reconcile live.rs build_signed_envelope_with to full ThingApiParams.initUrlParams (appRnVersion only if app sets non-empty mAppRNVersion; fold getCommonParams into bizData+top-level). Only emit what the app emits.
4. TASK-0047 wire ttid: RESOLVED statically. AppInitializer.d rewrites the CHANNEL arg (str4) to sdk_<ver>@<appKey> when mSdk==true; that str4 becomes j()-str3 which the ThingSdk.init 6-arg->CHANNEL_OEM overload routes to the TTID slot (mTtid). So wire ttid = sdk_<ver>@<appKey>, channel becomes "oem". Record in tuya_cloud_auth.md; make live.rs send sdk_<ver>@<appKey> ttid + channel=oem. Multi-source: AppInitializer.d:334-341, j:1247-1323, ThingSdk.init:1152-1156, initThingData:1529.
Commit Stage A.

STAGE B (live, guardrails absolute): probe un-tried hosts ONE token.get each in ranked order: apigw-eu.iotbing.com (fusionUrl), a1-us.iotbing.com, px.tuyaeu.com, a3.tuyaeu.com. token.get only, no password.login, no retry, stop at 2FA, stop on success. Record per-host outcome in live_login.md (no values). Build with --features live.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
STAGE A done (static, no network). Gates green: just e2e, just secret-scan, just check-evidence, + live-feature clippy/tests.
- regions_decrypt.py now emits EVERY regionConfig scalar host/port field (region_host_fields); EU has 24. Added re/scripts/test_regions_decrypt.py (>2-field assertion + real-asset cross-check) wired into just e2e via test-regions. Full EU host list recorded in re/regions_decrypt.md (public hosts).
- Over-claimed verdicts downgraded confirmed->likely + scoped to mobileApiUrl-only, inside CORRECTED frames (verdict-overturn guard stays green): regions_decrypt.md "REFUTED by ground truth", live_login.md host-exhaustion note.
- TASK-0047 RESOLVED statically (confirmed, >=2 methods): wire ttid = sdk_international@<appKey>, wire channel = oem. The sdk_<ver>@appKey rewrite hits the CHANNEL arg in AppInitializer.d:334-335, which the ThingSdk.init 6-arg->CHANNEL_OEM overload (ThingSdk.java:1152) routes into the ttid slot (mTtid). <channel>=UMENG_CHANNEL "international" (AndroidManifest:91). Recorded re/tuya_cloud_auth.md §1b; corrected identity_enumeration.md §1/§2a.
- live.rs reconciled to initUrlParams: wire_ttid() helper sends sdk_international@<appKey> as ttid (signed); channel=oem; appRnVersion=5.92 (BuildConfig non-empty, app emits it). getCommonParams() NOT folded: addCommonParams has zero callers -> mCommonParams empty (documented, not invented).
<!-- SECTION:NOTES:END -->
