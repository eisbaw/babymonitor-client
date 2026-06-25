---
id: TASK-0047
title: >-
  Confirm exact wire ttid value the SDK sends (philipsclnightowl vs
  sdk_<ver>@appKey rewrite)
status: Done
assignee:
  - '@implementer'
created_date: '2026-06-25 14:21'
updated_date: '2026-06-25 15:02'
labels:
  - auth
  - static-analysis
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0046 found AppInitializer.d rewrites the channel arg to 'sdk_<ver>@<appKey>' when mSdk==true, while BuildConfig.THING_SMART_TTID and the app_scheme string resource are both 'philipsclnightowl'. The exact str3 reaching ThingSdk.init -> ThingSmartNetWork.mTtid (wire 'ttid') is single-source-traced (likely). Resolve which value rides the wire as ttid. Secondary: ILLEGAL_CLIENT_ID is a clientId-identity rejection, not a ttid one, so this is not the gate. Unblock: Frida hook on the wire ttid or one app request capture (depends on TASK-0022). See re/identity_enumeration.md section 2a.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Wire 'ttid' value is determined (philipsclnightowl OR sdk_<ver>@appKey OR other), with >=2 sources or one live capture
- [x] #2 secrets/tuya_appkey_candidates.json ttid field updated if it differs from secrets/tuya_appkey.json
- [x] #3 re/identity_enumeration.md section 2a downgraded/promoted accordingly
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RESOLVED statically by TASK-0048 (no live capture needed). Wire ttid = sdk_international@<appKey>. Full >=2-method dataflow trace: AppInitializer.d (SmartApplication.java:121 -> AppInitializer.java:317-341) rewrites the CHANNEL arg (str4) to "sdk_"+GlobalConfig.b()+"@"+appKey when mSdk==true (default true, ThingSmartNetWork.java:103); that rewritten channel becomes j()-str3 (AppInitializer.java:341,1247-1323) which the ThingSdk.init 6-arg overload routes through CHANNEL_OEM (ThingSdk.java:1152-1153), placing it in the ttid slot; initThingData (ThingSdk.java:1512-1529) -> ThingSmartNetWork.initialize assigns mTtid=that value (ThingSmartNetWork.java:3873) and mChannel="oem". GlobalConfig.b()=UMENG_CHANNEL "international" (AndroidManifest.xml:91). The raw philipsclnightowl ttid only reaches UrlRouter.o() (AppInitializer.java:340), never the wire. Recorded in re/tuya_cloud_auth.md §1b; corrected re/identity_enumeration.md §1/§2a. live.rs now sends this form (wire_ttid()). secrets/tuya_appkey_candidates.json ttid field unchanged (it holds the raw scheme; the wire form is derived from appKey at runtime, not a stored value).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Resolved the wire ttid statically (no live capture needed): the SDK sends ttid = sdk_international@<appKey>, NOT the raw philipsclnightowl scheme.

Method: full dataflow trace through the production init chain, >=2 independent jadx methods (the AppInitializer.d/j bodies AND the ThingSdk.init overload routing + initialize assignment). The sdk_<channel>@<appKey> rewrite is applied to the CHANNEL arg in AppInitializer.d (mSdk==true by default), then routed into the ttid slot by the ThingSdk.init 6-arg->CHANNEL_OEM overload; the raw scheme only reaches UrlRouter.o(). channel becomes "oem". <channel>=UMENG_CHANNEL "international".

Changes: re/tuya_cloud_auth.md new §1b (full derivation); corrected the mis-trace in re/identity_enumeration.md §1/§2a (was likely/unresolved, now confirmed); live.rs wire_ttid() sends the app-faithful ttid (signed, in SIGN_WHITELIST) + channel=oem + appRnVersion. AC#2: candidates file ttid field unchanged by design (it stores the raw scheme; the wire form is derived from appKey at runtime, never a stored value). All done under TASK-0048; gates green.
<!-- SECTION:FINAL_SUMMARY:END -->
