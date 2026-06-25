---
id: TASK-0044
title: >-
  Recover chKey (native getChKey@0x16000) + add it + SDK-fidelity params to the
  live login request
status: To Do
assignee: []
created_date: '2026-06-25 12:46'
labels:
  - phase3
  - wave3
  - auth
  - native
  - ghidra
  - live-prep
dependencies:
  - TASK-0043
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-3, the likely ILLEGAL_CLIENT_ID fix (found by the TASK-0043 architect gate). The Tuya login wire request needs chKey = ThingNetworkSecurity.getChKey(ctx, mAppId.getBytes()) = native JNICLibrary.getChKey @0x16000 (signature (Context, byte[]appId)->String; catalogued re/tuya_sign_static.md:78). chKey is in the signed whitelist bdpdqbp AND our SIGN_WHITELIST, but our live.rs supplies NOTHING -> omitted from BOTH the wire request and the canonical sign. STATIC ONLY (no live attempt this cycle). (1) Ghidra-RE getChKey@0x16000: the algorithm + whether it is STATIC-derivable (from appId + app-cert, like the sign key) or runtime-only. (2) If static: port it (Rust in babymonitor-core, or python->secrets/) + recover the chKey value (to secrets/ if a value, never tracked). (3) Add chKey to the live.rs login envelope (wire + sign); add the SDK-fidelity params the real initUrlParams sends (channel, sdkVersion, deviceCoreVersion, osSystem, platform, timeZoneId, bizData, cp=gzip — values from the decompile/BuildConfig) so the request matches the app. (4) Verify the canonical string + sign now INCLUDE chKey. (5) Soften the unproven before-sign-eval claim in re/live_login.md + add the regions superseded pointer. The SINGLE live token.get re-attempt is the NEXT cycle.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 getChKey@0x16000 reverse-engineered (Ghidra-primary, symbol-anchored): algorithm + static-vs-runtime verdict; if static, chKey recovered (value to secrets/ only) and the canonical sign + wire envelope now include it
- [ ] #2 live.rs login request adds chKey + the SDK-fidelity params; e2e/secret-scan/check-evidence green; live path still gated out of e2e; the before-sign-eval overclaim softened + regions pointer added
<!-- AC:END -->
