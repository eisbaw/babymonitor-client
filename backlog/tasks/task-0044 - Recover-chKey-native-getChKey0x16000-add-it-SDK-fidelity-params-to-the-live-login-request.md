---
id: TASK-0044
title: >-
  Recover chKey (native getChKey@0x16000) + add it + SDK-fidelity params to the
  live login request
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 12:46'
updated_date: '2026-06-25 13:09'
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
- [x] #1 getChKey@0x16000 reverse-engineered (Ghidra-primary, symbol-anchored): algorithm + static-vs-runtime verdict; if static, chKey recovered (value to secrets/ only) and the canonical sign + wire envelope now include it
- [x] #2 live.rs login request adds chKey + the SDK-fidelity params; e2e/secret-scan/check-evidence green; live path still gated out of e2e; the before-sign-eval overclaim softened + regions pointer added
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Ghidra-RE getChKey@0x16000 (rebased 0x116000) + callees (FUN_001179f8 keyed digest, FUN_00117780 key-setup, FUN_00116528 cert-hash); r2 cross-check. 2. Determine algorithm + static-vs-runtime. 3. Port to babymonitor-core/sign.rs (ch_key + hmac_sha256) with RFC-4231 differential tests. 4. Wire chKey + SDK-fidelity params into live.rs envelope (chKey signed). 5. Doc re/chkey_static.md + soften live_login.md overclaim + regions pointer. 6. Gates: e2e/check-evidence/secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
VERDICT: chKey is STATIC-derivable. getChKey@0x16000 = lowercase_hex(HMAC-SHA256(key=appId_bytes, msg=packageName + "_" + certSha256Hex)). All inputs static: appId=appKey (secrets/), packageName=com.philips.ph.babymonitorplus (manifest), certSha256Hex=offline from APK (already in sign.rs). Keyed digest is HMAC-SHA256 (algo descriptor 0x132fe0 {id=6,name=SHA256,digest=0x20,block=0x40}; ipad 0x36/opad 0x5c pads in FUN_00117780) — NOT plain MD5 like the request sign.

GOTCHAS:
- chKey uses HMAC-SHA256, the request sign uses plain MD5 — two DIFFERENT primitives in the same lib; do not conflate.
- The two key-string parts live in .bss globals DAT_001390a0 (packageName) + DAT_00139058 (cert-sha256-hex), populated at runtime by FUN_00116528 (JNI getPackageName + getPackageInfo->signatures[0]->SHA256). They are EMPTY in the static image (_INIT_2 only zero-constructs), so a naive static dump shows nothing — the VALUES are static, derived from the cert+manifest, not embedded literals.
- Key/message ORDERING (appId=key, packageName_cert=message) is read from the call-site arg order on ONE native source -> labelled likely (not confirmed); only a server-accepted request or a captured device chKey promotes it. A wrong key/msg swap yields a plausible-but-wrong token with no local oracle.
- chKey is secret-by-policy (derived from appKey+cert): value only in secrets/chkey.txt (gitignored, 0600), computed from inputs in code; an operator-pinned secrets/chkey.txt overrides re-derivation.
- SDK-fidelity params channel=sdk (mChannel default), cp=gzip (et==3); sdkVersion/deviceCoreVersion/osSystem/platform/timeZoneId/bizData are runtime/device values -> app defaults used (representative, NOT signed, so no sign impact). Only chKey is whitelisted/signed.
- chKey NOT proven to be THE ILLEGAL_CLIENT_ID fix (server-opaque); it is a SIGNED identity param so it corrects wire+sign together. NEXT cycle single token.get decides.
<!-- SECTION:NOTES:END -->
