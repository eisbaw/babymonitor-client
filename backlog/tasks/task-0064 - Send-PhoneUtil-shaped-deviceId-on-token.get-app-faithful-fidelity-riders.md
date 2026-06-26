---
id: TASK-0064
title: Send PhoneUtil-shaped deviceId on token.get (app-faithful) + fidelity riders
status: Done
assignee:
  - '@claude'
created_date: '2026-06-26 01:43'
updated_date: '2026-06-26 15:20'
labels:
  - auth
  - illegal-client-id
  - fidelity
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Round-4 net-layer trace proved the genuine app ALWAYS sends+signs deviceId on token.get via the ApiParams subclass override (ApiParams.java:87-91,225-229); round-1 missed this and we wrongly removed it. Restore a stable, persisted, PhoneUtil.getDeviceID-shaped ~44-char deviceId, signed and wired into both the form body and the signed param set. Verified UNLIKELY to be the ICI cause but it is the one wire-param divergence and the last single-variable static-actionable test. Cheap correctness riders included.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 deviceId synthesized to PhoneUtil.getDeviceID shape (~44 char), generated-once + persisted under secrets/, sent in form body AND signed param set
- [x] #2 Stale live.rs:542-544 "real app sends NO deviceId" comment removed
- [x] #3 SIGN_WHITELIST h5 -> isH5 corrected (sign.rs:102) to match Java ThingApiSignManager:66
- [x] #4 appVersion pinned to the real build version (guard so the 1.9.0 placeholder never ships on a signed request)
- [x] #5 just e2e + --features live tests + just secret-scan all green; no literal secrets
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Re-confirm ground truth from jadx (ApiParams getRequestBody:89 + initUrlParams:227 inject deviceId; whitelist bdpdqbp includes KEY_DEVICEID + KEY_H5=isH5; PhoneUtil.getRemoteDeviceID:770 shape).\n2. sign.rs: fix whitelist h5->isH5; add pure generate_phone_util_device_id (44 lowercase-hex, 12+16+16 segments) + tests.\n3. live.rs: add load_or_create_device_id (pin>persist>generate), make device_id always-on String, always insert+sign deviceId, remove stale comment, hard-guard appVersion against the 1.9.0 placeholder.\n4. Update tests; run e2e + live clippy/test + secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented (static-only).

Ground truth re-confirmed from jadx:
- ApiParams (subclass of ThingApiParams) injects deviceId in BOTH getRequestBody (ApiParams.java:89) and initUrlParams (ApiParams.java:227) => the genuine app ALWAYS sends deviceId on token.get.
- Whitelist bdpdqbp (ThingApiSignManager.java:66) includes KEY_DEVICEID and KEY_H5; ThingApiParams.java:54 KEY_DEVICEID="deviceId", :60 KEY_H5="isH5" => deviceId IS signed; the wire H5 key is isH5 not h5.
- deviceId SHAPE (PhoneUtil.getRemoteDeviceID, PhoneUtil.java:770): md5AsBase64(BRAND+MODEL)[4:16] ++ md5AsBase64(rand)[8:24] ++ md5AsBase64(rand)[16:32]. MD5Util.md5AsBase64(byte[]) actually returns HexUtil.bytesToHexString(md5(..)) (MD5Util.java:577), i.e. 32-char LOWERCASE hex (HexUtil.java:138 uses Integer.toHexString). So deviceId = 12+16+16 = 44 lowercase-hex chars. Chose exactly this shape.

Why a generated id is faithful (not a workaround): the real app itself GENERATES this id once and caches it in SecuredPreferenceStore (PhoneUtil.java:326-333). The server does NOT validate the deviceId VALUE - it is merely SIGNED and the gateway recomputes the sign over received params. A stable, correctly-shaped, generated, PERSISTED id (secrets/device_id.txt, reused) is therefore app-faithful. Caller-pinned secrets/android_profile.json deviceId wins when present.

HONESTY CAVEAT: this does NOT claim to fix ILLEGAL_CLIENT_ID. Round-4 verified ICI is UNLIKELY caused by the missing deviceId (ICI names clientId; a fresh per-install id cannot be "illegal"). The corrupt-sign differential already showed ICI is sign-INSENSITIVE (an identity gate upstream of sign-verify). This change is for app-FIDELITY and to make the token.get a clean single-variable request for a future AUTHORIZED live A/B probe. BmpTokenPending honesty preserved (no fabricated signatures).

Gate results (all green):
- just e2e: EXIT 0 (core lib 111 ok, device_fixtures 10 ok, bmp-decode 18 ok, regions 5 ok; clippy/fmt/stub-grep/assert-offline clean).
- cargo clippy -p babymonitor-cli --features live --all-targets -- -D warnings: clean.
- cargo test -p babymonitor-cli --features live: 32 passed, 0 failed.
- New sign tests: phone_util_device_id_is_44_lowercase_hex_and_segment_shaped, whitelist_uses_is_h5_key_not_h5 -> ok.
- just secret-scan: OK (no secrets in tracked files / diff / backlog). No literal secret values entered any file or note.

Status left IN PROGRESS: the live A/B re-test (send token.get with the deviceId and observe whether the server response differs) is NOT statically performable - it needs an authorized live probe against the user's own Tuya account. Unblock path: the existing run_token_get_probe one-shot token.get.

LIVE A/B FIRED (2026-06-26, authorized, codes-only): candidate-sign token.get -> ILLEGAL_CLIENT_ID; corrupt-sign (one nibble of the valid 64-hex sign flipped) -> identical ILLEGAL_CLIENT_ID. Clean differential proves ICI is sign-insensitive (server rejects on identity before sign-verify). deviceId is therefore DEFINITIVELY refuted as the ICI cause (request is now byte-faithful + valid sign, ICI persists). Recorded in re/live_login.md. deviceId/h5/appVersion fidelity fixes stand on their own merit.

Signer whitelist field-name corrections (pairs with appId->clientId in TASK-0042): SIGN_WHITELIST/envelope key t -> time (KEY_TIMESTAMP). With the old t key the timestamp param was dropped from the canonical sign. Both clientId (was appId) and time (was t) must be the wire keys or the appKey/timestamp never enter the sign.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Restored app-faithful deviceId (PhoneUtil.getRemoteDeviceID shape: 44 lc-hex, md5 segments), always sent+signed+persisted; fixed SIGN_WHITELIST h5->isH5; guarded appVersion placeholder. Live A/B with the corrected signer confirmed ICI is a sign-insensitive server-side identity gate (deviceId not the cause). e2e + --features live + secret-scan green.

SUPERSEDED (2026-06-26, TASK-0062): the closing claim that ICI is a sign-insensitive server-side identity gate is WRONG. ICI root cause was chKey length ([8..24]->[8..16]). deviceId was correctly refuted as the cause, but the gate framing is superseded — token.get succeeds after the chKey fix.
<!-- SECTION:FINAL_SUMMARY:END -->
