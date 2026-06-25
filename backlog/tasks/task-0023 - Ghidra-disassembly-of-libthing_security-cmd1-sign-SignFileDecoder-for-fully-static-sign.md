---
id: TASK-0023
title: >-
  Ghidra disassembly of libthing_security cmd=1 sign + SignFileDecoder for
  fully-static sign
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 01:22'
updated_date: '2026-06-25 03:30'
labels:
  - phase3
  - re
  - auth
  - native
dependencies:
  - TASK-0005
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Heavier alternative to the Frida hook (TASK-0005 follow-up). Disassemble the doCommandNative cmd-dispatch and security_infra::SignFileDecoder in libthing_security.so / libthing_security_algorithm.so to recover: (a) the exact combination order of [app_cert_SHA256]_[bmp_token]_[appSecret], (b) the t_s.bmp -> token deobfuscation (imath mp_int + matrix), (c) the keyed hash (confirm HMAC-SHA256). Goal: make the signer reproducible without a device. Lower priority than the Frida hook.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Combination order + hash primitive of the native sign key derivation documented in re/tuya_sign.md with offset citations
- [x] #2 t_s.bmp decode routine characterized at offset level
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FINAL SUMMARY: dive complete. VERDICT=partially-recoverable. Disassembled JNI_OnLoad RegisterNatives (9 natives) -> doCommandNative@0x13ed8, isolated cmd=1 sign path, followed to the keyed hash. KEY FINDINGS (all confirmed at byte level): keyed primitive is PLAIN MD5-hex (not HMAC-SHA256) [MD5 IV @0x76c0, 16-byte out @0x194b0, hex @0x7810]; key-combine is underscore-joined [sep @0x88c4]; app-cert SHA-256 is COMPUTABLE OFFLINE from APK META-INF/BNDLTOOL.RSA (removes runtime-cert blocker); t_s.bmp token = deterministic imath-bignum+matrix decode in libthing_security_algorithm.so (read_keys_from_content/parse/transform + 'inited matrix:' @0x5eb0) — reproducible in principle but UN-PORTED = the single residual. 5 of 6 ingredients statically recovered. Doc: re/tuya_sign_static.md (Verdict:partially-recoverable, check-evidence GREEN). Fed forward MD5 algorithm to TASK-0012; filed TASK-0029 (port bmp matrix decode). Gates: check-evidence/secret-scan/e2e all GREEN; no secret value in any tracked file (appKey/appSecret + cert-hash method only in gitignored secrets/tuya_appkey.json).
<!-- SECTION:NOTES:END -->
