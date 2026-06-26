---
id: TASK-0056
title: Full Ghidra decompile of libthing_security.so + identity/clientId map
status: Done
assignee: []
created_date: '2026-06-25 22:48'
updated_date: '2026-06-26 02:05'
labels:
  - auth
  - native
  - illegal-client-id
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The APK logs in successfully, so ILLEGAL_CLIENT_ID is a request-construction defect on our side, not an unbeatable gate. Fully decompile libthing_security.so (every function, strings, symbols) and map where the outbound clientId/appKey/ttid/identity params and any security headers are constructed/validated, as native ground truth.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All functions of libthing_security.so decompiled to per-function .c under decompiled/ghidra_security/
- [ ] #2 doCommandNative cmd dispatch table enumerated (cmd id -> handler) with evidence
- [ ] #3 Every native-produced identity/sign field for the login token.get traced to its construction (clientId, appKey, ttid, sign, headers) with ghidra-func citations
- [ ] #4 Findings written to re/security_so_decompile.md with confidence levels; secrets referenced by secrets/ path only
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Full decompile DONE: 676 funcs + 522 strings + 258 symbols at decompiled/ghidra_security/ (script re/scripts/ghidra_decompile_all.py). JNI_OnLoad registers 9 natives to com.thingclips.smart.security.jni.SecureNativeApi: doCommandNative@0x113ed8, encryptPostData@0x1151f8, getEncryptoKey@0x115368, genKey@0x115720, computeDigest@0x115ad0, decryptResponseData@0x115e28, getChKey@0x116000, getConfig@0x1136e0, testSign@0x116408. Dispatch: cmd0=key provision (t_s.bmp->G), cmd1=HMAC-SHA256 sign, cmd2=SHA256 derivation.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
libthing_security.so fully decompiled (676 funcs, re/scripts/ghidra_decompile_all.py -> decompiled/ghidra_security/). JNI map (9 natives on SecureNativeApi), doCommandNative dispatch (cmd0 G-provision, cmd1 HMAC-SHA256 sign, cmd2 SHA256), cert reader, SignFileDecoder all mapped. Identity/sign construction documented in re/master_secret_g.md + re/live_login.md + memory. Drove the signer fix (0060) and the live A/B that proved the server-side gate.
<!-- SECTION:FINAL_SUMMARY:END -->
