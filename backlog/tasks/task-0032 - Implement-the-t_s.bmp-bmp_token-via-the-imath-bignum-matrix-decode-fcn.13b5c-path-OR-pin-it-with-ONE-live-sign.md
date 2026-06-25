---
id: TASK-0032
title: >-
  Implement the t_s.bmp bmp_token via the imath-bignum + matrix decode
  (fcn.13b5c path) OR pin it with ONE live sign
status: To Do
assignee: []
created_date: '2026-06-25 05:42'
updated_date: '2026-06-25 06:35'
labels:
  - phase3
  - re
  - auth
  - native
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0030 JOB-1 corrected the premise of the original TASK-0032 (which wrongly said t_s.bmp has a single xref and no static token-decode exists). r2 axt @ str.t_s.bmp (relocs applied) shows TWO code xrefs: (1) 0x19a64 in fcn.199d8 = the AES-128-CBC cert-pinning path (output is the TLS pin config, NOT the signer token); (2) 0x13bf0 in fcn.13b5c = a raw-bytes reader called from doCommandNative (fcn.13ef4) at 0x1466c, ON the cmd=1 sign path. fcn.13b5c returns the VERBATIM t_s.bmp bytes (no MD5/base64/slice; t_s_daily.bmp sibling selected by the JNI boolean Z flag, daily NOT shipped => production uses t_s.bmp). doCommandNative passes those raw bytes as arg x3 to read_keys_from_content (libthing_security_algorithm.so@0x4974), which validates the BMP header (fcn.4a34), takes the pixel array at offset 54, and drives the imath-bignum + matrix deobfuscation (fcn.4b28 -> fcn.5138/fcn.54f4 -> matrix fcn.5eb0, 'inited matrix:') of the SDK-config blob into the labelled key list that feeds the cmd=1 MD5 key-builder (fcn.13474). So the F1 model [cert_sha256]_[bmp_token]_[appSecret] is CORROBORATED and tuya_sign_static.md s5's 'imath matrix decodes t_s.bmp' model is CONFIRMED. BmpToken verdict: PARTIALLY (statically-recoverable-in-principle: the decode is fully deterministic + device-independent — only static t_s.bmp pixels + static config blob + embedded matrix constants — but NOT yet ported; requires porting imath mp_int_* + the matrix transform/fcn.5eb0 exactly). This task: EITHER (a) port the imath bignum + matrix decode offline (re/bmp_token_whitebox.md s8 has the exact chain + addresses; the embedded matrix constants and fcn.5eb0/5138/54f4 must be ported byte-exact; NO local oracle until the end-to-end sign differential, so a 1-element error fails silently) and write the recovered token VALUE only to secrets/; OR (b) the cheaper contingency: capture ONE real signed request (TASK-0012 AC#3) and differential it against babymonitor-core::sign to pin the middle _-part + SignBody KeyOnly-vs-KeyAndCanonical + postData 24-vs-32 length — all in sign::tests::full_signature_byte_parity_pending_task_0030. NOTE: option (a) is the fully-static route; STATIC-ONLY can in principle close this via (a).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The bmp_token middle _-part is identified either by porting the imath-bignum + matrix decode (fcn.5eb0 path) offline OR by one live/independent sign vector (value to secrets/ only)
- [ ] #2 SignBody KeyOnly-vs-KeyAndCanonical + postData 24-vs-32 ambiguities resolved in one place
- [ ] #3 sign::Signer wired with the confirmed bmp_token provider; sign::tests::full_signature_byte_parity_pending_task_0030 asserts byte parity
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-0033 (Ghidra-headless port) is the deep-static attempt to resolve this residual; if it lands a confident byte-exact port, TASK-0032 narrows to just the live-vector validation.
<!-- SECTION:NOTES:END -->
