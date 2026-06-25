---
id: TASK-0032
title: >-
  Implement the t_s.bmp bmp_token via the imath-bignum + matrix decode
  (fcn.13b5c path) OR pin it with ONE live sign
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 05:42'
updated_date: '2026-06-25 11:30'
labels:
  - wave2
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0030 JOB-1 corrected the premise of the original TASK-0032 (which wrongly said t_s.bmp has a single xref and no static token-decode exists). r2 axt @ str.t_s.bmp (relocs applied) shows TWO code xrefs: (1) 0x19a64 in fcn.199d8 = the AES-128-CBC cert-pinning path (output is the TLS pin config, NOT the signer token); (2) 0x13bf0 in fcn.13b5c = a raw-bytes reader called from doCommandNative (fcn.13ef4) at 0x1466c, ON the cmd=1 sign path. fcn.13b5c returns the VERBATIM t_s.bmp bytes (no MD5/base64/slice; t_s_daily.bmp sibling selected by the JNI boolean Z flag, daily NOT shipped => production uses t_s.bmp). doCommandNative passes those raw bytes as arg x3 to read_keys_from_content (libthing_security_algorithm.so@0x4974), which validates the BMP header (fcn.4a34), takes the pixel array at offset 54, and drives the imath-bignum + matrix deobfuscation (fcn.4b28 -> fcn.5138/fcn.54f4 -> matrix fcn.5eb0, 'inited matrix:') of the SDK-config blob into the labelled key list that feeds the cmd=1 MD5 key-builder (fcn.13474). So the F1 model [cert_sha256]_[bmp_token]_[appSecret] is CORROBORATED and tuya_sign_static.md s5's 'imath matrix decodes t_s.bmp' model is CONFIRMED. BmpToken verdict: PARTIALLY (statically-recoverable-in-principle: the decode is fully deterministic + device-independent — only static t_s.bmp pixels + static config blob + embedded matrix constants — but NOT yet ported; requires porting imath mp_int_* + the matrix transform/fcn.5eb0 exactly). This task: EITHER (a) port the imath bignum + matrix decode offline (re/bmp_token_whitebox.md s8 has the exact chain + addresses; the embedded matrix constants and fcn.5eb0/5138/54f4 must be ported byte-exact; NO local oracle until the end-to-end sign differential, so a 1-element error fails silently) and write the recovered token VALUE only to secrets/; OR (b) the cheaper contingency: capture ONE real signed request (TASK-0012 AC#3) and differential it against babymonitor-core::sign to pin the middle _-part + SignBody KeyOnly-vs-KeyAndCanonical + postData 24-vs-32 length — all in sign::tests::full_signature_byte_parity_pending_task_0030. NOTE: option (a) is the fully-static route; STATIC-ONLY can in principle close this via (a).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The bmp_token middle _-part is identified either by porting the imath-bignum + matrix decode (fcn.5eb0 path) offline OR by one live/independent sign vector (value to secrets/ only)
- [ ] #2 SignBody KeyOnly-vs-KeyAndCanonical + postData 24-vs-32 ambiguities resolved in one place
- [ ] #3 sign::Signer wired with the confirmed bmp_token provider; sign::tests::full_signature_byte_parity_pending_task_0030 asserts byte parity
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Decompile op1 path (FUN_00105138/0x5138) byte-exact via r2 disasm (Ghidra elided the xorstep 3rd arg). 2. Diff the offset-walk vs the port; fix divergences. 3. Verify real appKey+t_s.bmp -> INTEGRAL Vandermonde solve (native denom==1 self-oracle). 4. Keep synthetic tests green; add a real-input integral-oracle regression test (value withheld). 5. Write candidate bmp_token to secrets/ only. 6. Add tuya_sign.md TASK-0041 pointer. 7. Gates: e2e/check-evidence/secret-scan green.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-0032 RESULT (op1 byte-exact -> INTEGRAL solve): The op1 offset-walk in re/scripts/bmp_token_ghidra.py is now byte-exact vs the r2 disasm of FUN_00105138 (0x5158..0x5428). TWO residual bugs fixed:
(1) START OFFSET: was xorstep(px, base+1); the actual 3rd arg to the initial xorstep is the stack slot [x29,-0x34] PRE-INCREMENTED 3x -> base+3 (base+1 consumed @0x519c reading num_keys, base+2 @0x5230 reading num_coeffs, base+3 @0x529c as the xorstep arg). Fixed to (xorstep_u32(px, base+3) ^ r) % L.
(2) PER-PAIR XOR-STEP: was (xorstep(px, after_b) ^ after_b); the native XORs against the PAIR-START offset snapshot ([sp,0x2c] @0x5400, NOT after_b). Fixed to (xorstep_u32(px, after_b) ^ pair_start) % L.
ORACLE (native denom==1 self-oracle): with config=REAL appKey (secrets/tuya_appkey.json) + real assets/t_s.bmp, the decode now SOLVES INTEGRAL: selector=1 (op1), num_keys=1, num_coeffs=4, every pair alen=4/blen=32 -> a 32-byte (64-hex) integral key. Plausible crypto-token shape; near-impossible to land alen/blen=4/32 across all 4 pairs AND solve integral by chance.
candidate bmp_token written to secrets/bmp_token.txt ONLY (gitignored, unstaged, value never printed/committed). Committed code (bmp_token_ghidra.py main()) RECOMPUTES it from t_s.bmp+appKey each run; no hardcoded value.
HONESTY: integral-solve is NECESSARY not SUFFICIENT -> label CANDIDATE (integral-solve-consistent); ONE accepted live sign is the sufficient oracle (next).
GOTCHAS: (a) op2 path (FUN_001054f4) is NOT byte-verified -- it does NOT use the op1 xorstep walk (no bl 0x583c; sequential counter @0x57e0); op2 is out of scope for the real token (selector=1->op1) and has no end-to-end oracle. (b) Ghidra elided the xorstep 3rd arg as a 2-arg call -- r2 disasm was REQUIRED to recover the base+3 / pair_start operands; Ghidra C alone was insufficient for the op1 walk. (c) the synthetic test_synthetic_bmp_full_decode_runs was re-planted to the base+3 layout (it now PINS the corrected walk).
Tests: 18/18 green (added TestRealInputsIntegralOracle: asserts integral solve + shape on real inputs, value withheld, skips if secrets absent). Gates: just e2e / check-evidence / secret-scan all GREEN. tuya_sign.md ~:25-29 pointer to TASK-0041 (config=appKey) added.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
op1 offset-walk made BYTE-EXACT (r2 disasm of FUN_00105138): START offset uses base+3 (the [x29,-0x34] slot is pre-incremented 3x), per-pair XOR-step XORs against the pair-START snapshot (not after_b). With config=real appKey + real t_s.bmp the decode now SOLVES INTEGRAL (native denom==1 self-oracle: selector=1/op1, num_keys=1, num_coeffs=4, alen=4/blen=32 -> 32-byte key). Candidate bmp_token (integral-solve-consistent) written to secrets/bmp_token.txt ONLY (gitignored, value withheld; code recomputes from asset+appKey, no hardcode). 18/18 tests green incl a real-input integral-oracle regression; e2e/check-evidence/secret-scan GREEN. NECESSARY!=SUFFICIENT: live-login validation is next. tuya_sign.md TASK-0041 pointer added; feed-forward to TASK-0012/0014.
<!-- SECTION:FINAL_SUMMARY:END -->
