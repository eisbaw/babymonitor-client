---
id: TASK-0029
title: Port the t_s.bmp matrix/imath token decode to Rust (static signer residual)
status: In Progress
assignee:
  - '@reverser'
created_date: '2026-06-25 03:29'
updated_date: '2026-06-25 04:11'
labels:
  - phase3
  - re
  - auth
  - native
dependencies:
  - TASK-0023
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Residual blocker from TASK-0023 static signer dive (re/tuya_sign_static.md §5). The Tuya mobile sign needs a 'bmp_token' decoded from assets/t_s.bmp via a deterministic, device-independent white-box deobfuscation: imath multi-precision bignum (mp_int_init/mul/div/exptmod/invmod, exported by libthing_security_algorithm.so) + a matrix linear-algebra step ('inited matrix:' string @0x2b30; matrix-init fcn@0x5eb0; high-level read_keys_from_content@0x4974 / parse@0x4eec / transform@0x6c58; SignFileDecoder asset-read fcn@0x199d8 in libthing_security.so). It is reproducible IN PRINCIPLE (no runtime input — only t_s.bmp + embedded matrix constants) but was NOT ported within TASK-0023. GOAL: port these ~6 functions + the imath ops to Rust/python so the bmp_token is recoverable offline, unblocking the byte-for-byte differential for TASK-0012. STATIC-ONLY (no Frida/device). Validate against nalajcie/tuya-sign-hacking. SECRETS: the decoded token value goes to secrets/ only, never a tracked file.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1) Onboard: TASK-0029, tuya_sign_static §5, nalajcie ref, skill.
2) Study nalajcie BMP decode (hash->offset, (a,b) pairs, exact-rational matrix solve).
3) Disassemble OUR libthing_security_algorithm.so: confirm read_keys_from_content/parse/matrix-init = rational matrix (mp_rat_div/mul/sub/reduce, denom==1, numerator->bytes) -> MATCHES nalajcie BUT for the config-blob path.
4) Disassemble OUR libthing_security.so BMP driver fcn.1a030: t_s.bmp read + tecrkcehc_ext + constant -> transform fcn.11658 = WHITE-BOX TABLE CIPHER (tbl S-box, GF(2) eor, T-table @0x7800). NOT the matrix scheme.
5) Port: python re/scripts/bmp_token_decode.py = nalajcie reference (independent cross-check, known-vector validated) + recovered framing + wall marker. 12 unit tests.
6) Document re/bmp_token_decode.md (Decode: partially-ported). Wire test into e2e. Gates green.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GOTCHAS / honest findings:
- The tuya_sign_static.md §5 hypothesis (t_s.bmp decoded by imath matrix) is WRONG. Disassembly: read_keys_from_content (imath matrix, mp_rat_*) is only xref'd from cmd-dispatch fcn.13ef4 (SDK-config blob, asset tecrkcehc JSON); there is NO edge from the BMP driver fcn.1a030. The matrix decodes config keys, not the BMP token.
- The REAL t_s.bmp token decode (libthing_security.so fcn.1a030 -> fcn.19810 -> fcn.11570 -> fcn.11658) is a WHITE-BOX TABLE CIPHER: tbl v0.16b{v16-v19} S-box, ldr q1,[x9,0x800] T-table @.rodata 0x7800, dense eor v.8b GF(2) mixing, tables also @0x38000/0x39000. Keyed by embedded constant '7178265647164836' (.rodata 0x85f5) over the tecrkcehc_ext base64 ciphertext (header decimal 226 + 344-byte body, parsed by fcn.19cf0 base-10 pow accumulate).
- This is NOT nalajcie's polynomial/matrix BMP scheme — nalajcie reversed an OLDER Tuya SDK. Confirmed by porting nalajcie's exact-rational solver (validated on a planted known-vector) and showing it produces NO consistent token from this BMP.
- Decode: partially-ported. Framing (BMP read, ext decimal parse, offset string-hash acc*31+byte/abs, constant) recovered + unit-tested (12 tests, re/scripts/test_bmp_token_decode.py). White-box cipher = the WALL: needs all T-tables extracted + fcn.11658 SPN reconstructed byte-exact, with no local oracle until the end-to-end sign differential. Did NOT complete; chose Python (not a non-functional Rust stub).
- TASK-0012 byte-for-byte differential remains BLOCKED offline on bmp_token only; recommend its AC#3 contingency (one gated live-captured request as the gold vector) over completing the white-box port. Partial differential (cert-hash+appSecret+MD5+'_'-join, placeholder token) achievable now.
- No secret value written to any tracked file (secret-scan green). The embedded constant '7178265647164836' is a public APK whitebox parameter, not a recovered token/key.
<!-- SECTION:NOTES:END -->
