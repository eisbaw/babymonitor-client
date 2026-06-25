---
id: TASK-0029
title: Port the t_s.bmp matrix/imath token decode to Rust (static signer residual)
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 03:29'
updated_date: '2026-06-25 06:32'
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
FINAL: partial result delivered + committed (c2298cd). Follow-up filed as TASK-0030 (white-box port OR live-vector contingency). Task stays In Progress — NOT Done — because the decode is only partially ported (framing + independent cross-check), the white-box token producer (fcn.11658) is the un-ported wall.

Cycle-13 review: both GO. Architect reproduced the disassembly (fcn.11658 = white-box table cipher, no AES/imath/pow, disjoint from the matrix). REFUTES TASK-0023 §5 (matrix decodes SDK config blob, NOT the token). White-box wall is honest. Both reviewers: static-only auth is GENUINELY BLOCKED on the bmp_token; handoff justified. P2: bmp_token_decode.md §4 should attribute the 'matrix doesn't apply' conclusion primarily to the disassembly (the nalajcie reader is an unvalidated reconstruction) -> note on TASK-0030.

Subsumed: the white-box-wall conclusion was corrected by TASK-0030 (the imath+matrix decode IS the bmp_token on the sign path); the un-ported residual is owned by TASK-0032. Closing — work delivered (the partial port + the AES/cert-pinning disambiguation).
<!-- SECTION:NOTES:END -->
