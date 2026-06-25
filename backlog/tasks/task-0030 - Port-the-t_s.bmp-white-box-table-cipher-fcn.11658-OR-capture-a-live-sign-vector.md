---
id: TASK-0030
title: >-
  Port the t_s.bmp white-box table cipher (fcn.11658) OR capture a live sign
  vector
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 04:12'
updated_date: '2026-06-25 06:19'
labels:
  - phase3
  - re
  - auth
  - native
dependencies:
  - TASK-0029
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Residual from TASK-0029 (re/bmp_token_decode.md, Decode: partially-ported). The t_s.bmp bmp_token is produced by a white-box table cipher in libthing_security.so fcn.11658 (tbl S-box + GF(2) eor mixing + T-table @.rodata 0x7800, tables @.data.rel.ro 0x38000/0x39000), keyed by constant '7178265647164836' over the tecrkcehc_ext base64 ciphertext. nalajcie's polynomial/matrix scheme does NOT apply (different/older SDK). Two paths to unblock TASK-0012 byte-for-byte differential: (a) RECOMMENDED — capture ONE real signed request from a gated live run (TASK-0012 AC#3 contingency) and use its sign as the gold vector; far cheaper, no white-box port. (b) Complete the static white-box port: extract all T-tables byte-exact, reconstruct fcn.11658 SPN round function instruction-faithfully, feed t_s.bmp + tecrkcehc_ext + the constant, validate the recovered token only into secrets/. STATIC-ONLY risk: no local oracle until the end-to-end sign differential, so a 1-byte table error fails silently.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1) Onboard: TASK-30/29, re/bmp_token_decode.md, sign.rs interface, skill. 2) Disassemble fcn.11658 + callers (11570/19810/1a030/199d8/19bf4/19cf0/119e4) instruction-level via r2. 3) Identify the SPN: extract S-boxes, round structure, key schedule, I/O. 4) Port byte-exact to python + unit tests (FIPS KAT + .so byte-match + structural oracle). 5) Document re/bmp_token_whitebox.md. 6) Gates green; wire/leave provider honestly.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Script reconciliation (follow-up to commit 8753bf1) completed: re/scripts/bmp_token_decode.py + re/scripts/test_bmp_token_decode.py corrected to the FINAL verified model. Removed the retracted 'white-box table cipher / matrix-doesn-t-apply / no-edge-from-BMP-driver' assertions from the module docstring, thisapp_decode() residual, and the CLI report. thisapp_decode() now raises MatrixResidual (WhiteBoxResidual kept as a back-compat alias) citing the imath+matrix decode of raw t_s.bmp on the sign path (fcn.13b5c->doCommandNative->read_keys_from_content@0x4974->fcn.5eb0), un-ported (no local oracle; nalajcie's older byte-layout mismatches). Tests test_matrix_scheme_does_not_apply -> test_nalajcie_older_layout_does_not_match_this_apk (narrow layout-mismatch fact only) and test_thisapp_decode_is_walled -> test_thisapp_decode_is_unported. 12 decode tests pass; check-evidence/secret-scan/e2e all GREEN. No live retracted-model assertion remains in re/scripts/.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
JOB-1 + JOB-2 complete. JOB-1 BmpToken verdict: PARTIALLY (statically-recoverable-in-principle, un-ported). Found the SECOND t_s.bmp xref (fcn.13b5c @0x13bf0) on the cmd=1 sign path: it returns the VERBATIM t_s.bmp bytes, which doCommandNative passes as arg x3 to read_keys_from_content -> imath-bignum + matrix decode (fcn.5eb0) of the SDK-config blob -> feeds the MD5 key-builder fcn.13474. Corroborates F1 + tuya_sign_static.md s5. The AES/cert-pinning finding (fcn.11658) STILL STANDS as a separate consumer. JOB-2: corrected the false single-xref claim across re/bmp_token_whitebox.md (ERRATUM + s8 trace), re/bmp_token_decode.md (s1/s3/s5/s6 reframed historical), re/tuya_sign_static.md s5; fixed bmp_token_aes.py P1-1 (RAW MD5 docstring) + P1-2 (renamed to cert-pinning). TASK-0032 re-scoped to the fcn.13b5c finding; TASK-0012 fed-forward. Gates: check-evidence/secret-scan/e2e all GREEN. Residual: the imath bignum + matrix port itself (deterministic, device-independent, but no local oracle) — owned by TASK-0032.
<!-- SECTION:FINAL_SUMMARY:END -->
