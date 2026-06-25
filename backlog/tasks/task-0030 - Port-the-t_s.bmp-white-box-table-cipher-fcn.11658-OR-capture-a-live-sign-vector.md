---
id: TASK-0030
title: >-
  Port the t_s.bmp white-box table cipher (fcn.11658) OR capture a live sign
  vector
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 04:12'
updated_date: '2026-06-25 06:07'
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
FINAL-SUMMARY: fcn.11658 fully ported + validated as standard AES-128-CBC (NOT a white-box; TASK-0029 wall RETRACTED). Tables extracted byte-exact (re/aes_tables.txt, .so-matched + FIPS-197 KAT). Key schedule, round function, CBC chaining, and full I/O mapping reconstructed. Decode: fully-ported-validated (cipher). BUT the decrypted output is the TLS cert-pinning config JSON, not provably the signer's bmp_token -- so TASK-0012 is NOT yet offline-unblocked. Stays In Progress; the remaining step (a single live sign-accept to pin the token mapping) is filed as TASK-0032. No guessed token wired; PendingBmpToken kept. Gates: e2e/check-evidence/secret-scan all GREEN.

JOB-1 (2026-06-25): re-analysed the FALSE single-xref claim. r2 axt @ str.t_s.bmp (relocs applied) returns TWO code xrefs: (1) 0x19a64 in fcn.199d8 (the AES cert-pinning path, already correct), (2) 0x13bf0 in fcn.13b5c (a raw-bytes reader). fcn.13b5c: Context.getAssets -> AAssetManager_fromJava -> select t_s.bmp vs t_s_daily.bmp by 'tst w20,1 / csel' (the JNI boolean Z flag; daily NOT shipped => production = t_s.bmp) -> AAssetManager_open/getLength/malloc/AAsset_read -> builds a std::string of the VERBATIM bytes (SSO or heap+memcpy; NO MD5/base64/slice). doCommandNative (fcn.13ef4) cmd=1 path calls it at 0x1466c, then passes the raw bytes as arg x3 to read_keys_from_content (libthing_security_algorithm.so@0x4974), which validates the BMP header (fcn.4a34: BM magic, size bounds, bfOffBits==size-0xe-0x28, 24/32bpp, compression 0), takes the pixel array at offset 54, and drives the imath-bignum + matrix decode (fcn.4b28 -> selector byte from pixels -> fcn.5138/fcn.54f4 -> matrix fcn.5eb0 'inited matrix:') of the SDK-config blob into the labelled key list, which feeds the cmd=1 MD5 key-builder fcn.13474. So the F1 model and tuya_sign_static.md s5's 'imath matrix decodes t_s.bmp' are CORROBORATED/CONFIRMED. BmpToken: PARTIALLY (statically-recoverable-in-principle — fully deterministic + device-independent; only static t_s.bmp pixels + static config blob + embedded matrix constants — but NOT ported: requires imath mp_int_* + matrix fcn.5eb0 ported byte-exact, no local oracle). The AES/cert-pinning finding (fcn.11658) STILL STANDS — it is a SEPARATE t_s.bmp consumer producing the TLS pin config, not the signer token. JOB-2 reconciliation: corrected re/bmp_token_whitebox.md (ERRATUM: two xrefs; removed F1 doubt; added s8 JOB-1 trace), re/bmp_token_decode.md (s1/s3/s5/s6 reframed historical, retracted the 'matrix unrelated to t_s.bmp' error), re/tuya_sign_static.md s5 note (reinstated the imath-matrix model), re/scripts/bmp_token_aes.py (P1-1 docstring fixed to RAW 16-byte MD5; P1-2 decode_bmp_token->decode_cert_pinning_config, --emit-secret->--emit-cert-pin, secrets/bmp_token.txt->secrets/cert_pinning_config.json) + its test. TASK-0032 re-scoped; TASK-0012 fed forward.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
JOB-1 + JOB-2 complete. JOB-1 BmpToken verdict: PARTIALLY (statically-recoverable-in-principle, un-ported). Found the SECOND t_s.bmp xref (fcn.13b5c @0x13bf0) on the cmd=1 sign path: it returns the VERBATIM t_s.bmp bytes, which doCommandNative passes as arg x3 to read_keys_from_content -> imath-bignum + matrix decode (fcn.5eb0) of the SDK-config blob -> feeds the MD5 key-builder fcn.13474. Corroborates F1 + tuya_sign_static.md s5. The AES/cert-pinning finding (fcn.11658) STILL STANDS as a separate consumer. JOB-2: corrected the false single-xref claim across re/bmp_token_whitebox.md (ERRATUM + s8 trace), re/bmp_token_decode.md (s1/s3/s5/s6 reframed historical), re/tuya_sign_static.md s5; fixed bmp_token_aes.py P1-1 (RAW MD5 docstring) + P1-2 (renamed to cert-pinning). TASK-0032 re-scoped to the fcn.13b5c finding; TASK-0012 fed-forward. Gates: check-evidence/secret-scan/e2e all GREEN. Residual: the imath bignum + matrix port itself (deterministic, device-independent, but no local oracle) — owned by TASK-0032.
<!-- SECTION:FINAL_SUMMARY:END -->
