---
id: TASK-0033
title: >-
  Ghidra-headless port of the bmp_token imath+matrix decode (byte-exact,
  2nd-tool corroboration)
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 06:35'
updated_date: '2026-06-25 07:12'
labels:
  - phase3
  - re
  - auth
  - native
  - ghidra
dependencies:
  - TASK-0030
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
USER DIRECTIVE 2026-06-25: actually USE Ghidra (analysis so far was radare2-only despite Ghidra name-drops). Ghidras decompiler is far stronger for the white-box bignum/matrix logic. Run Ghidra headless on libthing_security_algorithm.so AND libthing_security.so (the JNI lib); use Ghidras C decompilation as the PRIMARY source to port the bmp_token decode byte-exact: read_keys_from_content@0x4974 -> BMP header check fcn.4a34 -> pixel array @offset 54 -> imath mp_int bignum (fcn.4b28/5138/54f4) -> matrix transform fcn.5eb0 ("inited matrix:") -> key list feeding cmd=1 MD5 builder fcn.13474. Cross-check Ghidra C-decompile against the existing r2 axt trace (must agree; record any divergence). Deep-static path to close the TASK-0032 residual with real 2nd-tool corroboration. ALSO fix labeling: only claim "Ghidra" where Ghidra was actually run — correct task-0023 title + the tuya_sign_static.md/tuya_sign.md/native_libs.md "Ghidra/radare2" headers to reflect reality (radare2 for prior cycles; Ghidra here).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Ghidra headless actually run on both libs; the decompiled C for read_keys_from_content + the bignum/matrix chain is captured (committed under re/ as text); divergences vs the r2 trace recorded
- [x] #2 bmp_token decode ported to runnable+tested code (python or Rust) from Ghidras C as primary source; if it produces a candidate token, value to secrets/ only, code computes it from t_s.bmp
- [x] #3 Honest validation status labelled {fully-ported-validated|fully-ported-unvalidated|partially}: state what static oracle (if any) confirms it, and that the only true oracle is a live sign-accept (excluded). If the BmpTokenProvider can be wired with the real (even unvalidated) decoder, wire it clearly marked UNVALIDATED; else keep PendingBmpToken
- [x] #4 Labeling corrected: task-0023 title + re/ doc headers accurately attribute radare2 (prior) vs Ghidra (this task); no doc claims Ghidra where only r2 ran
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1) Onboard (done): tasks 33/30/32/23, bmp_token_whitebox.md s8, tuya_sign_static.md s5, review_gate F1, decode scripts. Confirmed imath lib (standard mp_int_/mp_rat_ exports) + read_keys_from_content@0x4974, transform@0x6c58, matrix fcn.5eb0. 2) Run Ghidra headless (ghidra-analyzeHeadless wrapper in nixpkgs ghidra 11.4.2 bin/) on BOTH libs into gitignored analysis/ghidra/; postScript (Jython) decompiles target fcns to C, dumped under re/ghidra/. 3) Read Ghidra C for read_keys_from_content, fcn.4a34 (BMP hdr), fcn.4b28/5138/54f4, matrix fcn.5eb0, transform; and in libthing_security: doCommandNative fcn.13ef4, fcn.13b5c, fcn.13474, call site 0x1466c. 4) Cross-check Ghidra call graph vs r2 axt trace (s8) -- record agreement/divergence. 5) Port the decode from Ghidra C as PRIMARY source to python under re/scripts/ (reuse imath semantics from exported symbol names), feed real t_s.bmp + config blob; unit tests. 6) Honest Decode: status. Wire BmpTokenProvider (Rust) only if confident, CLEARLY UNVALIDATED; else keep Pending. 7) Fix labeling: task-0023 title -> radare2; doc headers attribute radare2 (prior) vs Ghidra (this). 8) Gates: just e2e, check-evidence, secret-scan, python tests. One/two commits, no AI-credit trailer.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FINAL SUMMARY: Ghidra-headless port COMPLETE. Decode: fully-ported-unvalidated. Ran Ghidra 11.4.2 (ghidra-analyzeHeadless) on both libs; decompiled 21 functions to C (re/ghidra/*.c) as the primary source; ported the t_s.bmp imath+matrix bmp_token decode byte-exact to re/scripts/bmp_token_ghidra.py (16 tests, all green). The decode is the nalajcie Vandermonde/rational-interpolation scheme, CONFIRMED byte-exact: strhash(config) selector -> op1(direct bytes)/op2(LSB-packed bytes) -> (a,b) hex coeff pairs -> Vandermonde over imath mp_rat -> Gauss-elim -> denom==1 gate -> mp_int_to_binary numerator -> %02x key; transform is a no-op stub. Ghidra-vs-r2: AGREE on the chain; Ghidra adds the exact math; DIVERGENCE recorded (decode runs on cmd=0 not cmd=1; r2 was off-by-one). NEW finding: config input is a RUNTIME JNI byte[], not static -> the production token is NOT computable from assets alone (refutes the prior 'no runtime input' claim); residual shifts from the matrix (done) to the runtime config blob / a live vector. Labeling fixed: task-0023 title + 4 doc headers attribute radare2 (prior) vs Ghidra (this). Gates e2e/check-evidence/secret-scan GREEN. Commit 90cacc8. BmpTokenProvider stays PendingBmpToken (honest). HONEST LIMITATION: no static oracle exists, so 'unvalidated'; a 1-byte error in the offset-walk would fail silently, and the full production path additionally needs the runtime config blob.

DOC RECONCILIATION (follow-up to the §9 REFUTED finding; review NO-GO closed). The §9 finding -- bmp_token decode keys off a RUNTIME JNI byte[] SDK-config (doCommandNative param_6), so it is NOT statically recoverable -- was authoritative in re/bmp_token_whitebox.md §9, but three docs still asserted the prior 'deterministic / no runtime input / statically-recoverable-in-principle' model as current (4th recurrence of the overturn-lag pattern). Reconciled (documentation-only, authoritative source = §9): (1) re/tuya_sign_static.md §5 + §6 verdict table/summary -- struck the 'depends ONLY on static assets, no runtime input' claim, added CORRECTED/REFUTED + §9 pointer, flipped the verdict row to 'matrix-ported BUT needs runtime SDK-config byte[] -- not static-only achievable'; (2) re/bmp_token_whitebox.md §1 caveat + §6 verdict bullet + §7 table row/summary -- added 'see §9 -- REFUTED: needs runtime SDK-config byte[]' forward-pointers and flipped the skim-first labels so §6/§7 agree with §9; (3) re/bmp_token_decode.md banner -- 'partially (un-ported imath matrix)' corrected to 'matrix ported (TASK-0033); needs runtime SDK-config byte[] -- not static-only, see §9'; (4) re/tuya_sign.md superseded-banner -- 'only the t_s.bmp token-decode port remains' corrected to point at §9 (matrix ported; residual is the runtime config). Also added §9 pointers to two script docstrings (bmp_token_ghidra.py VALIDATION STATUS, bmp_token_decode.py MatrixResidual/thisapp_decode) that still framed the decode as deterministic/device-independent without the runtime-config caveat -- docstring-only, no logic change. Verified: rg -n 'no runtime input|deterministic.*device-independent|statically-recoverable-in-principle' re/ -- every remaining hit is now in a REFUTED/CORRECTED/historical context with a §9 pointer. Gates GREEN: just check-evidence, just secret-scan, just e2e. Also strengthened TASK-0021's systemic note (Wave-2 should implement the verdict-overturn grep-guard; the manual checklist has now failed 4x).

Cycle-20 review: qa GO; architect NO-GO on the 4th overturn-lag (refuted 'no runtime input' model left in tuya_sign_static §5/§6 + whitebox §6/§7 + bmp_token_decode.md) -> reconciled in d67210e (sweep clean). TERMINAL FINDING (reviewer-confirmed): bmp_token decode keys off a RUNTIME JNI byte[] SDK-config (doCommandNative param_6) -> static-only auth is a DEAD END for the token. Matrix fully ported (Ghidra), but production token needs the runtime config blob OR one live sign vector (both excluded by static-only).
<!-- SECTION:NOTES:END -->
