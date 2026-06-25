---
id: TASK-0033
title: >-
  Ghidra-headless port of the bmp_token imath+matrix decode (byte-exact,
  2nd-tool corroboration)
status: In Progress
assignee:
  - '@reverser'
created_date: '2026-06-25 06:35'
updated_date: '2026-06-25 06:57'
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
Decode: fully-ported-unvalidated.

GHIDRA INVOCATION THAT WORKED (successors reuse this):
  nixpkgs ghidra 11.4.2 ships the wrapper at $(dirname ghidra)/ghidra-analyzeHeadless.
  ghidra-analyzeHeadless analysis/ghidra bmptok -import <lib.so> -scriptPath analysis/ghidra -postScript DumpDecomp.py re/ghidra <spec...>
  - spec = NAME (exported symbol) or NAME@0xADDR. Ghidra applies image base 0x100000, so a file-offset 0x4b28 must be passed as 0x104b28. Exported symbols resolve directly.
  - DO NOT pass -deleteProject if you want to re-run -process later (it nukes the project). Re-import the SECOND lib into the SAME project name with a fresh -import (not -process) run.
  - DumpDecomp.py (analysis/ghidra/, gitignored) uses DecompInterface + createFunction for raw addrs; writes one .c per fcn to re/ghidra/.

KEY FINDINGS:
1. The decode is the nalajcie Vandermonde scheme CONFIRMED byte-exact via Ghidra: strhash(config)->selector pixel->op1(direct bytes)/op2(LSB-packed bytes)->coeff (a,b) hex pairs->Vandermonde over imath mp_rat->Gauss-elim->require denom==1->mp_int_to_binary numerator->%02x hex key. transform@0x6c58 is a NO-OP stub.
2. r2-vs-Ghidra DIVERGENCE: r2 trace (bmp_token_whitebox s8) attributed read_keys_from_content + fcn.13b5c to cmd=1; Ghidra doCommandNative.c shows cmd=0 runs the decode (caches '_'-joined key in DAT_00139070); cmd=1/cmd=2 MD5 that cache. Model unchanged, cmd-number corrected.
3. BIG FINDING: config arg = RUNTIME JNI byte[] (param_6), NOT static. So even the complete port cannot emit the production token offline -- refutes the 'no runtime input' claim in tuya_sign_static.md s5 / whitebox s8. Residual shifts from 'port the matrix' (DONE) to 'obtain the runtime SDK-config byte[]' or a live vector.

GOTCHAS:
- objdump -d produced near-empty output on this .so; use r2 (default base, no reloc-shift) for cross-checking disassembly. r2 -e bin.relocs.apply=true SHIFTS addresses and broke .rodata px reads; objdump -s -j .rodata read the format strings cleanly (DAT_00102b69 = '%02x').
- Ghidra dropped the 3rd arg on two FUN_0010583c (xorstep) calls in decode_op1; recovered them from r2 disasm of 0x5138 (start off = xorstep(px,base+1)^r; per-pair off = xorstep(px,off)^off).
- BmpTokenProvider kept PendingBmpToken (NOT wired to a fake) -- correct since no production token is computable offline yet.
<!-- SECTION:NOTES:END -->
