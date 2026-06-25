---
id: TASK-0033
title: >-
  Ghidra-headless port of the bmp_token imath+matrix decode (byte-exact,
  2nd-tool corroboration)
status: To Do
assignee: []
created_date: '2026-06-25 06:35'
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
- [ ] #1 Ghidra headless actually run on both libs; the decompiled C for read_keys_from_content + the bignum/matrix chain is captured (committed under re/ as text); divergences vs the r2 trace recorded
- [ ] #2 bmp_token decode ported to runnable+tested code (python or Rust) from Ghidras C as primary source; if it produces a candidate token, value to secrets/ only, code computes it from t_s.bmp
- [ ] #3 Honest validation status labelled {fully-ported-validated|fully-ported-unvalidated|partially}: state what static oracle (if any) confirms it, and that the only true oracle is a live sign-accept (excluded). If the BmpTokenProvider can be wired with the real (even unvalidated) decoder, wire it clearly marked UNVALIDATED; else keep PendingBmpToken
- [ ] #4 Labeling corrected: task-0023 title + re/ doc headers accurately attribute radare2 (prior) vs Ghidra (this task); no doc claims Ghidra where only r2 ran
<!-- AC:END -->
