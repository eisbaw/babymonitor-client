---
id: TASK-0029
title: Port the t_s.bmp matrix/imath token decode to Rust (static signer residual)
status: To Do
assignee: []
created_date: '2026-06-25 03:29'
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
