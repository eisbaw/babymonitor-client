---
id: TASK-0022
title: Frida hook to capture Tuya sign vector + derived key at runtime
status: To Do
assignee: []
created_date: '2026-06-25 01:22'
updated_date: '2026-06-25 01:59'
labels:
  - phase3
  - re
  - auth
  - runtime
dependencies:
  - TASK-0005
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Spike TASK-0005 verdict was needs-runtime-hook: the mobile-app sign KEY is derived in native (libthing_security.so) from app-cert SHA256 + matrix-deobfuscated t_s.bmp token + appSecret, and the routine is stripped. Hook com.thingclips.smart.security.jni.JNICLibrary.doCommandNative (cmd=1) and/or pbddddb.bdpdqbp(String)/SecureNativeApi.testSign on the user's authorized device to log (string-to-sign bytes -> returned sign) pairs. Output: a known-answer differential test vector for TASK-0012 (TESTING.md Part-2 signal #2) and, if possible, the derived sign key. Authorized scope: user's own device/account only; secrets to secrets/ only, never committed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A captured (string-to-sign,sign) vector is stored in secrets/ and a non-secret description (method+symbol) is in re/
- [ ] #2 TASK-0012 Rust signer can validate against the captured vector
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OUT OF SCOPE for this STATIC-ONLY effort (user directive 2026-06-25): do NOT run Frida/on-device dynamic capture. Superseded by TASK-0023 (fully-static Ghidra recovery of the sign key on libthing_security_algorithm.so). Leave To Do as a documented non-goal; the signing differential vector for TASK-0012 comes from TASK-0023, not from here.
<!-- SECTION:NOTES:END -->
