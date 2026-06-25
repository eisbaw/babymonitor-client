---
id: TASK-0023
title: >-
  Ghidra disassembly of libthing_security cmd=1 sign + SignFileDecoder for
  fully-static sign
status: To Do
assignee: []
created_date: '2026-06-25 01:22'
updated_date: '2026-06-25 02:00'
labels:
  - phase3
  - re
  - auth
  - native
dependencies:
  - TASK-0005
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Heavier alternative to the Frida hook (TASK-0005 follow-up). Disassemble the doCommandNative cmd-dispatch and security_infra::SignFileDecoder in libthing_security.so / libthing_security_algorithm.so to recover: (a) the exact combination order of [app_cert_SHA256]_[bmp_token]_[appSecret], (b) the t_s.bmp -> token deobfuscation (imath mp_int + matrix), (c) the keyed hash (confirm HMAC-SHA256). Goal: make the signer reproducible without a device. Lower priority than the Frida hook.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Combination order + hash primitive of the native sign key derivation documented in re/tuya_sign.md with offset citations
- [ ] #2 t_s.bmp decode routine characterized at offset level
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ELEVATED to the static-only critical path (user directive 2026-06-25): Frida (TASK-0022) is out of scope, so this Ghidra route is now THE way to recover a reproducible signer + the differential vector that TASK-0012 needs. No longer 'lower priority than Frida'.
<!-- SECTION:NOTES:END -->
