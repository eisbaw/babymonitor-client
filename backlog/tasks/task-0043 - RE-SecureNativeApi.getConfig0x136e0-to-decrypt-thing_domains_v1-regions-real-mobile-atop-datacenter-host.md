---
id: TASK-0043
title: >-
  RE SecureNativeApi.getConfig@0x136e0 to decrypt thing_domains_v1/regions ->
  real mobile-atop datacenter host
status: To Do
assignee: []
created_date: '2026-06-25 12:16'
labels:
  - phase3
  - wave3
  - auth
  - native
  - ghidra
dependencies:
  - TASK-0042
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-3 unblock for the live login. TASK-0042 hit ILLEGAL_CLIENT_ID on the legacy a1.tuya{eu,us}.com hosts — the appKey is likely provisioned for the region-config datacenter host shipped ENCRYPTED in assets/thing_domains_v1/regions, decrypted at runtime by native SecureNativeApi.getConfig (@0x136e0 in libthing_security.so). The ported AES (AES-128-CBC key=MD5(t_s.bmp), and the localKey ECB) is the CERT-PINNING cipher — NO evidence it decrypts regions; getConfig is UN-RE-d. STATIC SPIKE: Ghidra-decompile getConfig + its key/IV/mode for the regions/pins blob (shared 4db6 envelope header), decrypt it, recover the EU mobileApiUrl/gwApiUrl host. Honest verdict if the key is itself runtime/unrecoverable. If recovered, the host feeds ONE more token.get (not lockout-sensitive). CAVEAT: even with the right host, ILLEGAL_CLIENT_ID may be a PROVISIONING/app-cert-pin gate a standalone client cannot reproduce — weigh that hypothesis too.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 getConfig key/IV/mode for the regions blob reverse-engineered (Ghidra-primary, symbol-anchored) OR an honest verdict it is itself runtime-only; if decryptable, the real EU mobile-atop host recovered (to secrets/ or doc as non-secret host) and fed to a single re-attempt
<!-- AC:END -->
