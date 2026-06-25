---
id: TASK-0032
title: Pin the request-signer bmp_token mapping via ONE live sign-accept
status: To Do
assignee: []
created_date: '2026-06-25 05:42'
labels:
  - phase3
  - re
  - auth
  - native
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0030 fully ported + validated the AES-128-CBC decryptor (fcn.11658) that the SignFileDecoder runs over t_s.bmp + tecrkcehc_ext (re/bmp_token_whitebox.md). The decrypted blob is the TLS cert-pinning config {securityOpen, data:[2x sha256]}, NOT obviously the signer's middle _-part. t_s.bmp has a single xref (this AES path), so a separate token-decode does not exist statically. The signer's bmp_token is therefore one of these decrypted artifacts (likely a data[] cert fingerprint) OR tuya_sign_static.md s7 over-split the key. RESOLUTION REQUIRES a non-static oracle: capture ONE real signed request (TASK-0012 AC#3 contingency) and differential it against babymonitor-core::sign with each candidate middle-part. That single vector pins (a) the middle _-part, (b) SignBody KeyOnly-vs-KeyAndCanonical, (c) the postData 24-vs-32 length contradiction -- all in sign::tests::full_signature_byte_parity_pending_task_0030. STATIC-ONLY cannot close this.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A single live/independent sign vector identifies the exact bmp_token middle-part (value to secrets/ only)
- [ ] #2 sign::Signer wired with the confirmed provider; full_signature_byte_parity test asserts byte parity
- [ ] #3 SignBody + postData ambiguities resolved in one place
<!-- AC:END -->
