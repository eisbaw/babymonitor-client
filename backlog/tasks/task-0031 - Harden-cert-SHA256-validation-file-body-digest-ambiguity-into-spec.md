---
id: TASK-0031
title: Harden cert-SHA256 validation + file body-digest ambiguity into spec
status: To Do
assignee: []
created_date: '2026-06-25 04:53'
labels:
  - rust
  - auth
  - review-followup
dependencies:
  - TASK-0012
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-14 review of TASK-0012 (both GO, P1/P2). The cert ingredient value is confirmed CORRECT (Rust hashes the raw embedded PKCS#7 leaf cert = Android signatures[0] semantics; the naive openssl `x509 -outform DER` re-encode is the misleading path) but its validation is weak: (P1a) extract_leaf_cert_der returns the FIRST DER SEQUENCE >=64 bytes — in a multi-cert PKCS#7 chain that may not be the leaf; add a guard or pick by leaf semantics. (P1b) the openssl byte-for-byte cross-check is claimed in notes but not committed; add an #[ignore]d test (or Justfile recipe) asserting app_cert_sha256_hex_from_apk equals SHA-256 of the raw embedded leaf cert via an independent reference (openssl pkcs7 -print_certs without the re-encoding x509 step), value withheld. (P2) file the 24-vs-32 swap/postData body-digest contradiction (md5AsBase64=24 chars vs swap slices 32) as a caveat into re/tuya_sign.md ~:83-89 (currently only in sign.rs rustdoc + task notes).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 extract_leaf_cert_der robust against multi-cert chains (or documented+guarded); a committed #[ignore]d test pins the cert digest against an independent reference (value withheld)
- [ ] #2 re/tuya_sign.md records the body-digest 24-vs-32 ambiguity caveat; check-evidence green
<!-- AC:END -->
