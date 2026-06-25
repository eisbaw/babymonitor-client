---
id: TASK-0030
title: >-
  Port the t_s.bmp white-box table cipher (fcn.11658) OR capture a live sign
  vector
status: In Progress
assignee:
  - '@reverser'
created_date: '2026-06-25 04:12'
updated_date: '2026-06-25 05:43'
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
<!-- SECTION:NOTES:END -->
