---
id: TASK-0030
title: >-
  Port the t_s.bmp white-box table cipher (fcn.11658) OR capture a live sign
  vector
status: To Do
assignee: []
created_date: '2026-06-25 04:12'
updated_date: '2026-06-25 04:12'
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
