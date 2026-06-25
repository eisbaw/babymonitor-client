---
id: TASK-0030
title: >-
  Port the t_s.bmp white-box table cipher (fcn.11658) OR capture a live sign
  vector
status: To Do
assignee: []
created_date: '2026-06-25 04:12'
updated_date: '2026-06-25 04:44'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0012 (commit c60d2fc): your decoder MUST satisfy this exact injected interface so it plugs into the signer with NO rework — babymonitor-core::sign::BmpTokenProvider { fn bmp_token(&self) -> Result<String, crate::Error>; }. Return Ok(token) with the decoded t_s.bmp bmp_token (the 2nd '_'-joined sign-key part) on success; return Err(Error::BmpTokenPending) (NOT a panic, NOT a fake value) while the white-box port is incomplete. The token VALUE goes ONLY to secrets/ — never a tracked file or test. Once it works, swap the default sign::PendingBmpToken for your provider in the Signer; sign::StaticBmpToken::new(token) already exists to wrap a recovered/live token. ALSO: TASK-0012 left two 'likely' ambiguities for your gold vector to pin in ONE place each: (a) sign::SignBody (MD5(key) vs MD5(key||canonical_string)); (b) the postData fold 24-vs-32 length contradiction in sign::post_data_digest (md5AsBase64 is 24 chars but swapSignString expects 32 — currently returns Error::InvalidSignInput by honest design). A single captured/independent vector resolves both; the #[ignore]d test sign::tests::full_signature_byte_parity_pending_task_0030 is where the byte-for-byte AC#1 assertion lands.
<!-- SECTION:NOTES:END -->
