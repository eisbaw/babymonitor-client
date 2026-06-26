---
id: TASK-0063
title: 'Correct RE docs to match the HMAC-SHA256(G,str2) signer ground truth'
status: To Do
assignee: []
created_date: '2026-06-26 00:56'
updated_date: '2026-06-26 01:21'
labels:
  - auth
  - docs
  - signer
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0060/0061 corrected the signer in code + re/master_secret_g.md, but several older RE docs still assert the SUPERSEDED model and would mislead a future session/sub-agent. Reconcile them (or add a top-of-file correction banner pointing at re/master_secret_g.md): re/tuya_sign_static.md still says the request sign is plain MD5 (computeDigest) with a 3-part underscore sign key and lowercase-64-hex cert; re/chkey_static.md still describes the chKey cert input as lowercase 64-hex (it is colon-grouped UPPERCASE 95-hex); re/bmp_token_provenance.md/tuya_sign.md should note matrixKey0 = hex_decode(bmp_token) is RAW 32 bytes inside G. Do NOT delete the originals wholesale - prefer a dated correction note so the provenance trail stays auditable. No secret values.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/tuya_sign_static.md no longer claims the request sign is MD5/computeDigest or a 3-part key; points to re/master_secret_g.md (HMAC-SHA256(G,str2), 4-part G)
- [ ] #2 re/chkey_static.md states the chKey cert input is colon-grouped UPPERCASE 95-hex, not lowercase 64-hex
- [ ] #3 re/bmp_token_provenance.md (or tuya_sign.md) notes matrixKey0 is the RAW 32-byte hex_decode(bmp_token) inside G
- [ ] #4 check_evidence.py still passes; no secret values introduced
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Also stale after Fix-4: re/chkey_static.md:194-195 and task-0044 still describe a removed operator-pin chKey override (secrets/chkey.txt) — chKey is now always derived. Correct these doc refs.
<!-- SECTION:NOTES:END -->
