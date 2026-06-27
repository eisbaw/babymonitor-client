---
id: TASK-0063
title: 'Correct RE docs to match the HMAC-SHA256(G,str2) signer ground truth'
status: To Do
assignee: []
created_date: '2026-06-26 00:56'
updated_date: '2026-06-27 18:09'
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

Also: re/chkey_static.md documents chKey as hex[8..24]/16-char throughout (lines ~24,37,77-81,190) — now WRONG. Capture-verified chKey is hex[8..16]/8 chars. Mark superseded + correct to [8..16].

Also reconcile PRD/CLAUDE.md: static-analysis-only is SUPERSEDED — live capture is available via ../android_emulator_re (see memory live-capture-available). Update the methodology constraint + the in-code CAPTURE-VERIFIED/LIVE-VALIDATED comments are now accurate.

Also correct re/webrtc_session.md: §2a/§3c/§3d/§4/§7 describe cap3 media as DTLS-SRTP — WRONG. That is PATH B (return-audio SRTP worker FUN_0016b3f0). cap3 AES/KCP (PT 6001) is PATH A = AES-128-CBC + HMAC-SHA256 over KCP, keyed by the SDP a=aes-key (no DTLS). See re/media_decode_spec.md.

CORRECT re/media_decode_spec.md from cap4 ground truth: (1) suite-3 auth trailer = 20-byte HMAC-SHA1 (NOT 32-byte HMAC-SHA256). (2) PATH-A VIDEO framing = imm-wrapper (28B base / 36B when u32@off16==8) + a FIXED 12-byte header; byte0 0x80/0xb8=video,0x80=audio is an imm marker, not RTP CC/X. The variable CC-honoring imm_p2p_rtp_decode_rtp2 is the audio/PATH-B decoder. PATH-A video depacketizer lives in libThingCameraSDK (not decompiled; empirically pinned by the clean decode).

Also STALE: re/stream_playback.md line 45 says emulator_captures/cap4 does not exist (it now does, byte-validates the decode), line 26 says HMAC-SHA256 (cap4-corrected = HMAC-SHA1 / 20-byte trailer). And there is no re/live_stream_run.md (the owner run doc) — create it.
<!-- SECTION:NOTES:END -->
