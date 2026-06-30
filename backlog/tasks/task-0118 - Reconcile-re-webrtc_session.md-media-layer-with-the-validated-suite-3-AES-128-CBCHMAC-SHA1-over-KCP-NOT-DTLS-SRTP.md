---
id: TASK-0118
title: >-
  Reconcile re/webrtc_session.md media-layer with the validated suite-3
  (AES-128-CBC+HMAC-SHA1 over KCP, NOT DTLS-SRTP)
status: To Do
assignee: []
created_date: '2026-06-30 05:40'
labels:
  - docs
  - re
  - streaming
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The top-level README §2 was corrected to state the SCD921 media is Tuya's own KCP / AES-128-CBC + 20B HMAC-SHA1 framing (cap4 'suite 3'), not DTLS-SRTP. re/webrtc_session.md §3d still describes the media path as standard WebRTC DTLS-SRTP, which is superseded by the live-validated media_decode_spec. Reconcile the doc (and add the verdict-overturn pointer the grounding guard expects) so the two are consistent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/webrtc_session.md §3d (and any other DTLS-SRTP media claims) updated to the validated suite-3 KCP/AES-128-CBC/HMAC-SHA1 framing, with a superseded/overturn pointer to re/media_decode_spec.md
- [ ] #2 check-evidence shows no NEW finding introduced by the edit; the README and re/ docs agree on the media layer
<!-- AC:END -->
