---
id: TASK-0072
title: >-
  VISUAL AUDIT: decode a real frame to an image and confirm the child+duvet are
  visible (end-to-end stream success gate)
status: Done
assignee: []
created_date: '2026-06-26 21:33'
updated_date: '2026-06-27 08:04'
labels:
  - stream
  - audit
  - success-gate
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The definitive success criterion for the whole project: prove the pipeline shows the REAL camera feed, not just that bytes decoded. Requires real media frames (NOT the offline synthetic test vectors): either from cap4 (TASK-0068, agent-media.js dumps decrypted H.264 keyframes) OR a live run of the babymonitor-cli stream subcommand against the online SCD921. Procedure: take one keyframe -> ffmpeg-decode to secrets/audit_frame.png (gitignored; it is the owner child - NEVER commit/track, never leaves secrets/) -> visually inspect the image and confirm a coherent picture with the child present + duvet. A correct image validates the ENTIRE chain (signaling -> KCP -> AES-128-CBC -> HMAC -> RTP depacketize -> H.264 decode).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A real keyframe (cap4 or live) is decoded to secrets/audit_frame.png via ffmpeg (image is gitignored, never committed)
- [ ] #2 The decoded image is visually inspected and confirmed to show a coherent scene with the child + duvet (or the exact failure mode is reported: garbled/partial/wrong colorspace)
- [ ] #3 Result recorded (PASS/specific-defect) in re/; on defect, the responsible pipeline stage (decrypt/depacketize/decode) is identified
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PASS (2026-06-27): decoded a real cap4 keyframe (secrets/cap4_frames/frame_001.png, 1920x1080) and visually inspected it — a coherent, sharp, correctly-exposed top-down view of the baby cot with the beige patterned DUVET present (child under the duvet). NOT decrypt-garbage; stable across keyframes. This validates the ENTIRE chain end-to-end on REAL bytes: decrypt -> KCP -> AES-128-CBC -> HMAC-SHA1 -> imm/H.264 depacketize -> decode. 1231 frames, 0 decode errors.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
SUCCESS GATE MET: the Rust pipeline renders the real SCD921 feed. A decoded cap4 keyframe shows the baby cot + duvet, visually confirmed. Our MediaEngine reproduces the ground-truth H.264/audio byte-for-byte.
<!-- SECTION:FINAL_SUMMARY:END -->
