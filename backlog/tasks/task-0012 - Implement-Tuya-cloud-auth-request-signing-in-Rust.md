---
id: TASK-0012
title: Implement Tuya cloud auth + request signing in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 04:11'
labels:
  - phase5
  - rust
  - wave1
  - auth
dependencies:
  - TASK-0011
  - TASK-0007
  - TASK-0023
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: the first genuinely buildable+testable slice. Implement Tuya HMAC request signing, account login, token issue/refresh, datacenter base-URL selection in babymonitor-core, per re/tuya_cloud_auth.md. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::auth signs requests; a differential unit test reproduces the captured signing vector from task 7 byte-for-byte (this gate bites with no network)
- [ ] #2 Token store persists to ~/.local/share/babymonitor/; refresh-before-expiry covered by a unit test; no unflagged stubs
- [ ] #3 If task 5 verdict is not 'recoverable-statically', the byte-for-byte differential (AC#1) may be unsatisfiable purely statically: implement+unit-test the sign ALGORITHM, and obtain the expected vector from the user's gated live run instead; record the blocker, do NOT fake a vector
- [ ] #4 Any live auth calls are rate-limited and single-shot; no retry loops against Tuya auth (no account lockout / infra hammering)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0029 (bmp_token residual): the byte-for-byte differential signer is NOT yet fully achievable offline. The bmp_token decode (key-join part [cert_sha256]_[bmp_token]_[appSecret]) is the single remaining blocker. Finding: t_s.bmp is decoded by a WHITE-BOX TABLE CIPHER (libthing_security.so fcn.11658), not the nalajcie polynomial/matrix scheme — see re/bmp_token_decode.md (Decode: partially-ported). Exact remaining step: either (a) AC#3 contingency — capture ONE real signed request (gated live run) and use its sign as the gold vector (recommended; far cheaper), or (b) complete the white-box port (extract .rodata 0x7800 + .data.rel.ro 0x38000/0x39000 T-tables, reconstruct fcn.11658 SPN byte-exact, feed t_s.bmp + tecrkcehc_ext + constant '7178265647164836'). Everything ELSE in the signer is recovered+portable (canonical string, MD5-hex, '_'-join, offline cert-SHA256, appKey/appSecret) — a PARTIAL differential over those sub-steps with a placeholder token bites now, no network.
<!-- SECTION:NOTES:END -->
