---
id: TASK-0012
title: Implement Tuya cloud auth + request signing in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 01:22'
labels:
  - phase5
  - rust
  - wave1
  - auth
dependencies:
  - TASK-0022
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
[from TASK-0005 SPIKE] Rust signing guidance (see re/tuya_sign.md):
- Implement string-to-sign EXACTLY: sorted whitelist params joined by "||" with key=value; postData folded as swapSignString(md5AsBase64(body)); swapSignString(s)= s[8:16] + s[0:8] + s[24:32] + s[16:24] (i.e. B1+A+C+B2 where A=s[0:8],B=s[8:24],C=s[24:32]).
- The keyed wire-sign is native (HMAC-SHA256 likely) over key=[app_cert_SHA256]_[bmp_token]_[appSecret]. appSecret is static (secrets/tuya_appkey.json). The bmp_token and the exact cert-hash combination are NOT static.
- DIFFERENTIAL TEST VECTOR MUST BE LIVE: blocked on TASK-0022 (Frida hook) — capture (string-to-sign, sign) pairs on the user's device; do NOT self-derive the reference (circular, forbidden by TESTING.md). dep edge added.
- The app-cert SHA-256 half can be computed offline from the APK signing cert if the combination order is learned (TASK-0023 Ghidra). Until then, treat the native sign as a black box validated against the captured vector.
<!-- SECTION:NOTES:END -->
