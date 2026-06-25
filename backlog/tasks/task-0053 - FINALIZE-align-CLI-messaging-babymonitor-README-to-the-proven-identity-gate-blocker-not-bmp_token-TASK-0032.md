---
id: TASK-0053
title: >-
  FINALIZE: align CLI messaging + babymonitor/README to the proven identity-gate
  blocker (not bmp_token/TASK-0032)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 17:50'
updated_date: '2026-06-25 17:56'
labels:
  - phase3
  - wave3
  - docs
  - finalize
  - cli
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The top-level README was corrected (TASK-0052) but babymonitor/README.md and the CLI user-facing strings in babymonitor/babymonitor-cli/src/main.rs still assert the DISPROVEN reason for the login wall ("token-pending ... bmp_token ... TASK-0032"). This is now actively wrong: TASK-0050 PROVED the reject is sign-INSENSITIVE, so even a perfect bmp_token would NOT enable login — the blocker is a server-side identity gate (ILLEGAL_CLIENT_ID). The CLI literally prints a false reason. CORRECT the messaging for a coherent honest ship: (1) babymonitor/README.md "Login status" section + the per-command table -> reframe from "token-pending (bmp_token/TASK-0032)" to "cannot obtain a session: Tuya rejects token.get with a proven sign-insensitive server-side identity gate (TASK-0050/0051); the client is token-INJECTABLE — supply a captured session (TASK-0022) to use it". (2) main.rs doc-comments + println/JSON status strings (e.g. login:"token-pending", blocked_on:"TASK-0032", "cannot log in yet — bmp_token / TASK-0032") -> same reframing; lead with the identity gate; keep the bmp_token mention ONLY as "the signer’s 6th ingredient is an un-validated static candidate, NOT the login blocker". (3) Update any unit/e2e tests that assert the old strings/JSON fields to the new honest wording. Keep the token-injectable design accurate. NO secret values. Root-cause honesty fix, not a workaround.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 babymonitor/README.md + main.rs user-facing strings (doc-comments, println, JSON status/reason/blocked_on) reframed to the proven sign-insensitive identity gate; bmp_token mentioned only as the un-validated sign ingredient that is NOT the login blocker; no stale TASK-0032-as-login-blocker claim remains
- [x] #2 All tests asserting the old token-pending/TASK-0032 strings updated to the new wording; just e2e + just secret-scan + just check-evidence all green
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Reframe babymonitor/README.md "Login status" section + per-command table from token-pending/TASK-0032 to the proven sign-insensitive identity gate (ILLEGAL_CLIENT_ID, TASK-0050/0051); client is token-INJECTABLE via a captured session (TASK-0022).
2. Reframe main.rs: module doc-comments, auth login/info/--live doc-comments, and runtime println/eprintln/JSON. auth login stops presenting BmpTokenPending message as the login reason; lead with identity gate. JSON: status blocked, blocked_on identity-gate, add identity-gate reason. info login field -> blocked. bmp_token mentioned only as the un-validated 6th sign ingredient, NOT the blocker.
3. Reframe live_e2e.rs doc-comments (login harness) to the identity gate; keep the BmpTokenPending match (control flow unchanged — the signer genuinely lacks a validated token).
4. Do NOT change control flow; do NOT rename PendingBmpToken. Keep offline/fixture descriptions accurate.
5. just e2e + just secret-scan + just check-evidence all green; report numbers.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- Reframed babymonitor/README.md "Login status" section + per-command table + live gold-oracle section from token-pending/TASK-0032 to the proven sign-insensitive server-side identity gate (ILLEGAL_CLIENT_ID, TASK-0050/0051); client is token-injectable via a captured session (TASK-0022).
- Reframed main.rs: module doc-comment, Auth/Devices/Login/--live doc-comments, info + auth login human/JSON output, auth status no-session note, load_device_list/live_device_list/print_device_show comments + the unit test name. auth login now uses a local LOGIN_BLOCKED_REASON const (identity gate) instead of surfacing Error::BmpTokenPending.to_string() as the login reason. JSON: status "blocked", blocked_on "identity-gate", info login "blocked" + login_blocked_on "identity-gate".
- Reframed live_e2e.rs login-harness doc-comments, #[ignore] reason, and panic/assert messages to the identity gate; kept the BmpTokenPending match (control flow unchanged — signer genuinely lacks a validated token).
- Justfile showcase label + --live omission comment reframed.
- Did NOT rename PendingBmpToken/BmpTokenPending (signer genuinely still lacks a validated token; type is about the signer, not the login wall).
- Residual: core stream/device doc-comments + live_e2e stream test still frame TASK-0032/bmp_token as the stream-credential auth blocker -> filed TASK-0054 (out of this task scope which is the login-wall reason).
- Gates: just e2e green (113+10 tests pass, 3 ignored); just secret-scan OK; just check-evidence OK (22 docs).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Aligned the user-facing login-wall reason in babymonitor/README.md and the CLI to the PROVEN server-side identity gate, replacing the disproven "token-pending / bmp_token / TASK-0032" framing.

Why: TASK-0050 proved the token.get reject (ILLEGAL_CLIENT_ID) is sign-INSENSITIVE (corrupted-sign differential), so even a perfect bmp_token would not enable login. The top-level README was already corrected (TASK-0052); the CLI and babymonitor/README still printed the false reason. This is a root-cause honesty fix, not a workaround.

Changes:
- babymonitor/README.md: "Login status" section, per-command table, and live gold-oracle section reframed to the sign-insensitive identity gate (TASK-0050/0051) + token-injectable design (inject a captured session, TASK-0022). bmp_token noted only as the signer un-validated 6th ingredient, not the blocker.
- babymonitor-cli/src/main.rs: module + Auth/Devices/Login/--live doc-comments; info and auth login human+JSON output; auth status no-session note; live/device-fetch comments. auth login now states a local LOGIN_BLOCKED_REASON (identity gate) instead of surfacing Error::BmpTokenPending as the login reason. JSON: status="blocked", blocked_on="identity-gate" (was "TASK-0032"); info login="blocked" + login_blocked_on="identity-gate".
- babymonitor-cli/tests/live_e2e.rs (login harness): doc-comments, #[ignore] reason, panic/assert text reframed to the identity gate. The BmpTokenPending match is kept (control flow unchanged; the signer genuinely still lacks a validated token).
- Justfile: showcase label + --live omission comment.

User impact: the CLI no longer prints a false reason for the login wall; human + JSON now state the identity-gate cause and the token-injectable unblock path.

Scope notes: did NOT rename PendingBmpToken/BmpTokenPending (those are about the signer, not the login wall). Control flow unchanged — login still honestly produces no session; --live still fabricates no call.

Tests/gates: just e2e green (113 + 10 integration tests pass, 3 ignored); just secret-scan OK; just check-evidence OK (22 docs).

Follow-up: TASK-0054 filed for residual core stream/device doc-comments that still frame TASK-0032/bmp_token as the stream-credential auth blocker (out of this task scope).
<!-- SECTION:FINAL_SUMMARY:END -->
