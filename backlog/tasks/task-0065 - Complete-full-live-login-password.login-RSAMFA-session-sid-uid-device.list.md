---
id: TASK-0065
title: >-
  Complete full live login: password.login (RSA+MFA) -> session sid/uid ->
  device.list
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-26 10:31'
updated_date: '2026-06-26 12:10'
labels:
  - auth
  - login
  - stream-unblock
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
token.get now succeeds (returns the RSA pubkey + ticket). Complete the login flow: RSA-encrypt the password under the token.get pubkey (PKCS#1 v1.5), submit user.email.password.login (handle the graphic/captcha + MFA code steps seen in emulator_captures/cap1), capture the session (sid/uid/home DC domain), then drive device.list against a1.tuyaeu.com. Validate each step against cap1/flows.json. Interactive MFA is owner-gated.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 password.login succeeds and yields a session (sid/uid + home-DC domain)
- [x] #2 MFA/captcha steps handled per cap1 sequence (token.get refresh + mfa.code.get)
- [ ] #3 device.list returns the account home + baby-monitor device record (post-AES-decrypt)
- [x] #4 Each request validated against emulator_captures/cap1/flows.json; secrets stay in secrets/
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Decrypt cap1 login postData/result with recovered G + et3 key -> exact spec for each step (token.get, password.login, graphic.verification.code.get, mfa.code.get); validates crypto round-trip\n2. Implement captcha+MFA flow in live.rs (after 1st password.login: graphic.verification.code.get + mfa.code.get, prompt user for MFA code, final password.login)\n3. Capture+persist session (sid/uid/home-DC domain)\n4. device.list on a1.tuyaeu.com, decrypt result, find SCD921\n5. Validate each request vs cap1/flows.json
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LOGIN SPEC decrypted from cap1 (crypto round-trip VALIDATED via re/scripts/decrypt_capture_login.py — our G+et3 key decrypts genuine postData AND result):
- All postData = ET3 AES-128-GCM, key=et3_encrypto_key(requestId,G), wire=base64(nonce12||ct||tag16).
- MFA code rides password.login/mfa.code.get options = JSON {"group":1,"mfaCode":"<code>"}.
1. token.get {countryCode,isUid:false,username} -> {exponent:65537,publicKey,pbKey,token}
2. password.login v3.0 {countryCode,email,ifencrypt:1,options:{group:1,mfaCode:""},passwd:RSA(pubkey)->hex,token} -> errorCode MFA_NEED_SEND_CODE
3. graphic.verification.code.get v1.0 (no postData) -> {state:0}
4. token.get (fresh)
5. mfa.code.get v1.0 {countryCode,ifencrypt:1,options:{group:1,mfaCode:"null"},passwd,token,username} -> code emailed
6. [user enters MFA code]
7. token.get (fresh)
8. password.login v3.0 {...options:{group:1,mfaCode:<CODE>}...} -> SUCCESS result has domain{tuyaeu urls}+session
Each password.login needs a FRESH token.get pubkey+token. MFA code source: secrets/tuya_login.json twofa_code_file.

TASK-0065 PARTIAL (code change; live interactive run is owner-gated) — babymonitor/babymonitor-cli/src/live.rs.

Implemented the full CAPTURE-VERIFIED MFA login handshake (emulator_captures/cap1):
- token.get -> password.login(mfaCode:"") -> on MFA_NEED_SEND_CODE: graphic.verification.code.get (NO postData) -> FRESH token.get -> mfa.code.get(mfaCode:"null", emails code) -> read code from secrets/tuya_login.json twofa_code_file -> FRESH token.get -> final password.login(mfaCode:<code>) -> session.
- Each password.login/mfa.code.get RSA-encrypts the password under THAT step fresh token.get pubkey (PKCS#1v1.5 -> lowercase hex), using THAT ticket.
- options field hand-formatted to the exact capture bytes: {"group": 1,"mfaCode": "<x>"} (space after each colon, none after comma); serde_json would drop the colon spaces. New build_login_options() + pure postData builders.
- password.login version corrected 4.0 -> 3.0 (capture is v3.0).
- New no-postData signed-envelope path for graphic.verification.code.get.
- Session persisted via existing SessionStore (sid/uid/ecode + domain.mobileApiUrl, 12h TTL) AND captured to secrets/.

ROOT-CAUSE FIX (was structurally blocking): ET=3 RESPONSES are fully encrypted — {result:<base64 nonce||ct||tag>, sign, t} with NO top-level success/errorCode (confirmed: 8/8 cap1 login responses encrypted; real server debug response also encrypted). The old send_atop never decrypted, so it could never parse a server-accepted token.get nor detect MFA_NEED_SEND_CODE. Added decrypt_et3_result() reusing the validated et3_encrypto_key(requestId,G[,ecode]); send_atop now decrypts (and still handles a plaintext gateway-reject envelope).

MFA code input: secrets/tuya_login.json twofa_code_file (default secrets/tuya_2fa.txt). Missing/empty -> STOP with instruction + LiveOutcome::Needs2fa (no hang, no fabrication). Driven by auth live-login (NOT --probe-only); all network gated behind --features live.

OFFLINE VALIDATION (no live calls):
- just e2e EXIT=0 (cli 6, core 111, py 10 + bmp/regions). cargo test -p babymonitor-cli --features live = 38 passed. clippy --features live -D warnings clean. fmt OK.
- New tests: options byte format vs capture; password.login/mfa.code.get/token.get postData shapes; no-postData envelope omits postData from wire+sign; ET3 response decrypt round-trip (success + MFA error + wrong-key tag-fail); read_mfa_code (missing/empty->None, trimmed code->Some, unset->Config err).
- STRONGEST CHECK: recomputed request sign vs GENUINE cap1 sign matches 5/5 login steps incl. the no-postData graphic.verification.code.get and token.get v1.0 — proves the signer + no-postData path are byte-correct on real wire.

HONESTY: live login NOT proven (interactive MFA is the owner). Code is built + structurally validated against the capture; owner runs auth live-login --features live, pastes the emailed code into twofa_code_file, re-runs.

Secrets: 0 new secret-scan diff findings. (secret-scan is RED on PRE-EXISTING tracked emulator_captures dumps with real tokens — not from this change; suggest a separate backlog task to quarantine those.)

Review-fix pass (BLOCKER-1 + MEDIUM-2/3 + LOW-4), pre-commit, NOT committed:

- BLOCKER-1 (re-run re-sends mfa.code.get, invalidating the pasted code): rewrote run_live_login control flow in babymonitor/babymonitor-cli/src/live.rs to the genuine cap1 two-run model. Now: read_mfa_code FIRST (Option) -> ONE token.get -> ONE password.login(mfaCode = code.unwrap_or("")). Success -> finish_login_success. MFA_NEED_SEND_CODE -> email the code EXACTLY ONCE (graphic.verification.code.get -> FRESH token.get -> mfa.code.get) then STOP with Needs2fa. mfa.code.get is now reachable ONLY via the new ResendCodeThenStop arm, so a re-run carrying the pasted code goes straight to password.login(code) and never re-emails/invalidates it. New pure seam decide_post_login(login, code_present) + send_mfa_code_then_stop + mfa_resend_message. No poll/sleep loop. Net: Run1 (no code) -> email -> STOP; Run2 (code in file) -> login success, NO new email; stale code on Run2 -> one fresh email -> STOP (converges).

- User-facing messages now printed (both embed the exact twofa_code_file path):
  - no-code: "MFA code emailed to your account. Put it in '<path>' (a single line) and re-run `auth live-login`. STOP."
  - stale-code: "Your previous MFA code was stale/invalid; a NEW code was emailed. Replace it in '<path>' (a single line) and re-run `auth live-login`. STOP."

- MEDIUM-2: replaced the real captured MFA code 563318 -> synthetic 000000 at all 3 test sites (login_options_byte_format_matches_capture, password_login_post_data_shape_and_embedded_options, read_mfa_code_resolves_file_or_reports_none); updated the now-inaccurate "exact cap1 literals" comment.

- MEDIUM-3: babymonitor-core/src/session.rs SessionStore::save now writes 0600 via new write_private() (OpenOptions.mode(0o600) at create + set_permissions re-assert for pre-existing files, #[cfg(unix)] gated; plain truncating write fallback on non-unix). Added unix-gated test saved_session_file_is_owner_only_0600 (also asserts re-save stays 0600).

- LOW-4: tightened is_need_send_code to EXACTLY MFA_NEED_SEND_CODE (dropped speculative NEED_MFA / USER_NEED_MFA / substring matches); strengthened the test to assert those variants are now rejected.

Validation (all green): just e2e EXIT 0; cargo test -p babymonitor-cli --features live = 41 passed/0 failed; cargo clippy -p babymonitor-cli --features live --all-targets -- -D warnings = clean; cargo test -p babymonitor-core session = 17 passed incl new perms test. No live network calls.

PRE-EXISTING (out of scope of this fix, NOT introduced by my diff): just secret-scan FAILS with 215 findings, 210 from tracked emulator_captures/cap1/flows.full.txt (a mitmproxy dump whose hex bytes match the email regex). Zero findings originate from my .rs edits. Filed as a separate backlog task.
<!-- SECTION:NOTES:END -->
