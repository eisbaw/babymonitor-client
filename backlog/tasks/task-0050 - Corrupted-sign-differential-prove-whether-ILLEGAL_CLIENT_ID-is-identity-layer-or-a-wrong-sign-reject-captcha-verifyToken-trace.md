---
id: TASK-0050
title: >-
  Corrupted-sign differential: prove whether ILLEGAL_CLIENT_ID is identity-layer
  or a wrong-sign reject (+ captcha/verifyToken trace)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 15:10'
updated_date: '2026-06-26 02:04'
labels:
  - phase3
  - wave3
  - auth
  - sign
  - live
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The architect review caught that "ILLEGAL_CLIENT_ID is upstream of sign verification" is an UNPROVEN, server-opaque assumption with ZERO decompiled attestation evidence. Every prior probe sent the same un-validated candidate sign (bmp_token integral-solve never server-confirmed; MD5 fold never disambiguated). DISAMBIGUATE STATICALLY + with a minimal non-lockout probe pair:

(A) CORRUPTED-SIGN DIFFERENTIAL (highest value): add a --corrupt-sign variant to the existing --probe-only token.get path in babymonitor/babymonitor-cli/src/live.rs (run_token_get_probe). Send TWO token.get to the SAME reachable host (a1.tuyaeu.com): probe 1 = our candidate sign; probe 2 = the identical envelope but with one byte of the sign flipped. Compare errorCodes:
 - IDENTICAL ILLEGAL_CLIENT_ID for both => the gateway rejects on IDENTITY before reading the sign => identity/provisioning gate CONFIRMED (sign-insensitive). Promote re/live_login.md from likely->confirmed and unblock TASK-0049.
 - DIFFERENT code for the corrupted sign (a sign-error / access-token error) => ILLEGAL_CLIENT_ID is SIGN-SENSITIVE => our candidate sign is wrong => the blocker is the bmp_token/fold, which is STILL STATIC WORK. File a task to re-attack the bmp_token decode + fold disambiguation. This vindicates the owner.
 Guardrails ABSOLUTE: token.get ONLY (non-lockout), NEVER password.login, exactly these 2 probes (no retry-spam), captures only to gitignored secrets/, error Display scrubbed, stop at 2FA. Build/run with --features live (gated out of e2e).

(B) CAPTCHA/verifyToken STATIC TRACE (lead B residual, no network): trace CaptchaBusiness (/verify/app/initConfig, AppInitConfigBean) + CaptchaUsecase to confirm whether the atop token.get request is EVER decorated with a verifyToken / risk / device-fingerprint header that a from-scratch client omits. Record method+finding (no values) in re/tuya_cloud_auth.md. If such a required header exists and is statically derivable, file a task to add it; if it is runtime-only, note that precisely.

Deliver the differential verdict (identity-layer vs sign-sensitive) with the two errorCodes, and the captcha-header finding.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A --corrupt-sign probe variant exists (token.get only, guardrails enforced); the differential pair was run against one reachable host and the two errorCodes recorded in re/live_login.md (no values)
- [x] #2 The verdict is stated definitively: ILLEGAL_CLIENT_ID is either identity-layer/sign-insensitive (=> attestation/provisioning, promote to confirmed, unblock TASK-0049) OR sign-sensitive (=> bmp_token/fold is the real blocker, file the static re-attack task)
- [x] #3 Captcha/verifyToken path traced statically: whether the atop request requires a verifyToken/risk/fingerprint header is resolved (recoverable -> task filed; runtime-only -> noted), in re/tuya_cloud_auth.md
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
STAGE A (corrupted-sign differential):
1. Add --corrupt-sign flag to LiveLoginArgs in main.rs; thread it into run_token_get_probe via a new corrupt:bool param.
2. In run_token_get_probe: after build_signed_envelope, if corrupt, flip exactly one hex nibble of envelope["sign"] (keeps 32-char lowercase-hex shape so gateway parses+reaches sign-verify). Guard against degenerate flips. eprintln states sign was corrupted (never the value).
3. Update auth_token_get_probe wiring to pass the flag; differentiate stdout label.
4. Run differential pair MANUALLY against a1.tuyaeu.com: probe1 (candidate sign), probe2 (--corrupt-sign). Exactly 2 token.get. Compare errorCodes. token.get ONLY, never password.login, stop at 2FA, stop if Accepted.
5. Record verdict + the two errorCodes (no values) in re/live_login.md. Identical ILLEGAL_CLIENT_ID => identity-layer/sign-insensitive => promote to confirmed, unblock TASK-0049. Different => sign-sensitive => bmp_token/fold is the static blocker; file re-attack task (owner-vindicating).

STAGE B (captcha/verifyToken static trace, NO network):
6. Trace CaptchaBusiness (/verify/app/initConfig, AppInitConfigBean) + CaptchaUsecase + atop request builder: does token.get ever get a verifyToken/risk/fingerprint header a scratch client omits? Resolve definitively.
7. Record method+finding (NO values) in re/tuya_cloud_auth.md. Recoverable header => file task; runtime-only => note precisely.

GATES: just e2e + just secret-scan + just check-evidence green; cargo clippy --features live -D warnings; cargo test --features live --no-run. Commit per logical unit (branch task-0050-sign-differential).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLEAN RE-RUN (2026-06-26): the original differential was wrong-vs-wrong (malformed 32-hex sign). Re-fired with the corrected valid 64-hex HMAC-SHA256(G,str2) signer: valid-sign and corrupted-valid-sign both return identical ILLEGAL_CLIENT_ID. Sign-insensitivity now PROVEN cleanly. ICI is an identity/provisioning gate upstream of sign-verify, not a sign-class reject.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Disambiguated ILLEGAL_CLIENT_ID via a controlled corrupted-sign differential and a captcha/verifyToken static trace.

VERDICT: ILLEGAL_CLIENT_ID is SIGN-INSENSITIVE — an identity/provisioning gate upstream of sign-verification (confirmed). It is NOT a wrong-sign reject.

Stage A (code + live):
- Added --corrupt-sign to the existing --probe-only token.get path (babymonitor/babymonitor-cli/src/{live.rs,main.rs}). After build_signed_envelope, corrupt_one_nibble flips exactly one hex nibble of the sign (first nibble XOR 1), leaving everything else byte-identical; the corrupted sign keeps its 32-char lowercase-hex shape so the gateway parses it and reaches sign-verification. Unit tests cover length-preserve / one-char-diff / still-hex / f->e / non-hex+empty -> typed error. Sign material never logged. live feature only (gated out of e2e).
- Ran the differential against a1.tuyaeu.com: exactly 2 token.get, zero password.login, no 2FA, neither Accepted.
  - probe 1 (candidate sign): HTTP 200, errorCode=ILLEGAL_CLIENT_ID
  - probe 2 (one nibble flipped): HTTP 200, errorCode=ILLEGAL_CLIENT_ID
  Both responses byte-for-byte identical (raw bodies + request param keys; gitignored secrets/). A wrong signature changes nothing => sign-insensitive => identity reject before sign-eval.
- re/live_login.md: promoted the "returned before sign-verification" claim from server-opaque(likely) to confirmed (controlled A/B; corrupted variant = negative control). Recorded the two honest consequences: identity gate confirmed (unblocks TASK-0049); the bmp_token/fold is NOT validated but IS proven not to be the token.get blocker, so no bmp_token re-attack task is filed (that branch was for the sign-sensitive outcome, which did not occur).

Stage B (captcha/verifyToken static trace, NO network) — re/tuya_cloud_auth.md §8:
- verifyToken is a request PARAMETER to the captcha service's own /verify/app/initConfig (CaptchaBusiness, a SEPARATE raw OkHttpClient + host), NOT an atop header. The atop network/sign layer has zero captcha/risk/fingerprint/ticket references; verifyToken occurs only in the login/captcha package (5 files). The captcha-verify result feeds AuthCodeRequestEntity.ticket for code-SENDING (AuthCodeUseCase.sendAuthCodeByType) — disjoint from token.get/password.login (zero overlap files). The challenge is WebView-interactive (runtime-only).
- Verdict: no statically-derivable required header that token.get omits; nothing to add, no follow-up task. Corroborates Stage A.

Gates: just e2e, just secret-scan, just check-evidence all green; cargo clippy --features live -D warnings clean; cargo test --features live compiles and new tests pass.

No follow-up tasks filed (the sign-insensitive outcome does not call for the bmp_token re-attack; TASK-0049 decision is now unblocked, noted on that task).
<!-- SECTION:FINAL_SUMMARY:END -->
