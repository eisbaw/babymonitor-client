---
id: TASK-0050
title: >-
  Corrupted-sign differential: prove whether ILLEGAL_CLIENT_ID is identity-layer
  or a wrong-sign reject (+ captcha/verifyToken trace)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-25 15:10'
updated_date: '2026-06-25 15:12'
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
- [ ] #1 A --corrupt-sign probe variant exists (token.get only, guardrails enforced); the differential pair was run against one reachable host and the two errorCodes recorded in re/live_login.md (no values)
- [ ] #2 The verdict is stated definitively: ILLEGAL_CLIENT_ID is either identity-layer/sign-insensitive (=> attestation/provisioning, promote to confirmed, unblock TASK-0049) OR sign-sensitive (=> bmp_token/fold is the real blocker, file the static re-attack task)
- [ ] #3 Captcha/verifyToken path traced statically: whether the atop request requires a verifyToken/risk/fingerprint header is resolved (recoverable -> task filed; runtime-only -> noted), in re/tuya_cloud_auth.md
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
