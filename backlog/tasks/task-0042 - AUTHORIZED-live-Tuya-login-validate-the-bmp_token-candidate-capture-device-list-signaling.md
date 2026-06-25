---
id: TASK-0042
title: >-
  AUTHORIZED live Tuya login: validate the bmp_token candidate + capture
  device-list/signaling
status: In Progress
assignee:
  - '@architect'
created_date: '2026-06-25 11:40'
updated_date: '2026-06-25 12:08'
labels:
  - phase3
  - wave3
  - auth
  - live
  - authorized
dependencies:
  - TASK-0032
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AUTHORIZED one-time live login (account owner relaxed no-dynamic for THIS auth-path capture only). Implement the SAME Tuya mobile-app login path in the Rust client (token.get -> RSA-encrypt password -> password.login) reusing the recovered signer (MD5(cert_sha256_"_"_bmp_token_"_"_appSecret), wire param clientId, canonical ||-join + swapSignString) with the bmp_token CANDIDATE from secrets/bmp_token.txt. Perform the real login to VALIDATE the candidate (server accept = gold differential) + disambiguate the MD5 fold; then capture device-list + stream signaling. GUARDRAILS: real cloud + real account; READ-only (login, device list, configs, signaling) — NO account/device modifications; MINIMIZE attempts, NO retry-spam (lockout); if login/sign fails STOP + report. 2FA: stop at the emailed code step + report NEED 2FA CODE (operator writes secrets/tuya_2fa.txt). SECRETS: read creds from secrets/tuya_login.json; ALL captured values (session/uid/token/device-list/signaling/bmp_token) go ONLY to secrets/; commit method/algorithm only, NEVER values; secret-scan + e2e stay green.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Live login attempted ONCE with the candidate signer; reaching the 2FA prompt or a successful login = the signer (bmp_token + MD5 fold) is VALIDATED (server accepted the signed token.get/password.login); the result (validated / sign-rejected) recorded honestly; captured artifacts in secrets/ only
- [ ] #2 If 2FA reached: STOP + report NEED 2FA CODE. If sign-rejected: STOP, do not retry, report the server error + that the candidate/fold needs revisiting. No secret values in any tracked file or report
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. FIX whitelist bug: sign.rs SIGN_WHITELIST has 'appId' but recovered wire name is 'clientId' (provenance §2.1) — appKey param keyed clientId would be dropped from canonical str => wrong sign. Change to clientId.
2. Add gated 'live' Cargo feature to babymonitor-cli (optional reqwest blocking+rustls + rsa deps); default e2e build never compiles them => assert-offline stays green.
3. Implement live module: load secrets (tuya_login.json, tuya_appkey.json, bmp_token.txt), compute cert_sha256 offline via app_cert_sha256_hex_from_apk, build StaticBmpToken, Signer(KeyAndCanonical fold most-likely).
4. Resolve EU mobile-atop host; DNS/HEAD probe BEFORE any signed account request.
5. Build+sign+send ONE token.get (sessionRequire=false). Inspect: sign-rejected => STOP+report (candidate/fold wrong); success => signer VALIDATED (gold differential).
6. If token.get ok: RSA-encrypt password with returned pubkey, send THE ONE password.login. 2FA => capture state to secrets/tuya_2fa_state.json, STOP, NEED 2FA CODE. Success => capture session/uid + device-list to secrets/ (values withheld), confirm SCD921+p2pType. Failure => STOP report.
7. Deliverable doc re/live_login.md (no values). Gates: e2e+secret-scan+check-evidence green; live gated OUT of e2e.
GUARDRAILS: password.login AT MOST ONCE; no retry-spam; READ-only; all values to secrets/ only.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LIVE RUN OUTCOME (no values; all captured artifacts in gitignored secrets/):
- The live SIGN ORACLE was UNREACHABLE. The public Tuya/thingclips atop gateway (a1.tuyaeu.com, HTTP 200) rejected token.get with errorCode=ILLEGAL_CLIENT_ID / 'Invalid client;No access' at the CLIENT-IDENTITY layer, BEFORE evaluating our sign. token.get SIGN was neither accepted nor rejected.
- => bmp_token candidate + MD5 fold are NEITHER validated NOR refuted. This is NOT a sign-rejection (would need the server to judge our sign); it is a gateway routing/provisioning blocker upstream of signature verification.
- password.login was NOT attempted (ZERO lockout-sensitive calls consumed). 2FA NOT reached.
- token.get tried (a few minimal network-level routing attempts, guardrail-allowed): a1.tuyaeu.com (EU default), a1.tuyaus.com (US) -> both ILLEGAL_CLIENT_ID; m1.tuyaeu.com is MQTT/media host (no /api.json). Retry with SDK-correct User-Agent (Thing-UA=APP/Android/<ver>/SDK/<ver>) also ILLEGAL_CLIENT_ID -> UA not the gate. STOPPED per 'a few calls max'.
SHIPPED (code+doc, method only, no values):
- Gated live path behind CLI 'live' Cargo feature (reqwest+rsa+rustls OUT of default build; just e2e/assert-offline stay green). New: babymonitor-cli/src/live.rs (token.get->RSA pw->ONE password.login; 2FA capture; READ-only device-list; all captures->secrets/ only; URL/secret scrub on network errors).
- FIX: signer SIGN_WHITELIST had 'appId'/'t' but recovered wire names are 'clientId'/'time' (provenance §2.1, auth §1); old values silently dropped appKey+timestamp from the canonical str => wrong sign. Now correct.
- Added post_data_digest_hex (32-hex-MD5+swap; the well-defined postData fold) resolving the len-24-vs-32 ambiguity for the live path.
- Deliverable: re/live_login.md (outcome + method, no values).
LIKELY CAUSE (speculative, NOT validated): appKey provisioned for a region-config-decrypted datacenter host (encrypted thing_domains_v1/regions, native getConfig), not the legacy a1.tuya*.com gateway. NEXT: decrypt regions blob OR one Frida/proxy capture (TASK-0022) to get the real host + any missing provisioning field, then re-run the ONE token.get to reach the sign oracle.
GATES: just e2e GREEN; check-evidence GREEN; secret-scan GREEN; secrets/* gitignored+unstaged.
<!-- SECTION:NOTES:END -->
