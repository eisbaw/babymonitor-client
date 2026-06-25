---
id: TASK-0042
title: >-
  AUTHORIZED live Tuya login: validate the bmp_token candidate + capture
  device-list/signaling
status: In Progress
assignee:
  - '@architect'
created_date: '2026-06-25 11:40'
updated_date: '2026-06-25 13:36'
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
FEED-FORWARD (TASK-0044): chKey + SDK-fidelity params are now IN the live request, ready for the single token.get re-attempt. chKey = HMAC-SHA256(appId, packageName_"_"_certSha256Hex) recovered STATIC from native getChKey@0x16000 (re/chkey_static.md); computed in live.rs::load_config from appKey+manifest-package+offline-cert-hash, persisted to secrets/chkey.txt (gitignored). It is added to the atop envelope BEFORE signing (chKey is in SIGN_WHITELIST), so it rides the wire query AND enters the canonical sign. Also added the SDK-fidelity wire params the real initUrlParams sends: channel=sdk, sdkVersion, deviceCoreVersion, osSystem, platform, timeZoneId, bizData, cp=gzip (these are NOT signed; app defaults used for device-ish values). This was the likely ILLEGAL_CLIENT_ID cause (chKey was previously omitted from BOTH wire+sign). NEXT-cycle action: spend exactly ONE token.get with the corrected request; if ILLEGAL_CLIENT_ID clears, the bmp_token+MD5-fold sign oracle finally becomes reachable. NB the chKey key/message ordering is likely (not confirmed) — a token.get rejection could also be a wrong chKey ordering, not only a wrong sign.

RESUMING the single live token.get with the CORRECTED request: host a1.tuyaeu.com (TASK-0043, refuted as the issue), clientId/time wire params (already correct), chKey HMAC-SHA256 confirmed-ordering in wire+sign (TASK-0044), SDK-fidelity params, bmp_token candidate, most-likely MD5 fold. This is THE validation attempt.

SINGLE LIVE token.get RE-ATTEMPT (chKey-corrected request) — OUTCOME: still ILLEGAL_CLIENT_ID. The one corrected token.get was sent ONCE against a1.tuyaeu.com; the wire carried chKey+clientId+time+sign + all SDK-fidelity params (verified via captured request_param_keys in secrets/tuya_live_debug.json). Server: HTTP 200, success=false, errorCode=ILLEGAL_CLIENT_ID, errorMsg='Invalid client;No access', no result. Classified as non-sign Server error -> STOPPED before password.login per guardrail (zero lockout-sensitive calls; no retry; no host/fold sweep; 2FA not reached). chKey did NOT clear ILLEGAL_CLIENT_ID, so chKey/SDK-fidelity were not the (sole) gate; the bmp_token candidate + MD5 fold remain NEITHER validated NOR refuted (sign oracle still unreachable). Remaining server-opaque hypotheses: (a) provisioning/app-cert-pin/app-attestation identity gate a standalone client cannot reproduce; (b) a still-wrong chKey ordering (single-source) or an un-modelled signed identity input. Owner decides next (more material / authorized on-device Frida getChKey+request capture). Leak-hardening this cycle: routed probe_host's reqwest error through scrub_url_secrets so EVERY reqwest-error path is URL-redacted; ran with RUST_LOG unset (no reqwest/hyper debug). Captured to secrets/ only: tuya_live_debug.json (gitignored). Docs: re/live_login.md outcome updated (no values); re/chkey_static.md §3a strengthened (register re-trace) but kept 'likely' (one binary artifact, two views = one source per evidence rubric). Gates: e2e GREEN (live gated out), check-evidence GREEN, secret-scan GREEN.

STATIC SURFACE EXHAUSTED (qa GO + static lead-hunt conclusive): corrected request matched host + clientId/time + chKey(confirmed) + ALL signed/whitelisted params + ALL 3 SDK headers (User-Agent/Connection/x-client-trace-id; no interceptor adds identity headers) + NO attestation gate exists anywhere in the decompile. ILLEGAL_CLIENT_ID is server-only, identity-layer, PRE-sign -> appKey/ttid PROVISIONING, not a missing static field. Likely: (a) our extracted appKey/ttid isn't the live value, or (b) appKey is server-bound to the official Philips app registration. STOPPING per guardrail -> owner decides. The ONLY remaining unblock is an on-device capture (broader than the authorized cloud login) -> TASK-0045. P2: live.rs scrub_url_secrets docstring stale-mentions without_url (not called).
<!-- SECTION:NOTES:END -->
