---
id: TASK-0051
title: >-
  Airtight exhaustion: match the last static wire differences (x-client-trace-id
  header + body deviceId), re-fire ONE token.get
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 15:31'
updated_date: '2026-06-25 15:35'
labels:
  - phase3
  - wave3
  - auth
  - sign
  - live
dependencies:
  - TASK-0050
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Final static-fidelity probe before declaring the cloud-login avenue exhausted to the owner. The architect end-to-end request-shape sweep (post-0050) closed every substantive lead and found only TWO remaining statically-derivable wire differences between our token.get and the apps: (1) the app adds an x-client-trace-id request HEADER = requestId (OKHttpBusinessRequest.java:342, unconditional); the CLI omits it. (2) ApiParams.getRequestBody() places deviceId in the request BODY form (ApiParams.java:89), while the CLI sends it only in the signed query envelope. Both are judged very unlikely to move a sign-INSENSITIVE ILLEGAL_CLIENT_ID (trace-id is client telemetry; deviceId is a per-install random the server has never seen), but closing them removes the last wire-level doubt. IMPLEMENT: add the x-client-trace-id header (=requestId) to the live token.get request and also include deviceId in the POST body (keep it in the signed set). Then fire EXACTLY ONE token.get against a1.tuyaeu.com under the standard guardrails (token.get only, no password.login, capture to gitignored secrets/, scrubbed Display, stop at 2FA/success). EXPECTED: still ILLEGAL_CLIENT_ID -> static cloud-login avenue is then airtight-exhausted; record in re/live_login.md and report. If it UNEXPECTEDLY changes the errorCode or clears -> report loudly, that reopens the avenue.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 x-client-trace-id header (=requestId) added to the live token.get request; deviceId included in the POST body (still signed); change behind the live feature, e2e stays green
- [x] #2 Exactly one token.get fired against a1.tuyaeu.com under guardrails; errorCode recorded in re/live_login.md (no values); result classified (still ILLEGAL_CLIENT_ID = airtight exhaustion, or changed = avenue reopened)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Confirm the two wire diffs in decompiled sources (DONE): OKHttpBusinessRequest.java:23,342 (x-client-trace-id = getRequestId, unconditional); ApiParams.java:87-89 (getRequestBody puts KEY_DEVICEID="deviceId" into the request body).
2. In send_atop (live.rs), add header `x-client-trace-id` = envelope["requestId"] to the reqwest request builder. Used by BOTH the probe and login paths (single send path).
3. Append `&deviceId=<urlencoded device_id>` to the form body (currently only `postData=...`). deviceId stays in the signed query envelope (it is in SIGN_WHITELIST) so the canonical sign string is UNCHANGED.
4. Keep everything else byte-identical (ttid, channel=oem, appRnVersion, chKey, etc.).
5. Gates: just e2e + secret-scan + check-evidence + clippy --features live -Dwarnings + cargo test --features live --no-run. Commit.
6. Fire EXACTLY ONE token.get probe: --probe-only --host a1.tuyaeu.com. Record errorCode+HTTP in re/live_login.md (no values). Classify: still ILLEGAL_CLIENT_ID = airtight exhaustion; changed = avenue reopened.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in send_atop (single send path → covers probe + login):
- Added `x-client-trace-id` request header = envelope requestId (OKHttpBusinessRequest.java:23,342, unconditional).
- Added `deviceId` to the POST form body alongside postData (ApiParams.getRequestBody, ApiParams.java:87-89); deviceId stays in the signed query envelope (SIGN_WHITELIST), so the canonical sign string is unchanged.
Gates green: just e2e, secret-scan, check-evidence, clippy --features live -D warnings, cargo test --features live --no-run.
Fired EXACTLY ONE token.get --probe-only --host a1.tuyaeu.com (no corrupt-sign, no password.login). Result: HTTP 200, success=false, errorCode=ILLEGAL_CLIENT_ID (Invalid client;No access) — UNCHANGED. Recorded in re/live_login.md (no values). Verdict: static cloud-login avenue AIRTIGHT-EXHAUSTED.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the final two statically-derivable wire differences between our token.get and the real app, then re-fired ONE token.get to confirm the cloud-login avenue is exhausted.

Changes (babymonitor/babymonitor-cli/src/live.rs, behind the `live` feature, in the single send_atop path used by both probe and login):
- Add the `x-client-trace-id` request HEADER = requestId, mirroring OKHttpBusinessRequest.java:23,342 (CLIENT_TRACE_ID, unconditional, value = getRequestId()). Reuses the requestId already in the signed envelope.
- Add `deviceId` to the POST form body in addition to the signed query, mirroring ApiParams.getRequestBody() (ApiParams.java:87-89). deviceId is a SIGN_WHITELIST param signed from the envelope map, so the canonical sign string is UNCHANGED.

Gates: just e2e, just secret-scan, just check-evidence all green; clippy --features live -D warnings clean; cargo test --features live --no-run compiles. live is gated out of e2e.

Live probe: EXACTLY ONE signed token.get to a1.tuyaeu.com (--probe-only, no corrupt-sign, no password.login). Result HTTP 200, success=false, errorCode=ILLEGAL_CLIENT_ID — identical to before. ZERO password.login; 2FA not reached.

Verdict: every statically-derivable identity field/header/host and the sign are now matched to the app and the gateway STILL rejects → the static cloud-login avenue is AIRTIGHT-EXHAUSTED. The blocker is a server-side identity/provisioning gate (app-attestation / app-cert-pin / appKey↔package binding) a standalone static client cannot reproduce. Unblocking now requires on-device capture (TASK-0022) or more material from the owner. Recorded in re/live_login.md (no secret values).
<!-- SECTION:FINAL_SUMMARY:END -->
