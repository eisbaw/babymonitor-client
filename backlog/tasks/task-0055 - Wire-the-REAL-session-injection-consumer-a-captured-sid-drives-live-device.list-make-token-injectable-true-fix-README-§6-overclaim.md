---
id: TASK-0055
title: >-
  Wire the REAL session-injection consumer: a captured sid drives live
  device.list (make token-injectable true, fix README §6 overclaim)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 18:07'
updated_date: '2026-06-25 18:18'
labels:
  - phase3
  - wave3
  - cli
  - live
  - auth
dependencies:
  - TASK-0022
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Final-gate review found a genuine overclaim: README §6 + the pervasive "token-injectable" claim promise that injecting a captured session (sid) into SessionStore lets the live device.list read path run WITHOUT solving the identity gate — but live.rs NEVER reads SessionStore/Session. fetch_and_capture_device_list (live.rs ~:1273) takes its sid from the in-process password.login it just performs (the blocked step). So the store is write-only w.r.t. the live build; no --session/--sid flag, no store-load. The claim describes wiring that does not exist. FIX AT ROOT (make it true, do not just reword): (1) Add a live path that LOADS the SessionStore sid (session.rs SessionStore, ~:148 save / add a load) and threads it through a device.list atop call, BYPASSING password.login entirely. Trace how the real SDK carries the post-login sid on the device.list request (sid is a session token on the atop envelope / sign whitelist — confirm via decompiled ThingApiParams + the device.list business call) so the injected-sid request is byte-faithful. (2) Expose it on the CLI: e.g. `devices list --live` uses the injected session if present (else reports the identity-gate-blocked state honestly); optionally an `auth inject-session`/`--sid` helper. (3) Add an OFFLINE test (inject a fake sid, assert the device.list request is built+signed with it, no network) so e2e stays green and the claim is test-backed. (4) Re-verify README §6 steps now match real CLI surface (no invented flags). Keep guardrails: still no way to fabricate a session; injection requires a real captured sid the user supplies into gitignored secrets/. NO secret values committed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 live path loads an injected SessionStore sid and drives a byte-faithful device.list atop request bypassing password.login; CLI surface exposes it (devices list --live consumes the injected session); README §6 steps match real flags
- [x] #2 offline test injects a fake sid and asserts the device.list request is built+signed with it (no network); identity-gate-blocked state still reported honestly when no session is injected
- [x] #3 just e2e + just secret-scan + just check-evidence green; README §6 + token-injectable claims are now TRUE (no overclaim); no secret values in tracked files
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Trace device.list sid handling statically: confirm sid is KEY_SESSION whitelisted (tuya_sign.md bdpdqbp), device.list action name is R8-obfuscated/likely. Record method (no values) in re/tuya_cloud_auth.md.
2. core: confirm SessionStore::load exists (it does, session.rs:125).
3. live.rs: extract build_device_list_request() (pure, signs sid into envelope) as single source of truth; refactor fetch_and_capture_device_list to use it. Add run_injected_device_list() public entry that LOADS SessionStore sid + builds/sends device.list BYPASSING password.login. Add InjectedOutcome.
4. CLI: devices list --live consumes injected SessionStore session if present (build+send real device.list under --features live); else honest identity-gate-blocked. Keep --json.
5. Offline test: inject FAKE sid via temp store/fixture; assert device.list envelope is built+signed carrying that sid (inspect canonical/envelope) NO network. Keep no-session=blocked test.
6. Fix README §6 to reference only real shipped flags; token-injectable claim now literally true + test-backed.
7. Gates: just e2e + secret-scan + check-evidence + clippy --features live -D + cargo test --features live --no-run.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented injected-session device.list consumer.
- live.rs: extracted build_device_list_request() as single source of truth for the device.list request shape; refactored fetch_and_capture_device_list to use it. Added run_injected_device_list() public entry that LOADS SessionStore sid + drives ONE signed device.list BYPASSING password.login. Added InjectedOutcome enum + host_from_mobile_api_base().
- main.rs: devices list --live now consumes the injected session (feature-gated devices_list_live); non-live build + no-session both report the honest identity-gate-blocked state offline. Kept --json.
- SessionStore::load already existed (session.rs:125), reused it.
- Offline tests (no network): injected_sid_rides_device_list_envelope_and_canonical_sign (sid on wire AND in canonical sign string), empty_sid_is_dropped, different_injected_sid_changes_the_sign, no_injected_session_reports_blocked_offline, host_from_mobile_api_base_parses_and_falls_back.
- re/tuya_cloud_auth.md §3a records the sid/device.list trace (no values): sid is whitelisted (signed) + its envelope placement is confirmed; device.list action name is likely (single-source, R8-obfuscated).
- README §4 + §6 rewritten to reference only shipped flags (devices list --live, --features live); token-injectable claim now test-backed.
Gates: just e2e OK; secret-scan OK; check-evidence OK (22 docs); clippy --features live --all-targets -D warnings OK; cargo test --features live --no-run OK; live unit tests 27 passed; ignored live_e2e 2 passed (honest state unchanged).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wire the REAL session-injection consumer so a captured sid drives the live device.list read path, making the "token-injectable" claim literally true and test-backed (fixes the README §6 overclaim).

Root cause: live.rs never read SessionStore — fetch_and_capture_device_list took its sid only from the in-process password.login (the identity-gate-blocked step), so the store was write-only w.r.t. the live build and README §6 described wiring that did not exist.

Changes:
- live.rs: new build_device_list_request() is the single source of truth for the signed device.list request (folds the sid into the envelope BEFORE signing — sid is in the sign whitelist bdpdqbp, so it enters the canonical string); fetch_and_capture_device_list refactored onto it. New public run_injected_device_list() LOADS the SessionStore sid and drives ONE signed device.list, BYPASSING password.login; new InjectedOutcome enum; host taken from the session mobile_api_base (User.domain.mobileApiUrl).
- main.rs: devices list --live consumes the injected session under --features live (feature-gated devices_list_live); with no session injected, or in the default non-live build, it reports the honest identity-gate-blocked state and touches no network. --json kept on every path.
- re/tuya_cloud_auth.md §3a: records the sid/device.list trace method (no values) — sid placement + sign-whitelist membership are confirmed; the device.list business action name is likely (single-source, R8-obfuscated; one capture confirms it).
- README §4 + §6: rewritten to reference only shipped CLI surface (devices list --live, --features live); no invented flags.

User impact: given one separately-captured live sid written into the gitignored session store, `cargo run --features live -- devices list --live` drives the real read path. No way to fabricate a session remains; injection requires a real sid the user supplies into secrets/.

Tests (all offline, no network): injected_sid_rides_device_list_envelope_and_canonical_sign, empty_sid_is_dropped_from_device_list_request, different_injected_sid_changes_the_sign, no_injected_session_reports_blocked_offline, host_from_mobile_api_base_parses_and_falls_back.

Gates: just e2e OK; secret-scan OK; check-evidence OK (22 docs); clippy --features live --all-targets -D warnings OK; cargo test --features live --no-run OK.

Residual limitation: the device.list business API name is likely (single-source, R8-obfuscated) — the one non-confirmed ingredient on the injected-sid request; every other envelope field is confirmed. The injected path is wired + byte-faithful except for that one action string, which a live capture confirms/corrects.
<!-- SECTION:FINAL_SUMMARY:END -->
