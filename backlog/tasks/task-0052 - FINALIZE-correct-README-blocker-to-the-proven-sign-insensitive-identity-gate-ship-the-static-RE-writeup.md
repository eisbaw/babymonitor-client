---
id: TASK-0052
title: >-
  FINALIZE: correct README blocker to the proven sign-insensitive identity gate
  + ship the static RE writeup
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 17:43'
updated_date: '2026-06-25 17:48'
labels:
  - phase3
  - wave3
  - docs
  - finalize
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner decided (2026-06-25) to STOP static and SHIP. The README "honest blocker" section is now STALE/WRONG: it blames the runtime bmp_token, but TASK-0050/0051 PROVED the bmp_token is NOT the blocker. Correct it to the real, proven conclusion and finalize the deliverable. The README must: (1) replace the bmp_token blocker section with the proven chain: appKey is the real provisioned key (R8-inlined, TASK-0046); reject is SIGN-INSENSITIVE / identity-layer per the corrupted-sign differential (TASK-0050); all EU/AZ atop gateways incl. iotbing reject (TASK-0048); last wire fields (ttid=sdk_international@appKey, channel=oem, appRnVersion, x-client-trace-id, body deviceId) matched and still ILLEGAL_CLIENT_ID (TASK-0051); no attestation code in the app; => a server-side appKey<->app binding a from-scratch static client cannot reproduce. (2) State the goal impact honestly: this blocks the WHOLE view-baby objective (stream is cloud-brokered WebRTC-over-MQTT; LAN port 6668 is datapoint-only). (3) Describe what ONE on-device capture (TASK-0022) would unblock and exactly how to inject a captured session token into the token-injectable Rust client to validate the full chain. (4) Fix any other stale cross-refs (the section anchor, milestone language). Keep secret hygiene (no values). Cite re/*.md by name. This is documentation only; no code changes expected.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 README blocker section replaced with the proven sign-insensitive identity-gate conclusion + full proof chain citing TASK-0046/0048/0050/0051 and the re/*.md docs; no stale bmp_token-as-blocker claim remains
- [x] #2 README states the whole-goal impact (no video without a cloud session) and documents the one-capture unblock path (TASK-0022) + how to inject a session token into the Rust client
- [x] #3 just secret-scan + just check-evidence + just e2e all green; no secret values in README
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read README + the proven re/*.md docs + CLI surface (DONE).
2. Rewrite README header status line: drop bmp_token-blocker framing; point to the identity-gate section.
3. Rewrite the Auth section heading/anchor: keep mobile-app sign (correct), fix ttid to sdk_international@<appKey>/channel=oem; note bmp_token is an un-validated static candidate, NOT the proven blocker.
4. Replace the stale section 3 (runtime bmp_token blocker) with the proven sign-insensitive identity-gate conclusion + proof chain (TASK-0046 appKey real/R8-inlined; TASK-0050 corrupted-sign differential; TASK-0048 all gateways reject incl iotbing; TASK-0051 last wire fields matched; no attestation code) -> server-side appKey<->app binding a static client cannot reproduce.
5. State whole-goal impact: no video without a cloud session (stream=WebRTC-over-MQTT needs authed MQTT session; LAN 6668 datapoint-only).
6. Document the one-capture unblock (TASK-0022) + concrete steps to inject a captured session token into the Rust client, referencing real CLI flags.
7. Fix section-4 client text (token-injectable) + any in-page anchor links.
8. Run just secret-scan + check-evidence + e2e; commit on branch.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Corrected the README's stale, disproven blocker section and finalized the static-RE deliverable. Documentation only; no code changes.

What changed (README.md):
- Replaced the stale "honest blocker: the runtime bmp_token" section (§3) with the proven server-side appKey<->app identity-gate conclusion + full proof chain: appKey is the real Philips-provisioned R8-inlined key (TASK-0046); the ILLEGAL_CLIENT_ID reject is SIGN-INSENSITIVE per the corrupted-sign A/B differential (TASK-0050); all EU-family gateways incl. iotbing reject across the full 24-field regionConfig (TASK-0048); the last wire fields (ttid=sdk_international@<appKey>, channel=oem, appRnVersion, x-client-trace-id, body deviceId) were matched and still rejected, with no attestation code in the app (TASK-0051).
- Reframed bmp_token everywhere as an un-validated static candidate that is explicitly NOT the login blocker (the differential proved a corrupted sign yields the identical reject).
- Corrected the header status line + fixed the in-page blocker anchor and added a §6 anchor.
- Fixed the Auth section ttid to sdk_international@<appKey> / channel=oem.
- Stated the whole-goal impact honestly: no video under static-only (stream is cloud-brokered WebRTC-over-MQTT needing the authenticated MQTT session; LAN TCP 6668 is datapoint-only).
- Added §6 documenting the one on-device capture (TASK-0022) that unblocks the chain and concrete steps to inject a captured session sid into the token-injectable Rust client (session store path via auth status; Session JSON shape; gated --features live path login -> device.list -> p2pType -> MQTT 302 -> WebRTC). Referenced only real CLI flags from babymonitor-cli/src/main.rs (no invented flags).

Secret hygiene: no appKey/secret/token/ttid values; secrets referenced by secrets/ location only.

Gates (all green): just secret-scan OK; just check-evidence OK (22 docs, 0 waived); just e2e OK (build + 103/10/6 tests pass, 0 failed; clippy -D; fmt-check; stub-grep; assert-offline; bmp-decode + regions python suites).

Also included pre-existing backlog metadata updates closing TASK-0049 and related tasks per the owner STOP-and-SHIP decision (same finalization context).
<!-- SECTION:FINAL_SUMMARY:END -->
