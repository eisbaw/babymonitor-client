---
id: TASK-0013
title: Implement device list/binding models + service in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 04:44'
labels:
  - phase5
  - rust
  - wave1
  - device
dependencies:
  - TASK-0012
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: lets the client discover the SCD921 under the Tuya account - prerequisite for any streaming. Implement typed models + service from re/tuya_cloud_auth.md, serde camelCase, liberal Option/default. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::device lists devices and exposes the camera entry (id, p2p creds handles, online state); fixture test deserializes a real/representative device-list JSON (stored in secrets/) without error
- [ ] #2 Model mismatches found vs real shape are fixed; honest notes on any field whose meaning is still unknown
- [ ] #3 PROVE THE CHECK BITES: a negative test asserts the parser REJECTS/surfaces an error on a malformed device entry (missing camera P2P-credential handle / wrong type); the camera entry asserts required (non-Option) invariants (device id, p2p creds handle) so it is not a permissive serde sponge
- [ ] #4 ANONYMIZE: any device-list JSON quoted in re/*.md, notes, or summaries has uid/homeId/localKey/gwId/email/GPS/IP replaced with synthetic placeholders; a sanitized committable fixture is produced and tests run against it; localKey + P2P creds treated as secrets
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0012 (signer/auth, commit c60d2fc): build the device-list/service request decoration on babymonitor-core::sign::SigningKeyMaterial — { app_key:String (wire clientId), app_secret:String (sign-key part only), app_cert_sha256_hex:String (64-hex, sign-key part), ttid:String (wire ttid) }. It has a redacting Debug (never logs secret values). Load it ONCE from secrets/ (app_cert_sha256_hex via sign::app_cert_sha256_hex_from_apk on the extracted APK) and pass &SigningKeyMaterial into request building — do NOT re-read secrets per call. Session state comes from babymonitor-core::session::{Session, SessionStore}: Session.sid is the wire 'sid' param, Session.mobile_api_base is the datacenter base URL (User.domain.mobileApiUrl); call Session::needs_refresh() before using a session. NOTE: a full valid 'sign' is still TOKEN-PENDING (Signer::sign returns Error::BmpTokenPending until TASK-0030); plan request decoration to thread the signer through but expect signing to be unavailable offline until then.
<!-- SECTION:NOTES:END -->
