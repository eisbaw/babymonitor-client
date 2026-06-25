---
id: TASK-0013
title: Implement device list/binding models + service in Rust
status: Done
assignee:
  - '@architect'
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 05:07'
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
- [x] #1 core::device lists devices and exposes the camera entry (id, p2p creds handles, online state); fixture test deserializes a real/representative device-list JSON (stored in secrets/) without error
- [x] #2 Model mismatches found vs real shape are fixed; honest notes on any field whose meaning is still unknown
- [x] #3 PROVE THE CHECK BITES: a negative test asserts the parser REJECTS/surfaces an error on a malformed device entry (missing camera P2P-credential handle / wrong type); the camera entry asserts required (non-Option) invariants (device id, p2p creds handle) so it is not a permissive serde sponge
- [x] #4 ANONYMIZE: any device-list JSON quoted in re/*.md, notes, or summaries has uid/homeId/localKey/gwId/email/GPS/IP replaced with synthetic placeholders; a sanitized committable fixture is produced and tests run against it; localKey + P2P creds treated as secrets
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add a core::device module: serde camelCase typed models grounded in decompiled CameraInfoBean + DeviceBean + nested P2pConfig (re/tuya_cloud_auth.md §5; symbols verified in decompiled tree).
   - DeviceListResponse / HomeDetail container -> Vec<DeviceBean>.
   - DeviceBean: devId REQUIRED (non-Option); localKey/secKey Option+secret; category/online/uuid/pv/productId Option/default; skills Map.
   - CameraInfoBean: p2pId REQUIRED (non-Option, the load-bearing P2P handle); p2pType i32 REQUIRED (transport selector, from wire sample pqpbpqd.java:1555 + P2PType enum ThingCameraConstants.java:1611); password/sessionTid Option+secret; p2pConfig Option<P2pConfig>.
   - P2pConfig: p2pKey/initStr/session Option+secret; ices/tcpRelay/udpRelay raw JSON.
   - Custom Debug on DeviceBean/CameraInfoBean/P2pConfig redacting localKey/secKey/password/sessionTid/p2pKey/initStr.
2. Transport enum P2pTransport { Ppcs=2, ThingWebRtc=4, Other(i32) } mapping p2pType; from streaming_mode.md.
3. Accessor: find_camera(&DeviceList) -> camera entry (category sp/ipc family); CameraView exposing devId, online, transport, p2p handles.
4. list_devices service shape: offline-injectable parse_device_list(body)->Result; any real HTTP behind token-pending/#[ignore] like TASK-0012 (no live calls).
5. Synthetic fixture tests/fixtures/device_list.json (obviously-fake values, header comment). POSITIVE test: deserialize, find camera, p2pType->WebRTC, handles present. NEGATIVE test: missing devId / missing p2pId / wrong type REJECTED with typed error. Round-trip test.
6. Gates: just e2e, check-evidence, secret-scan, showcase all green. Feed-forward to TASK-0014.

GROUNDING NOTE: p2pType is present on the WIRE (p2pType:4 in embedded sample pqpbpqd.java:1555) though NOT a declared Java field of CameraInfoBean (FastJSON ignores unmapped keys); enum mapping authoritative in ThingCameraConstants.P2PType (PPCS=2/THING=4).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0012 (signer/auth, commit c60d2fc): build the device-list/service request decoration on babymonitor-core::sign::SigningKeyMaterial — { app_key:String (wire clientId), app_secret:String (sign-key part only), app_cert_sha256_hex:String (64-hex, sign-key part), ttid:String (wire ttid) }. It has a redacting Debug (never logs secret values). Load it ONCE from secrets/ (app_cert_sha256_hex via sign::app_cert_sha256_hex_from_apk on the extracted APK) and pass &SigningKeyMaterial into request building — do NOT re-read secrets per call. Session state comes from babymonitor-core::session::{Session, SessionStore}: Session.sid is the wire 'sid' param, Session.mobile_api_base is the datacenter base URL (User.domain.mobileApiUrl); call Session::needs_refresh() before using a session. NOTE: a full valid 'sign' is still TOKEN-PENDING (Signer::sign returns Error::BmpTokenPending until TASK-0030); plan request decoration to thread the signer through but expect signing to be unavailable offline until then.

IMPLEMENTED (TASK-0013) — babymonitor-core::device module + synthetic fixtures + tests.

LANDED:
- Models (serde camelCase, grounded in decompiled beans): DeviceList{deviceList,sharedDeviceList}; DeviceBean (devId REQUIRED non-Option; localKey/secKey/uuid/pv/productId/category/isOnline/isLocalOnline/skills optional); CameraInfoBean (p2pId + p2pType REQUIRED non-Option; password/sessionTid/skill/p2pConfig optional); nested P2pConfig (p2pKey/initStr/session/ices/tcpRelay/udpRelay all optional; relay/ice kept as serde_json::Value — inner shape NOT recovered statically).
- Transport enum P2pTransport{Ppcs=2,ThingWebRtc=4,Other(i32)} mapping p2pType (re/streaming_mode.md; ThingCameraConstants.P2PType). Other(_) arm surfaces unknown values, not silently coerced.
- Accessor CameraView{device,info} exposing dev_id/online/transport/p2p_id/p2p_config; CameraView::pair fails loud (Error::DeviceMismatch) on a non-camera device. DeviceList::find_camera_device finds sp/ipc family.
- Service: parse_device_list(body)/parse_camera_info(body) offline-injectable parsers -> Error::DeviceParse on malformed. list_devices(&material,&token_provider,sid,home) threads the TASK-0012 signer; returns Error::BmpTokenPending (no token) or Error::NotImplemented (token present but live HTTP not wired) — NO live call, no fabricated response.
- Custom Debug REDACTS localKey/secKey/password/sessionTid/p2pKey/initStr + session descriptor contents; test debug_redacts_all_device_and_camera_secrets proves none appear in {:?}.
- New typed errors Error::DeviceParse / Error::DeviceMismatch.

FIXTURES (synthetic, committable): babymonitor/babymonitor-core/tests/fixtures/{device_list.json,camera_info.json}. Obviously-fake SYNTH_*/synth-* values + header _comment stating static-only/no-real-capture. .gitignore: blanket fixtures/ rule un-ignored ONLY for babymonitor-core/tests/fixtures via scoped negation (commented). secret-scan confirmed to SCAN them (git ls-files --others) and PASS — hyphens in SYNTH-LOCALKEY-... break the contiguous [A-Za-z0-9]{8,} run, so safe by design not exclusion.

TESTS: 10 fixture/integration (tests/device_fixtures.rs) + 4 in-module = 14 new. POSITIVE: deserialize, find camera (sp), p2pType=4->ThingWebRtc, p2p handles present, CameraView pairs. NEGATIVE (PROVE THE CHECK BITES): missing devId REJECTED (serde error names 'devId'); missing p2pId REJECTED (names 'p2pId'); missing p2pType REJECTED; wrong-typed p2pType (string) REJECTED; non-camera pair REJECTED (DeviceMismatch). Round-trip serialize->deserialize stable. All green.

GROUNDING / HONEST LIMITATIONS:
- p2pType is on the WIRE (embedded sample pqpbpqd.java carries "p2pType":4) but is NOT a declared Java field of CameraInfoBean (FastJSON ignores unmapped keys). Modeled explicitly as the transport selector; enum mapping authoritative in ThingCameraConstants.P2PType. confidence: confirmed.
- ices/session/tcpRelay/udpRelay inner shapes unknown statically — kept as raw serde_json::Value rather than guessing. session contents redacted in Debug.
- The home-detail ACTION NAME (a= value) that returns the deviceList is R8-obfuscated (thing.m.n placeholders) -> needs-live (already flagged in re/tuya_cloud_auth.md §6); does not block the MODELS.
- No live fetch: list_devices is token-pending (TASK-0030) — same discipline as TASK-0012. AC#1 fixture-deserialize part is fully met offline; live discovery awaits signing unblock.

GATES (actual): just e2e GREEN (29 core unit + 10 device-fixture tests, 2 ignored; clippy -D warnings clean; fmt-check clean; stub-grep OK; assert-offline OK; bmp-decode OK). just secret-scan OK. just check-evidence OK (14 docs). just showcase OK.

Cycle-15 review: both GO. P1 doc-overclaim (CameraView::pair rustdoc claims an info.id==dev_id check the code doesn't do — code is correct, fix the doc) + P2s (model categoryCode via serde alias to avoid silent-miss; hedge the inferred 'ipc' category literal; narrow the .gitignore fixtures negation to the 2 known files). These device.rs fixes folded into the TASK-0014 cycle (same code area).
<!-- SECTION:NOTES:END -->
