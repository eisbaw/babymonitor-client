---
id: TASK-0127
title: Acquire owner SCD921 camera firmware without triggering OTA
status: In Progress
assignee:
  - '@firmware-acquisition'
created_date: '2026-07-16 18:27'
updated_date: '2026-07-16 21:14'
labels:
  - firmware
  - ota
  - live-test
  - security
dependencies: []
references:
  - re/firmware_ota.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Use the reverse-engineered Tuya OTA metadata APIs to obtain the firmware image offered for the owner's paired SCD921. The operation must remain read-only: query metadata and download bytes, but never confirm/start/cancel an upgrade or send firmware to the camera.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A session-signed read-only OTA-info request is made for the exact cached owner device without invoking any upgrade mutation endpoint
- [x] #2 Raw metadata, signed URLs, identifiers, and downloaded firmware remain under gitignored secrets/ with owner-only permissions and are never printed or committed
- [ ] #3 Any downloaded artifact is checked against server-provided size, MD5/signature metadata where possible, and independently classified with file/binwalk/entropy tooling
- [x] #4 If the generic OTA-info endpoint does not yield an image, the camera-specific metadata endpoint and device-side fetch path are evaluated without triggering an update
- [x] #5 Findings distinguish the currently installed image from a newer candidate image and do not claim an on-device flash dump unless flash contents were actually read
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Trace exact OTA-info request and response models. 2. Reuse the cached authenticated owner session to issue only metadata queries. 3. Download any returned image into secrets/ and validate it. 4. Classify/unpack the artifact. 5. Record honest installed-vs-candidate and acquisition limitations.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-07-16 owner validation: the exact current Settings endpoint `m.thing.firmware.upgrade.info.get` v1.1 and legacy read-only fallback `thing.m.device.upgrade.info` v1.2 both succeeded for the key-proven camera. Each returned idle type-0 and type-9 channel records with server-reported current version 1.4.0, but no offered version, URL, size, MD5, or signature. No package bytes existed to download or classify, and `upgrade_request_sent` remained false.

The explicitly experimental firmwareWIP CLI now rejects expired sessions before signing or network I/O and accepts only the exact app-evidenced HTTPS Tuya gateway hosts. Atop metadata is bounded to 2 MiB. Every successful metadata query is published under a unique gitignored `secrets/firmware/` directory, including a bounded failure record when a later package-stage acquisition fails: new directories are mode 0700, files are mode 0600, raw responses and private metadata are never printed, and validated parent and staging directory descriptors remain pinned for basename-relative create, inspect, rename, unlink, and fsync operations; Linux atomic no-replace publication prevents silent overwrite or ancestor-path redirection. Existing dedicated session directories must not be group/world-writable; session files must be regular, non-symlink files with exact mode 0600.

A future offered package is eligible only over HTTPS with redirects disabled and a syntactically valid server MD5. It is streamed under a 512 MiB cap, checked against nonzero server size when present, required to match MD5, independently SHA-256 hashed, and atomically published. On preflight, transport, size, or digest failure, unverified bytes are deleted while redacted categorical provenance and private raw metadata remain. Server-controlled versions are accepted only through a bounded ASCII version grammar and are never used in public filenames. The opaque server signature is retained privately and explicitly marked unverified because its algorithm/key remain unknown. Offline tests cover endpoint order, fallback, expiry rejection, gateway allowlisting, metadata/body caps, hostile strings, redirects, missing/invalid MD5, size/digest/interruption failures, sibling retention, symlink rejection, private modes, concurrency, and no-clobber publication.

No camera firmware payload was identified in the inspected APK/XAPK files. The camera-specific `thing.m.camera.hardware.upgrade.get` action string is present, but its version, request model, and Java call site remain unresolved; a guessed owner-account request would not be evidence-based. A separate direct-AP flow calls `thing.m.local.device.upgrade.info` v1.0 with devId/types/versions and models `diffOta`, but it is not the normal paired-camera Settings flow and has not been queried without proven serialization inputs. In the normal Wi-Fi path, the app sends only devId/types to the separate mutation endpoint; the camera then fetches bytes device-side. No mutation endpoint was invoked.

Exact blocker: neither validated read-only endpoint currently offers a candidate artifact, so AC3 cannot yet be completed. This does not prove that Tuya lacks a separate or undocumented archive. Obtaining the exact installed flash contents still requires an authorized device shell or physical UART/SPI/NAND/eMMC extraction; server-reported current version is not a flash dump. The owner session available during the final hardening validation had expired, so a fresh owner login was required for any later metadata recheck; the hardened firmwareWIP command failed closed instead of transmitting it.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Read-only acquisition path is validated end-to-end or the exact blocker is recorded
- [x] #2 just e2e and secret-scan pass before any code commit
- [x] #3 qa-test-runner and mped-architect review any code change before commit
<!-- DOD:END -->
