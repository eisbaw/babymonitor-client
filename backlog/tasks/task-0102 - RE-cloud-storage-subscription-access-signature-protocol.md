---
id: TASK-0102
title: RE cloud storage subscription & access-signature protocol
status: Done
assignee:
  - '@myself'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:14'
labels:
  - re
  - cloud-storage
  - crypto
  - native
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the cloud-storage service layer: subscription enable/state (DpCloudStorage), the request/access info (getCloudRequestInfo, configCloudDataV2), and the HMAC access-signature tools (TUNICloudStorageSignatureManager + native libThingCloudStorageSignatureTools.so) used to authorize cloud-clip access. Static-RE the signature construction surface (inputs, algorithm) into an re/ writeup; never commit recovered keys/tokens — reference secrets/ location only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The cloud-storage signature entrypoint (TUNICloudStorageSignatureManager) and the native lib it calls are identified with file:line evidence
- [x] #2 The signature inputs and algorithm are characterized as far as static analysis allows, with confidence and what dynamic evidence would close gaps; no secrets inlined
- [x] #3 re/cloud_storage_signature.md writeup exists
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Static-RE per ACs: grep decompiled/jadx + decompiled/apktool; write re/cloud_storage_signature.md with per-claim confidence + file:line evidence; verify just secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Traced full chain statically. JS bridge (miniapp_IPCKit.js.pretty:641 + TUNICloudStorageSignatureManager.json) -> Kotlin TUNICloudStorageSignatureManager.generateSignedUrl (line 154/158) -> JNI ThingCloudStorageSignatureTools.generateSignedUrl (line 62) -> libThingCloudStorageSignatureTools.so (ARM aarch64, stripped, BoringSSL static-linked). Algorithm reconstructed from embedded C format strings (recovered via strings) + un-stripped exported symbol names (readelf -sW), NOT from a Ghidra byte-level decompile (called out as residual). Two providers: AWS SigV4 query-presign and Aliyun OSS presign. getCloudRequestInfo (TRCTCameraManager.java:8404) returns only {userId(uid), uuid} identity context, NOT the STS creds; configCloudDataV2 (line 6727) -> configCloudDataTags is the clip-decrypt config, separate from URL signing. DpCloudStorage is the BaseDpOperator for the subscription-state DP (notify action CLOUD_STORAGE) but its numeric DP id is obfuscated away. Biggest residual: the Tuya cloud API that mints ak/sk/token+bucket/region is not in the IPCKit bundle (needs a live capture or the panel JS). No secrets written; secret-scan OK (exit 0) with doc in pending diff; direct pattern check on the doc = no hits. Left the doc untracked (not asked to commit).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the Tuya cloud-storage access-signature protocol for the SCD921 in re/cloud_storage_signature.md.

What changed: new static-RE writeup covering (1) the signature entrypoint chain Kotlin TUNICloudStorageSignatureManager.generateSignedUrl -> native ThingCloudStorageSignatureTools.generateSignedUrl -> libThingCloudStorageSignatureTools.so, with file:line + lib@offset evidence; (2) the 9 inputs and their roles; (3) the algorithm — a dual-scheme object-store presigned-URL generator: AWS S3 Signature V4 (AWS4-HMAC-SHA256, X-Amz-* query presign, UNSIGNED-PAYLOAD) and Aliyun OSS legacy presign (HMAC-SHA1+base64, security-token), reconstructed from verbatim native format templates and demangled exported symbols; (4) the surrounding service layer (getCloudRequestInfo identity context, configCloudDataV2/configCloudDataTags clip-decrypt config, DpCloudStorage subscription-state DP); (5) a residual-unknowns section.

Why: TASK-0102 needs the cloud-clip authorization surface characterized for a future Rust client. Key finding: this is a self-contained S3/OSS signer (NOT the t_s.bmp mobile-app signer); reimplementing the signing step is straightforward from public specs, and the real blocker is the upstream Tuya STS-credential-mint API, which is not present in the scanned JS bundle.

Honesty: scheme identification is high-confidence (named constants + exact templates); byte-exact canonical-request layout is medium (inferred from public SigV4/OSS specs, would be closed by a Ghidra decompile of ThingCloudSignatureCalculateSignatureDataV2@0x90b88 or a reference-diff). DP id and STS-mint API are explicit residual unknowns with stated unblock evidence.

Secrets: no values inlined — ak/sk/token described as roles only, PII (uid/uuid) flagged, secrets referenced to secrets/ location. `just secret-scan` passes (exit 0) with the doc in the pending diff; direct pattern check on the doc yields no hits.
<!-- SECTION:FINAL_SUMMARY:END -->
