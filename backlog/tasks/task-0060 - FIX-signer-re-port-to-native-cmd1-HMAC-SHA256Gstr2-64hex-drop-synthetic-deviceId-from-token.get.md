---
id: TASK-0060
title: >-
  FIX signer: re-port to native cmd1 HMAC-SHA256(G,str2)->64hex; drop synthetic
  deviceId from token.get
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-25 23:20'
updated_date: '2026-06-26 01:20'
labels:
  - auth
  - illegal-client-id
  - signer
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Native ground truth (doCommandNative.c:449-489) proves the request sign is HMAC-SHA256(key=G, msg=str2) rendered as 64 lowercase hex. Our Rust client wrongly ported computeDigest (MD5->32hex, the inbound response-verify path). Also our client sends+signs a synthetic 44-hex deviceId that the real app never puts on token.get (KEY_DEVICEID decl-only). Re-port the signer and remove deviceId from the envelope and canonical string. This is a confirmed critical bug that blocks login regardless of the identity gate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Signer computes HMAC-SHA256(key=G, msg=str2) -> 64 lowercase hex (not MD5/32hex)
- [x] #2 Synthetic deviceId removed from token.get envelope params AND from the sign whitelist/canonical string
- [x] #3 Unit test asserts 64-hex sign output shape; computeDigest kept only for response-verify
- [x] #4 Depends on G-assembly (cmd0) for the real key; until then signer is wired to take G as input
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. sign.rs: replace MD5 computeDigest sign with HMAC-SHA256(key=G, msg=str2)->64 lowercase hex via Signer::sign.\n2. Remove SignBody enum/field/with_body (fold ambiguity gone).\n3. SigningKeyMaterial.app_cert_sha256_hex -> app_cert_sha256: [u8;32]; fix Debug redaction.\n4. live.rs: stop fabricating deviceId; LiveConfig.device_id: Option<String>, insert only when caller-pinned (canonical_string drops absent).\n5. Tests: assert 64-hex sign shape; deviceId omitted by default, signed when pinned; keep computeDigest(md5) only for postData/response-verify.\n6. Run just e2e + secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GROUND TRUTH CONFIRMED (native + Java caller trace):\n- Real signer = doCommandNative cmd1 (FUN_00113ed8 param_4==1) = HMAC-SHA256(key=G, msg=str2) -> 64 lowercase hex.\n- Java chain: ThingApiSignManager.generateSignatureSdk:99/:159 -> pbddddb.bdpdqbp(str2):200 -> doCommandNative(ctx,1,...).\n- str2 = SIGN_WHITELIST sorted, k=v joined by literal || , postData value replaced by its swapped-MD5.\n- Our client wrongly ported computeDigest (FUN_00115ad0->FUN_00113318) = MD5/32-hex, which is only used by TokenRefreshManager/Highway/Fusion, NOT the login signer.\n- Also drop synthetic 44-hex deviceId (real app never puts deviceId on token.get).\nBlocked on G (TASK-0061).

- DONE: Signer::sign now = hex(HMAC-SHA256(key=G, msg=str2)) -> 64 lowercase hex. Removed SignBody enum/with_body/body field (MD5-fold ambiguity gone). md5_hex_lower retained ONLY for the postData fold swapSignString(md5_hex(postData)) - NOT the request sign.
- DONE: deviceId no longer fabricated. LiveConfig.device_id: Option<String>; envelope inserts deviceId ONLY when caller-pinned via secrets/android_profile.json. token.get/password.login send none -> canonical_string drops it. (Kept "deviceId" in SIGN_WHITELIST so a caller-pinned id is still signed, matching the app; for login it is simply absent.)
- SigningKeyMaterial.app_cert_sha256_hex -> app_cert_sha256:[u8;32]; Debug still redacts.
- Removed generate_phone_util_device_id/random_id/uuid32/load_or_create_device_id + their 2 tests (dead fabrication path).
- Tests: sign_output_is_64_lowercase_hex; device_id_omitted_by_default_and_signed_when_caller_pinned; partial_differential rewritten to HMAC(G,str2).
- just e2e EXIT=0 (125 tests), just secret-scan EXIT=0. live feature builds+clippy clean+30 live tests pass.

Review-gate hardening (signer crate + live path):
- Finding 3: killed stale 32-char-MD5 framing. live.rs corrupt_one_nibble test fixture is now a 64-char HMAC-SHA256 hex string (was 32-char "MD5 hex"); SigningKeyMaterial.ttid doc now notes it is VESTIGIAL for login — the wire ttid is wire_ttid(app_key)=sdk_international@<appKey>, not material.ttid.
- Finding 4: dropped the redundant on-disk chKey cache. live.rs load_config no longer reads/writes secrets/chkey.txt (the write swallowed errors); chKey is one HMAC, fully recomputable, so it is ALWAYS derived now (single source of truth). Removed the dead is_native_chkey_shape helper and the operator-pin read. Verified nothing ELSE reads secrets/chkey.txt (only load_config did); re/chkey_static.md + task-0044 still MENTION an operator-pin override — those notes are now stale (left untouched; not in scope).
- Finding 2 (shared with 0061): G/chKey now take the raw cert digest; login path passes &material.app_cert_sha256.
- Gate: just e2e PASS (exit 0), just secret-scan PASS, clippy --features live -D warnings clean, cargo test --features live 30 passed / 2 live-ignored.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Re-ported the Tuya request signer to the correct native function and dropped the fabricated deviceId.

What changed:
- sign.rs Signer::sign now computes HMAC-SHA256(key=master-key G, msg=str2) rendered as 64 lowercase hex (doCommandNative cmd1), replacing the wrong computeDigest MD5->32-hex port. Removed the SignBody fold enum/with_body/body plumbing (the MD5 fold ambiguity no longer exists).
- The MD5 primitive (md5_hex_lower/swap_sign_string/post_data_digest_hex) is retained ONLY for the ET3 postData digest that becomes the postData value inside str2 - it is no longer the request sign.
- live.rs no longer fabricates a synthetic 44-hex deviceId. LiveConfig.device_id is Option<String>; deviceId is inserted into the envelope (and thus the canonical sign string) ONLY when the caller pins one via secrets/android_profile.json. token.get/password.login send no deviceId.
- SigningKeyMaterial.app_cert_sha256_hex (String) -> app_cert_sha256 ([u8;32] raw digest); Debug impl still redacts.

Deviation from AC#2 wording: "deviceId" is kept in SIGN_WHITELIST (so a caller-pinned id is still signed, matching the real app); it is removed from the login canonical string by being OMITTED from the envelope, which canonical_string drops. Effect on token.get is identical to deletion.

Depends on TASK-0061 for the real key G (assemble_master_key_g); the signer takes G ingredients via injected SigningKeyMaterial + BmpTokenProvider and stays BmpTokenPending until the real token is available - no fabricated signature.

Tests: just e2e EXIT=0 (125 tests incl. new sign_output_is_64_lowercase_hex + device_id omitted/pinned tests); just secret-scan EXIT=0; live feature builds, clippy-clean, 30 live tests pass.

Status left In Progress: true server-accepted-sign parity remains blocked on the un-ported bmp_token (TASK-0032) and a live sign oracle.
<!-- SECTION:FINAL_SUMMARY:END -->
