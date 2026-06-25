---
id: TASK-0041
title: >-
  Trace bmp_token config-byte[] provenance + exact login sign construction
  (complete the signer, static)
status: In Progress
assignee:
  - '@reverser'
created_date: '2026-06-25 10:54'
updated_date: '2026-06-25 11:07'
labels:
  - phase3
  - wave3
  - auth
  - native
  - ghidra
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-3 (authorized live-auth path). PURE-STATIC pre-work before any live login (guardrail: minimize live attempts). Resolve the ONE open question that gates the signer: where does the runtime JNI byte[] `config` passed to read_keys_from_content (the bmp_token matrix decode, fcn.13b5c path) actually COME FROM in the Java/JNI flow? Candidates: a static asset, an AES-decrypted asset (e.g. the tecrkcehc blob — we already ported that AES), a cloud-fetched config, or computed at SDK-init. AND trace the EXACT sign construction for the LOGIN requests (token.get, password.login) — the canonical string + which key, and confirm bmp_token is needed for them. VERDICT: is a complete concrete signer now buildable STATICALLY (config derivable -> compute the bmp_token candidate to secrets/ ONLY)? Or is the config genuinely runtime-only? This determines whether the live login is just VALIDATION or a bootstrap dependency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 config-byte[] provenance resolved (symbol-anchored, Ghidra-primary + r2/jadx): static-asset | AES-decrypted-asset | cloud-fetch | sdk-init-computed — with a verdict on static buildability
- [x] #2 exact login sign construction documented (token.get + password.login: canonical string + key + whether bmp_token applies); if statically derivable, a concrete bmp_token candidate is computed to secrets/ (value NEVER in a tracked file) and the full signer is ready to attempt
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Trace doCommandNative Java callers in jadx (JNICLibrary/ThingNetworkSecurity) to find what byte[] is passed as the config (param_6). 2. Confirm against Ghidra doCommandNative.c cmd=0 branch which byte[] feeds read_keys_from_content. 3. Document exact login sign (token.get/password.login) + key path. 4. Attempt static bmp_token recovery via the ported matrix decode with the real config; if integral solution obtained, write value to secrets/ only. 5. Write re/bmp_token_provenance.md with provenance + verdict. 6. Gates: check-evidence, secret-scan, e2e.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RESOLVED config provenance + login sign in re/bmp_token_provenance.md.

KEY FINDING: read_keys_from_content's config byte[] = doCommandNative param_6 = ThingSmartNetWork.mAppId.getBytes() (the appKey). Java caller: ThingNetworkSecurity.initJNI -> doCommandNative(ctx, 0=cmd, mAppSecret.getBytes()=param_5, mAppId.getBytes()=param_6/config, mD=Z). Ghidra doCommandNative.c cmd=0 branch (param_4==0) proves config==param_6 feeds read_keys_from_content (line ~540). NOT cloud-fetched, NOT AES-decrypted asset, NOT device-derived. Category: sdk-init-from-static-appKey. appKey/appSecret in secrets/tuya_appkey.json.

GOTCHAS:
- The decode runs on the cmd=0 INIT call (not cmd=1 sign) -- corrects the §8 cmd-attribution; cmd=1 (pbddddb.bdpdqbp) and cmd=2 pass param_6=null and MD5 the CACHED key built at cmd=0.
- mD defaults false -> selects t_s.bmp (not t_s_daily.bmp, unshipped).
- strhash stops at first NUL; appKey has no NUL so whole 20-char appKey is hashed.
- With REAL appKey config: header VALIDATES (selector_byte=1->op1, num_keys=1, num_coeffs=4) -- strong evidence config=appKey is correct (arbitrary configs get rejected). BUT op1 offset-walk in bmp_token_ghidra.py is NOT byte-exact: coefficient lengths come out 200+ bytes, Vandermonde solve non-integral (native 0xb). NO static oracle in the .so.
- I prototyped a byte-exact op1 walk from decode_op1.c/build_mpint_op1.c/xorstep_583c.c but it (a) still didn't solve integral and (b) broke test_synthetic_bmp_full_decode_runs (crafted vs the old walk). Reverted rather than ship unvalidated -> NO bmp_token value written to secrets/ (would be fabrication).

VERDICT: config provenance = STATIC (appKey). All signer INPUTS known offline. But trustworthy bmp_token VALUE = needs-live-login for VALIDATION (one accepted sign) OR a finished+oracle'd op1-walk port. Login sign documented byte-exact (ThingApiSignManager.generateSignatureSdk): sorted whitelist key=val joined '||', postData->swapSignString(md5AsBase64(body)), key=cert_sha256_hex_<bmp keys>_appSecret, plain MD5 hex. bmp_token IS required for login (cached key reused).

Gates: check-evidence OK, secret-scan OK, e2e OK (16 port tests pass).
<!-- SECTION:NOTES:END -->
