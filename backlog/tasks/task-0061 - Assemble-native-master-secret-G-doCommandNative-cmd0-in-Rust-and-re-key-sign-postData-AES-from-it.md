---
id: TASK-0061
title: >-
  Assemble native master secret G (doCommandNative cmd0) in Rust and re-key sign
  + postData-AES from it
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-25 23:20'
updated_date: '2026-06-26 01:20'
labels:
  - auth
  - illegal-client-id
  - native
  - crypto
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doCommandNative cmd0 (doCommandNative.c:497-783) builds master secret G once at init from {packageName + _ + certSha256Hex + key material decoded from assets/t_s.bmp via read_keys_from_content keyed by appId/appKey + appSecret}, stored at .bss 0x39070, and consumed by cmd1 sign, cmd2 MQTT key, getEncryptoKey, encryptPostData. G is NOT statically resolvable without executing the t_s.bmp matrix decode (TASK-0032-adjacent). Port the exact cmd0 assembly so sign and postData-AES key derive from the real G.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cmd0 G-assembly byte-order + ingredients reproduced in Rust from native ground truth (decompiled/ghidra_security)
- [ ] #2 t_s.bmp key material extraction (read_keys_from_content, keyed by appId) ported or pinned with second-tool corroboration
- [x] #3 postData AES key = trunc16(HMAC-SHA256(requestId, G)) and sign key = G, both verified against native
- [x] #4 Written to re/master_secret_g.md with confidence levels; secrets/ refs only
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. sign.rs: add assemble_master_key_g(pkg, certColonUpper, bmpTokenHex, appSecret)->Vec<u8> building 4-part RAW byte string with 0x5f seps; matrixKey0 = hex_decode(bmp_token) (32 raw bytes).\n2. Add app_cert_sha256_digest(+_from_apk) raw-[u8;32] and cert_sha256_colon_upper(95-char UPPER colon hex); app_cert_sha256_hex now hex(digest).\n3. ch_key 3rd param -> cert_colon_upper.\n4. et3_encrypto_key(request_id, g:&[u8], ecode)->[u8;16] = first16 ASCII hex of HMAC-SHA256(requestId, G[++_++ecode]).\n5. live.rs master_key_g(cfg) replaces native_cached_key; sign + postData-AES both key off real G.\n6. Validation tests: RFC4231 HMAC, FIPS-180 SHA256, RFC1321 MD5, exact colon-upper gold vector, G-layout length. Recipe itself single-source (cannot offline-validate end-to-end) - documented.\n7. Write re/master_secret_g.md (confidence levels, secrets/ refs only).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GROUND TRUTH: G = DAT_00139070 (vaddr 0x139070) assembled by doCommandNative cmd0 from { packageName + _ + certSha256Hex + key-material from assets/t_s.bmp + appSecret }. t_s.bmp decoded by SignFileDecoder (ctor FUN_001199ac, decode FUN_0011a030) AES-128 with hardcoded key constant @0x1085f5 (secret -> secrets/), via read_keys_from_content, emitting NUL-separated JSON {securityOpen whitelist + key material}. Decompiled funcs at decompiled/ghidra_security/funcs/. Reuse prior art re/bmp_token_*.md + re/scripts/bmp_token_*.py.

- DONE AC#1: assemble_master_key_g(pkg, certColonUpper, bmpTokenHex, appSecret)->Vec<u8> reproduces cmd0 4-part RAW byte layout with single 0x5f seps; matrixKey0 = hex_decode(bmp_token) (32 raw bytes, NOT ascii hex).
- DONE AC#3 (code+shape): et3_encrypto_key(request_id, g:&[u8], ecode)->[u8;16] = first16 ASCII hex of HMAC-SHA256(requestId, G[++0x5f++ecode]); Signer::sign uses key=G. live.rs master_key_g() replaces native_cached_key for BOTH sign + postData-AES.
- Added cert_sha256_colon_upper (95-char colon-UPPER) + app_cert_sha256_digest(+_from_apk); app_cert_sha256_hex now hex(digest). ch_key 3rd param -> cert_colon_upper.
- DONE AC#4: re/master_secret_g.md written (confidence labels + ghidra/jadx citations, secrets/ refs only); passes check_evidence.py.
- NOT done AC#2: t_s.bmp read_keys_from_content decode still UN-PORTED (that is TASK-0032). matrixKey0 is sourced as hex_decode(secrets/bmp_token.txt). Signer stays BmpTokenPending honestly.
- Validation tests added: RFC4231 HMAC (cases 2+6), FIPS-180 SHA256, RFC1321 MD5, exact colon-upper gold vector, G-layout length, non-hex-token rejection. NO fabricated HMAC gold vector (none exists in the lib).
- HONEST LIMIT: recipe (key=G, msg=str2, 4-part order, matrixKey0-raw) is single-source native ground truth; CANNOT be offline-validated end-to-end - only primitive/encoding layers are KAT-checked.

Review-gate hardening (no behavior change to the recovered recipe):
- Finding 1 RESOLVED: matrixKey0 = hex_decode(bmp_token) -> 32 RAW bytes is now `confirmed` (two-source), not `likely`. The strlen at doCommandNative.c:546 reads the key as 64-char hex TEXT; the native then runs it through the hex-DECODER FUN_00113150 (doCommandNative.c:572), whose output is input_len/2 bytes decoding [0-9a-fA-F] pairs (funcs/00113150_FUN_00113150.c:32,46-76). So hex::decode is correct. Recorded in re/master_secret_g.md §2 + sign.rs module/fn docs.
- Finding 2: assemble_master_key_g + ch_key now take cert_digest: &[u8;32] and call cert_sha256_colon_upper INTERNALLY, so the wrong lowercase-64-hex cert string is unconstructable at the G/chKey boundary. All callers (Signer::sign, live::master_key_g, live::load_config) pass the raw digest.
- Gate: just e2e PASS (exit 0), just secret-scan PASS, clippy --features live -D warnings clean, cargo test --features live 30 passed / 2 live-ignored.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Assembled the native master secret G in Rust and re-keyed both the request sign and the ET3 postData AES off it.

What changed (sign.rs):
- assemble_master_key_g(package_name, cert_colon_upper, bmp_token_hex, app_secret)->Vec<u8> builds the cmd0 4-part RAW BYTE string: packageName ++ 0x5f ++ certColonUpper ++ 0x5f ++ matrixKey0 ++ 0x5f ++ appSecret, where matrixKey0 = hex_decode(bmp_token) (32 raw bytes, NOT the ascii hex).
- cert_sha256_colon_upper([u8;32])->95-char colon-grouped UPPERCASE hex (the exact native cert form for G AND chKey); app_cert_sha256_digest(+_from_apk) returns the raw [u8;32]; app_cert_sha256_hex is now hex(digest) (back-compat).
- ch_key 3rd param is now cert_colon_upper (output shape unchanged).
- et3_encrypto_key(request_id, g:&[u8], ecode)->[u8;16] = first 16 ASCII hex chars of HMAC-SHA256(key=requestId, msg=G[++0x5f++ecode]).

Wiring (live.rs): master_key_g(cfg) replaces native_cached_key and feeds both Signer::sign (via injected material) and the postData AES key.

Doc: re/master_secret_g.md records the byte layout, consumers, confidence levels and ghidra/jadx citations (secrets/ refs only); passes the grounding lint.

Validation: primitive/encoding layers checked against PUBLISHED vectors (RFC4231 HMAC cases 2+6, FIPS-180 SHA256, RFC1321 MD5, exact colon-upper gold string, G-layout length, non-hex-token rejection). just e2e EXIT=0, just secret-scan EXIT=0, live feature clippy-clean + 30 tests.

Open (status In Progress):
- AC#2 NOT met: the t_s.bmp read_keys_from_content decode that produces bmp_token is still un-ported (TASK-0032). matrixKey0 is currently hex_decode(secrets/bmp_token.txt); Signer stays BmpTokenPending honestly.
- The G recipe is single-source native ground truth and cannot be offline-validated end-to-end; final parity needs the recovered token + one server-accepted token.get (the sign oracle).
<!-- SECTION:FINAL_SUMMARY:END -->
