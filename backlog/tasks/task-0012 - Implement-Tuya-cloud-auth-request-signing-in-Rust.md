---
id: TASK-0012
title: Implement Tuya cloud auth + request signing in Rust
status: In Progress
assignee:
  - '@architect'
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 04:53'
labels:
  - phase5
  - rust
  - wave1
  - auth
dependencies:
  - TASK-0011
  - TASK-0007
  - TASK-0023
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: the first genuinely buildable+testable slice. Implement Tuya HMAC request signing, account login, token issue/refresh, datacenter base-URL selection in babymonitor-core, per re/tuya_cloud_auth.md. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::auth signs requests; a differential unit test reproduces the captured signing vector from task 7 byte-for-byte (this gate bites with no network)
- [x] #2 Token store persists to ~/.local/share/babymonitor/; refresh-before-expiry covered by a unit test; no unflagged stubs
- [x] #3 If task 5 verdict is not 'recoverable-statically', the byte-for-byte differential (AC#1) may be unsatisfiable purely statically: implement+unit-test the sign ALGORITHM, and obtain the expected vector from the user's gated live run instead; record the blocker, do NOT fake a vector
- [ ] #4 Any live auth calls are rate-limited and single-shot; no retry loops against Tuya auth (no account lockout / infra hammering)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
IMPLEMENTER plan (TASK-0012) — TOKEN-PENDING signer + token store.

DEPS available offline (cargo cache verified): md5 0.7, base64 0.22, hex 0.4, sha2 0.10, dirs 5, serde+serde_json, chrono. Add to babymonitor-core only.

1. babymonitor-core::sign module — mobile-atop signer per re/tuya_sign_static.md + re/tuya_sign.md, sub-steps as independently testable pure fns:
   a. swapSignString(s32) -> B1+A+C+B2 permutation (s[8:16]+s[0:8]+s[24:32]+s[16:24]).
   b. post_data_digest(body) = swapSignString(md5AsBase64(body)).
   c. canonical_string(params) — whitelist filter (a,v,lat,lon,lang,deviceId,appVersion,ttid,h5,h5Token,os,appId,postData,t,requestId,et,n4h5,sid,chKey,sp), drop empty, sort keys asc, 'k=v' joined by literal '||' (NOT '&'); postData value pre-replaced by post_data_digest.
   d. md5_hex_lower(bytes) -> 32-char lowercase.
   e. assemble_key(cert_sha256_hex,bmp_token,appSecret) = '_'-join.
   f. cert_sha256 helper — read META-INF/BNDLTOOL.RSA (PKCS#7) from a zip path, SHA-256 over DER leaf X509, lowercase hex. Recovered ingredient — validate against the ACTUAL cert (assert 64-hex; no value committed).

2. Injected key material: SigningKeyMaterial struct {appKey, appSecret, app_cert_sha256_hex, ttid} + BmpTokenProvider trait {fn bmp_token()->Result<String,Error>}. NO hardcoded secret; loaded from secrets/ at runtime by caller. SignerConfig wires material+provider.

3. TOKEN-PENDING discipline: sign(...) returns Err(Error::BmpTokenPending) when provider yields none. NEVER fake sig, NEVER todo!/unimplemented!. Rustdoc: full sign blocked on TASK-0030.

4. session token store (AC#2): babymonitor-core::session — persists Session{sid,uid,issued_at,expires_at} JSON to ~/.local/share/babymonitor/session.json (dirs crate), refresh-before-expiry (needs_refresh with buffer) + unit test. No live calls.

5. VALIDATE (prove the check bites): unit-test each sub-step vs static evidence (swapSignString known vector, canonical '||' sorted, md5_hex known vector, '_'-join, cert helper on real BNDLTOOL.RSA -> 64-hex). >=1 NEGATIVE/corrupt-input test per parser. PARTIAL differential over recovered sub-steps with placeholder token. Full byte-parity = #[ignore]d pending test citing TASK-0030 (AC#1 stays UNMET/honest).

GATE: nix-shell just e2e (build+test+clippy -D+fmt+stub-grep+offline) GREEN; check-evidence GREEN; secret-scan GREEN; showcase runs. NO secret value in any tracked file/test (SYNTHETIC only). One/two commits, no AI-credit trailer. Leave In Progress (AC#1 token-pending). Feed-forward SigningKeyMaterial -> TASK-0013, BmpTokenProvider -> TASK-0030.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPLEMENTER FINAL SUMMARY (TASK-0012) — TOKEN-PENDING, left In Progress.

LANDED (babymonitor-core, commit c60d2fc):
- sign module: recovered 5/6 signer ingredients as independently-testable pure fns + an injected key interface. swap_sign_string (B1+A+C+B2), md5_hex_lower/md5_as_base64 (plain MD5, NOT HMAC), canonical_string (sorted whitelist, literal '||' join, drop-empty), assemble_sign_key ('_'-join), app_cert_sha256_hex[_from_apk] (offline cert hash). Injected interface: SigningKeyMaterial{app_key,app_secret,app_cert_sha256_hex,ttid} + BmpTokenProvider trait (PendingBmpToken / StaticBmpToken impls) + Signer{material,provider,SignBody}.
- session module (AC#2): SessionStore -> ~/.local/share/babymonitor/session.json, refresh-before-expiry (2-min buffer), load/save/clear, unit + negative tests.

PER-AC STATUS:
- AC#1 (byte-for-byte differential vector): UNMET — honestly TOKEN-PENDING. The full valid sign needs the real bmp_token (TASK-0030) AND an INDEPENDENT gold vector (nalajcie tooling or one live capture). Did NOT fabricate a vector. Encoded as a #[ignore]d pending test (sign::tests::full_signature_byte_parity_pending_task_0030) citing TASK-0030. A PARTIAL differential over the recovered sub-steps composes NOW (partial_differential_recovered_substeps_compose) with a synthetic placeholder token.
- AC#2 (token store + refresh + no unflagged stubs): MET. Unit-tested incl. corrupt-store negative.
- AC#3 (impl+unit-test the ALGORITHM, record blocker, do NOT fake a vector): MET. Algorithm + all recovered sub-steps implemented and unit-tested against independent/known vectors; blocker (bmp_token white-box cipher) recorded; no faked vector.
- AC#4 (live auth rate-limited single-shot): N/A this task — NO live calls made (structure + unit tests only, per static-only). To be honored by the login-flow task that actually issues requests.

VALIDATION (prove-the-check-bites):
- swap_sign_string: known 32-char vector -> documented permutation; negatives reject wrong-length + non-ASCII.
- md5_hex_lower/md5_as_base64: RFC1321 + python-hashlib-independent vectors; corrupt-input diverges.
- canonical_string: '||'-joined sorted output; asserts NOT '&'; differs-from-query-form negative.
- assemble_sign_key: order-is-load-bearing negative.
- cert helper: synthetic-DER 64-hex shape + reject-no-cert negative; AND the REAL ingredient cross-checked byte-for-byte vs the openssl reference on extracted/xapk/...'s META-INF/BNDLTOOL.RSA (Rust pure path prefix == openssl prefix; value withheld). Real-cert test is #[ignore]d (needs gitignored APK).

GATES (actual): just e2e GREEN (build+test 27 pass/2 ignore + clippy -D + fmt-check + stub-grep + assert-offline + bmp-decode); check-evidence GREEN; secret-scan GREEN; showcase GREEN; gates-selftest bites.

GOTCHAS / HONEST LIMITATIONS:
1. post_data_digest 24-vs-32 length contradiction: md5AsBase64(16-byte digest)=24 chars, but the decompiled swapSignString is characterized on a 32-char input (slices [0:8],[8:24],[24:32]). On a 24-char input those slices are OOB. We surface this as a typed Error::InvalidSignInput (documented gotcha) rather than silently mangling — the real postData fold is an OPEN ambiguity the gold vector (TASK-0030/live) must resolve. So post_data_digest is currently non-functional on real bodies BY DESIGN-HONESTY.
2. SignBody fold (MD5(key) vs MD5(key||canonical)) and the '_'-part ORDER are 'likely' (control-flow read, not executed) per re/tuya_sign_static.md §7-8. Made EXPLICIT (SignBody enum, single assemble_sign_key) so one gold vector fixes them in one place; NOT silently guessed.
3. cert extractor is a pragmatic DER scanner (no full ASN.1 crate); validated against the real cert but could mis-pick on an unusual PKCS#7 layout — fails loud if no cert SEQUENCE found.
4. Added flate2 (rust_backend / miniz_oxide, pure-Rust, offline) to inflate the DEFLATE-compressed signature block; keeps the offline gate self-contained.

FEED-FORWARD: appended interface shapes to TASK-0013 (SigningKeyMaterial) and TASK-0030 (BmpTokenProvider). Kept In Progress: AC#1 stays token-pending until TASK-0030 lands the token + an independent gold vector.

Cycle-14 review: both GO. Architect re-derived all 5 recovered sub-steps independently = correct; token-pending honest; cert value confirmed correct (raw-embedded-cert = Android semantics). Non-blocking P1/P2 -> TASK-0031 (cert validation reproducibility + leaf-selection robustness + spec contradiction caveat). AC#1 stays token-pending.
<!-- SECTION:NOTES:END -->
