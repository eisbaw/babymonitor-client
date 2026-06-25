---
id: TASK-0012
title: Implement Tuya cloud auth + request signing in Rust
status: In Progress
assignee:
  - '@architect'
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 11:29'
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
FEED-FORWARD (TASK-0032): bmp_token is now RECOVERED as a CANDIDATE (integral-solve-consistent) to secrets/bmp_token.txt via re/scripts/bmp_token_ghidra.py (op1 walk made byte-exact; real appKey config + t_s.bmp solve INTEGRAL on the native denom==1 self-oracle; 32-byte/64-hex key). The signer's middle _-part is therefore computable offline NOW: config=appKey bytes (secrets/tuya_appkey.json), input=assets/t_s.bmp. Wire BmpTokenProvider to the static decode (key = cert_sha256 _ <bmp_token> _ appSecret per bmp_token_provenance.md s2.3). Keep PendingBmpToken ONLY until ONE live sign validates the candidate (NECESSARY!=SUFFICIENT). cert-sha256 + appSecret + MD5 + _-join + canonical-string (str2) are all ready (provenance.md s2).
<!-- SECTION:NOTES:END -->
