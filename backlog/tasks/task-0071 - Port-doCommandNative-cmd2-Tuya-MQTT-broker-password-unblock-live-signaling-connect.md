---
id: TASK-0071
title: >-
  Port doCommandNative cmd2 -> Tuya MQTT broker password (unblock live signaling
  connect)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-26 20:20'
updated_date: '2026-06-26 22:20'
labels:
  - stream
  - signaling
  - mqtt
  - auth
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0069 signaling codec is byte-validated but the live MQTT connect is gated on the broker password = middle-16 chars of doCommandNative(cmd=2, ecode) (qpqbppd.java:128; re/mqtt_signaling.md). NOT a hard blocker: we already have the session ecode (live login), master key G, and the decompiled cmd2 routine (libthing_security, cmd2 = SHA256/HMAC derivation off G+ecode). Port cmd2 to Rust, derive the password, build clientId=<partnerIdentity>/mb/<uid> + username=<partnerIdentity>_v1_<mAppId>_<chKey>_mb_<token><md5tail>, then the rumqttc+TLS connect (live-tls feature) authenticates to m1.tuyaeu.com:8883 / the session gwMqttUrl.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 doCommandNative cmd2 ported in Rust and validated against the decompile (re/master_secret_g.md family)
- [x] #2 MQTT clientId/username/password derived per re/mqtt_signaling.md from the live session
- [ ] #3 rumqttc+TLS connect authenticates to the Tuya broker (live, owner-gated); 302 publish/subscribe works
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Recover cmd2 = FUN_00113474 from re/ghidra (md5_key_builder) + funcs/00113318,001135d8,001194b0.\n2. Confirm primitive: finalize writes 16 bytes => MD5; FUN_00113318 = md5_hex_lower (two-source via computeDigest).\n3. cmd2 = md5_hex_lower(md5_hex_lower(G) ++ ecode); password = middle-16 [8..24].\n4. clientId/username per qpqbppd.java (sep _, chKey=sign::ch_key, md5tail=last16).\n5. Implement babymonitor-core/src/stream/mqtt_auth.rs + BrokerConfig::from_credentials.\n6. Offline tests vs independent Python MD5 gold + decompile structure + string assembly.\n7. Correct re/mqtt_signaling.md S4 (no longer a hard native block).\n8. Run just e2e + cargo test -p babymonitor-core.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
cmd2 RECOVERED + PORTED. doCommandNative(2,ecode)=FUN_00113474 (re/ghidra/md5_key_builder.c) is nested MD5: out=md5_hex_lower(md5_hex_lower(G) ++ ecode), 32 hex chars; password=middle-16 [8..24] (qpqbppd.java:132-133). Primitive proven MD5 (not SHA256/HMAC as the task hint guessed): finalize FUN_001194b0 writes exactly 16 bytes; FUN_00113318=md5_hex_lower, two-source via computeDigest.c:109 already pinned MD5->32-hex. FUN_001135d8=raw concat.

Implemented babymonitor-core/src/stream/mqtt_auth.rs: do_command_native_cmd2, mqtt_password, mqtt_client_id, username_md5_tail, mqtt_username, derive_credentials, MqttCredentials (Debug-redacts password). Wired BrokerConfig::from_credentials (transport.rs). username sep=ddbdpdp.bdpdqbp=_; chKey=sign::ch_key; md5tail=last16 of md5_hex_lower(md5_hex_lower(mAppId)++ecode); MD5Util.md5AsBase64 is lowercase-32-hex MD5 not base64.

AC1 (offline): 10 mqtt_auth unit tests pass incl. bit-exact vs INDEPENDENT Python hashlib MD5 gold (cmd2=b55acd76..4851, pw=e9c82619e3079fe2) + decompile-structure check. AC2 (offline): clientId/username/password assembly asserted vs exact synthetic strings + derive_credentials wiring. AC3: LIVE/owner-gated - no captured CONNECT exists (TLS:8883, cap3 HTTP-only) so output has no wire ground-truth; needs owner live broker connect. just e2e PASS (E2E_EXIT=0), cargo test -p babymonitor-core 134+10+2 pass. Corrected re/mqtt_signaling.md S0/S4/S5.

IMPLEMENTED (stream/mqtt_auth.rs): cmd2 corrected to MD5 (not SHA256) = md5_hex_lower(md5_hex_lower(G) ++ ecode); password = middle-16 [8..24]; clientId/username assembled. Validated bit-exact vs an independent Python hashlib gold vector + decompile structure. Live broker CONNECT still owner-gated (no MQTT CONNECT ever captured).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Ported native doCommandNative cmd2 -> Tuya MQTT broker CONNECT credentials; offline-validated; live connect (AC3) owner-gated.

What changed:
- New module babymonitor-core/src/stream/mqtt_auth.rs: do_command_native_cmd2, mqtt_password, mqtt_client_id, username_md5_tail, mqtt_username, derive_credentials, MqttCredentials (password redacted in Debug).
- Wired BrokerConfig::from_credentials in stream/transport.rs (the live injection seam); corrected its doc (password no longer a hard native block).
- Registered pub mod mqtt_auth in stream/mod.rs.
- Corrected re/mqtt_signaling.md S0/S4/S5: cmd2 is recovered+ported, not an opaque native block.

Recovered algorithm (confidence confirmed, two-source decompile):
- cmd2(ecode) = md5_hex_lower( md5_hex_lower(G) ++ ecode ) = 32 lowercase-hex chars. FUN_00113474 (re/ghidra/md5_key_builder.c) = MD5(G)->hex, concat ecode, MD5->hex. Primitive is MD5 (finalize FUN_001194b0 writes 16 bytes), NOT SHA256/HMAC as the task hint guessed; FUN_00113318=md5_hex_lower, corroborated by computeDigest.c:109 (already pinned MD5->32-hex in master_secret_g.md).
- password = middle-16 [8..24] (qpqbppd.java:132-133).
- clientId = partnerIdentity/mb/uid. username = partnerIdentity_v1_<mAppId>_<chKey>_mb_<token><md5tail>; sep ddbdpdp.bdpdqbp=_, chKey=sign::ch_key (capture-verified 8 chars), md5tail=last16 of md5_hex_lower(md5_hex_lower(mAppId)++ecode). MD5Util.md5AsBase64 is lowercase-32-hex MD5 not base64.

Tests (offline): 10 mqtt_auth unit tests + 1 transport wiring test. cmd2 + md5tail asserted bit-exact vs INDEPENDENT Python hashlib MD5 gold vectors (cross-impl differential), plus decompile-structure check and exact string-assembly. No secret literal committed (synthetic only). just e2e PASS (exit 0). cargo test -p babymonitor-core: 134 lib + 10 device + 2 signaling pass.

Honest limits: AC3 (live broker connect) is OWNER-gated and unverified here - there is NO captured MQTT CONNECT (TLS:8883; cap3 mitmproxy HTTP-only), so the credential OUTPUT has no wire ground-truth; only the algorithm is offline-validated. G also carries the shared bmp_token-provenance caveat (master_secret_g.md). No live network calls were made.
<!-- SECTION:FINAL_SUMMARY:END -->
