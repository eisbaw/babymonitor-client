---
id: TASK-0069
title: >-
  Implement WebRTC-over-MQTT signaling client (MQTT-302 offer/answer/ICE) in
  Rust
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-26 17:38'
updated_date: '2026-06-26 22:20'
labels:
  - stream
  - signaling
  - wave2
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cap3 gives the complete signaling spec (plaintext). Implement the Rust client: connect to the Tuya MQTT broker (m1.tuyaeu.com:8883 / session gwMqttUrl) with rumqttc+TLS, subscribe/publish the 302 channel, send the offer SDP (m=application imm 6001, ice-ufrag/pwd, a=aes-key, a=rtpmap AES/KCP) + trickle candidates over path=mqtt and path=lan, receive the camera answer, parse its SDP (aes-key, ice creds, candidates). 302 payload = AES-ECB(deviceLocalKey). Reuse stream/ codecs (connect_v2, 302 codec, sdp). Validate each message byte-against cap3/signaling_plaintext.jsonl.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rumqttc TLS client connects+authenticates to the Tuya MQTT broker with the live session creds
- [x] #2 302 offer + trickle candidates published (AES-ECB localKey) matching cap3 format; answer received+parsed
- [x] #3 SDP build/parse byte-validated against cap3/signaling_plaintext.jsonl; secrets stay in secrets/
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read cap3 ground truth + existing stream/ modules (DONE).
2. Rewrite signaling.rs to cap3-accurate inner-302 model: full header (path,is_pre,p2p_skill,security_level,sub_dev_id), msg as object {sdp|candidate, preconnect, token:[IceServer], tcp_token, log}; builders + answer extraction.
3. mqtt_crypto.rs: add outer 302 frame codec {data(base64 AES-ECB localKey),gwId,protocol,pv,t} (variant pinned Base64 by cap3 DECRYPT.md); fill MqttEnvelopePending gap.
4. sdp.rs: full offer-SDP builder (imm 6001, ufrag/pwd, aes-key, AES/KCP, ssrc cname) byte-matching cap3; answer ice-creds parser.
5. session.rs: signaling state machine offer->trickle->answer; emit ParsedAnswer.
6. transport.rs + Cargo feature live-tls (default off): rumqttc TLS connect skeleton taking injected creds.
7. MQTT-auth investigation -> re/mqtt_signaling.md (qpqbppd CONNECT derivation; password native doCommandNative cmd2(ecode) -> BLOCKED finding).
8. Tests: byte-validate against cap3 (redacted fixture + gated real-file test); just e2e + clippy green.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## TASK-0069 implementation (WebRTC-over-MQTT signaling)

Built the cap3-grounded 302 signaling client in babymonitor-core/src/stream/.

**Codec (signaling.rs, rewritten to cap3 ground truth):** corrected the inferred webrtc_session.md §2b schema. Real wire shape (from emulator_captures/cap3): top level is exactly {header,msg}; msg is an OBJECT {sdp|candidate, preconnect, token:[IceServer], tcp_token, log} — there is NO top-level token. Added full header (path mqtt|lan, is_pre/p2p_skill/security_level offer-only, sub_dev_id answer-only), IceServer/TcpToken types, offer()/candidate() builders, parse_answer()->ParsedAnswer (remote ufrag/pwd + media key + ICE servers).

**Outer frame + crypto (mqtt_crypto.rs):** filled the MqttEnvelopePending gap. The 302 data variant is now PINNED to Base64 (cap3 DECRYPT.md: decrypt seam = qpqddqd.bdpdqbp = AESUtil.decryptWithBase64). Added build_302_frame/parse_302_frame for the outer {data,gwId,protocol,pv,t} publish map (pbbppqb.java:399-406). Honest caveat: cap3 logged decrypted plaintext only, so AES->base64->frame is round-trip-tested, NOT byte-compared against captured ciphertext.

**SDP (sdp.rs):** build_offer_sdp reproduces the cap3 imm offer (m=application 9 imm 6001, ufrag/pwd, a=aes-key, AES/KCP, ssrc cname) BYTE-FOR-BYTE; extract_ice_creds parses answer ufrag/pwd.

**State machine (session.rs):** SignalingFlow = offer(mqtt+lan) -> trickle candidates(mqtt+lan) -> answer -> ParsedAnswer. LiveSessionDriver.run now builds+publishes the offer over both paths via the transport seam, then returns StreamPending (honest gate).

**MQTT-auth investigation -> re/mqtt_signaling.md.** FINDING: the device-IPC MQTT CONNECT creds (SdkMqttCertificationInfo = qpqbppd.java) are: clientId=<partnerIdentity>/mb/<uid>; username=<partnerIdentity>_v1_<mAppId>_<chKey>_mb_<token><md5tail>; password=middle-16 of doCommandNative(2, ecode). The PASSWORD IS NATIVE-DERIVED (doCommandNative cmd=2 on per-session ecode) and ALL params depend on per-login secrets -> NOT statically recoverable. BLOCKED: needs a CONNECT packet capture (port 8883; cap3 mitmproxy is HTTP-only so it was NOT captured — the clientId in flows.full.txt is the app OEM REST clientId, a different value) OR a live ecode + the native routine. AC#1 (live connect+auth) cannot be satisfied statically.

**TLS skeleton (transport.rs):** BrokerConfig gains tls + documents the cred derivation; live-tls cargo feature (default OFF) wires rumqttc Transport::tls_with_default_config (API verified against cached rumqttc 0.24 src). NOTE: the feature cannot compile in THIS offline sandbox (tokio-rustls 0.25.0 not in the local cargo cache); it builds on a networked machine. Default build / just e2e / assert-offline are unaffected (feature off).

**Validation:** tests/signaling_cap3.rs byte-validates against the REAL gitignored cap3 capture when present (ran here, not skipped): every message parses, build_offer_sdp reproduces the real offer SDP byte-for-byte, parse_answer extracts the answer fields, all 11 messages round-trip the 302 frame codec. A committed REDACTED fixture (tests/fixtures/signaling_cap3_redacted.jsonl, synthetic ids/keys) covers CI. just e2e GREEN (core 123 + cap3 2 + device 10 + cli 6; clippy/fmt/stub-grep/assert-offline pass).

**secret-scan:** my contributed files add ZERO findings (fixed one field-name false-positive in session.rs). The gate is red ONLY due to the pre-existing local emulator_captures/cap3 capture (real values), which .gitignore documents as intentionally-tracked-for-RE / LOCAL-ONLY / do-NOT-push-without-redacting. Not committing/pushing.

AC#1 left UNCHECKED (live broker connect+auth is blocked: native-derived password). AC#2/#3 checked (offer/candidate format + AES-ECB + answer parse + SDP byte-validated against cap3; secrets stay in secrets/).

MQTT-AUTH derivation recovered (re/mqtt_signaling.md): clientId=<partnerIdentity>/mb/<uid>; username=<partnerIdentity>_v1_<mAppId>_<chKey>_mb_<token><md5tail>; PASSWORD = middle-16 chars of doCommandNative(cmd=2, ecode) (qpqbppd.java:128). NOT a hard blocker: we already have the session ecode (from live login) + master key G + the decompiled cmd2 routine (libthing_security, cmd2=SHA256/HMAC derivation) -> PORTABLE. Next: port cmd2 to derive the MQTT password, then the rumqttc+TLS connect (live-tls feature) can authenticate. The 302 codec + SDP build/parse are byte-validated against cap3.

## TASK-0069 finish — LIVE MQTT signaling connect wired on top of stage-1 creds

Built the transport-coupled 302 signaling orchestrator that ties the (already byte-validated) 302 codec + SDP + stage-1 MQTT creds + rumqttc transport together.

**New (stream/session.rs):** `MqttSignalingSession<T: MqttTransport>` — engine-free, transport-generic orchestrator:
- `publish_offer(args)` / `publish_candidate(line)` — frame each envelope (AES-ECB/localKey + base64 + {data,gwId,protocol,pv,t}) and publish over BOTH paths (mqtt+lan), as cap3 does.
- `poll_inbound()` -> `InboundSignal` (Answer(Box<ParsedAnswer>) | RemoteCandidate(line) | Disconnect) — decrypts+parses inbound 302 frames; Answer carries the camera aes-key + ICE ufrag/pwd; empty-sentinel candidate -> None; unexpected inbound offer -> loud Error::Transport.
- `negotiate(offer_args, local_candidates, max_polls)` — full publish-offer -> trickle candidates+sentinel -> bounded-poll-for-answer exchange, returns ParsedAnswer. No-answer-within-budget -> honest Error::Transport (never a fabricated stream).
Refactored `LiveSessionDriver::run` to delegate offer framing/publish to the new session (DRY; removes the duplicated inline framing).

**New (stream/transport.rs):** `connect_and_negotiate(config, LiveSignalingParams)` — the LIVE wiring: RumqttcTransport::connect (opens socket + subscribes to the device 302 topic) -> MqttSignalingSession::negotiate. `LiveSignalingParams` bundles flow/local_key/dev_id/pv/offer_args/candidates/max_polls (keeps it under clippy arg-limit). TLS for the 8883 broker stays behind the existing `live-tls` feature (BrokerConfig::to_mqtt_options); the connect scaffolding compiles offline (base rumqttc) but is NEVER called offline.

**Offline-validated (mock transport, NO broker), 9 new tests:** publish offer+candidate over both paths (4 frames, each decrypts to right type/path under localKey); poll parses inbound answer (ufrag/pwd/16-byte media key, state->Answered); remote-candidate surfaced + empty sentinel filtered; inbound-offer rejected; empty-poll None; wrong-localKey decrypt fails loud; negotiate full exchange returns ParsedAnswer (6 frames published); negotiate times out without answer; negotiate aborts on disconnect.

**Test results (ACTUAL):** just e2e -> PASS (E2E_EXIT=0: build/test/clippy -D warnings/fmt-check/stub-grep/assert-offline/bmp-decode/regions). cargo test -p babymonitor-core -> PASS: 143 lib (was 134) + 10 device + 2 signaling, 0 failed, 3 ignored (live). Real gitignored cap3 capture present and re-validated.

**Honest limits / live-gated:** AC#1 (rumqttc TLS connect+AUTHENTICATE to the real broker) is OWNER-gated and left UNCHECKED — no live broker/camera in this sandbox, and live-tls cannot compile here (tokio-rustls not in local cargo cache), so the actual TLS:8883 CONNECT + auth handshake + real answer were NOT executed. Only the publish/subscribe/poll/answer LOGIC is offline-validated against a mock + cap3/synthetic vectors; the wire-level connect is the owner s live run (--features live-tls). No live network calls were made. secret-scan: my changed files add ZERO findings (synthetic keys only, secret-scan:allow annotated); the gate s 214 matches are all pre-existing capture-file false-positives (TASK-0066), none reference my files. Did NOT git commit.

IMPLEMENTED: 302 codec byte-validated vs cap3 + 9 mock-transport tests (publish mqtt+lan, answer parse, wrong-localKey loud-fail, timeout). Live TLS:8883 connect gated + the live-tls path is NOT forwarded from the CLI feature (new follow-up task) and did not compile here (tokio-rustls absent).
<!-- SECTION:NOTES:END -->
