---
id: TASK-0037
title: >-
  Wave-2: webrtc-rs media engine wiring + 302-payload localKey-AES mode + MQTT
  TLS (live stream completion)
status: In Progress
assignee:
  - '@architect'
created_date: '2026-06-25 07:59'
updated_date: '2026-06-25 08:20'
labels:
  - phase3
  - rust
  - wave2
  - stream
  - followup
dependencies:
  - TASK-0034
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from TASK-0034 (the Tuya-custom protocol layer landed offline-complete). Wire the live media + the un-pinned crypto:
1. webrtc-rs PeerConnection engine implementing babymonitor_core::stream::session::WebRtcEngine (create_offer/set_answer/add_remote_candidate/recv_frame): standard SDP + ICE (from injected P2pConfig.ices) + DTLS-SRTP + SRTP, H.264 (openh264) + PCMU/Opus de-packetize -> stream::frame::Frame. Deliberately deferred in TASK-0034 to protect the just assert-offline gate from webrtc-rs's large dep tree.
2. 302-payload localKey-AES: pin the exact AES mode/IV/padding (currently stream::mqtt_crypto::{encrypt,decrypt}_302_payload return Error::MqttCryptoPending). NOT statically pinned: Tuya MQTT AESUtil.ALGO is set at runtime (setALGO(i)); the obfuscated Cipher.getInstance arg is jadx-mangled (Cipher.il). Needs a port of com/thingclips/sdk/mqtt/ crypto OR one live 302 capture.
3. MQTT TLS: re-enable rumqttc use-rustls feature for the real (TLS) Tuya broker; stream::transport::RumqttcTransport currently builds with default-features=false (no TLS) to keep the offline gate green. Pin the exact Tuya 302 topic string + the Tuya MQTT protocol-version binary envelope framing (also unpinned).
Gated on the auth decision (TASK-0035) + a live SCD921 returning p2pType=4. The #[ignore]d live test babymonitor-cli/tests/live_e2e.rs::live_webrtc_session_renders_first_frame asserts the honest stream-pending state today; replace its fakes with the real engine/transport when this lands.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RE-SCOPED per TASK-0034 cycle-22 review: the localKey-AES mode IS statically pinned (AES-128/ECB/PKCS5Padding, key=localKey.getBytes() 16 ASCII bytes, NO IV; output hex via byte2hex or base64/raw by pv variant — evidence: decompiled/jadx/sources/com/thingclips/sdk/mqtt/qpqddqd.java setALGO("AES")/encrypt|encryptWithBase64|encryptWithBytes + com/thingclips/smart/android/common/utils/AESUtil.java getInstance(this.ALGO)/encrypt). FIRST deliverable of this task = correct the false 'not statically pinnable' claim (lib.rs MqttCryptoPending msg, stream/mqtt_crypto.rs docs, re/webrtc_session.md §2a/§7) AND implement the AES primitive with a known-answer test; the gate then narrows to ONLY the pv->variant binding for code 302 + the outer Tuya MQTT envelope framing (genuine live-capture residual). webrtc-rs media engine + TLS remain the larger live-gated pieces.

--- AES-PRIMITIVE PORTION DONE (cycle-23 implementer) ---
CORRECTED the false 'AES not statically pinnable / runtime AESUtil.ALGO' claim in 3 locations: babymonitor-core/src/lib.rs (the MqttCryptoPending error, renamed -> MqttEnvelopePending), src/stream/mqtt_crypto.rs (module + fn docs), re/webrtc_session.md (new SS2a evidence block + SS7 table + SS9 residual #5). Also fixed two sibling docs that carried the stale claim: src/stream/mod.rs:11 and src/stream/session.rs (run() doc + MqttTransport doc + a test comment), plus cli/tests/live_e2e.rs.

VERIFIED decompiled facts (exact lines, decompile is gitignored):
- AESUtil.java: :526/:329 Cipher.getInstance(this.ALGO); :527 init(1=ENCRYPT) / :330 init(2=DECRYPT) -- NO IvParameterSpec => ECB no IV; :189 new SecretKeySpec(keyValue, ALGO); :64 byte2hex .toUpperCase() (hex is UPPER); :528 encrypt->hex, :586 encryptWithBase64->b64, :593 encryptWithBytes->raw.
- qpqddqd.java: :133/:234/:632 setALGO("AES") (CONSTANT string, not runtime numeric); :134/:235/:633 setKeyValue(str.getBytes()) (key = localKey ASCII bytes); :136 encrypt / :237 encryptWithBase64 / :635 encryptWithBytes selected by publish-bean variant.
=> cipher pinned: AES-128/ECB/PKCS5(=PKCS7), key=localKey (16 ASCII), NO IV; out = hex(UPPER)|base64|raw by variant.

IMPLEMENTED in src/stream/mqtt_crypto.rs: aes128_ecb_{encrypt,decrypt} (aes crate + manual PKCS7), Aes302Output{Hex,Base64,Raw}, aes302_{encrypt,decrypt}. KAT vector from INDEPENDENT oracle 'openssl enc -aes-128-ecb' (NOT self-derived): pt='Tuya302' key='0123456789abcdef' -> hex EEF67DC369F4E9DF3684DD2C314E02D6 / b64 7vZ9w2n06d82hN0sMU4C1g== ; 16-byte block-aligned KAT proves the full PKCS7 pad block. Negative tests: wrong key len, wrong-key bad padding, misaligned/empty ciphertext, non-hex input.

GATE NARROWED: encrypt_302_payload/decrypt_302_payload now AES-compute then return Error::MqttEnvelopePending for ONLY the genuinely-unpinned part (pv->output-variant binding for code 302 + outer Tuya MQTT framing -- no offline oracle / live 302). The AES primitive itself never returns pending.

GOTCHAS:
- The 'ecb' crate is absent from the offline cargo index, so it could NOT be added without breaking 'just assert-offline'. Used the aes block cipher + cipher::BlockEncrypt/Decrypt traits + manual PKCS7 instead (aes 0.8.4 / cipher 0.4.4 / inout 0.1.4 were already cached). One new dep: aes.
- byte2hex UPPER-cases its output -- the 302 hex variant is UPPERCASE, UNLIKE the SDP a=aes-key codec which is lowercase. Easy to get wrong.
- block-aligned plaintext gets a FULL extra 16-byte PKCS7 pad block (JCE + openssl both do this); KAT covers it.
- MSRV 1.74: std::iter::repeat_n is 1.82+, tripped clippy::incompatible_msrv; used repeat().take() instead.
- DECRYPT with the wrong key trips PKCS7-unpad validation probabilistically (~255/256), NOT deterministically -- the negative test relies on this overwhelming likelihood, not a guarantee. Acceptable for a unit test but noted.

STILL OPEN on TASK-0037 (task stays In Progress): webrtc-rs media engine, the pv->variant binding + outer MQTT framing (live capture), MQTT TLS (rumqttc use-rustls). Gate green: e2e (95 lib tests incl. 6 new AES KAT/neg, clippy -D, fmt-check, assert-offline after aes cached), check-evidence, secret-scan.
<!-- SECTION:NOTES:END -->
