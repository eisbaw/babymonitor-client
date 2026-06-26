---
id: TASK-0037
title: >-
  Media transport+decrypt engine (cap3 PATH A): ICE + KCP + AES-128-CBC + HMAC +
  RTP depacketize
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-25 07:59'
updated_date: '2026-06-26 22:20'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add offline-cached crates cbc+hmac (+aes-gcm to core) — verify just assert-offline stays green.
2. New stream::media submodule, hand-rolled ikcp RX (no kcp crate) with per-segment decrypt hook.
3. crypto.rs: datagram HMAC-SHA256 verify+strip (suite3); per-segment AES-128-CBC inline-IV+PKCS7 (suite3) and AES-128-GCM (suite4); pkcs7 unpad.
4. kcp.rs: 24B LE header parse, conv demux, window/dup, frg reassembly, recv().
5. rtp.rs: 12B BE RTP parse (V/P/X/CC/M/PT/seq/ts/ssrc, ext+pad).
6. h264.rs: STAP-A/FU-A -> Annex-B depacketize.
7. transport.rs: ICE candidate parse+select (host/srflx/relay) + MediaTransport seam + live-gated UDP transport.
8. mod.rs: CipherSuite from security_level + MediaEngine.push_datagram -> MediaUnit(payload,pt,marker,seq,ts).
9. Unit-test each layer + an end-to-end synthetic vector (RTP->frag->CBC->KCP->HMAC datagram -> engine -> RTP). Validate cap3 candidate/SDP structure. cap4 does not exist (skip).
10. Run just e2e + cargo test -p babymonitor-core; report actual pass/fail; offline-only, live path honestly gated.
<!-- SECTION:PLAN:END -->

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

CORRECTION (cycle-23, supersedes Description item 2): the localKey AES IS statically pinned — AES-128/ECB/PKCS5Padding, key=localKey ASCII bytes, NO IV, output UPPERCASE-hex|base64|raw by pv variant (now IMPLEMENTED + openssl-KAT-tested in stream/mqtt_crypto.rs). The error is MqttEnvelopePending (NOT MqttCryptoPending), and it gates ONLY the pv->variant binding for code 302 + the outer Tuya envelope framing (genuine live-capture residual). Remaining for this task: webrtc-rs media engine + that pv-binding/framing + MQTT TLS.

Cycle-23 review (AES portion): both GO. Correction accurate (re-derived from qpqddqd.java/AESUtil.java); AES impl correct (openssl-independent KAT eef67dc3...); hex-case not conflated (302=UPPERCASE byte2hex, SDP=lowercase); gate honestly narrowed; rename clean. P2 (future): the SDP a=aes-key 'lowercase' claim is uncited (imm_p2p_misc_hex_to_char body not decompiled) but non-load-bearing (decoder case-insensitive).

Reconciled at ship (2026-06-25): BLOCKED/unbuilt, by design. The WebRTC-over-MQTT protocol layer is built+tested (302 codec, connect_v2, SDP aes-key, localKey AES), but the webrtc-rs media engine wiring + a live stream need an authenticated session (blocked by the identity gate) AND are commodity/untestable offline. Stays open as the documented future work once a session is injected (TASK-0055 path) / captured (TASK-0022).

Transport CONFIRMED live (TASK-0065): SCD921 p2pType=4=WebRTC -> this WebRTC-over-MQTT media engine is the right path. Auth is no longer the blocker: a full session (sid/uid/ecode/domain) + device record are obtainable via devices list --live. Real remaining blocker = capturing the live MQTT signaling handshake (native-hook capture; cap1 only has the atop REST layer).

MEDIA-ENGINE FORK (from the critical-path map, evidence in secrets/cap1_rtc_decrypted/smartlife.m.rtc.config.get.json): the LIVE rtc.config says transmission=kcp and the cloud hands out session.{aesKey,icePassword,iceUfrag} directly — i.e. likely NOT standard DTLS-SRTP, so webrtc-rs may be the WRONG engine and a native KCP/moto + Tuya-SRTP port from libThingP2PSDK.so may be required. This is UNDECIDED and capture-gated. Do NOT commit the webrtc-rs wiring until the new signaling+media capture (new task) classifies the transport. Have today: connect_v2 + 302 codec + AES-128-ECB cipher (KAT). Missing: MQTT topic, 302 outer framing, real SDP, media transport verdict.

FORK RESOLVED (cap3, 2026-06-26): the media-transport question is settled. cap3/signaling_plaintext.jsonl SDP says a=rtpmap:6001 AES/KCP and m=application 9 imm/tuya 6001 -> media is AES-over-KCP (reliable UDP), custom imm/tuya, NOT DTLS-SRTP. So webrtc-rs is the WRONG engine; the media engine = ICE (host/srflx/TURN) + KCP transport + AES-decrypt(media payload, key=SDP a=aes-key) + imm/RTP depacketize (PT 6001) + H.264/PCMU/Opus decode. AES MODE + KCP/imm framing still to recover from re/ghidra/imm_p2p_rtc_recv_frame.c / sdp_get_aes_key.c / imm_p2p_h264_packetize.c + full libThingP2PSDK decompile (decompiled/ghidra_p2p/).

MEDIA RX FULLY SPECCED (re/media_decode_spec.md, from libThingP2PSDK decompile). Pipeline: UDP datagram -> (suite3) verify+strip trailing 32B HMAC-SHA256(key=16B SDP aes-key) -> ikcp_input (stock skywind ikcp) -> per PUSH segment: IV=seg[0:16], AES-128-CBC-decrypt(seg[16:],iv), PKCS#7 unpad -> KCP frg reassembly -> 12B RTP header -> depacketize H.264 STAP-A/FU-A (Annex-B) | PCMU(PT0, G.711 ulaw). Cipher suite = security_level (cap3=3=CBC; suite4=GCM, suite2=ChaCha). Crates: fork kcp for per-segment decrypt hook (or hand-roll ~200 lines), hmac+sha2, aes+cbc(Pkcs7), rtp, openh264/ffmpeg. Validation: HMAC match + valid PKCS#7 + RTP V=2 + NAL type in range = conclusive. CORRECTION: re/webrtc_session.md called cap3 media DTLS-SRTP - WRONG, that is PATH B (return audio); cap3 AES/KCP is PATH A.

RESCOPED: title was the stale webrtc-rs guess (disproven — cap3 media is AES/KCP, not DTLS-SRTP). This task = the TRANSPORT+DECRYPT layer only: ICE connectivity (host/srflx/TURN) -> KCP RX (fork ikcp for per-segment decrypt hook, or hand-roll) -> datagram HMAC-SHA256 verify -> per-segment AES-128-CBC decrypt (inline IV, PKCS#7) -> KCP reassembly -> 12B RTP parse, emitting NAL/audio payloads. The H.264/audio DECODE + display is split to a new task; the MQTT-auth port (to actually connect) is a new task.

--- MEDIA TRANSPORT+DECRYPT ENGINE (cap3 PATH A) — implementer cycle ---

Built the offline-complete media receive→decode engine per re/media_decode_spec.md in a new submodule babymonitor-core/src/stream/media/ (6 files, ~63 new unit tests):
- crypto.rs: datagram HMAC-SHA256 verify+strip (suite3, key=16B SDP a=aes-key, constant-time verify_slice); per-segment AES-128-CBC inline-16B-IV + manual PKCS#7 unpad (suite3, [C]); AES-128-GCM inline-IV+trailing-tag (suite4, [G]).
- kcp.rs: hand-rolled ikcp RX (NO kcp crate — absent from offline cache + has no per-segment hook). 24B LE header parse, conv demux, acceptance window + dup drop, frg reassembly (frg counts DOWN to 0), recv()/drain_messages(). Per-segment decrypt hook via SegmentDecryptor trait (mirrors native ctx_session_chan_process_pkt: decrypt AFTER window/dup checks, store plaintext; KCP concatenates plaintexts not ciphertexts).
- rtp.rs: 12B BE RTP parse (V=2 gate, P/X/CC handling, marker/PT/seq/ts/ssrc, ext+pad strip).
- h264.rs: RFC-6184 single-NAL/STAP-A/FU-A → Annex-B (00000001) depacketize, stateful FU-A reassembly across packets, keyframe(IDR) detect.
- transport.rs: ICE candidate parse (host/srflx/prflx/relay) + order_candidates (host<srflx<relay, then desc priority) — validated against cap3 candidate shapes; MediaTransport seam + live-gated UdpMediaTransport.
- mod.rs: CipherSuite::from_security_level (0/1 plaintext, 2 ChaCha20 honest-unimpl, 3 CBC+HMAC, 4 GCM); MediaEngine.push_datagram(datagram)->Vec<MediaUnit{payload,pt,marker,seq,ts,ssrc}> running the full §1 pipeline per conv; key+payload redacted in Debug.

OFFLINE-VALIDATED (synthetic vectors built per the spec SEND path): full e2e suite3 single-segment + KCP-fragmented(2-seg) + STAP-A→depacketize; suite4 GCM; suites0/1 plaintext; control-conv routed away from media. NEGATIVE: wrong key fails datagram HMAC; tampered ciphertext (re-HMAC) fails per-segment PKCS#7; ChaCha20 loud-unimpl; bad version/short/overrun/bad-pad in every layer. Each layer also unit-tested in isolation.

LIVE-GATED / HONEST RESIDUALS (no live broker/camera in sandbox, never fabricated): (a) actual ICE/UDP connectivity — UdpMediaTransport does plain UDP only; STUN-binding(srflx)/TURN-Allocate(relay) NOT implemented (webrtc-rs excluded to protect assert-offline); only directly-routable host candidates reachable. (b) NO emulator_captures/cap4 exists → zero captured media bytes to byte-validate against (spec TASK-0068); pipeline proven on synthetic vectors only. (c) suite-4 GCM nonce length/tag placement is [G] (round-trips but unconfirmed on-wire). (d) spec §3 [G]: assumed one KCP message == one bare RTP packet (length-prefix variant would surface as a loud RTP-parse error, not silent mis-decode). (e) live CBC-vs-GCM still security_level-gated.

GOTCHAS: cbc+hmac added as deps — both already in offline cargo cache so assert-offline stays green (verified); aes-gcm added to core (was cli-only). NO unreachable!/todo! in production (stub-grep gate) — ChaCha20 handled as a match arm returning Error::Transport, not unreachable!. KCP frg counts DOWN (first frag=N-1, last=0) — easy to invert.

GATE: just e2e GREEN (exit 0; 203 core lib tests + 6 cli + integration, clippy -D warnings, fmt-check, stub-grep, assert-offline all OK). cargo test -p babymonitor-core: 203 passed / 0 failed / 3 ignored. Did NOT git commit (per task). webrtc-rs PATH B media engine + MQTT TLS + 302 envelope live-capture remain open on this task.

SECRET-SCAN: my media/* files add ZERO findings (no email/key/token value-shapes; synthetic test keys 0123456789abcdef / fedcba9876543210 / IVIVIV... all carry the secret-scan:allow marker). NOTE: `just secret-scan` is currently RED on this worktree, but that is PRE-EXISTING and unrelated to this task — 5697 of 5702 hits are email/JWT-regex FALSE POSITIVES in the committed capture dumps emulator_captures/cap1+cap2/flows.full.txt (committed in 5603d96, before this work). Flagging for the owner; not fixed inline (out of scope / would be a tangent — candidate follow-up: gitignore or scrub the cap1/cap2 flow dumps, or add them to secret_scan EXCLUDE_GLOBS).

IMPLEMENTED (stream/media/): AES-128-CBC inline-IV+PKCS7 + GCM (suite4) + datagram HMAC-SHA256 verify, hand-rolled ikcp RX with per-segment decrypt hook, 12B RTP parse, STAP-A/FU-A->Annex-B. ~63 unit tests + independent openssl AES KAT. Proven on SYNTHETIC vectors (self-consistent loop) — cap4 (TASK-0068) needed to validate REAL bytes + pin [G]: CBC-vs-GCM, conv ids, bare-vs-prefixed RTP. ICE = host-candidate only (STUN/TURN not impl -> follow-up).
<!-- SECTION:NOTES:END -->
