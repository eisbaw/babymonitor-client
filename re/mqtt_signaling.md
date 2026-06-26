# WebRTC-over-MQTT signaling — wire spec + MQTT-CONNECT cred finding (TASK-0069)

The implementable spec for the Tuya **302** WebRTC signaling as it actually
appears on the wire, corrected against the **cap3** plaintext capture
(`emulator_captures/cap3/signaling_plaintext.jsonl` — 11 messages logged
post-decrypt by the Frida hook), plus the recovered derivation of the Tuya MQTT
broker CONNECT credentials and the honest finding that they are **not statically
recoverable**.

> **Method / citation convention.** Native + Java claims cite a decompiled path
> (`decompiled/jadx/.../*.java:NN`, jadx-run-dependent line) or the cap3 capture.
> cap3 is GROUND TRUTH (real bytes, post-decrypt) and counts as one independent
> source alongside the static decompile. No secret value (device id / localKey /
> media key / token / TURN credential / OEM appKey-clientId) is reproduced here;
> reference `secrets/` or the gitignored capture for values. Static analysis only.

---

## 0. TL;DR

(confidence: confirmed — sources: `emulator_captures/cap3/signaling_plaintext.jsonl`
+ `decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`.)

The app negotiates the live A/V session over the device's standard Tuya MQTT
channel as message **protocol 302**. Each 302 publish is
`{data, gwId, protocol, pv, t}`, where `data` is **base64(AES-128/ECB/PKCS5(
localKey, innerJson))**. The inner JSON is `{header, msg}` — the app emits an
`offer` (SDP) over BOTH `path:"mqtt"` and `path:"lan"`, trickles `candidate`
messages over both paths, and the camera returns one `answer` (SDP) over
`path:"mqtt"`. The media AES key + ICE creds ride **in the SDP** (`a=aes-key`,
`a=ice-ufrag`/`a=ice-pwd`). This whole inner layer is implemented + byte-validated
in `babymonitor-core::stream` (`tests/signaling_cap3.rs`). The MQTT broker CONNECT password — once thought a hard
native block — is now **recovered + ported** (§4, TASK-0071): `doCommandNative(2)`
is a nested MD5 over the master key `G` + `ecode`
(`stream::mqtt_auth`). What remains live-gated is only the broker *connect* itself
(no captured CONNECT exists to diff the output against).

---

## 1. The outer MQTT 302 frame

(confidence: likely — sources:
`decompiled/jadx/sources/com/thingclips/sdk/mqtt/pbbppqb.java:399-406`
+ `emulator_captures/cap3/DECRYPT.md`. "likely" not "confirmed" because the raw
outer frame bytes were NOT captured — cap3 logged the decrypted plaintext only —
so the AES→base64→frame layer is round-trip-tested, not byte-compared.)

The publish-map builder `pbbppqb.bdpdqbp(PublishBean)` puts five keys into a
`ConcurrentHashMap<String,String>` (all values are JSON **strings**):

```
data     = <base64 ciphertext>     // AES-128/ECB/PKCS5(localKey), base64
gwId     = <devId>
protocol = "302"                   // String.valueOf(getProtocol())
pv       = <device protocol version>
t        = <unix seconds>          // String.valueOf(getT())
```

The `data` cipher is **base64 AES-ECB(localKey)**: cap3's decrypt seam is
`com.thingclips.sdk.mqtt.qpqddqd.bdpdqbp(ciphertext, localKey)` =
`AESUtil.decryptWithBase64` (`emulator_captures/cap3/DECRYPT.md` §2). This
**resolves** the previously-gated `pv → output-variant` binding for code 302 to
the **Base64** variant (it had been `Error::MqttEnvelopePending`). The cipher
itself (AES-128/ECB/PKCS5, key = localKey ASCII bytes, no IV) is pinned in
`re/webrtc_session.md` §2a and KAT-tested against `openssl enc -aes-128-ecb`.

> The inbound shape in `DECRYPT.md` is described as `{protocol, data, dataId, …}`
> (protocol as an int, a `dataId` field). Our parser is tolerant: `protocol`/`t`
> accept a JSON number or string, and unknown keys (`dataId`, …) are ignored.

Implemented: `stream::mqtt_crypto::{build_302_frame, parse_302_frame,
encrypt_302_payload, decrypt_302_payload}`.

---

## 2. The inner 302 envelope — cap3 CORRECTION of `webrtc_session.md` §2b

(confidence: confirmed — sources:
`emulator_captures/cap3/signaling_plaintext.jsonl`
+ `decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`.)

**CORRECTED.** `re/webrtc_session.md` §2b *inferred*, from native validator
strings, an envelope `{header, msg:"<sdp>", token:"…"}` — `msg` a string and a
top-level `token`. The cap3 capture shows the **real** shape is different, and
the Rust codec now matches the capture, not the inference:

```jsonc
{ "header": { "from","to","sessionid","moto_id","type",
              "trace_id","is_pre","p2p_skill","security_level","path" },
  "msg":    { "sdp": "...",              // offer/answer
              "preconnect": true,        // offer
              "token":     [ <ICE servers> ],   // STUN/TURN (was thought top-level)
              "tcp_token": { ... },             // TCP relay descriptor
              "log":       { ... } } }          // RTC-log sink
```

Key corrections vs the inference:
- The top level is **exactly `{header, msg}`** — there is NO top-level `token`.
- `msg` is an **object**, not a string. The SDP is `msg.sdp`.
- The ICE `token` (STUN/TURN array), `tcp_token`, and `log` live **inside
  `msg`**, not at the top level.
- A `candidate` message is `{header, msg:{candidate:"a=candidate:…\r\n"}}`; an
  empty `candidate` string is the end-of-candidates sentinel.
- The header carries offer-only numerics `is_pre`/`p2p_skill`(=1635)/
  `security_level`(=3) and a `path` (`"mqtt"`|`"lan"`); the device `answer`
  header adds `sub_dev_id` and is serialized with sorted keys.

`header.trace_id` is the session-correlation key the Java dispatcher keys
`mP2PMqttStateMap` on (`P2PMQTTServiceManager.handleMqttAnswer`). Implemented:
`stream::signaling::{SignalingEnvelope, SignalingHeader, SignalingMsg, IceServer,
TcpToken, ParsedAnswer}`.

---

## 3. SDP — offer / answer / candidate

(confidence: confirmed — sources:
`emulator_captures/cap3/signaling_plaintext.jsonl`
+ `re/ghidra/imm_p2p_rtc_sdp_encode.c`.)

The offer SDP (`m=application 9 imm 6001`) and answer SDP (`m=application 9 tuya
6001`) carry a single custom application section. Offer template (cap3 message 1,
reproduced byte-for-byte by `stream::sdp::build_offer_sdp` — see
`tests/signaling_cap3.rs::assert_offer_sdp_reproduces`):

```
v=0
o=- <o_session> 1 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE imm0
a=msid-semantic: WMS <sessionid>
m=application 9 imm 6001
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:<ufrag>
a=ice-pwd:<pwd>
a=ice-options:trickle
a=aes-key:<32-hex media key>      // 16-byte AES key, plaintext-in-SDP, per-session
a=mid:imm0
a=rtpmap:6001 AES/KCP <param>     // offer param 330; answer 3
a=ssrc:0 cname:<from>
```

- The media AES **key** is the prize: `a=aes-key:<hex>` = the per-session key that
  decrypts the RTP A/V (`re/webrtc_session.md` §3c; the frame cipher itself is a
  separate open item, TASK-0034/0037).
- The remote ICE creds (`a=ice-ufrag`/`a=ice-pwd`) and key are extracted from the
  **answer** by `stream::sdp::extract_ice_creds` + `extract_aes_key` and surfaced
  as `ParsedAnswer` for the media engine.
- Candidates are standard ICE lines (`typ host`/`srflx`/`relay`).

---

## 4. The MQTT broker CONNECT credentials — cmd2 RECOVERED + PORTED (TASK-0071)

(confidence: likely — sources:
`decompiled/jadx/sources/com/thingclips/sdk/mqtt/qpqbppd.java:28-152`
+ `decompiled/jadx/sources/com/thingclips/sdk/mqtt/bqbppdq.java:1900-1929`
+ `re/ghidra/doCommandNative.c:315-376` / `re/ghidra/md5_key_builder.c`.)

**CORRECTED (TASK-0071).** This section previously claimed the password was
"native-derived and cannot be reproduced statically." That is **wrong** — the
`doCommandNative(cmd=2)` transform is now recovered: it is a plain **nested MD5**
over the cached master key `G` and the per-session `ecode`, and is ported in
`babymonitor-core::stream::mqtt_auth`. The remaining gate is only the *live broker
connect* (no captured CONNECT exists to diff the output against), not the algorithm.

The IPC signaling MQTT uses `SdkMqttCertificationInfo` (`qpqbppd.java`, the
`IMqttCertificationInfo`/`pbpdpdp` impl). Its three CONNECT params:

- **clientId** (`bdpdqbp()`, `qpqbppd.java:28-33`):
  `<partnerIdentity> + "/mb/" + <uid>`.
- **username** (`qddqppb()`, `qpqbppd.java:142-152`):
  `<partnerIdentity> + "_v1_" + <mAppId> + <sep> + getChKey(<mAppId>) + "_mb_" +
  <token> + md5tail`, where `<sep>` = `ddbdpdp.bdpdqbp` = `"_"`
  (`com/thingclips/sdk/device/ddbdpdp.java:12`), `getChKey(<mAppId>)` is the
  capture-verified `sign::ch_key` (`re/chkey_static.md`), and
  `md5tail` = the **last 16 chars** of `md5AsBase64( md5AsBase64(mAppId) + ecode )`.
  `MD5Util.md5AsBase64` is — despite its name — **lowercase-32-hex MD5**
  (`MD5Util.java:576-577` → `HexUtil.bytesToHexString`), so
  `md5tail = md5_hex_lower( md5_hex_lower(mAppId) ++ ecode )[16..32]`.
- **password** (`bppdpdq()`, `qpqbppd.java:125-133`): the **middle 16 chars**
  (`length = str.length()>>1; substring(length-8, length+8)` → `[8..24]`) of
  `doCommandNative(app, 2, ecode.getBytes(), null, mD)`, where cmd2 =

  ```text
  doCommandNative(2, ecode) = md5_hex_lower( md5_hex_lower(G) ++ ecode )   // 32 lowercase-hex chars
  ```

  **cmd2 derivation (confidence: confirmed, two-source).** `re/ghidra/doCommandNative.c`
  cmd2 branch (`:315-376`) reads the `ecode` byte[] (`param_5`) and calls
  `FUN_00113474(ecode, out)` (`re/ghidra/md5_key_builder.c`). `FUN_00113474`:
  (1) `FUN_00113318(&G, out)` → `out = hex(MD5(G))`; (2) `FUN_001135d8(t, out, ecode)`
  → `t = out ++ ecode` (raw concatenation,
  `decompiled/ghidra_security/funcs/001135d8_FUN_001135d8.c`); (3) `FUN_00113318(t, out)`
  → `out = hex(MD5(t))`. `FUN_00113318`
  (`decompiled/ghidra_security/funcs/00113318_FUN_00113318.c`) hashes its input with
  the lib's 128-bit digest — finalize `FUN_001194b0` writes exactly **16 bytes**, i.e.
  **MD5** — and lowercase-hex-encodes it; it is the SAME primitive `computeDigest`
  (`re/ghidra/computeDigest.c:109`) uses, which `re/master_secret_g.md`/`sign.rs`
  already pin as "MD5 → 32-hex" (the two-source corroboration). `G` is the same cached
  master secret (`DAT_00139070`) that cmd0 assembles and cmd1 signs with.

Broker URL (`bqbppdq.java:1900-1929`): `ssl://<getMobileMqttsUrl()>:8883`, where
the host is a region domain from the login `baseConfig.getDomain()` (a
runtime/account value, not a static constant). `setCleanSession(true)`,
`setKeepAlive(60)`, QoS 1.

**What is now derivable vs still live-gated.** Given a live login we have
`ecode`/`token`/`uid`/`partnerIdentity` (`secrets/tuya_session.json`), `mAppId`
(`= appKey`), `chKey` (`sign::ch_key`) and `G` (`sign::assemble_master_key_g`) — so
all three CONNECT params are now **computable offline** by
`stream::mqtt_auth::derive_credentials`. Two honest caveats remain: (a) `G`'s
provenance still carries the same `bmp_token`-value caveat that gates the signer
(`re/master_secret_g.md` §4 — needs the recovered token to be server-confirmed);
and (b) there is **no captured MQTT CONNECT** to diff the output against — the
broker is TLS:8883 and cap3's mitmproxy is HTTP-only, so the CONNECT bytes were
NOT captured (the `clientId:` in `cap3/flows.full.txt` is the **app OEM clientId
REST param**, a different value). So the cmd2 ALGORITHM is offline-validated (vs an
independent MD5 reference + the decompile structure), but the end-to-end credential
**output** is only confirmable by the owner's live broker connect.

The Rust client injects these via `stream::transport::BrokerConfig`
(`BrokerConfig::from_credentials`), and a `live-tls` cargo feature wires rumqttc's
rustls transport for the 8883 broker. The connect is therefore ready to take the
derived creds on the live path.

---

## 5. Validated vs open

(confidence: confirmed — sources: `babymonitor/babymonitor-core/tests/signaling_cap3.rs`
+ `emulator_captures/cap3/signaling_plaintext.jsonl`.)

**Byte-validated against cap3** (`tests/signaling_cap3.rs`, runs over the real
gitignored capture when present + a committed redacted fixture):
- every cap3 message parses to the typed envelope;
- `build_offer_sdp` reproduces the captured **offer SDP byte-for-byte**;
- `parse_answer` extracts the answer's ICE ufrag/pwd + 16-byte media key;
- every message round-trips through the 302 frame codec (base64 AES-ECB
  localKey + `{data,gwId,protocol,pv,t}`).

**Round-trip-tested but NOT byte-validated against captured ciphertext** (cap3
logged decrypted plaintext only, no raw frame): the AES→base64→outer-frame layer.

**Connect orchestration WIRED, offline-validated against a mock transport**
(`stream::session::MqttSignalingSession`, TASK-0069): the engine-free, transport-
generic layer that frames+publishes the offer + trickle candidates over `mqtt`+`lan`
and decrypts+parses inbound 302 frames into `InboundSignal` (Answer / RemoteCandidate
/ Disconnect). `negotiate()` runs the full offer→trickle→answer exchange and returns
the camera `ParsedAnswer` (media aes-key + ICE ufrag/pwd + relays). The live entry
point is `stream::transport::connect_and_negotiate` (RumqttcTransport::connect →
subscribe device 302 topic → negotiate). Nine offline tests exercise publish/poll/
answer/timeout/disconnect through a fake in-memory transport with NO broker.

**Open / live-gated:**
- The actual **TLS:8883 broker connect + auth handshake** (AC#1/AC#3): the connect
  orchestration is wired (above) but never executed here — no live broker/camera in
  the sandbox, and `live-tls` (rumqttc rustls) is not in the local cargo cache, so the
  real CONNECT/auth + answer round-trip are the **owner's live run** (`--features
  live-tls`). The cmd2 CONNECT-credential derivation is **ported + offline-validated**
  (§4, TASK-0071, `stream::mqtt_auth`); residual: there is no captured CONNECT to diff
  the credential output against, and `G`'s `bmp_token` provenance caveat (§4) is shared
  with the signer.
- The RTP/SRTP **frame cipher** that consumes the SDP `a=aes-key` (TASK-0034/0037).
- The WebRTC media engine (webrtc-rs) — a follow-up; not in this build.
