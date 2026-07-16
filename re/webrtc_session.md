# WebRTC-over-MQTT Live A/V Session — Implementable Spec (TASK-0010)

> **STATUS BANNER — milestone `v0.1.0-live-stream` (2026-06-28, commit `fa930f0`).**
> The self-contained Rust client now connects to the REAL SCD921 and decodes the
> **live 1080p H.264 keyframe END-TO-END** (displayed in VLC). **The live media
> transport is NOT DTLS-SRTP / webrtc-rs SRTP.** It is a custom **ICE + KCP +
> AES-128-CBC (inline-IV, PKCS7) per segment + 20-byte HMAC-SHA1(`media_key16`) per
> datagram**, multiplexed over **conv ids** (`0`=control/auth, `1`=video, `2`=
> downstream audio — 16 kHz mono S16LE, inferred). The static native-lib recoveries
> below — §1 `connect_v2` JSON, §2 the 302 envelope, §3a–§3c the SDP encoder strings
> — remain **accurate descriptions of the lib code**, but they describe the Tuya
> SDK's **WebRTC mode**, which is **NOT the wire path this device uses for live A/V**.
> Several DTLS-SRTP / webrtc-rs claims below are superseded — each is flagged inline
> (look for "Superseded 2026-06-28, v0.1.0-live-stream"). The conv=0 media
> authorization (§5b) is the actual unblock. Sustained continuous A/V is now verified
> (TASK-0085 fixed the KCP ACK-loop starvation). Secrets remain referenced by `secrets/` location
> only.

> **LAN UPDATE — TASK-0126 (2026-07-16).** The same SCD921 now streams with
> signaling entirely over key-proven `IPC_LAN_302` frame type 32 on TCP 6668.
> The Rust client advertises a numeric LAN-local RFC 5389 responder instead of
> cloud ICE servers; the camera trickles a host candidate and media continues over
> direct ICE/KCP UDP. A fresh run succeeded under a kernel egress allowlist that
> denied every destination except loopback and the camera. This proves cloud-free
> runtime for cached paired-device metadata, not factory pairing or localKey
> recovery after reset.

The end-to-end, implementable spec for the Tuya WebRTC-over-MQTT live A/V session
the SCD921 uses, so the Rust stream client (TASK-0034) can be built against it.
This goes **deeper than** `re/streaming_mode.md` (the transport verdict + 302
envelope) and `re/p2p_triage.md` (the exported-symbol surface): those are the
inputs; this doc adds the **Ghidra control-flow recovery** of the actual native
implementation — the `connect_v2` JSON it really emits, the exact SDP it really
generates (including the AES-key line), the `imm_p2p_rtc_frame_t` struct layout
recovered from `send_frame`/`recv_frame`, and the session state machine.

> **Method.** Ghidra (`analyzeHeadless`) is the PRIMARY decompiler (user directive);
> radare2 is the cross-check. Both run over the same arm64
> `decompiled/nativelibs/libThingP2PSDK.so` (gitignored; inventoried in
> `re/native_libs.md`). Statically recovered; the live path was later validated end-to-end (v0.1.0-live-stream).
>
> **Citation convention (symbol-anchored — TASK-0024).** Native claims are
> anchored on a **demangled symbol** or a **literal string**, plus a committed
> Ghidra C dump under `re/ghidra/` (the `.c` files are committed; the `.so` is
> not). A `lib@0xADDR` is a **file offset**; Ghidra applies image base `0x100000`,
> so a file offset `0xX` appears in Ghidra as `0x10X` (e.g. file `0x60c10` →
> Ghidra `0x160c10`). Two views of one `.so` (Ghidra C + r2 of the same lib) count
> as **ONE** source per TESTING.md; `confirmed` pairs that with an independent
> source (the decompiled Java bridge in a different artifact, or a named public
> ref). A cross-`.md` reference is a navigation pointer, **not** a source.
> Line hints into the jadx tree are approximate (jadx-run-dependent); the symbol
> is authoritative.

---

## 0. TL;DR — the session lifecycle in one paragraph

(confidence: confirmed — sources: `libThingP2PSDK.so` Ghidra/r2 + the decompiled
Java `P2PMQTTServiceManager.java`; details and per-claim cites in §1–§9.)

The Rust client fetches per-device creds from the cloud device-list
(`CameraInfoBean` + `P2pConfig`: `p2pId`, `p2pKey`, `ices`, `session`, plus a
per-session `token`/`connect_session`; `re/tuya_cloud_auth.md` §5c). It issues a
`connect_v2` control message (the native lib builds the SDP **offer** locally and
emits it as a `{header,msg,token}` **302** message over the device's Tuya MQTT
channel, AES-encrypted with the device `localKey`). The device replies with an
**answer** SDP over 302; trickle-ICE **candidates** flow both ways as more 302
messages. The SDP carries standard WebRTC ICE/DTLS-SRTP attributes **plus a
Tuya-custom `m=application` section with an `a=aes-key:<hex>` line** that conveys
the media AES key.

That paragraph describes the original cloud carrier. In LAN mode the client
loads previously provisioned `devId`, sender ID, `localKey`, Hgw version, and
camera media password from its mode-0600 config; it mints the per-run SDP/ICE/media
values locally. The 302 envelope rides TCP 6668 and `msg.token` contains only the
client's numeric LAN-local STUN responder. No REST, DNS, MQTT, public STUN, or TURN
endpoint is constructed.

**(Superseded 2026-06-28, v0.1.0-live-stream — the media plane below replaces the
old "after the DTLS-SRTP handshake" claim.)** The SCD921's live A/V does **NOT**
ride a DTLS-SRTP handshake or webrtc-rs SRTP tracks. After ICE connectivity the
client opens a custom **`imm`/KCP application channel over the negotiated UDP path**
and the media flows there: **KCP**-segmented, each segment **AES-128-CBC encrypted
(inline IV, PKCS7)** and each datagram authenticated with a **20-byte
HMAC-SHA1(`media_key16`)**. Three logical streams are multiplexed by **conv id**:
`conv=0` = control/auth, `conv=1` = video (H.264), `conv=2` = downstream audio
(16 kHz mono S16LE, inferred). The media key (`media_key16`) is the SDP
`a=aes-key` value (§3c) and feeds AES-128-CBC+HMAC, **not** SRTP. **webrtc-rs
DTLS-SRTP is NOT used for media.**

The static native lib still exposes the frame plane (`recv_frame` → `imm_p2p_rtc_frame_t`),
H.264 video + G.711/Opus audio — but that is the SDK's WebRTC mode, not the live
wire path. **Verdict (Superseded 2026-06-28, v0.1.0-live-stream → now proven):** a
self-contained Rust client (custom ICE + KCP + AES-128-CBC/HMAC-SHA1 media over
`rumqttc` 302 signaling, **NO webrtc-rs media path**) decodes the live keyframe
end-to-end (§9). The runtime-gated inputs (token, p2pId/p2pKey, ices,
connect_session, localKey, and the camera password for conv=0 auth) are still
required for the cloud path — see §5b, §9. LAN runtime instead needs the cached
device/sender IDs, `localKey`, Hgw version, and camera password; the client mints
the remaining session material.

---

## 1. connect_v2 — the session-init call (confidence: confirmed)

**Native entry:** `imm_p2p_rtc_connect_v2` (file `0x60c10` / Ghidra `0x160c10`),
wrapped by the C++ export
`ThingSmartP2PSDK::thing_p2p_rtc_connect_v2(char* remote_id, char* dev_id,
char* skill, uint skill_len, char* token, uint token_len, char* trace_id,
int timeout_ms, int lan_mode)` and the JNI `ThingP2PSDK.connectV2`. Ghidra C:
`re/ghidra/imm_p2p_rtc_connect_v2.c`. Cross-checked in r2 (same function, same
call sequence — see §8).

The decompilation shows **exactly** what the native lib does with the args:

1. **Clamps `timeout_ms`**: `< 1001 → 1000`; `> 29999 → 30000`. (Ghidra lines
   30–35.) So the Rust client should pass a value in **[1000, 30000] ms**.
2. **Requires `remote_id`** (`param_1`) non-empty, else returns `-5`. `remote_id`
   is the peer/device handle.
3. **Defaults** empty `skill` (`param_3`) and empty `token` (`param_5`) to the
   literal `"{}"`. So both are JSON-ish strings; `skill` is a capability JSON
   object, `token` is the per-session signaling token (passed as `%.*s`).
4. **Defaults** empty `dev_id` (`param_2`) to `remote_id`.
5. **Generates `connect_session` itself**: `imm_p2p_misc_rand_string(&local_b0,
   0x21)` — a **33-byte (0x21) random string**, NOT supplied by the caller. (The
   C++ signature has 9 args; `connect_session` is the internally-generated
   correlation id, distinct from `trace_id`.)
6. **Builds the control JSON** into a 4096-byte buffer
   (`re/ghidra/imm_p2p_rtc_connect_v2.c` lines 75–78), format string verified
   byte-identical in Ghidra **and** r2 (`izz`, file `0x11759a`):

```json
{"cmd":"connect_v2","args":{"remote_id":"%s","dev_id":"%s","skill":%.*s,"token":%.*s,"trace_id":"%s","timeout_ms":%d,"lan_mode":%d,"preconnect_enable":1,"connect_session":"%s"}}
```
   Note `skill` and `token` are emitted **unquoted** (`%.*s` → raw JSON), so
   `skill` must be a JSON object/value and `token` likewise. `preconnect_enable`
   is hard-coded `1`.
7. **Pushes the message onto the internal queue** (`bc_msg_queue_push_back(...,1,
   buf,len)`) and waits for a result keyed by the generated `connect_session`
   (`FUN_0016011c(ctx,&local_b0,&local_1150)`), then logs
   `connect_v2: try connect to %s, token: %.*s`. On error it calls
   `imm_p2p_rtc_close(session,0)`.

**Variants** (r2 `izz`, confirmed strings):
- `connect_v3` (`0x117668`): drops inline `skill`, adds a `preconnect_enable:%d`
  arg (so v3 lets the caller toggle preconnect). Ghidra:
  `re/ghidra/imm_p2p_rtc_connect_v3.c`.
- `connect` (v1, `0x117500`): no `dev_id`/`skill`.
- `pre_connect` / `pre_connect_v2` (`0x11737f` / `0x117419`): warm-up, carry
  `remote_id`/`dev_id`/`connect_session` (+ `token` in the v2 form).
- `set_remote_online` (`0x117dd3`): `{"cmd":"set_remote_online","args":{"remote_id":"%s"}}`
  — tells the SDK the peer is online so it (re)sends the offer. Ghidra:
  `re/ghidra/imm_p2p_rtc_set_remote_online.c`.

### 1a. connect_v2 arg sources — which are runtime/auth-gated

(confidence: confirmed for the field→bean mapping; two independent sources — the
native arg consumption in `libThingP2PSDK.so` (`imm_p2p_rtc_connect_v2`) and the
Java bean `decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/bean/CameraInfoBean.java`
(`p2pId`/`P2pConfig.p2pKey`/`ices`/`session`).)

| `connect_v2` arg | Source | Runtime/auth-gated? |
|---|---|---|
| `remote_id` | the P2P device handle = `CameraInfoBean.p2pId` (IOTC UID) | **YES** — per-device, from the cloud device-list (auth-gated) |
| `dev_id` | the Tuya `devId` (the cloud device id) | **YES** — from the device-list |
| `skill` | `CameraInfoBean.skill` (capability JSON: `videos[]`/`audios[]`/`p2p`/`webrtc`) | **YES** — per-device cloud record |
| `token` | the per-session signaling token | **YES** — issued per-session by the cloud (NOT a static constant; `re/tuya_cloud_auth.md` §7) |
| `trace_id` | session correlation id; echoed in every 302 `header.trace_id` | client-generated per session (free to choose; UUID-shaped) |
| `timeout_ms` | client choice, clamped [1000,30000] | client constant |
| `lan_mode` | 0 = signal via cloud MQTT, 1 = signal via LAN | client choice (use 0 for remote) |
| `connect_session` | **generated inside the native lib** (33-byte rand) | N/A for the Rust client to mint — but the Rust client must mint its OWN, since it re-implements the native side; treat as a fresh random per session |

The media-key/relay creds (`P2pConfig.p2pKey`, `ices`, `session`,
`tcpRelay`/`udpRelay`) are NOT `connect_v2` args — they feed the SDP/ICE/DTLS
machinery (§3). `p2pKey`/`session` are secrets; `ices` are the ICE server
endpoints. **All are auth-gated** (per-account device-list call). None are in the
APK; the SDK only ships a demo bean (`re/tuya_cloud_auth.md` §5c, secret-free).

---

## 2. The MQTT 302 signaling envelope (confidence: confirmed)

Two independent sources: the native validator strings + cJSON parse in
`libThingP2PSDK.so`, AND the decompiled Java parser
`P2PMQTTServiceManager.handleMqttAnswer` /
`P2PMQTTServiceManager.send302MessageThroughMqtt`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`).

### 2a. Carrier

(confidence: confirmed — two sources: the native upcall in `libThingP2PSDK.so`
(`SendMessageThroughMQTT`) and the Java publisher
`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`.)

The carrier is the device's standard Tuya MQTT channel, **message code 302** (not a
dedicated WebRTC topic). `P2PMQTTServiceManager`:
- **Outbound, cloud:** `homeCamera.publish(devId, pv, localKey, jsonMsg, 302, cb)`
  — AES-encrypted with the device **`localKey`** at protocol version `pv`.
- **Outbound, LAN (`lan_mode=1`):** `homeCamera.lan302Publish(devId, jsonMsg, cb)`.
- **Inbound:** `registerMqtt302(cb)` → `homeCamera.registerCameraP2P302Listener`.

**The 302-payload AES cipher IS statically pinned** (a prior claim in
`babymonitor-core` that the mode was "not statically pinnable / runtime
`AESUtil.ALGO`" was FALSE — corrected by reading the decompile). Evidence:
- `decompiled/jadx/sources/com/thingclips/sdk/mqtt/qpqddqd.java`:
  `aESUtil.setALGO("AES")` (`:133`, `:234`, `:632`) — a **CONSTANT string `"AES"`**,
  not a runtime numeric mode — then `aESUtil.setKeyValue(str.getBytes())`
  (`:134`/`:235`/`:633`): the key is the **ASCII bytes of the `localKey` string**
  (16 bytes). Output is chosen by the publish bean: `encrypt(data)` (`:136`),
  `encryptWithBase64(jSONString)` (`:237`), or `encryptWithBytes(jSONString)` (`:635`).
- `decompiled/jadx/sources/com/thingclips/smart/android/common/utils/AESUtil.java`:
  `Cipher.getInstance(this.ALGO)` with `ALGO=="AES"` (`:526` encrypt, `:329` decrypt)
  ⇒ the JCE default transformation **`AES/ECB/PKCS5Padding`**; `cipher.init(1/2,
  key)` (`:527`/`:330`) with **NO `IvParameterSpec` ⇒ no IV (ECB)**; key =
  `new SecretKeySpec(this.keyValue, this.ALGO)` (`:189`). `encrypt()` returns
  **UPPERCASE** hex via `byte2hex` (`.toUpperCase()`, `:64`/`:528`);
  `encryptWithBase64` returns base64 (`:586`); `encryptWithBytes` returns raw bytes
  (`:593`).

So the cipher = **AES-128 / ECB / PKCS5(=PKCS7) padding, key = `localKey` (16 ASCII
bytes), NO IV**; output = hex (upper) | base64 | raw by the publish variant. This
is implemented + KAT-tested in `babymonitor-core::stream::mqtt_crypto`
(`aes128_ecb_encrypt`/`aes302_encrypt`, vector checked against `openssl enc
-aes-128-ecb`).

**What GENUINELY remains live-gated (residual, not the cipher):** (1) the **`pv` →
output-variant binding** for message code 302 — which of `encrypt`/
`encryptWithBase64`/`encryptWithBytes` a 302 publish uses at a given `pv` — and (2)
the **outer Tuya MQTT envelope framing** around the AES payload. There is no
offline oracle / captured live 302 to pin those, so they stay gated
(`Error::MqttEnvelopePending`); see §9.

The native side hands the JSON to Java via
`ThingSmartP2PSDK::SendMessageThroughMQTT(char* target, char* jsonMsg, uint len)`
(Ghidra `re/ghidra/ThingSmartP2PSDK_Initialize.c` callback `on_msg`, and
`re/ghidra/ThingSmartP2PSDK_SendMessageThroughMQTT.c`): it `CallStaticVoidMethod`s
a Java static with `(target, jsonMsg)` — i.e. **native builds the JSON, Java
publishes it on 302**. The Rust client collapses both halves: it builds the JSON
itself and publishes on 302 via `rumqttc`.

### 2b. Envelope schema (the bytes the Rust MQTT client implements)

The signaling **message** carried inside each 302 publish is:

```jsonc
{
  "header": {
    "type":      "offer" | "answer" | "candidate" | "disconnect",  // native validators: "type: sdp" / "type: candidate"
    "from":      "<sender device/user id>",     // Java: header.getString("from")
    "to":        "<recipient id>",
    "sessionid": "<session id>",                // a.k.a. connect_session correlation
    "trace_id":  "<trace id>",                  // Java: header.getString("trace_id") — the session key in mP2PMqttStateMap
    "moto_id":   "<media-server id>"            // present in Tuya IPC ref; NOT a CameraInfoBean field in THIS app (see note)
  },
  "msg":   "<SDP string | ICE candidate string>",   // native: "no msg field" validator
  "token": "<per-session signaling token>"          // native: "no token field" validator
}
```

**Field provenance:**
- `header`, `msg`, `token` are the three **required** top-level fields — native
  validators `invalid signaling: invalid json, no header field` / `… no msg field`
  / `… no token field` (string-grep of `libThingP2PSDK.so`, confirmed).
- `header.type` values: native validators `invalid signaling: type: sdp`,
  `… type: candidate`, `… type: handle or seq`. Java reads `header.getString("type")`
  and compares to `"offer"` and `"answer"` (`handleMqttAnswer` ~:1057, ~:1074).
  So **offer/answer carry an SDP in `msg`; candidate carries an ICE candidate
  line in `msg`**.
- `header.trace_id` + `header.from` are read by name in Java
  (`P2PMQTTServiceManager` ~:994–995, ~:1056). `trace_id` is the **session
  correlation key**: the inbound dispatcher keys `mP2PMqttStateMap` on it and
  only accepts an `offer` for a new `trace_id` (~:1056–1057).
- `moto_id`: present in the public Tuya IPC signaling ref (`seydx/tuya-ipc-terminal`)
  but **NOT a field of `CameraInfoBean`/`DeviceBean` in this app** — a whole-tree
  grep returns no hit (`re/tuya_cloud_auth.md` §5c). For the SCD921 the media-server
  routing handle is `p2pId` + the `session`/relay descriptors, so a live capture is
  needed to confirm whether `moto_id` appears on this device's wire (residual, §9).

### 2c. Inbound dispatch (the Rust client's receive path)

`registerMqtt302` → on each inbound 302, parse `header.type`:
- `answer` → feed `msg` (the answer SDP) to the local peer connection
  (native: `thing_p2p_rtc_set_signaling(from, msg, len)` →
  `re/ghidra/imm_p2p_rtc_set_signaling.c` → `imm_p2p_rtc_sdp_decode`).
- `candidate` → add the remote ICE candidate
  (native: same `set_signaling`, type=candidate → `imm_p2p_ice_session_add_remote_candidate`).
- the client emits its own `offer` first and then trickles its own `candidate`s as
  ICE gathering completes.

---

## 3. SDP, ICE, DTLS-SRTP — standard WebRTC vs Tuya-custom (confidence: confirmed)

**Native SDP builder:** `imm_p2p_rtc_sdp_encode(sdp_ctx, "offer"|"answer", out_buf,
out_len)` (file `0x73ed8` / Ghidra `0x173ed8`). Ghidra C:
`re/ghidra/imm_p2p_rtc_sdp_encode.c`. This is the **exact SDP the device
generates** — recovered format strings, not inference. Cross-checked in r2 (the SDP
attribute strings, §8).

### 3a. Session-level (standard WebRTC)
```
v=0
o=- <unix_time> 1 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE<mids>
a=msid-semantic: WMS <stream>
```

### 3b. m=audio / m=video sections (standard WebRTC — webrtc-rs handles all of this)
For each media section the encoder emits:
```
m=<audio|video> 9 <RTP/SAVPF> <pts>
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:<ufrag>
a=ice-pwd:<pwd>
a=ice-options:trickle
a=fingerprint:<dtls fp>
a=setup:<actpass|active|passive>     // sdp_ctx+0x430: 1=active, 2=passive, else actpass
a=mid:<mid>
a=<sendrecv|sendonly|recvonly|inactive>   // direction, sdp_ctx+0x480/0x560 indexed into a 4-ptr table
a=msid:<stream> <track>
a=rtcp-mux
a=rtpmap:<pt> <codec>/<clock>        // audio: PCMU/8000 (G.711); video: H264/90000
// video adds feedback + fmtp:
a=rtcp-fb:<pt> ccm fir
a=rtcp-fb:<pt> nack
a=rtcp-fb:<pt> nack pli
a=fmtp:<pt> level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=<hex>
a=rtpmap:<rtx_pt> rtx/90000           // when RTX enabled (sdp_ctx+0x55c == 2)
a=fmtp:<rtx_pt> apt=<pt>
a=ssrc-group:FID <ssrc> <rtx_ssrc>    // RTX present → FID group
a=ssrc:<ssrc> cname:<cname>
```
Codecs confirmed via strings: **`H264`** and **`PCMU`** (the SDP-negotiated audio
codec is G.711 µ-law); the camera-level `skill` also advertises Opus/H265 (the
media codecs), but the WebRTC m-line audio codec in the encoder is PCMU. This SDP
shape is **vanilla WebRTC** as emitted by the SDK's encoder, and webrtc-rs could
build equivalent SDP. Confidence: confirmed (the format strings are literal in
Ghidra and r2). **(Superseded 2026-06-28, v0.1.0-live-stream as the live path:**
the `m=audio`/`m=video` SRTP tracks these strings describe are **present in the
native lib but NOT the path the SCD921 uses for live A/V** — the live frames ride
the `imm`/KCP AES-CBC+HMAC channel (§3c/§3d/banner), not SRTP. This section stays as
an accurate record of the lib's WebRTC mode.)**

### 3c. m=application section — the Tuya-custom `imm` codec + the MEDIA AES KEY
(confidence: confirmed — two sources: `libThingP2PSDK.so` `imm_p2p_rtc_sdp_encode`
+ the `imm_p2p_rtc_sdp_set_aes_key`/`_get_aes_key` pair (Ghidra + r2 both show the
`a=aes-key:%s` string and the `sdp_ctx+0x86` buffer), and the named public Tuya
WebRTC ref `tuya-ipc-terminal` which documents the same Tuya SDP/AES media key.)

The encoder emits a **third media section** (Ghidra lines 534–595, the `imm` branch):
```
m=application 9 <fmt> <pts>
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:<ufrag>
a=ice-pwd:<pwd>
a=ice-options:trickle
a=aes-key:<hex>            // <-- THE MEDIA AES KEY, plaintext-in-SDP
a=mid:<mid>
a=rtpmap:<pt> <imm-codec> <param>
a=ssrc:<ssrc> cname:<cname>
```
The `a=aes-key:%s` line (string at file `0x11ac06`, confirmed in both Ghidra and
r2) emits `sdp_ctx + 0x86` — the buffer that `imm_p2p_rtc_sdp_set_aes_key` /
`_get_aes_key` write/read. Those two functions
(`re/ghidra/imm_p2p_rtc_sdp_set_aes_key.c` / `…_get_aes_key.c`) hex-encode/decode
a raw key of up to **23 bytes** (`param_3<<1 < 0x30`, i.e. `len*2 < 48`) at
`sdp_ctx+0x86`, as ASCII hex. **This is the F3 "key carried in SDP" hypothesis,
now CONFIRMED by decompilation:** the media AES key is conveyed **in the SDP**
(the `imm`/application m-section), not derived from a DTLS exporter. A single
capture of the offer/answer 302 messages yields the media key directly — and
**(Superseded 2026-06-28, v0.1.0-live-stream)** this has been captured: the
`a=aes-key` value is the **`media_key16`** that feeds **AES-128-CBC (inline IV,
PKCS7) + per-datagram 20-byte HMAC-SHA1**, the live media crypto (§3d/banner),
**not** SRTP.

> Implication for Rust (Superseded 2026-06-28, v0.1.0-live-stream — now the proven
> path): the `a=aes-key` line and the `m=application`/`imm` codec are
> **Tuya-custom**. webrtc-rs will not produce or parse them; the Rust client must
> (a) emit the `aes-key` it chose into its offer's application section, and (b) read
> the peer's `aes-key` (= `media_key16`) from the answer's application section, then
> apply that key to the `imm`-codec media. **RESOLVED:** the proprietary `imm`/KCP
> AV transport rides the negotiated ICE/UDP pipe **instead of** (not alongside) the
> standard SRTP tracks — the live frames come over `imm`/KCP, and the SRTP tracks
> are not the path this device uses.

### 3d. ICE / DTLS-SRTP (standard WebRTC, webrtc-rs handles)
- **ICE:** `imm_p2p_ice_session_create` + `…_add_remote_candidate` +
  `…_add_remote_userinfo` + `…_get_handshake_info`; trickle via `a=ice-options:trickle`
  and the `candidate` 302 messages. In cloud mode STUN/TURN endpoints come from
  runtime `P2pConfig.ices` (and `tcpRelay`/`udpRelay`) — confirmed by the runtime error
  `Invalid STUN server or server not configured (IMM_P2P_ESTUNINSERVER)`: the
  servers are **not static**, they are configured at session setup from the cloud
  `ices` list. In LAN mode, Ghidra
  `re/ghidra/ice_gather_from_tokens.c` (`libThingP2PSDK.so@0x152108`) proves an
  empty token list creates no camera ICE socket and that a numeric STUN entry
  creates the socket before emitting host candidates. The authorized TASK-0126
  frame-32 run independently live-proved the resulting host-candidate trickle;
  Java's LAN frame-32 carrier is independently visible in
  `decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`.
  The camera sent zero Binding queries in those runs; RFC 5389
  Binding/XOR-MAPPED response behavior is only loopback/unit-proven, and camera
  srflx media selection remains unproven.
  (confidence: confirmed for token→socket→host candidate; bounded as stated for
  Binding/srflx.)
- **DTLS-SRTP:** bundled **static mbedTLS** inside `libThingP2PSDK.so`
  (`mbedtls_ssl_conf_dtls_srtp_protection_profiles`, cert `CN=Cert,O=WebRTC,C=US`,
  `imm_p2p_misc_generate_cert`/`_calculate_cert_fingerprint`). The fingerprint is
  emitted as `a=fingerprint`. This is standard DTLS-SRTP code that webrtc-rs could
  speak. **(Superseded 2026-06-28, v0.1.0-live-stream:** this DTLS-SRTP path is
  **present in the native lib but NOT the path the SCD921 uses for live A/V.** The
  live media rides the `imm`/KCP AES-CBC+HMAC channel below, not SRTP. The code is
  recorded here as an accurate lib description only.)**
  (`re/native_libs.md` headline + p2p_triage §1c.)
- **Reliable data plane — THE ACTUAL MEDIA TRANSPORT** (Superseded 2026-06-28,
  v0.1.0-live-stream — promoted from "only if using imm" to the proven path):
  strings reveal **KCP** pacing (`kcp pacing ...`) and an ARQ/NACK layer
  (`handle nack %d failed: rtx budget limited`) on top of the UDP transport — Tuya's
  reliability for the `imm` data path. **This `imm`/KCP path IS the live A/V
  transport** the SCD921 uses (not SRTP). On top of KCP: each segment is
  **AES-128-CBC encrypted (inline IV, PKCS7)** and each datagram carries a **20-byte
  HMAC-SHA1(`media_key16`)**; streams are multiplexed by **conv id** (`0`=control/
  auth, `1`=video, `2`=downstream audio). This is **Tuya-custom**; see §4 and §5b.

---

## 4. AV frame delivery — `imm_p2p_rtc_frame_t` + recv_frame (confidence: confirmed)

**Entries:** `imm_p2p_rtc_recv_frame(int session, imm_p2p_rtc_frame_t* frame)`
(file `0x62ad8`) and `imm_p2p_rtc_send_frame(int, imm_p2p_rtc_frame_t*)`
(file `0x626b8`). Ghidra C: `re/ghidra/imm_p2p_rtc_recv_frame.c`,
`re/ghidra/imm_p2p_rtc_send_frame.c`.

### 4a. `imm_p2p_rtc_frame_t` — reconstructed struct
Recovered from the field offsets the two functions (`imm_p2p_rtc_send_frame` /
`imm_p2p_rtc_recv_frame` in `libThingP2PSDK.so`) read/write on `param_2`
(confidence: likely — single-lib source (the two frame functions of one `.so`);
offsets 0x00/0x08/0x0c/0x10/0x20 are directly read in the code, the field at 0x18
is inferred from the recv timestamp write):

```c
typedef struct imm_p2p_rtc_frame_t {   // 0x28 bytes used
    /* 0x00 */ void*    payload;     // data pointer (memcpy src in send; dst in recv: *param_2)
    /* 0x08 */ uint32_t capacity;    // buffer capacity passed IN to recv (*(uint*)(param_2+1))
    /* 0x0c */ uint32_t length;      // filled length OUT (recv writes; send reads) — *(uint*)((char*)p+0xc)
    /* 0x10 */ uint64_t pts;         // presentation timestamp (recv writes from RTP ts >>3 & 0x1fffffff)
    /* 0x18 */ uint64_t dts;         // recv writes same value as pts (param_2[3])
    /* 0x20 */ uint32_t type;        // frame type: 0=audio; 1=video non-key; 2=video KEYFRAME boundary
                                     //   (send_frame: type==0 → audio list; type!=0 → packetized video;
                                     //    type==2 toggles the keyframe/marker state, plVar10[0xc45])
    /* 0x24 */ uint32_t _pad;
} imm_p2p_rtc_frame_t;
```
> Caveat (likely): the **exact codec-id enum** for `type` beyond
> {audio=0, video, keyframe=2} is not named in these two functions; the
> audio-vs-video split and the keyframe meaning are directly readable from the
> branch logic. A field naming the codec (H264 vs Opus) is not visible in
> `recv_frame` — the codec is implied by which list (audio vs video) the frame
> came from. The committed Ghidra files are the source of truth for the offsets.

### 4b. recv path
(confidence: likely — single-lib source: `libThingP2PSDK.so`
`imm_p2p_rtc_recv_frame`, shown by Ghidra and r2 (two views of one `.so` = ONE
source); the session-state enum matches `imm_p2p_rtc_send_frame` /
`imm_p2p_rtc_recv_data` of the same lib.)
`recv_frame` (Ghidra `re/ghidra/imm_p2p_rtc_recv_frame.c`):
1. Validates `frame->payload != NULL && frame->capacity != 0`, else returns 0.
2. Looks up the session in the session list (`ctx+0x43e0`) by id; rejects with
   `-0xb` "invalid session" if absent or state != active.
3. **Session state gate** (the `switch` on `plVar7+0x1a` = the `rtc_state` enum):
   the frame path **proceeds on state 0** (only if sub-flags `+0xd4==0` and
   `+0x1b==0`) and **state 5** (via the `-100 - x` path); **state 3 returns error
   `-0x13`** (the init value — no frame delivered), and other states map to error
   codes (state 4 → `-0xe`, 0xb → `-0x29`, 0xc → `-0x17`, 0x10 → `-0x1f`, 0x11 →
   `-0x1e`). This is the same state enum used by send_frame/recv_data.
   (confidence: likely — REVIEW-CORRECTED: an earlier draft wrongly listed state 3
   as the data-flow state; per `recv_frame.c:46-60` / `send_frame.c:45-59` the
   frame pop/push is reached from case 0/5, not case 3. The human-readable
   `on_state=active` name vs this numeric enum value needs a live capture to pin.)
4. Pops a frame from `imm_p2p_rtc_audio_frame_list_pop_front` (this branch is the
   **audio** path), copies the payload (`memcpy` from `frame_buf + 0x18 + 0x1c +
   0x48`, i.e. past the RTP header), sets `frame->length`, `frame->type=0`, and
   `frame->pts = frame->dts = imm_p2p_rtp_get_timestamp(buf+0x48) >> 3 &
   0x1fffffff` (RTP timestamp → presentation ts). Frees the pooled buffer.
   The **video** path is symmetric via `imm_p2p_rtc_frame_list_*` /
   `imm_p2p_rtc_frame_list_get_current_frame`
   (`re/ghidra/imm_p2p_rtc_frame_list_get_current_frame.c`).

So **audio and video are delivered as separate frame lists** behind a single
`recv_frame` call, each frame a decoded-payload-ready unit (RTP de-paid by the
native side, payload past the 0x48-byte RTP header). The Rust client over webrtc-rs
instead receives RTP packets on the SRTP tracks and must de-packetize itself
(webrtc-rs gives RTP; H.264 NAL reassembly via the standard depacketizer; the
native `imm_p2p_h264_packetize_*` functions are the **send-side** packetizer,
mirror them for receive). Ghidra: `re/ghidra/imm_p2p_h264_packetize.c`.

### 4c. send path (two-way talk / video talk)
(confidence: likely — single-lib source: `libThingP2PSDK.so`
`imm_p2p_rtc_send_frame` (Ghidra + r2 = one `.so`).)
`send_frame` (Ghidra `re/ghidra/imm_p2p_rtc_send_frame.c`):
- `frame->type == 0` (audio): allocates a pooled packet, writes an RTP header
  (seq from `rand()`, ts advanced by `len * 0x7d` per the 8kHz/G.711 pacing),
  copies payload, pushes to the audio frame list. This is **outbound talk audio**.
- `frame->type != 0` (video): `imm_p2p_rtc_packetized_frame_create` (H.264
  packetize) then pushes to the video frame list; `type==2` marks a keyframe/IDR
  boundary. This is **outbound video talk** (the SCD921 is a one-way cam for live
  view, but the API supports send for two-way video on capable devices).

### 4d. Codecs the Rust client needs (confidence: confirmed for the codec identities)
- **Video: H.264** (OpenH264 / Cisco `CWelsDecoder`, build tag
  `1.5.0-Philips620.3`; `re/native_libs.md`, `re/p2p_triage.md` §3). Decode with an
  `openh264`/`ffmpeg`-backed Rust crate. Packetization-mode 1 (per the `a=fmtp`).
- **Audio: G.711 µ-law (PCMU)** at the SDP/RTP layer (confirmed string), and
  **Opus** for the higher-quality two-way talk path (`libopus.so` / `libopusJni.so`,
  Tuya audio engine; `re/native_libs.md`). Decode with `audiopus`/`opus` +
  a G.711 decoder.

---

## 5. Session state machine (confidence: likely)

(single-lib source: the `rtc_state` switch in `libThingP2PSDK.so`
`imm_p2p_rtc_recv_frame` / `imm_p2p_rtc_send_frame` / `imm_p2p_rtc_recv_data`
(Ghidra + r2 = one `.so`); the numeric gate is directly present in the disassembly,
the human-readable state names are inferred.)

The `rtc_state` enum (the `switch` value at session-struct offset `0x1a`, used
identically in recv_frame / send_frame / recv_data) gates all data transfer.
Recovered numeric cases:

| state | recv/send behavior | inferred meaning |
|---|---|---|
| 0 | **proceeds** (data flows) if sub-flag `+0xd4==0` and `+0x1b==0` | active data-transfer (sub-flags clear) |
| 3 | returns `-0x13` (no frame) | NOT a data-flow state (review-corrected) |
| 4 | `-0xe` | closing/closed |
| 5 | **proceeds** (data flows) via `-100 - x` path | active data-transfer / (re)negotiating |
| 0xb | `-0x29` | error (auth?) |
| 0xc | `-0x17` | error |
| 0x10 | `-0x1f` | error |
| 0x11 | `-0x1e` | error |

The **Initialize 3-callback contract** drives the state machine from the host
(`re/ghidra/ThingSmartP2PSDK_Initialize.c`,
`_ZN16ThingSmartP2PSDK10Initialize…`):
- `on_msg(bool byLan, char* target, char* jsonMsg, uint len)` — **signaling send**
  (the lib calls this to emit a 302 message; the Rust client publishes it on MQTT).
- `on_https(char*, char*, char*, uint) -> int` — an HTTPS request callback (used
  for fetching runtime config / relay creds).
- `on_state(char* id, int, int, rtc_state, rtc_active_state_e, int)` — **session
  state change** (the host learns connect/active/close transitions).

Driver sequence the Rust client implements **(Superseded 2026-06-28,
v0.1.0-live-stream — the tail "DTLS-SRTP handshake → on_state=active → recv_frame
loop" is replaced by the proven `imm`/KCP path):**
`init → (optional pre_connect) → connect_v2 [builds+sends offer via on_msg] →
recv answer (302) [set_signaling] → trickle candidates both ways (302) →
ICE connectivity`. The real ICE behaviors the live client needs (live-validated):
the client **binds the media UDP socket early**, **trickles its own host
candidate**, uses **NO USE-CANDIDATE** flag, and **tolerates ICMP ECONNREFUSED** on
the media path. There is **no DTLS-SRTP handshake**. After ICE comes the
**`conv=0` media-start** (AUTH + VERSION + 3 cmd PDUs — see §5b) and then **`conv=1`
video** (H.264) over KCP + AES-128-CBC/HMAC-SHA1. (The native `recv_frame`/
`send_frame` data path — the SDK's WebRTC mode — still gates on the internal
frame-transfer states **0/5**, not 3 — see the state-gate note above; it is not the
live wire path.)
(confidence: likely — the call set is directly present in the
`Initialize` callback contract + the cmd builders of `libThingP2PSDK.so`; the
precise inter-leaving of candidate vs answer timing needs a live capture, §9.)

### 5b. conv=0 media-channel authorization + media-start order (the actual unblock)

(Added 2026-06-28, v0.1.0-live-stream. This is the conv=0 control/auth handshake
that the old implicit "DTLS-SRTP = auth" model missed. **Supersedes** the assumption
that ICE+DTLS-SRTP alone unlocks the stream.)

Once ICE connectivity is up, the live A/V is gated by an **application-level
authorization on `conv=0`**, sent over the `imm`/KCP channel and **suite-3 sealed**
(AES-128-CBC inline-IV/PKCS7 + 20-byte HMAC-SHA1(`media_key16`)). Sending nothing —
or sending the wrong credential — makes the camera tear down `conv=0` (total KCP
silence); the correct blob makes it accept auth and begin streaming. This was the
final unblock for the keyframe path.

**Auth credential** (confidence: live-validated, not byte-verified):
- `username` = the constant **`"admin"`**.
- `password` = **`md5_hex_lower( <camera password> ++ "||" ++ <localKey> )`** — a
  32-char lowercase-hex string. Separator is the literal `"||"`. The
  **lowercase-hex** encoding is **INFERRED** (the `HexUtil.a` body did not survive
  decompile) but **live-validated** (the derived value is accepted; the raw camera
  password is rejected). Evidence: jadx `IPCThingP2PCamera.connect` (the username/
  password/separator construction) + `chaos::MD5Utils.b` = `HexUtil.a(MD5(...))`.
  Rust: `control::derive_media_auth_password()` + the `media_auth_args()` seam in
  `stream_live.rs`. The camera password and `localKey` are secrets — referenced by
  `secrets/` location only; **no derived MD5 value is written here.**

**Native blob builder** (confidence: confirmed offsets):
`C++ ThingNetProtocolManager::SendAuthorizationInfo @002c8028` builds a **104-byte
blob**: `magic@0 = 0x12345678`, `reqId@4`, `username@8` (`strncpy 0x1f`),
`password@0x28` (`strncpy 0x3f`). Sent as `conv=0` `sn=0`.

**Media-start order** (confidence: confirmed from cap4; reqId values likely):
all PDUs are CONTIGUOUS on `conv=0` and suite-3 sealed:
1. `AUTH` — `sn=0`, 104 B (the blob above, `SendAuthorizationInfo @002c8028`).
2. `VERSION` — `sn=1`, 24 B = `SendCommand(0, 10, 0, {0x00010000})`.
3. three cap4 command PDUs — `sn=2,3,4`: commands `(9,0)`, `(6,0)` ("open video"),
   `(6,4)`.

`SendCommand` builder `@002c5e54`: `@0` magic `0x12345678`, `@4` reqId (MEDIUM
confidence — captured values 4,3,5 are non-monotonic and unexplained), `@8`
direction (`0`=app cmd / `1`=camera resp), `@0xc = (low_cmd<<16)|high_cmd`, `@0x10`
payload-len, `@0x14` payload. After this, the camera opens **`conv=1`** (video).
conv id map: `0`=control/auth, `1`=video, `2`=downstream audio (16 kHz mono S16LE,
inferred).

---

## 6. Two-way talk + camera control (brief, for later parity) (confidence: likely)

- **Talk audio out:** `send_frame(type=0)` (§4c) → RTP/G.711 or Opus on the
  outbound media track. Higher level: `ThingCameraNative_startAudioTalk` /
  `sendAudioTalkData` / `stopAudioTalk` (`re/p2p_triage.md` §2,
  `libThingCameraSDK.so`).
- **Video talk out:** `send_frame(type!=0)` + `startVideoTalk` /
  `startSendVideoTalkData`.
- **Camera control (PTZ / nightlight / etc.):** NOT over the WebRTC media path —
  these are **MQTT DP (datapoint) writes** on the device's standard control
  channel (the Tuya control plane, `re/js_bundle_map.md` `TUNIMQTTManager`),
  separate from the 302 signaling. Out of this task's scope; modeled in the control
  feature tasks.

---

## 7. Standard-WebRTC vs Tuya-custom — the implementation split

(confidence: confirmed — the split is grounded in two sources: the native SDP/ICE/
DTLS machinery of `libThingP2PSDK.so` (§3, Ghidra+r2) and the named public Tuya
WebRTC ref `tuya-ipc-terminal` (same 302 + SDP architecture).)

| Piece | Standard WebRTC (webrtc-rs handles) | Tuya-custom (Rust client must add) |
|---|---|---|
| SDP session/audio/video sections (§3a/3b) | ✅ webrtc-rs builds/parses | — |
| ICE (gather/connectivity/trickle) | ✅ | ICE servers come from runtime `P2pConfig.ices` (inject) |
| DTLS-SRTP handshake + SRTP | ❌ NOT used by SCD921 for live A/V (mbedTLS DTLS-SRTP is present in the native lib but the device streams over `imm`/KCP instead — Superseded 2026-06-28, v0.1.0-live-stream) | — |
| H.264 frame decode | ❌ no SRTP RTP path on this device | **H.264 arrives over `imm`/KCP (conv=1), AES-128-CBC-decrypted; reassemble + decode with an `openh264`/`ffmpeg` crate (NOT webrtc-rs RTP) — Superseded 2026-06-28, v0.1.0-live-stream** |
| **Signaling transport** | ❌ | **MQTT 302 `{header,msg,token}` envelope (§2), via rumqttc** |
| **`connect_v2`/`set_remote_online` control JSON** | ❌ | **emit the cmd JSON (§1) — but only if talking to the device's native SDK; if peering directly via SDP it's the offer that matters** |
| **`m=application` + `a=aes-key` + `imm` codec** (§3c) | ❌ | **parse/emit the application m-section; apply the SDP-carried AES key to the imm media** |
| **KCP/imm — THE ACTUAL MEDIA TRANSPORT** (§3d/§5b) | ❌ | **Tuya-custom; this IS the live media transport (Superseded 2026-06-28, v0.1.0-live-stream — promoted from "only if using imm"). KCP segmentation/ARQ + per-segment AES-128-CBC (inline IV, PKCS7) + per-datagram 20-byte HMAC-SHA1(`media_key16`); conv-multiplexed (0=auth, 1=video, 2=audio)** |
| **conv=0 media authorization** (§5b) | ❌ | **`username="admin"` + `password = md5_hex_lower(camera_pw ++ "\|\|" ++ localKey)` 104-byte blob (`SendAuthorizationInfo @002c8028`) then VERSION + 3 cmd PDUs (`SendCommand @002c5e54`), all suite-3 sealed — the actual unblock (Added 2026-06-28, v0.1.0-live-stream)** |
| 302 payload AES (localKey) | ❌ | **DONE — AES-128/ECB/PKCS5, key=localKey, no IV (recovered §2a; impl `mqtt_crypto::aes128_ecb_encrypt`, KAT vs openssl)** |
| 302 `pv`→output-variant binding + outer MQTT framing | ❌ | **live-gated residual — which of hex/base64/raw a 302 publish uses + the envelope framing need a live 302 capture (`Error::MqttEnvelopePending`)** |

---

## 8. Ghidra-vs-r2 cross-check (confidence: likely — no divergence)

(single-lib cross-check: Ghidra and r2 over the same `libThingP2PSDK.so` are two
views of ONE source per TESTING.md; this section reports their agreement, not an
independent corroboration. The independent corroboration of the *protocol* lives
in §1–§4 via the Java bridge and the public refs.)

Both tools ran over the same `decompiled/nativelibs/libThingP2PSDK.so`.

- **`connect_v2`** (Ghidra `0x160c10` / r2 file `0x60c10`): r2 `pdf` shows the
  identical call sequence — `__strlen_chk` ×2, `imm_p2p_misc_rand_string`,
  `__strlen_chk`, `bc_msg_queue_push_back` — matching Ghidra lines 73–82, and the
  same `0x1000` buffer size and timeout immediates. r2 `izz` confirms the
  `connect_v2` format string byte-for-byte at file `0x11759a`. **Agree.**
- **SDP attributes** (`a=aes-key:%s`, `a=fingerprint:%s`, `a=ice-options:trickle`,
  `m=audio`/`m=video`, `a=group:BUNDLE`, `a=ssrc … cname`): r2 `izz` finds every
  string Ghidra's `sdp_encode` references, at the offsets Ghidra used. **Agree.**
- **Signaling validators** (`no header field` / `no msg field` / `no token field`,
  `type: sdp` / `type: candidate`): present in both. **Agree.**
- One **non-divergence note**: r2 initially failed `s 0x160c10` because r2 loads
  the lib at file base (offset `0x60c10`), while Ghidra applies image base
  `0x100000`. Same function, different displayed base — not a disassembly
  discrepancy. After `af @ 0x60c10` r2 matched Ghidra.

No semantic divergence between the two decompilers was found on any checked
function.

---

## 9. IMPLEMENTABILITY VERDICT (for TASK-0034)

**Verdict: partially** (recoverable statically — the full session spec is
recovered from `libThingP2PSDK.so` (`imm_p2p_rtc_connect_v2`/`_sdp_encode`/
`_recv_frame`) + the Java bridge
`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`;
the one remaining piece — the per-session `a=aes-key` value + negotiated SDP bytes
— is live-only, hence `partially`, not fully `recoverable-statically`).

**IMPLEMENTABLE — a Rust client (webrtc-rs + rumqttc) CAN drive this session,
GIVEN the runtime-gated inputs.** (confidence: confirmed for the spec — two
sources: `libThingP2PSDK.so` and the decompiled Java `P2PMQTTServiceManager.java`;
the single residual below is the only live-only unknown.)

The static recovery is now deep enough to build against:
- The `connect_v2` control JSON is byte-exact (§1, Ghidra+r2).
- The 302 `{header,msg,token}` envelope + field names are pinned (§2, native+Java).
- The SDP the device emits is byte-exact, including the Tuya `a=aes-key`/`imm`
  extension (§3, Ghidra `sdp_encode`).
- The `imm_p2p_rtc_frame_t` struct + codec identities are recovered (§4).
- The DTLS-SRTP/ICE pieces are standard and map to webrtc-rs (§3d, §7).

**Runtime-gated inputs the Rust client must inject (all from one authed
device-list call on the user's own account; none in the APK):**
`token` (per-session), `p2pId` (`remote_id`), `dev_id`, `skill`,
`P2pConfig.p2pKey`, `P2pConfig.ices` (STUN/TURN), `P2pConfig.session`, the device
`localKey` (302 payload AES), `pv`. The Rust client mints its own `trace_id` and
`connect_session`.

**Residual uncertainty — what ONLY a live device/capture confirms** (this is also
the AC#2/#3 "which bytes a pcap unblocks" answer):
1. **The on-wire `a=aes-key` value and the full offer/answer/candidate SDP bytes.**
   The SDP *shape* and the *fact* that the media key rides in `a=aes-key` are
   confirmed statically; the *actual key + the negotiated codecs/SSRCs/fingerprints*
   are per-session and only appear in a capture of the two 302 messages. **This is
   the single pcap-unblockable artifact** — one capture of the offer + answer 302
   payloads yields the media AES key and the exact negotiated SDP. (Static analysis
   cannot produce it because it is generated live; F3 "key in SDP" is confirmed, so
   no DTLS-exporter reverse-engineering is needed — just the capture.)
2. **Whether THIS firmware returns `p2pType=4`** (WebRTC) vs `2` (PPCS). The demo
   bean shows `4`; the real SCD921's value comes from the live device-list. If `2`,
   the transport flips to PPCS (the low-priority fallback, `re/p2p_triage.md` §5).
3. **Whether `moto_id` appears in this device's 302 `header`** (present in the
   public Tuya IPC ref, absent from this app's beans — §2b).
4. **Exact candidate-vs-answer interleaving / renegotiation timing** (§5) — a
   capture pins it; webrtc-rs's trickle handling is tolerant of either order.
5. **The 302-payload `pv`→output-variant binding + outer Tuya MQTT framing** (§2a).
   The AES *cipher* is statically pinned and implemented (AES-128/ECB/PKCS5,
   key=localKey, no IV); what a capture confirms is which output variant
   (`encrypt` hex / `encryptWithBase64` / `encryptWithBytes` raw) a 302 publish
   uses at a given `pv`, and the envelope framing around it
   (`Error::MqttEnvelopePending`). This is NOT a cipher-mode unknown — it is a
   wire-encoding/variant selection that one captured 302 resolves.

None of these block writing the TASK-0034 scaffolding now (signaling envelope +
webrtc-rs session + decoders, unit-tested offline); they gate only the final live
stream, exactly as TASK-0034's ACs already state.

---

## 10. Limitations (confidence: confirmed — scoping caveats)

(scoping record, grounded in the same two sources the doc rests on:
`libThingP2PSDK.so` (the native machinery) and
`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`
(the Java bridge).)

- **No live values.** Every per-session/per-account value (token, keys, ices,
  SSRCs, fingerprints, the actual `aes-key`) is runtime-issued; this doc recovers
  the *shapes/format strings*, not values. The committed `re/ghidra/*.c` are the
  decompiler's output; Ghidra renames (`FUN_*`, `param_N`) are preserved.
- **The `imm_p2p_rtc_frame_t` codec-id enum** beyond {audio=0, video, keyframe=2}
  is not fully named in the two frame functions (likely); the offsets are
  confirmed.
- **The `imm` (application) media transport** — whether the device streams the
  real A/V over the standard SRTP tracks, over the `imm` AES-keyed application
  channel, or both, is `likely` (the SDP advertises all three sections; which
  carries the live frames needs a capture). The recv_frame path proves frames
  arrive as de-paid audio/video units regardless.
- **Two-views-of-one-`.so` honored:** Ghidra C + r2 of `libThingP2PSDK.so` count
  as ONE source; `confirmed` claims pair that with an independent artifact (the
  decompiled Java `P2PMQTTServiceManager`, or a named public Tuya ref).
- **No secret/real identifier** is reproduced here. The `CameraInfoBean` creds the
  session needs are referenced by field name / `secrets/` location only
  (`re/tuya_cloud_auth.md` §5c); `just secret-scan` is green over the tracked tree.
