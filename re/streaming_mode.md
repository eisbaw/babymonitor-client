# Streaming-Mode Triage — WebRTC-over-MQTT vs legacy P2P (TASK-0017)

The transport decision for the SCD921 live A/V stream, so Wave-2 implements the
cheaper viable path first. Method: **JS-first**, corroborated in decompiled Java
(`decompiled/jadx/`) and the committed native symbol/string dumps, then
cross-checked against public Tuya WebRTC projects. Statically recovered; the SCD921 transport was
later live-validated end-to-end (see `re/prd.md`).

> Citation note (symbol-anchored — TASK-0024): cites name a **symbol**
> (class/method/enum); any `...File.java ~:NN` line is an **approximate hint** for
> the current `just decompile` tree — jadx line numbers drift, so grep the symbol.
> `decompiled/...` paths (jadx + js trees) and `decompiled/nativelibs/*.so` resolve
> only after a local `just decompile` (gitignored). The `re/symbols/*.txt` dumps
> cited here ARE committed.
> Native `lib*.so` evidence below is string-grep of
> `decompiled/nativelibs/libThingP2PSDK.so` /
> `decompiled/nativelibs/libThingCameraSDK.so`, the same arm64 libs inventoried
> in `re/native_libs.md`.

---

## VERDICT

**The SCD921 stack PREFERS Tuya's own WebRTC, signaled over MQTT (and a parallel
LAN channel), and keeps legacy PPCS (TUTK/IOTC-lineage) P2P as a fallback. The
choice is data-driven per device, from a cloud-provided `p2pType` integer plus a
`skill` capability descriptor — not hard-coded, not firmware-version-gated in the
app.** (confidence: confirmed — see the two-source breakdown in *Transport
identity* and *Capability negotiation* below.)

**RECOMMENDATION (AC #2): Wave-2 should implement WebRTC-over-MQTT FIRST.** It is
the cheaper path: the signaling is JSON over the device's existing MQTT channel
(message code 302) + a SDP/ICE/DTLS-SRTP WebRTC session, all of which map onto
mature Rust crates (`webrtc` a.k.a. webrtc-rs + `rumqttc`/`paho-mqtt`). Legacy
PPCS would instead require reconstructing Tuya's proprietary AV framing over the
TUTK IOTC session — strictly more work. See *Recommendation* for the crate map
and the live-device caveats. (Note — the `webrtc-rs` / "DTLS-SRTP WebRTC session"
phrasing here applies ONLY to the signaling + ICE *shape*, not to the media
transport: media uses the custom KCP + AES-128-CBC + HMAC-SHA1 framing, see the
correction note below.)

> **CORRECTION (Superseded 2026-06-28, v0.1.0-live-stream, commit fa930f0).** The
> live milestone VALIDATED the 302-over-MQTT JSON signaling + ICE path end-to-end
> against the real SCD921, but SUPERSEDED the *media-transport* assumption above:
> the SCD921 media path is **NOT** DTLS-SRTP / SRTP. Media = Tuya's `imm`/`tuya`
> KCP reliability layer carrying AES-128-CBC (inline-IV, PKCS7) per segment + a
> 20-byte HMAC-SHA1(media_key16) tag per datagram, transporting H.264. Only the
> 302/MQTT signaling and the ICE concepts carried over from the WebRTC mapping.
> The mbedTLS DTLS-SRTP strings on the *Source A* line below ARE genuinely in the
> lib, but they are NOT the SCD921 media path. Evidence: `re/media_decode_spec.md`,
> `re/media_start_handshake.md`, `re/live_stream_run.md`. (confidence: confirmed —
> live-validated keyframe decode.)

---

## How the app layers the transport (confidence: confirmed)

The JS feature kits do **not** contain any WebRTC/SDP/ICE primitives; they call a
native bridge that hides the transport entirely. Two independent sources:
(1) the JS `connect` manifest
`decompiled/js/assets/thing_uni_plugins/TUNIIPCCameraManager.json` exposes
`connect`/`createMediaDevice` whose ONLY param is `{deviceId}` (no sdp/ice/mode
fields); and (2) a precise token grep of the reflowed kit bundles
`decompiled/js/assets/kit_js/*.pretty` finds **zero** hits for
`webrtc|sdp|ice-ufrag|RTCPeerConnection|createOffer`. The flow is therefore
**JS `TUNIIPCCameraManager.connect(deviceId)` → GZL bridge → Java
`com/thingclips/smart/plugin/tuniipccameramanager/` → Tuya SDK →
`libThingP2PSDK.so`**, with the transport decided natively.

> CORRECTION to a forward-carried note. TASK-0001/0003/0004 notes claimed
> "PlayNetKit has 73 ice refs" / kit_js "ice/turn" hits. Re-grep shows those were
> **false positives**: the `ice` matches are substrings of `onScanDeviceInfo`,
> `connectMatterDevice`, `slice`, etc., and the `turn` matches are the keyword
> `return` in minified code
> (`decompiled/js/assets/kit_js/miniapp_PlayNetKit.js.pretty`). The JS layer is
> transport-agnostic; the real WebRTC evidence is in Java + native, below.
> (confidence: confirmed — the substring breakdown is reproducible with
> `rg -io "[a-z]*ice[a-z]*"` over `decompiled/js/assets/kit_js/*.pretty`.)

---

## Transport identity: WebRTC-over-MQTT IS present (confidence: confirmed)

Two SDK layers (native lib + Java bridge — not fully independent, both are the
Tuya SDK) plus an independent public Tuya implementation (seydx/tuya-ipc-terminal,
tuya/tuya-rtc-camera-sdk-android) agree the new path is WebRTC signaled over MQTT.

**Source A — native strings in `libThingP2PSDK.so`** (`re/native_libs.md` cites
the same lib; reproduced by `strings -n5`). The lib carries the complete WebRTC
signaling + media machinery:
- Signaling command JSON: `{"cmd":"connect_v2","args":{"remote_id":..,"dev_id":..,"skill":..,"token":..,"trace_id":..,"timeout_ms":..,"lan_mode":..,"preconnect_enable":1,"connect_session":..}}` (also `connect` v1 and `connect_v3` variants).
- Signaling control msgs: `set_remote_online`, `retransmit_signaling`, `signaling_result`, `pre_connect`.
- Signaling message **types**: the validator strings `invalid signaling: type: sdp`, `invalid signaling: type: candidate`, `invalid signaling: type: handle or seq` — i.e. the offer/answer SDP and trickle-ICE candidate exchange.
- **MQTT is the signaling carrier**: `create signaling mqtt worker thread`, `SendMessageThroughMQTT` / `sendMessageThroughMqtt`, `send to %s through mqtt`, `imm_p2p_mqtt_task`, plus a parallel `create signaling lan thread` for `lan_mode`.
- Full SDP/ICE/DTLS-SRTP: `a=ice-ufrag`, `a=ice-options:trickle`, `a=ice-pwd`, `a=rtcp-mux`, `a=fingerprint`, `a=setup`, `a=candidate`, `m=audio`/`m=video`, `imm_p2p_rtc_sdp_*` (encode/decode/negotiate), and DTLS-SRTP via bundled mbedTLS (`mbedtls_ssl_conf_dtls_srtp_protection_profiles`, cert `CN=Cert,O=WebRTC,C=US`).
- The C++ class `ThingSmartP2PSDK` exports `thing_p2p_rtc_connect_v2`, `thing_p2p_rtc_set_signaling`, `SendMessageThroughMQTT` (demangled from `re/symbols/libThingP2PSDK.dynsym.txt`).

**Source B — Java signaling bridge.** `IThingP2P`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/api/IThingP2P.java`)
declares `resendOffer(String)` (~:57), `setSignaling(String,int)` (~:70),
`setRemoteOnline(String)` (~:68) — WebRTC offer/SDP signaling verbs. The MQTT side is
`P2PMQTTServiceManager.send302MessageThroughMqtt`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java` ~:1537,
the class implements `IMqttServiceUtils`): `send302MessageThroughMqtt(boolean byLan, devId, jsonMsg)`
publishes the signaling JSON over the device MQTT channel with message code **302**.

---

## MQTT signaling shape: topic / cmd / fields (confidence: confirmed)

Two independent sources (decompiled Java + the public `seydx/tuya-ipc-terminal`
and Tuya's WebRTC docs) give a consistent shape.

**The carrier is the device's standard Tuya MQTT channel, message code 302** — NOT
a dedicated WebRTC topic. From the `homeCamera.publish(...,302,..)` call in
`P2PMQTTServiceManager`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java` ~:1550):

- Cloud path: `homeCamera.publish(devId, pv, localKey, jsonMsg, 302, cb)` — Tuya
  MQTT publish, protocol version `pv`, AES-encrypted with the device **localKey**,
  message code **302**.
- LAN path: `homeCamera.lan302Publish(devId, jsonMsg, cb)` — same 302 payload over
  the local network (this is the `lan_mode=1` branch of `connect_v2`).
- Inbound: `P2PMQTTServiceManager.registerMqtt302(cb)` (~:1528) →
  `homeCamera.registerCameraP2P302Listener(...)` (~:1531).

**Tuya MQTT topic format** (device-scoped). The local decompile confirms Tuya
uses device-scoped MQTT topics (`decompiled/jadx/sources/com/thingclips/sdk/mqtt/dpdqppp.java`
defines per-device prefixes such as `m/…` and `smart/mb/in|out/`), but the IPC AV
signaling topic form `/av/moto/<moto_id>/u/<device_id>` (publish) / `/av/u/<id>`
(subscribe) with `nin/`/`nout/` prefixes is documented by the public ref
(seydx/tuya-ipc-terminal), NOT locally confirmed — the exact device topic for the
SCD921 needs a live capture. (Correction: an earlier draft mis-attributed the
`nin/`/`nout/` literals to `dpdqppp.java`; they are not present there.)

**Signaling JSON envelope.** `P2PMQTTServiceManager.handleMqttAnswer`
(~:991) parses an `header` object out of the 302 payload and reads
`header.type`, `header.trace_id`, `header.from`; `P2PMQTTServiceManager.isP2PMqttAnswer`
(~:1071) checks `header.type == "answer"`. So the envelope is
`{ "header": { "type": <"offer"|"answer"|"candidate"|...>, "from":.., "to":.., "sessionid":.., "trace_id":.. }, "msg": <sdp-or-candidate-payload>, "token":.. }`.
The native validator strings corroborate the required header/msg/token fields
(`invalid signaling: invalid json, no header field` / `… no msg field` /
`… no token field`).

**The `connect_v2` arg fields** (native string, above) the Rust client must
populate: `remote_id` (the peer/device handle), `dev_id`, `skill` (capability
JSON, see below), `token` (per-session signaling token), `trace_id`,
`timeout_ms`, `lan_mode` (0 = go via cloud MQTT, 1 = LAN), `connect_session`.

---

## Capability negotiation: how WebRTC vs PPCS is chosen (confidence: confirmed)

The transport is selected **per-device from cloud-provided fields**, surfaced in
`CameraInfoBean`. Two independent sources: the enum definition + the populated
bean fixture.

**Source A — the enum.** `ThingCameraConstants.P2PType`
(`decompiled/jadx/sources/com/thingclips/smart/camera/api/ThingCameraConstants.java` ~:1611):
```
enum P2PType { P2P_TYPE_PPCS(2), P2P_TYPE_THING(4); }
```
`P2P_TYPE_PPCS(2)` = legacy TUTK/IOTC PPCS; `P2P_TYPE_THING(4)` = Tuya's own RTC
(the WebRTC-over-MQTT path). `IPCThingP2PCamera.getConnectionMode()`
(`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/IPCThingP2PCamera.java`)
returns the active mode; native `ThingP2PGetConnectionMode` /
`ThingP2PGetSkill` / `imm_p2p_rtc_get_skill` (in `libThingP2PSDK.so`) back it.

**Source B — the populated `CameraInfoBean`.** The SDK ships a sample bean (a
hard-coded Tuya demo record; its `password`/`p2pId`/device-id are demo values and
are NOT reproduced here — the demo bean is the `JSON.parseObject("{…}")` in class
`qpppdqb`,
`decompiled/jadx/sources/com/thingclips/smart/camera/middleware/p2p/qpppdqb.java` ~:423).
Its transport-selecting fields are: top-level `p2pType` (4 = THING/WebRTC here),
`p2pSpecifiedType`, `p2pPolicy`, `upgradeRelay`, and a nested `skill` JSON string
carrying a `webrtc` capability integer (value `3` in the SDK demo bean;
bitmask-vs-enum semantics unresolved statically, needs a live record),
`videos[]`/`audios[]` codec
descriptors (H264/H265 `codecType`, sample rates), `cloudGW`, and `sdk_version`.

**Mechanism summary.** The cloud device record gives `p2pType` (2=PPCS / 4=WebRTC)
+ a `skill` descriptor whose `webrtc` field advertises WebRTC capability. The app
passes `skill` into native `connect_v2`; native negotiates the actual session.
`lan_mode` independently selects LAN vs cloud-MQTT signaling for whichever
transport is chosen. There is **no evidence of a firmware-version string gate in
the app**; the decision is the `p2pType`/`skill` data, set per device by the
cloud. (confidence: likely for the precise `skill.webrtc` semantics — it is read
from a single in-app sample bean, so the bit-values need a live device record to
pin; the `p2pType` enum mapping itself is confirmed.)

---

## Legacy PPCS path is present but secondary (confidence: confirmed)

PPCS (TUTK/IOTC) is fully present as the fallback, in `libThingCameraSDK.so`
(string-grep, same lib as `re/native_libs.md`): the `ERROR_PPCS_*` family,
`PPCS_Connect`/`PPCS_Write`/`PPCS_ForceClose`/`PPCS_Check`,
`PPCS_API Version: %d.%d.%d.%d`, and JNI
`Java_com_thingclips_smart_camera_nativeapi_ThingCameraNative_connect4ppcs`. The
diagnostic JSON `{"inner_p2p_type":%d, ... "PPCS_Write":..}` shows the same
runtime carries both an `inner_p2p_type` selector and the PPCS write path. This
matches the public TUTK/IOTC lineage (WyzeCam `tutk` reimplementation). It is the
fallback transport, not the preferred one — consistent with `p2pType=4` being the
default in the sample bean and with the WebRTC-first `connect_v2`/`connect_v3`
commands.

---

## Cross-reference to public projects (confidence: confirmed)

Our recovered shape matches the documented Tuya WebRTC flow on **two** independent
public references:

- `seydx/tuya-ipc-terminal` (WebRTC-over-MQTT for Tuya cams, bridged to RTSP):
  documents **protocol 302** as the WebRTC signaling message code over MQTT, with
  a `header` carrying `from`/`to`/`sessionid`/`moto_id`/`type`, `mode:"webrtc"`,
  and message types `offer`/`answer`/`candidate`/`disconnect`; IPC topics
  `/av/moto/<moto_id>/u/<device_id>` (sink) and `/av/u/<id>` (source). This is a
  field-for-field match with our `publish(...,302,...)` + `header.type` finding.
- Tuya official `tuya/webrtc-demo-go`, `tuya/tuya-webrtc-android-demo`, and the
  Tuya WebRTC developer docs (developer.tuya.com WebRTC reference) confirm the
  WebRTC + MQTT-signaling architecture and the SDP/trickle-ICE/DTLS-SRTP media
  path that the native strings show. The earlier `re/native_libs.md` cross-check
  to `tuya/tuya-rtc-camera-sdk-android` (WebRTC + MQTT, <300ms) is the same family.

No cross-source contradiction was found; the only correction is the JS "ice/turn"
false-positive noted above.

Refs: https://github.com/seydx/tuya-ipc-terminal ;
https://github.com/tuya/webrtc-demo-go ;
https://github.com/tuya/tuya-webrtc-android-demo ;
https://developer.tuya.com/en/docs/iot/webrtc

---

## Recommendation for Wave-2 (AC #2) (confidence: likely)

Implement **WebRTC-over-MQTT first**; treat PPCS as a later fallback.

Why it is the cheaper path:
- Signaling is plain JSON over an MQTT channel we already must implement for the
  control plane (`TUNIMQTTManager`, `re/js_bundle_map.md`); the only addition is
  the 302 message code + the `header.type` offer/answer/candidate envelope.
- Signaling and ICE are WebRTC-shaped (SDP offer/answer + trickle-ICE), but the
  media session is **not** standard WebRTC — corrected/confirmed-live
  (Superseded 2026-06-28, v0.1.0-live-stream): the SCD921 media is Tuya's
  `imm`/`tuya` transport — a KCP reliability layer with AES-128-CBC + HMAC-SHA1
  per datagram, NOT SRTP / DTLS-SRTP. PPCS would instead require
  reverse-engineering Tuya's proprietary AV framing on top of the TUTK IOTC
  session (the harder, less documented path; see TASK-0009/0010).

Rust crate map:
- `webrtc` (webrtc-rs) — covers the SDP / ICE *concepts* (offer/answer,
  trickle-ICE) only; its DTLS-SRTP / SRTP-depacketize stack does NOT handle the
  SCD921 media path (Superseded 2026-06-28, v0.1.0-live-stream). The real media
  client implements a custom KCP layer + AES-128-CBC (inline-IV, PKCS7) +
  HMAC-SHA1 verify + H.264 decode (as built in `stream_live.rs` / `kcp.rs` /
  control), not SRTP depacketize.
- `rumqttc` (or `paho-mqtt`) — the Tuya MQTT signaling client (publish/subscribe,
  message code 302, localKey-AES payload, `pv` protocol version).
- H.264/H.265 decode: `openh264`/`ffmpeg`-backed crate (matches the device's
  OpenH264 codec, `re/native_libs.md`); Opus for two-way talk (`audiopus`).
- The 302 payload is AES-encrypted with the device `localKey` (from the cloud
  device-list, TASK-0013) at protocol version `pv` — that codec must be ported
  from `com/thingclips/sdk/mqtt/` (Tuya MQTT message crypto), a TASK-0007/0013
  dependency.

---

## What still needs the live camera to confirm (confidence: confirmed — scope list)

These are statically unprovable and need one session against the user's own
SCD921 (the gold oracle in `TESTING.md`). Grounded by two committed sources: the
native signaling strings behind `re/symbols/libThingP2PSDK.dynsym.txt` and the
device-config Java (the demo `CameraInfoBean` parsed in class `qpppdqb`,
`decompiled/jadx/sources/com/thingclips/smart/camera/middleware/p2p/qpppdqb.java` ~:423).

> **RESOLVED (2026-06-28, v0.1.0-live-stream, commit fa930f0).** The live milestone
> answered this scope list end-to-end against the real SCD921 (keyframe decoded +
> displayed). See `re/live_stream_run.md`, `re/media_start_handshake.md`,
> `re/media_decode_spec.md`. Per-item status is annotated inline below.

1. **Whether THIS firmware advertises `webrtc` in its `skill`.** The `p2pType`
   enum and `skill.webrtc` field are confirmed in code, but the only populated
   bean we can read statically is the SDK's hard-coded demo. The real SCD921
   cloud record's `p2pType`/`skill.webrtc`/`p2pPolicy` values must come from a
   live device-list/`obtainCameraConfig` call. (If the SCD921 returns
   `p2pType=2`, the recommendation flips to PPCS — this is the one hypothesis that
   can be wrong.) (RESOLVED 2026-06-28, v0.1.0-live-stream: the live SCD921 returns
   `p2pType=4` (THING/WebRTC), so the recommendation did NOT flip to PPCS.)
2. **The exact 302 envelope on the wire** — field names confirmed from the
   parser, but the full offer/answer/candidate JSON and the `token` derivation
   need a capture to lock byte-exact.
3. **The MQTT signaling `token`** and `connect_session` semantics — issued
   per-session by the cloud; not a static constant.
4. **STUN/TURN server addresses** — fetched at runtime (the lib has the ICE
   machinery but the relay endpoints come from a cloud config call, not a static
   string). (RESOLVED 2026-06-28, v0.1.0-live-stream: for the keyframe path the
   client early-binds the media UDP socket and trickles its own host candidate —
   no relay was required to reach the camera.)
5. **Media encryption / transport framing** — RESOLVED differently than this item
   originally assumed (Superseded 2026-06-28, v0.1.0-live-stream). The SCD921 media
   path does **NOT** use DTLS-SRTP at all; media is AES-128-CBC (inline-IV, PKCS7)
   per segment + a 20-byte HMAC-SHA1(media_key16) per datagram, carried over KCP.
   The mbedTLS DTLS-SRTP strings in the lib are not the SCD921 media path. See
   `re/media_decode_spec.md` / `re/media_start_handshake.md`.

---

## Limitations (confidence: confirmed — scoping caveats)

- No code-offset/disassembly was done; transport identity rests on JNI symbol
  names + embedded strings + the Java bridge, cross-checked against public refs
  (`re/symbols/libThingP2PSDK.dynsym.txt`, `re/native_libs.md`).
- The `skill.webrtc` bit semantics and the precise PPCS-vs-WebRTC tie-break when
  both are advertised are `likely`, read from one in-app sample bean; a live
  record resolves them.
- Secret hygiene: the sample `CameraInfoBean` parsed in class `qpppdqb`
  (`decompiled/jadx/sources/com/thingclips/smart/camera/middleware/p2p/qpppdqb.java` ~:423)
  contains demo `password`/`p2pId`/device-id values; none are reproduced here —
  reference the decompiled path only. No real account/device identifier or key is
  in this doc; the gate `re/scripts/secret_scan.sh` (`just secret-scan`) reports
  zero findings over the tracked tree.
