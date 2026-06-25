# P2P / Camera / Codec Native-Lib Triage (TASK-0009)

Maps the **exported API surface** of `libThingP2PSDK.so` (and briefly
`libThingCameraSDK.so` + the codec libs), the **session-init + send/recv entry
points** for both transports, the visible **protocol magic**, the **public-lineage
mapping**, and the **prioritised next-dive targets** for the TASK-0010 deep spike.

> **Transport priority (carried from TASK-0017 / `re/streaming_mode.md`).** The
> verdict is already settled: the SCD921 stack **PREFERS Tuya WebRTC-over-MQTT**
> (`p2pType=4` / `P2P_TYPE_THING`), and keeps **legacy PPCS (TUTK/IOTC)** as the
> **fallback** (`p2pType=2` / `P2P_TYPE_PPCS`). So this doc frames the **WebRTC
> signaling/session surface as the relevant target** for the Rust WebRTC client,
> and the **PPCS AV-framing reconstruction as LOW priority**, gated behind a live
> device returning `p2pType=2`. This triage does **not** re-litigate that verdict;
> it inventories the entry points behind it.

> **Citation convention (symbol-anchored — TASK-0024).** Line hints are
> **approximate** (jadx-run-dependent); the **symbol/SONAME/string is
> authoritative**. Native evidence is anchored on committed dumps
> `re/symbols/*.dynsym.txt` / `*.dynamic.txt` and on string-greps of
> `decompiled/nativelibs/*.so` (gitignored; the `re/symbols/` dumps ARE committed).
> Per TESTING.md, **two views of the same `.so`** (its `.dynsym.txt` dump and a
> `strings` grep of the same lib) **count as ONE source**; a cross-`.md` reference
> is a navigation pointer, **not** an independent source.

---

## 0. JS-FIRST gate (AC #3) — what the JS bundle reveals, and where it stops

**Confidence: confirmed.** The JS layer is **transport-agnostic**: it exposes
`connect`/`createMediaDevice` verbs whose only param is `{deviceId}` and contains
**zero** WebRTC/SDP/ICE primitives — the native bridge hides the transport. The
JS plugin manifest is
`decompiled/js/assets/thing_uni_plugins/TUNIIPCCameraManager.json` (47 methods,
the live-view kit) with its Java bridge package
`decompiled/jadx/sources/com/thingclips/smart/plugin/tuniipccameramanager/`; the
P2P param wrapper is `miniapp_P2PKit.js`
(`decompiled/js/assets/kit_js/miniapp_P2PKit.js.pretty`). A token grep
`rg -lc 'RTCPeerConnection|createOffer|ice-ufrag' decompiled/js/assets/kit_js/`
returns nothing (the earlier "73 ice refs" claim was a false positive —
`onScanDeviceInfo`/`slice`/`return` substrings; see `re/streaming_mode.md` and
`re/js_bundle_map.md`).

**Conclusion of the JS-first gate:** the JS bundle reveals the **orchestration**
(bridge method names, `{deviceId}`-only signaling, MQTT control plane) but **none
of the transport mechanics** — those are native. Everything below therefore
necessarily dives into the `.so`, which is the correct order per AC #3 (JS first,
then native only for what JS does not reveal). This is grounded by two independent
sources: the JS manifest path above AND the negative-grep over the `kit_js`
bundle.

---

## 1. Exported API surface — `libThingP2PSDK.so` (the AV transport)

`libThingP2PSDK.so` is **one library hosting BOTH transports** behind a single C++
class `ThingSmartP2PSDK` and a single JNI facade
`com.thingclips.smart.p2p.p2psdk.ThingP2PSDK`. (confidence: confirmed —
SONAME + JNI prefix in `re/symbols/libThingP2PSDK.dynamic.txt` and the
`Java_com_thingclips_smart_p2p_p2psdk_ThingP2PSDK_*` exports in
`re/symbols/libThingP2PSDK.dynsym.txt`.)

### 1a. JNI facade (`ThingP2PSDK_*`) — what Java/RN calls

**Confidence: confirmed.** All 26 JNI exports are in
`re/symbols/libThingP2PSDK.dynsym.txt`; cross-checked against the Java declarations
in `decompiled/jadx/sources/com/thingclips/smart/p2p/api/IThingP2P.java` (the
signaling verbs `setSignaling`/`setRemoteOnline`/`resendOffer` named in
`re/streaming_mode.md`). Grouped by purpose:

| Group | JNI exports (`Java_…_ThingP2PSDK_*`) | Transport |
|---|---|---|
| **Lifecycle** | `init`, `deInit`, `initLogModule`, `getVersion`, `getP2pVersion`, `uploadLog`, `activeCheck` | shared |
| **WebRTC session connect** | `connectV2`, `connectV3`, `startPreConnect`, `startPreConnectV2`, `closePreConnect`, `connectBreak` | **WebRTC** |
| **WebRTC signaling I/O** | `setSignaling`, `setSignalingSendResult`, `setRemoteOnline`, `setHttpResponse`, `sendAuthorizationInfo` | **WebRTC** |
| **RTC v1 connect** | `connect`, `disConnect` | RTC v1 (in `libThingP2PSDK`; NOT PPCS — real PPCS is `connect4ppcs` in `libThingCameraSDK`) |
| **AV/data plane** (transport-agnostic at this layer) | `sendData`, `recvData` | both |
| **Session mgmt** | `getP2PSessionList`, `freeP2PSessionList`, `closeAllSessions` | both |

> `connect` (v1) and `connectV2`/`connectV3` coexist; v2/v3 carry the WebRTC
> `skill`/`token`/`lan_mode` args (see §3). `sendData`/`recvData` are the generic
> byte-stream plane shared by whichever native session is active.

### 1b. Native C++ class `ThingSmartP2PSDK` — full demangled signatures

**Confidence: confirmed** (two independent sources: the demangled C++ exports of
`libThingP2PSDK.so`, and the public ref `tuya/tuya-rtc-camera-sdk-android` (github
reference) whose IMM-P2P RTC `connect`/`sdp`/`signaling` API shape matches these
`thing_p2p_rtc_*` signatures). Demangled (via `c++filt`) from the mangled
`_ZN16ThingSmartP2PSDK*` exports, dumped to the committed
`re/symbols/libThingP2PSDK.dynsym.txt`. This is the
**richest surface for the Rust client** — full argument types are recovered. The
WebRTC core is the `imm_p2p_rtc_*` family (Tuya "IMM-P2P RTC"); these are the
real session-init / send / recv entry points:

```
// --- lifecycle / init ---
ThingSmartP2PSDK::Initialize(char const* id, _OSTYPE_, char const*, char const*,
    void(*on_msg)(bool,char*,char*,uint),          // signaling send callback
    int(*on_https)(char*,char*,char*,uint),        // https request callback
    int(*on_state)(char*,int,int,rtc_state,rtc_active_state_e,int))  // session-state cb
ThingSmartP2PSDK::thing_p2p_rtc_init(imm_p2p_rtc_options*)
ThingSmartP2PSDK::thing_p2p_rtc_reset(imm_p2p_rtc_options*)
ThingSmartP2PSDK::thing_p2p_rtc_deinit()

// --- WebRTC SESSION-INIT (the relevant path) ---
ThingSmartP2PSDK::thing_p2p_rtc_connect_v2(char* remote_id, char* dev_id, char* skill,
    uint, char* token, uint, char* trace_id, int timeout_ms, int lan_mode)
ThingSmartP2PSDK::thing_p2p_rtc_connect_v3(char*,char*,char*,uint,char*,uint,char*,int,int,int)
ThingSmartP2PSDK::thing_p2p_rtc_connect(char*,char*,uint,char*,int,int)      // v1
ThingSmartP2PSDK::thing_p2p_rtc_pre_connect(char*,char*)
ThingSmartP2PSDK::thing_p2p_rtc_pre_connect_v2(char*,char*,char*,uint)
ThingSmartP2PSDK::thing_p2p_rtc_set_remote_online(char* remote_id)

// --- WebRTC SIGNALING I/O (the relevant path) ---
ThingSmartP2PSDK::thing_p2p_rtc_set_signaling(char*, char*, uint)            // inbound sdp/candidate
ThingSmartP2PSDK::thing_p2p_rtc_set_signaling_send_result(char*,char*,uint,int)
ThingSmartP2PSDK::SendMessageThroughMQTT(char*, char*, uint)                 // outbound carrier
ThingSmartP2PSDK::SendMessageThroughLAN(char*, char*, uint)                  // lan_mode carrier
ThingSmartP2PSDK::p2p_rtc_signaling / p2p_rtc_httpsRequest / p2p_rtc_session_state_cb

// --- SEND / RECV data + frame plane (both transports flow through here) ---
ThingSmartP2PSDK::thing_p2p_rtc_send_data(int session, uint chan, char* buf, int len, int)
ThingSmartP2PSDK::thing_p2p_rtc_recv_data(int session, uint chan, char* buf, int* len, int)
ThingSmartP2PSDK::thing_p2p_rtc_send_frame(int, imm_p2p_rtc_frame_t*)        // AV-framed send
ThingSmartP2PSDK::thing_p2p_rtc_recv_frame(int, imm_p2p_rtc_frame_t*)        // AV-framed recv
ThingSmartP2PSDK::thing_p2p_rtc_check_buffer(int,uint,uint*,uint*)
ThingSmartP2PSDK::thing_p2p_getwaitsnd(int,uint)

// --- session mgmt / capability ---
ThingSmartP2PSDK::thing_p2p_rtc_get_connection_mode(int, rtc_connection_mode_e*)
ThingSmartP2PSDK::thing_p2p_rtc_get_skill()
ThingSmartP2PSDK::thing_p2p_rtc_get_session_info(int, imm_p2p_rtc_session_info_t*)
ThingSmartP2PSDK::thing_p2p_rtc_get_session_list() / free_session_list / clear_sessions
ThingSmartP2PSDK::SendAuthorizationInfo(int,int,int,char const*,char const*,int)
```

Two recovered struct/enum names worth noting for TASK-0010: `imm_p2p_rtc_frame_t`
(the AV frame container passed to send_frame/recv_frame), `imm_p2p_rtc_options`
(init config), `rtc_state` / `rtc_active_state_e` / `rtc_connection_mode_e`
(session-state machine), and `imm_p2p_rtc_session_info_t`.

### 1c. WebRTC media machinery — the `imm_p2p_rtc_sdp_*` / `imm_p2p_ice_*` family

**Confidence: confirmed.** Flat C exports of `libThingP2PSDK.so` (dump:
`re/symbols/libThingP2PSDK.dynsym.txt`), cross-checked against the SDP attribute
strings string-grepped from the same `decompiled/nativelibs/libThingP2PSDK.so`
plus the public WebRTC ref `tuya/tuya-rtc-camera-sdk-android` (github reference).
This is the full offer/answer + trickle-ICE + DTLS-SRTP toolkit:

| Subsystem | Key exported symbols |
|---|---|
| **SDP encode/decode/negotiate** | `imm_p2p_rtc_sdp_init`, `imm_p2p_rtc_sdp_encode`, `imm_p2p_rtc_sdp_decode`, `imm_p2p_rtc_sdp_negotiate`, `imm_p2p_rtc_sdp_add_media`, `imm_p2p_rtc_sdp_add_{audio,video,video_rtx,imm}_codec`, `imm_p2p_rtc_sdp_add_candidate`, `imm_p2p_rtc_sdp_set_dtls_cert_fingerprint`, `imm_p2p_rtc_sdp_{get,set}_aes_key`, `imm_p2p_rtc_sdp_set_media_type` |
| **ICE session** | `imm_p2p_ice_session_create`, `…_destroy`, `…_add_remote_candidate`, `…_add_remote_userinfo`, `…_get_handshake_info`, `…_sendto` |
| **RTP packetize** | `imm_p2p_h264_packetize`, `…_nal`, `…_nal_fua`, `…_nal_stapa`, `…_find_next_nal_unit` |
| **AV frame / ARQ reliability** | `imm_p2p_rtc_frame_list_create/destroy/close`, `…_arq_find_packet`, `…_arq_set_packet`, `…_check_limit`, `…_get_status`, `…_get_current_frame` |
| **Signaling transport** | `imm_p2p_rtc_set_signaling`, `imm_p2p_rtc_set_remote_online`, `imm_p2p_rtc_set_http_result(_v2)` |
| **DTLS-SRTP (bundled mbedTLS)** | `mbedtls_ssl_conf_dtls_srtp_protection_profiles`, `imm_p2p_misc_generate_cert`, `imm_p2p_misc_calculate_cert_fingerprint`, `imm_p2p_misc_generate_pkey` (the P2P SDK links its **own static mbedTLS**, not the app's OpenSSL — see `re/native_libs.md`) |

### 1d. Crypto/util helpers (shared)

`imm_p2p_hmac_sha1*`, `imm_p2p_md5_*`, `imm_p2p_crc32_*`, `aes_decrypt_with_raw_key`,
`imm_p2p_misc_rand_hex`/`rand_string` — the per-session keying / integrity
primitives (confidence: likely — single-source symbol read: exports of
`libThingP2PSDK.so`, dump `re/symbols/libThingP2PSDK.dynsym.txt`; the routines'
exact roles in key derivation are a TASK-0010 dive, not yet corroborated).
The SDP-level `imm_p2p_rtc_sdp_{get,set}_aes_key` suggests an **AES key carried in
SDP** for the media path — a TASK-0010 dive target (key derivation, the historically
non-statically-recoverable part per review-gate F3).

---

## 2. `libThingCameraSDK.so` — the high-level camera control plane (both transports)

**Confidence: confirmed.** JNI exports in `re/symbols/libThingCameraSDK.dynsym.txt`;
PPCS strings string-grepped from the same `decompiled/nativelibs/libThingCameraSDK.so`
(two views of one lib = ONE source — corroborated by the public TUTK/IOTC lineage,
the second source, in §4).

This lib sits **above** the transport: it exposes the camera-feature verbs
(`com.thingclips.smart.camera.nativeapi.ThingCameraNative`) and selects the
transport via an `inner_p2p_type` runtime selector.

- **Connect (transport tie-break lives here):**
  `ThingCameraNative_connect` (mode-selected) vs
  `ThingCameraNative_connect4ppcs` (explicit **PPCS** path); `getConnectionMode`,
  `disconnect`. `ThingCameraEngineNative_initP2PModule` / `deInitP2PModule`.
- **AV feature plane (transport-agnostic verbs):** `startPreview`/`stopPreview`,
  `startPlayBack`(+`WithPlayTime`)/`stopPlayBack`, `startAudioTalk`/`sendAudioTalkData`/
  `stopAudioTalk`, `startVideoTalk`/`startSendVideoTalkData`, `startAudioRecord`,
  `startRecordLocalMp4`, `playCloudDataWithStartTime`, `startDownloadAlbumFile`.
- **PPCS magic (fallback transport):** the `ERROR_PPCS_*` error family
  (`ERROR_PPCS_DEVICE_NOT_ONLINE`, `…_NO_RELAY_SERVER_AVAILABLE`,
  `…_INVALID_SESSION_HANDLE`, `…_MAX_SESSION`, …), the `PPCS_Write` /
  `PPCS_ForceClose` call sites, and `Cannot write a 0 size RTP packet.`
  (string-grep of `libThingCameraSDK.so`).
- **The runtime selector** — the diagnostic JSON literal
  `{"inner_p2p_type":%d, "action":"SendAuthorizationInfo", … "PPCS_Write":%d}`
  **vs** the sibling `… "thing_p2p_rtc_send_data":%d}` — proves the **same camera
  runtime carries both send paths and picks one by `inner_p2p_type`**. This is the
  concrete artifact of the `p2pType` 2-vs-4 decision from `re/streaming_mode.md`.

`libThingP2PFileTransSDK.so` (out of streaming scope, noted for completeness):
JNI `com.thingclips.smart.p2pfiletrans.jni.ThingP2pFileTransSDKJni` —
`initP2pFileTransSDK`, `createP2pFileTransfer`, `connect`, `startUploadFiles`,
`startDownloadFiles`, `startGetFilesStream`, `queryAlbumFile` — album/cloud-clip
file transfer over a P2P session, NOT the live stream (confidence: confirmed —
`re/symbols/libThingP2PFileTransSDK.dynsym.txt`).

---

## 3. Protocol magic / constants / version strings (already visible)

**Confidence: confirmed** unless noted. String-greps of
`decompiled/nativelibs/libThingP2PSDK.so` / `…CameraSDK.so` / `…VideoCodecSDK.so`
(see `re/native_libs.md` / `re/streaming_mode.md` for the originals — not
re-dumped here, only the load-bearing magic):

- **WebRTC signaling command (the wire envelope the Rust client must emit):**
  `{"cmd":"connect_v2","args":{"remote_id":"%s","dev_id":"%s","skill":%.*s,"token":%.*s,"trace_id":"%s","timeout_ms":%d,"lan_mode":%d,"preconnect_enable":1,"connect_session":"%s"}}`
  — plus `connect_v3` (drops inline `skill`), `set_remote_online`,
  `retransmit_signaling` (`{"sessionid","remote_id","path"}`), `pre_connect`.
- **Signaling message-type validators:** `invalid signaling: type: sdp`,
  `… type: candidate`, `… type: handle or seq`, and the required-field checks
  `invalid signaling: invalid json, no header field` / `… no msg field` /
  `… no token field` — i.e. the envelope is `{header,msg,token}` (the 302 MQTT
  payload parsed in `P2PMQTTServiceManager.handleMqttAnswer`, `re/streaming_mode.md`).
- **MQTT carrier:** `create signaling mqtt worker thread`, `SendMessageThroughMQTT`,
  `imm_p2p_mqtt_task`; parallel `create signaling lan thread` for `lan_mode=1`.
- **SDP/ICE attributes:** `a=ice-ufrag`, `a=ice-options:trickle`, `a=ice-pwd`,
  `a=rtcp-mux`, `a=fingerprint`, `a=setup`, `a=candidate`, `m=audio`/`m=video`.
- **PPCS (fallback):** `ERROR_PPCS_*` family, `PPCS_Write`/`PPCS_ForceClose`,
  `inner_p2p_type` selector JSON (§2).
- **Versions:** P2P SDK token `3.10.0` (likely — `ThingGetApiVersion`/
  `imm_p2p_rtc_get_version`, runtime `%s`-substituted); Camera `1.2.x`;
  **Video codec `1.5.0-Philips620.3`** — an OpenH264 (Cisco `CWelsDecoder`) fork
  carrying a **Philips-specific build tag** (new finding this task, string-grep of
  `decompiled/nativelibs/libThingVideoCodecSDK.so`; confidence: confirmed for the
  literal); Audio engine = Tuya `ipc-tymedia-sdk` WebRTC `audio_processing`
  (`ThingWebRTCVAD`, AEC/AGC/NS, build-path leak in
  `decompiled/nativelibs/libThingAudioEngineSDK.so`).

---

## 4. Mapping to public lineage (AC #4)

**Confidence: confirmed** (each row pairs a native source —
`libThingP2PSDK.so` / `libThingCameraSDK.so` — with an independent named public
ref; two distinct sources per row).

| Our entry points | Public reference | What it tells us | Confidence |
|---|---|---|---|
| `imm_p2p_rtc_connect_v2/v3`, `imm_p2p_rtc_sdp_*`, `imm_p2p_ice_*`, `SendMessageThroughMQTT`, 302 envelope `{header,msg,token}` | `tuya/tuya-rtc-camera-sdk-android` ; `tuya/webrtc-demo-go` ; `tuya/tuya-webrtc-android-demo` ; `seydx/tuya-ipc-terminal` | Confirms the **WebRTC-over-MQTT** architecture (SDP offer/answer + trickle-ICE + DTLS-SRTP, signaled as message code 302 over Tuya MQTT). `seydx/tuya-ipc-terminal` gives the wire shape: `header.type` = `offer`/`answer`/`candidate`/`disconnect`, `mode:"webrtc"`, IPC topics `/av/moto/<moto_id>/u/<device_id>`. **A field-for-field match** with our recovered strings → the Rust client can model signaling directly from this ref. | confirmed (native strings in `libThingP2PSDK.so` + the named public refs = 2 independent sources) |
| `ThingCameraNative_connect4ppcs`, `ERROR_PPCS_*`, `PPCS_Write`/`PPCS_Read`/`PPCS_Connect`, IOTC session model | `tuya/tuya-iotos-android-iot-p2p-demo` (P2P **channel API surface**) ; WyzeCam `tutk.py`/`tutk_ioctl_mux.py` (IOTC/TUTK **AV framing**) ; `miguelangel-nubla/videoP2Proxy` | The PPCS path is the **TUTK/IOTC PPCS lineage**. WyzeCam `tutk.py` is a full Python reimpl of the IOTC session + AV framing → if the SCD921 ever returns `p2pType=2`, this ref is the template for the AV de-framer. The Tuya P2P demo documents the channel/connect API surface that `connect4ppcs` wraps. | confirmed (PPCS strings in `libThingCameraSDK.so` + named public refs = 2 independent sources) |

Refs: `tuya/tuya-rtc-camera-sdk-android`, `tuya/webrtc-demo-go`,
`tuya/tuya-webrtc-android-demo`, `seydx/tuya-ipc-terminal`,
`tuya/tuya-iotos-android-iot-p2p-demo`, `miguelangel-nubla/videoP2Proxy`;
WyzeCam `tutk` (https://kroo.github.io/wyzecam/reference/tutk/tutk/).

---

## 5. NEXT-DIVE TARGETS for TASK-0010 (PRIORITISED) (AC #2)

**Confidence: likely** for the priority ordering (it follows the confirmed
`re/streaming_mode.md` WebRTC-first verdict); the per-symbol targets are
**confirmed** present (`re/symbols/libThingP2PSDK.dynsym.txt`). Targets are named
functions/symbols (no fixed code offsets — no disassembly was done this task; the
offsets in the `.dynsym.txt` dumps are symbol addresses, the disassembly entry
points for radare2/Ghidra in TASK-0010).

### PRIORITY 1 — WebRTC signaling/session path (the CHOSEN transport)

**Confidence: likely** for the ordering (follows the confirmed WebRTC-first
verdict); the targets themselves are confirmed-present exports of
`libThingP2PSDK.so` (`re/symbols/libThingP2PSDK.dynsym.txt`).

1. **`ThingSmartP2PSDK::thing_p2p_rtc_connect_v2`** (`imm_p2p_rtc_connect_v2`) —
   the session-init entry. Recover how `skill`/`token`/`connect_session`/`lan_mode`
   are consumed and how it kicks off the SDP offer. **Highest value** — this is the
   first call the Rust client makes.
2. **`imm_p2p_rtc_sdp_encode` / `_decode` / `_negotiate`** + `_add_*_codec` —
   the offer/answer construction. Confirm codec list (OpenH264 H.264 + the `imm`
   codec) and the trickle-ICE candidate flow vs `webrtc-rs` defaults.
3. **`imm_p2p_rtc_sdp_get_aes_key` / `_set_aes_key`** and the
   `imm_p2p_hmac_sha1` / `aes_decrypt_with_raw_key` helpers — the **media/session
   key derivation** (review-gate F3's expected hard blocker; the part typically NOT
   statically recoverable — verify whether it is here or needs a live DTLS capture).
4. **`ThingSmartP2PSDK::set_signaling` / `SendMessageThroughMQTT` + the 302
   envelope** — pin the exact `{header,msg,token}` byte shape vs the parser in
   `P2PMQTTServiceManager.handleMqttAnswer` and the `seydx/tuya-ipc-terminal` ref.
5. **`imm_p2p_rtc_frame_t` + `thing_p2p_rtc_recv_frame` + `imm_p2p_rtc_frame_list_*`
   (ARQ)** — the AV frame container + reliability layer the Rust depacketizer reads
   after SRTP. `imm_p2p_h264_packetize_nal_fua`/`_stapa` give the RTP/H.264 framing.
6. **`Initialize` callback contract** (`on_msg` / `on_https` / `on_state` +
   `rtc_state`/`rtc_active_state_e`) — the state machine the Rust client must drive.

### PRIORITY 2 — PPCS fallback (LOW priority — gated behind a live `p2pType==2`)

> **Honest scoping:** because WebRTC won (`re/streaming_mode.md`, confirmed), the
> PPCS AV-framing reconstruction is now **low priority** and should only be pursued
> if a live `obtainCameraConfig`/device-list returns `p2pType=2` / `P2P_TYPE_PPCS`
> for the real SCD921. Statically we only see the SDK demo bean (`p2pType=4`).

7. **`ThingCameraNative_connect4ppcs`** + the `inner_p2p_type` selector — how the
   runtime picks PPCS vs RTC (the tie-break site in `libThingCameraSDK.so`).
8. **`PPCS_Write` / `PPCS_Read` call sites + the RTP de-framer** (`invalid RTP
   packet`, `Cannot write a 0 size RTP packet.`) — the proprietary AV framing over
   the IOTC session, templated by WyzeCam `tutk.py`. Only if PPCS goes live.

### Explicitly de-scoped here (TASK-0010 / disassembly required)

**Confidence: likely** (scoping caveat about method, not a protocol claim;
grounded in the exported-symbol-only evidence of `libThingP2PSDK.so` /
`re/symbols/libThingP2PSDK.dynsym.txt` — no call graph was analyzed, so the
argument semantics remain a single-source open item for TASK-0010).

- No radare2/Ghidra disassembly was done — argument **semantics** (e.g. the meaning of
  the trailing `int` flags on `connect_v2`, the `skill` bitmask vs enum) need
  decompilation. This task is the **API-surface + entry-point map**, not the
  control-flow recovery.
- The `skill.webrtc` bit semantics and the `token` derivation are runtime/cloud
  values — they need the live device (the `TESTING.md` gold oracle), not static RE.

---

## 6. Limitations (confidence: confirmed — scoping caveats, not protocol claims)

- **No code-offset/disassembly.** All evidence is exported-symbol names
  (`re/symbols/*.dynsym.txt`), demangled C++ signatures, and embedded strings. The
  addresses in the dumps are symbol addresses (disassembly entry points), not
  analyzed call graphs. Argument semantics await TASK-0010.
- **Two-views-of-one-`.so` rule honored:** where a claim rests on a single lib, a
  `.dynsym.txt` dump + a `strings` grep of that same `.so` count as ONE source; the
  `confirmed` labels above pair such a lib-internal source with an **independent**
  one (a named public ref, or a second distinct lib/Java symbol).
- **Versions are `%s`-substituted at runtime** (`3.10.0`, `1.2.x`); the literal
  tokens are the best static read but `likely`, except `1.5.0-Philips620.3` and the
  OpenSSL banner which are literal (`confirmed`).
- **PPCS dive is deliberately shallow** — it is the fallback and low priority; the
  AV-framing reconstruction is gated behind a live `p2pType==2`.
- **No secret/real identifier** is reproduced here: the SDK demo `CameraInfoBean`
  (class `qpppdqb`) carries demo `password`/`p2pId`/device-id values referenced by
  path only (`decompiled/jadx/sources/com/thingclips/smart/camera/middleware/p2p/qpppdqb.java`),
  never copied in.
