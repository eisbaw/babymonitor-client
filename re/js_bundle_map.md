# JS Bundle Map (TASK-0003)

The app is React Native on **V8** (`libv8android.so`, `libv8executor.so`,
`libthing_j2v8.so`) plus Tuya's "GZL" mini-app / "uni" runtime. The user-facing
auth/pairing/streaming orchestration lives in plain JavaScript assets, NOT in
Hermes bytecode or a V8 snapshot. This is the most readable layer.

Extraction: `unzip assets/{kit_js,mini_app_js,thing_uni_plugins}` →
`decompiled/js/assets/` (gitignored). A string-aware reflow
(`re/scripts/reflow_js.py`) produced `*.pretty` siblings for the kit_js/
mini_app_js bundles so the minified one-liners are greppable.

Citations point at `decompiled/js/assets/...` paths (gitignored, but stable) and
the public Tuya refs already established for this project.

## Bundle format verdict (confidence: confirmed) — AC #2

- `assets/kit_js/*.js` (12 files) and `assets/mini_app_js/*.js` (8 files) are
  **plain minified JavaScript** (UMD: `!function(e,a){if("object"==typeof
  exports...`), confirmed by `file` ("JavaScript source, UTF-8, very long lines")
  and the leading bytes (`decompiled/js/assets/kit_js/miniapp_IPCKit.js`). They
  are NOT Hermes bytecode (no `0x1F1903C1` magic) and NOT a V8 snapshot/cache.
- `assets/thing_uni_plugins/*.json` (101 files; 74 non-trivial) are **bridge API
  descriptor manifests** (JSON), one per native "TUNI…Manager" module, listing
  each method name → param/`success` schema. They are data, not code.
- **No follow-up bytecode-decompile task is needed** — everything is directly
  readable. (If a future bundle ships Hermes, the tool would be `hermes-dec`/
  `hbctool`; not required here.)

## kit_js bundles (the feature kits) (confidence: confirmed)

| Bundle | Size | Role (where flows live) |
|---|---|---|
| miniapp_IPCKit.js | 45 KB | **IPC camera live-view kit** — the camera panel feature surface (connect/talk/playback/snapshot) |
| miniapp_P2PKit.js | 25 KB | **P2P transport kit** — wraps `TUNIP2pFileManager` / ThingP2P connection params |
| miniapp_PlayNetKit.js | 36 KB | **Play/network kit** — streaming play-mode + ICE (73 `ice` hits) |
| miniapp_DeviceKit.js | 115 KB | device model, DP control, device list |
| miniapp_HomeKit.js | 33 KB | home/family + **login ticket** (`onTicketSuccess`) |
| miniapp_MediaKit.js | 22 KB | media playback (lullaby/audio) |
| miniapp_BaseKit / BizKit / MiniKit / CategoryCommonBizKit | 117/96/56/27 KB | base utils, business logic, mini-app host, category biz |
| miniapp_HealthKit / MapKit | 23/28 KB | health, maps (not baby-cam-core) |

mini_app_js: `jsBridgeService.js` + `jsBridgeWebView.js` are the JS↔native bridge
shims; `polyfill.min.js` is a core-js polyfill; `gzlConstant*/gzlTheme*` are
config/theme constants.

## The JS↔native bridge mechanism (confidence: confirmed)

`decompiled/js/assets/mini_app_js/jsBridgeService.js` defines the bridge:
`window.gzlJSBridge.serviceInvoke = (webViewId, args, callback) =>
gzlServiceNativeBridge.serviceInvoke(...)` and a native `serviceInvokeNative`.
JS calls native modules through `gzlServiceNativeBridge` (the GZL = Tuya mini-app
runtime injected object). Each native module is described by a
`thing_uni_plugins/TUNI…Manager.json` schema. So: **JS feature kits → GZL bridge
→ native `TUNI…Manager` (Java) → Tuya SDK (`.so`)**. To reimplement in Rust we
target the native/cloud layer the bridge funnels into, using these manifests as
the API contract.

## Tuya RN bridge module names (the API contract) (confidence: confirmed)

Method names below are the literal `keys` of each
`decompiled/js/assets/thing_uni_plugins/<name>.json`.

### Streaming / live view — `TUNIIPCCameraManager.json` (47 methods)
(confidence: confirmed; `decompiled/js/assets/thing_uni_plugins/TUNIIPCCameraManager.json`)

`connect`, `disConnect`, `createMediaDevice`, `isConnected`, `isConnecting`,
`isDisConnect`, `getCurrentSupportedTalkMode`, `isSupportedTalk`,
`enableAudioAEC`, `enableAudioAGC`, `enableAudioNS`, `enableVoiceEffect`,
`getVideoBitrateKbps`, `snapshootToSandbox`, `publishDps`, `obtainCameraConfig`,
`startDownloadMessageVideo`, `downloadCloudPlayBack`, `downloadEncryptionImage`,
`wakeUpDoorBell`, … This is the **live-stream connect/talk/playback control API**
for the SCD921 — the Rust streaming client mirrors `connect` →
`createMediaDevice` → (P2P/WebRTC session) → frame callbacks.

### Two-way talk / doorbell — `TUNIIPCDoorbellManager.json` (8 methods)
`acceptDoorbellCall`, `hangupDoorbellCall`, `refuseDoorbellCall`,
`doorbellCallConfig`, `onDoorBellCallCancel`, `onDoorBellCallHangUp`,
`onDoorBellCallHangUpByOther` — the call/two-way-audio session control.

### P2P file/stream transport — `TUNIP2pFileManager.json` (19 methods)
`P2PSDKInit`, `connectDevice`, `disconnectDevice`, `downloadStream`,
`appendDownloadStream`, `onStreamPacketReceive`, `onSessionStatusChange`,
`isP2PActive`, `uploadFile`, `queryAlbumFileIndexs` — direct surface of
`libThingP2PFileTransSDK` (JNI `ThingP2pFileTransSDKJni`, see re/native_libs.md).

### Cloud control plane — `TUNIMQTTManager.json` (10 methods)
(confidence: confirmed; `decompiled/js/assets/thing_uni_plugins/TUNIMQTTManager.json`)

`createMQTTClient`, `connect`, `disconnect`, `subscribe`, `unsubscribe`,
`publish`, `onMessage`, `onStateChange` — params include
`host/port/userName/password/clientId/ssl` and `taskId/topic/message`. This is
the **MQTT signaling/control channel**; combined with the native WebRTC strings
in `libThingP2PSDK.so` (re/native_libs.md), it is the **WebRTC-over-MQTT signaling
transport** (review-gate F2). The streaming-mode triage (task 10) should trace
which topic carries the SDP/ICE offer/answer.

### Cloud API gateway from JS — `TUNIAPIRequestManager.json` (2 methods)
(confidence: confirmed for the method/param shape; `likely` for the F1 sign link;
`decompiled/js/assets/thing_uni_plugins/TUNIAPIRequestManager.json`, ref nalajcie/tuya-sign-hacking)

- `apiRequestByAtop` — params `{api, version, postData, extData}` → the Tuya
  **"atop" mobile-app API gateway** call. This is the path that carries the
  **mobile-app request signing** scheme (review-gate F1; key derivation via
  `t_s.bmp` + cert pin, native side). Any Rust cloud client reproduces this
  `atop` api/version/postData envelope + sign.
- `apiRequestByHighwayRestful` — params `{host, api, header, query, body,
  method(GET/POST/PUT/DELETE)}` → the newer "Highway" RESTful gateway.

### Login / account — `TUNILoginManager.json` (2 methods)
`logout`, `onTicketSuccess`. Login is **ticket-based**: JS receives an
`onTicketSuccess` event; the actual account credential handling and the
session/uid are managed natively (Java/`.so`), not in JS. `HomeKit.js` also
references `onTicketSuccess` and `login`. → the cloud-auth code itself is in the
DEX/native layer (forward to task 7), NOT in these bundles.

### Pairing / provisioning — `TUNIActivationManager.json` (13) + `TUNIDeviceActivationManager.json` (12)
(confidence: confirmed; `decompiled/js/assets/thing_uni_plugins/TUNIActivationManager.json`)

`startDeviceActivate`, `startScanDevice`, `stopScanDevice`, `requestWifiList`,
`resumeActive`, `analysisMatterQRCode`, `connectMatterDevice`,
`onDeviceActivateResult`, `onScanDeviceInfo`, `onActivateIntermediateState`.
The `startDeviceActivate` param schema is the **full pairing model**: `scanType`,
`token`, `ssid`, `password`, `cipher`, `gwId`, `uuid`, `mac`, `pid`, `devId`,
plus an `hgwBean` (local-gateway: `ip/gwId/productKey/encrypt/version/token/
wf_cfg/ssid/apConfigType`) and `currentMeshBean` (`localKey/meshId/password`).
This is EZ/AP/SmartLink + Matter provisioning — matches `libThingSmartLink.so`.

### Cloud storage signing — `TUNICloudStorageSignatureManager.json` (1)
(confidence: confirmed; `decompiled/js/assets/thing_uni_plugins/TUNICloudStorageSignatureManager.json`)

`generateSignedUrl` — params `{path, expiration, region, token, sk, provider,
endpoint, ak, bucket}` → signs S3-style cloud-clip URLs (matches
`libThingCloudStorageSignatureTools.so`).

### Other notable plugins
(confidence: confirmed; `decompiled/js/assets/thing_uni_plugins/TUNIDeviceControlManager.json`)

`TUNIDeviceControlManager` (DP control incl. `yuChannel*` sync), `TUNIBLEPairingManager`,
`TUNIBluetoothManager`, `TUNIDLIPCManager` (`onPlayMessageVideoInfo/Finish`,
`onPlayMessageAudioInfo` — playback frame callbacks).

## Where each flow lives — summary for the Rust port (confidence: likely)

| Flow | JS entry | Native target |
|---|---|---|
| Account login / session | ticket (`onTicketSuccess`); real auth NOT in JS | DEX/native (task 7) |
| Cloud API + signing | `apiRequestByAtop` (atop gateway) | native sign (`t_s.bmp`, task 5) |
| Device pairing | `startDeviceActivate` (ssid/token/pid/hgwBean) | `libThingSmartLink.so` |
| Cloud control / signaling | `TUNIMQTTManager` publish/subscribe | `MqttService` + `libThingP2PSDK` |
| Live stream connect | `TUNIIPCCameraManager.connect`/`createMediaDevice` | `libThingP2PSDK` (WebRTC/PPCS) |
| Two-way talk / doorbell | `TUNIIPCDoorbellManager` | P2P + Opus (`libopus.so`) |

The "likely" label reflects that the JS gives the *contract* (method+param names)
but the wire behavior is confirmed only by cross-referencing the native strings
in re/native_libs.md (which it does, consistently).

## Secret-safety note (confidence: confirmed)
The bundles and manifests reference `password`, `localKey`, `token`, `sk`, `ak`,
`secretKey` as **schema field names only** — no literal secret VALUES are present
(a base64/hex-literal scan of the P2P/bridge bundles returned only concatenated
identifier names, e.g. `TUNIP2pFileManagerThingP2PConnectionParams` in
`decompiled/js/assets/kit_js/miniapp_P2PKit.js`). Nothing secret was copied into
this doc; raw bundle content stays under the gitignored `decompiled/js/`.
`just secret-scan` stays green.

## Limitations (confidence: confirmed — scoping caveats)
- The kit_js bundles are minified with mangled local identifiers; the *module
  boundaries and string literals* are readable, but tracing exact call graphs
  inside a kit is laborious. The TUNI manifests (un-mangled) are the reliable
  API contract and were used as the primary source.
- No cloud hostnames/endpoints are in the JS (they come from native
  `assets/thing_domains_v1` + login response, review-gate F5); JS only names the
  `atop`/`highway` gateway *kinds*.
- Actual login credential/token handling is native, so the full auth flow is
  deferred to the DEX/native analysis (task 7), only pointed at here.
