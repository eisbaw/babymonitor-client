# Firmware OTA update and acquisition path — Baby Unit (TASK-0107/TASK-0127)

How the app checks for, offers, triggers, and tracks a firmware update of the SCD921/923
baby unit, and what can actually be acquired without starting an update. Evidence combines
static RE of the decompiled Philips/Tuya APK, the recorded decrypted settings-screen call,
and an owner-authorized **read-only** live validation on 2026-07-16. No confirm, start,
cancel, version-report, or other OTA mutation was called.

> **Live metadata result (confidence: confirmed):** the current camera Settings UI checks
> `m.thing.firmware.upgrade.info.get` v1.1 with only `{devId}`. Its
> `BLEUpgradeBean`/`UpgradeInfoBean` response model can represent `version`, `url`, `md5`,
> `sign`, and `fileSize`. On 2026-07-16, both this primary endpoint and the legacy
> `thing.m.device.upgrade.info` v1.2 endpoint returned success with two firmware-channel
> records. Every record had the server-reported `currentVersion="1.4.0"`, with no offered
> version, URL, MD5, signature, or size. The observed no-offer responses therefore supplied
> no way to retrieve package bytes, but they do not prove when candidate URLs are populated
> and do not rule out an undocumented/archive API.
>
> **Package acquisition result (confidence: likely; loopback transfer only):** the Rust
> client has a no-confirm downloader for a future metadata URL, but no real URL was returned
> and no Tuya package/CDN transfer has succeeded yet. With the currently identified surfaces,
> obtaining the exact installed flash bytes still requires device-shell access or physical
> flash/UART/SPI extraction. The separate direct-AP model has a `diffOta` field; the queried
> v1.1/v1.2 response models do not.
>
> The normal Wi-Fi trigger is a separate call,
> `m.thing.firmware.upgrade.confirm` v1.0, carrying only `devId` and firmware `types`; the
> official phone path does not download or upload the bytes. The camera subsequently fetches
> the package. The read-only validation and CLI described below never call that endpoint.

The bundled BLE/BLE-mesh OTA machinery is generic Tuya SDK code and is **not applicable** to
this Wi-Fi-only camera. The provisioning-time orange-LED forced update is also distinct from
the in-app Settings check.

---

## 1. Current Settings UI check path (confidence: confirmed)

The exact active camera-settings chain is:

1. `CameraSettingPresenter.handleMessage`, message `1025`, calls
   `UrlRouterUtils.gotoOTAPanel(...)`
   (`decompiled/jadx/sources/com/thingclips/smart/ipc/panelmore/presenter/CameraSettingPresenter.java:4583-4585`).
2. `UrlRouterUtils.gotoOTAPanel` calls `OTAManagerUtils.checkUpgradeFirmware`
   (`decompiled/jadx/sources/com/thingclips/smart/camera/base/utils/UrlRouterUtils.java:3248-3249`).
3. `OTAManagerUtils.checkUpgradeFirmware` resolves `AbsOTACheckService` and calls `h1`
   (`decompiled/jadx/sources/com/thingclips/smart/camera/base/ota/OTAManagerUtils.java:23-27`).
4. `OTACheckService.h1` obtains `IOtaUseCase`/`IOtaLogicPlugin` and calls plugin method `f`
   (`decompiled/jadx/sources/com/thingclips/smart/panel/newota/OTACheckService.java:1070-1092,1119-1170`).
5. `DefaultOtaLogicPlugin.f` calls
   `IThingOTAService.getFirmwareUpgradeInfo(...)`
   (`decompiled/jadx/sources/com/thingclips/smart/ota/biz/logic/DefaultOtaLogicPlugin.java:1292,1365-1370`).
6. `ThingSmartOTAService` (obfuscated class `dqqdbpp`) and its wrapper `pbbqpqd` delegate to
   `OtaCenterBusiness` (obfuscated class `bqqbpqb`):
   `dqqdbpp.java:2612-2626,3467-3518`, `pbbqpqd.java:3080-3081`, and
   `bqqbpqb.java:1019-1023`.
7. `OtaCenterBusiness.pppbppp` constructs
   `ApiParams("m.thing.firmware.upgrade.info.get", "1.1")`, requires a session, adds only
   `devId`, and deserializes an array of `BLEUpgradeBean`.

The `BLEUpgradeBean` name is misleading: it extends `UpgradeInfoBean` and is reused for
Wi-Fi OTA records. Its added fields are `fileSize`, `md5`, `sign`, and `url`
(`decompiled/jadx/sources/com/thingclips/smart/android/blemesh/bean/BLEUpgradeBean.java:7-11`);
the base bean holds `currentVersion`, offered `version`, status/type/mode, and the same
candidate metadata surface
(`decompiled/jadx/sources/com/thingclips/smart/android/device/bean/UpgradeInfoBean.java:20-43`).
Firmware `sign` is metadata returned inside the authenticated response; it is distinct from
the mobile API request signature. The APK trace does not establish its verification
algorithm or prove that the downloaded firmware body is encrypted.

### Legacy SDK check surface (confidence: confirmed)

The older `IThingOta` API still exists
(`decompiled/jadx/sources/com/thingclips/smart/sdk/api/IThingOta.java:5-19`), implemented by
`ddppdbq.java` (`getOtaInfo` at `:2838`, `setOtaListener` at `:3261`, and mutating
`startOta` at `:3266`). Its cleaner business wrapper sends
`thing.m.device.upgrade.info` v1.2 with the same `{devId}` and `BLEUpgradeBean[]` response
(`decompiled/jadx/sources/com/thingclips/smart/device/ota/DeviceOTABusiness.java:24-30`).
This is a useful read-only fallback, but it is **not** the endpoint selected by the captured
camera Settings UI chain above.

---

## 2. Cloud OTA API boundary and live result (confidence: confirmed)

The relevant calls are authenticated Tuya mobile-gateway requests with
`setSessionRequire(true)` and the normal encrypted/signed request envelope described in
`re/tuya_cloud_auth.md` and `re/tuya_sign.md`.

| Purpose | API name | ver | request fields | evidence |
|---|---|---:|---|---|
| **Current Settings check** | `m.thing.firmware.upgrade.info.get` | 1.1 | `devId` | `bqqbpqb.java:1019-1023`; captured Settings call |
| Legacy read-only check | `thing.m.device.upgrade.info` | 1.2 | `devId` | `DeviceOTABusiness.java:24-30` |
| **Current Wi-Fi confirm/trigger** | `m.thing.firmware.upgrade.confirm` | 1.0 | `devId`, comma-separated `types` | `bqqbpqb.java:1011-1016` |
| Legacy confirm/trigger | `thing.m.device.upgrade.confirm` | 3.0 | `devId`, one `type` | `bqqbpqb.java:851-857`; literal version at `GwBroadcastMonitorService.java:45` |
| Current cancel | `m.thing.firmware.upgrade.cancel` | 1.0 | mutation | `bqqbpqb.java:288`; constant at `:39` |
| Legacy cancel | `thing.m.device.upgrade.cancel` | 1.0 | mutation | `bqqbpqb.java:111`; constant at `:47` |
| Report firmware version | `thing.m.device.version.update` | 4.2 | `devId`, `channel`, `version` | `bqqbpqb.java:266-270` |
| Legacy version report | `thing.m.device.version.update` | 4.1 | `devId`, `softVer`, `type=1` | `bqqbpqb.java:1076-1082` |
| Report OTA progress | `thing.m.device.upgrade.progress.report` | 1.0 | mutation | `bqqbpqb.java:102` |
| Update OTA status | `thing.m.device.upgrade.status.update` | 1.0 | mutation | `bqqbpqb.java:828` |
| Get upgrade process info | `thing.m.device.upgrade.process.info` | 1.1 | status query | `bqqbpqb.java:525` |
| Auto-upgrade switch get/save | `thing.m.device.upgrade.auto.switch.get` / `.save` | 1.0 | query/mutation | `bqqbpqb.java:936,1027` |
| Direct-AP upgrade info | `thing.m.local.device.upgrade.info` | 1.0 | `devId`, `types`, `versions` | `bqqbpqb.java:477-483` |
| Camera hardware upgrade get | `thing.m.camera.hardware.upgrade.get` | unresolved | unresolved | action constant in `pqqqbbp.java:32`; no Java call site found |

### 2026-07-16 owner-query result (confidence: likely from committable evidence)

The primary v1.1 request and legacy v1.2 fallback each returned `success=true` and two
channel records. Every record reported `currentVersion="1.4.0"`; this is a server-reported
metadata value, not a readback of installed flash bytes. Neither endpoint returned an
offered `version`, `url`, `md5`, `sign`, or `fileSize`, so the run made no package/CDN
request.
The result is consistent with the earlier recorded Settings exchange in
`emulator_captures/cap3/flows.json:3561`, whose decrypted request also contains only
`devId` and whose two no-update records omit the same candidate fields.
The two fresh response sources were retained privately and separately; their account-linked
contents are intentionally not committed or quoted. The current CLI similarly stores
primary and optional legacy responses as distinct files in each immutable acquisition.
The post-hardening CLI was **not** queried live again because the owner session available
during that validation was expired/inside the refresh window and rejected before network work. Thus
the result above remains the latest live evidence; the hardening claims in section 7 are
code- and test-backed, not evidence of a newer server response.

This closes the earlier uncertainty about the observed no-offer request/response shape, but
it does not show a populated candidate record or establish the package/CDN behavior. The
Java model is evidence that the response type can carry a URL and integrity/signature
metadata; it neither proves that a future offer will populate every field nor establishes
whether Tuya maintains a separate downloadable archive.

### Why normal Wi-Fi OTA is device-side

The UI trigger method `DefaultOtaLogicPlugin.g` passes the selected records to
`IThingOTAService.startFirmwareUpgrade`
(`DefaultOtaLogicPlugin.java:1596-1662`). The SDK selects `ThingOTAWIFITask` (`dpqqpqq`) and
reduces the selected list to sorted, comma-separated firmware `type` values
(`decompiled/jadx/sources/com/thingclips/sdk/device/bdpqqdq.java:2063-2129,3196-3223`).
`ThingOTAWIFITask` then confirms with only the device ID and those types
(`decompiled/jadx/sources/com/thingclips/sdk/device/dpqqpqq.java:1466-1575,1689-1706`),
ending at the v1.0 confirm call above. URL, MD5, signature, file path, size, and firmware
bytes are not sent by this phone-side task.

As a negative cross-check, `getUrl()` is used by the Mesh, BLE, and direct-AP local flows
(`MeshOtaModel.java:585`, `FirmwareUpgradeBLEModel.java:329`,
`ApConnectionOtaAutoChecker.java:684`, `pdpqqpp.java:1981`, `qbqpbbd.java:2110`) but not by
`ThingOTAWIFITask` (`dpqqpqq.java`). Thus the official paired Wi-Fi path tells the device
which channels to update; it does not stream the package from the phone.

### Direct-AP/delta-package nuance (confidence: confirmed)

The separate direct-AP model `FirmwareUpgradeInfoBean` adds `diffOta`, local `filePath`, and
`hmac` to the URL/MD5/signature fields
(`decompiled/jadx/sources/com/thingclips/smart/device/bean/FirmwareUpgradeInfoBean.java:7-13`).
That path downloads the URL in the app (`ApConnectionOtaAutoChecker.java:662-686`), validates
the cached file's MD5, then supplies file length, HMAC, `isDiffOta`, channel/version, and the
local path to the LAN OTA engine (`decompiled/jadx/sources/com/thingclips/sdk/device/pdddqqd.java:167-185`).
It is not the normal SCD921 paired-Wi-Fi path. More importantly for acquisition, a candidate
marked `diffOta=true` may be usable only as a patch against a particular base release; it
must not be described as a complete dump of the installed flash.

---

## 3. OTA state machine

The authoritative status enum is `DevUpgradeStatusEnum`
(`decompiled/jadx/sources/com/thingclips/sdk/device/enums/DevUpgradeStatusEnum.java:7-18`):

| name | code | meaning |
|---|---|---|
| DEFAULT | 0 | idle / no upgrade |
| READY | 1 | firmware available, not started |
| UPGRADING | 2 | flashing in progress |
| SUCCESS | 3 | completed OK |
| FAILURE | 4 | failed |
| WAITEXE | 5 | command sent, device queued to execute |
| DOWNLOADED | 6 | firmware downloaded (device-side) |
| TIMEOUT | 7 | timed out |
| PENDING | 13 | pending |
| PREPARATION | 14 | preparing |
| LOCALPREPARE | 100 | local (LAN/BLE direct) prepare |
| OTA_DEVICE_PID_TYPE | -101 | PID/type mismatch error |

These line up with the older constants on `UpgradeInfoBean`
(`UpgradeInfoBean.java:10-22`): `UPGRADE_STATUS_DEFAULT=0`, `READY=1`, `UPGRADING=2`,
`UPGRADE_STAUS_COMMAND_SEND=5`, `PENDING=13`, `PREPARE=14`; and the upgrade-**type**
constants `UPGRADE_TYPE_REMIND=0`, `UPGRADE_TYPE_FORCED=2`, `UPGRADE_TYPE_CHECKING=3`
(+ `controlType` `UPGRADE_CAN_CONTROL=1` / `NOT_CONTROL=0`). Upgrade **mode**:
`UpgradeModeEnum { OTA(0), PID(1) }`
(`decompiled/jadx/sources/com/thingclips/sdk/device/enums/UpgradeModeEnum.java:7-8`) — the
SCD921 path is `OTA(0)` (cloud), `PID(1)` is the accessory/product-firmware variant.
Confidence: **high** (literal enum bodies).

Progress/state is surfaced to the app through `IOtaListener`
(`decompiled/jadx/sources/com/thingclips/smart/sdk/api/IOtaListener.java`):
`onStatusChanged(int channel, int status)`, `onProgress(int channel, int percent)`,
`onSuccess(int)`, `onFailure(int, code, msg)`, `onFailureWithText(int, msg, OTAErrorMessageBean)`,
`onTimeout(int)`. (`IExtOtaListener` adds a 3-arg `onProgress`.)

---

## 4. Notify path — how the app learns an update happened

Two channels (confidence **high** on existence, **medium** on exact wire payload, which is
runtime/MQTT and not fully in the APK):

1. **MQTT push → listener.** The device pushes upgrade events over the Tuya MQTT control
   channel; `ddppdbq.java` decodes them into `otaUpdateEventBean` / `otaProgressEventBean`
   and calls `onStatusChanged(status, firmwareType)` (`ddppdbq.java:3148`, `:3026`). The
   richer device-OTA push bean is `ThingDevUpgradeStatusBean`
   (`decompiled/jadx/sources/com/thingclips/smart/device/bean/ThingDevUpgradeStatusBean.java:9-20`:
   `devId, errorCode, errorMsg, firmwareType, groupId, isGroupOTA, progress, remainTime,
   status:DevUpgradeStatusEnum, statusText, statusTitle, upgradeModeEnum`), delivered via
   `IDevOTAListener.firmwareUpgradeStatus(...)`
   (`decompiled/jadx/sources/com/thingclips/smart/sdk/api/IDevOTAListener.java`). A
   product-firmware MQTT event also exists:
   `ProductUpgradeEvent.onEvent(ProductUpgradeEventBean)`
   (`decompiled/jadx/sources/com/thingclips/sdk/device/event/ProductUpgradeEvent.java`;
   bean fields `devId, eventData{nodeId}, eventType`,
   `decompiled/jadx/sources/com/thingclips/sdk/device/bean/ProductUpgradeEventBean.java:7-13`).

2. **UI notification string.** `camera_dp_update_titile` = "Upgrade Notification"
   (`decompiled/apktool/res/values/strings.xml:1659`, R id `0x7f1305eb` at
   `decompiled/jadx/sources/com/philips/ph/babymonitorplus/R.java:18571`). This string is
   **not referenced from smali or the bundled JS** (grep negative) → it is consumed by the
   runtime-downloaded camera React-Native panel, so its exact trigger DP could not be pinned
   statically. Confidence: **medium** (string exists and is camera-OTA-labelled; wiring is
   in the un-bundled panel).

---

## 5. Provisioning-time forced firmware upgrade + status-LED semantics (confidence: confirmed)

Distinct from the in-app OTA check, the baby unit performs a **forced self-upgrade during
Wi-Fi setup**. This is a Philips-custom config screen (`config_activity_update_device`,
layout owned by the Philips app: `R.java` id `0x7f0d0256` at
`decompiled/jadx/sources/com/philips/ph/babymonitorplus/R.java:15720`; layout
`decompiled/apktool/res/layout/config_activity_update_device.xml:7-10` binds the four tip
strings). The flow + **status-LED semantics** come from the Philips strings
(`decompiled/apktool/res/values/strings.xml`):

- `:2779` `firmware_upgrade_process_1` — "Your baby monitor requires an upgrade to the latest
  firmware."
- `:2780` `firmware_upgrade_process_2` — after the unit reads the **Wi-Fi QR code**, the
  status light: **blink green → solid red → (after 15 s) solid orange** for **≥10 min** (do
  not touch).
- `:2782` `firmware_upgrade_process_4` — after ~10 min it **auto-upgrades**; status light
  **blinks orange** while upgrading; on success **Wi-Fi status light + nightlight (2) go
  solid orange**; then tap Continue to finish Wi-Fi setup.
- `:1124` `bm_blinking_orange_desc` — "Baby Unit firmware is being updated." paired with
  `:1123` `bm_blinking_orange` = "Blinking orange"; surfaced by the connection-lost LED
  status screen `decompiled/apktool/res/layout/activity_connectlost_color_led.xml:10`
  (`StatusIndicatorView … statusSubTitle="@string/bm_blinking_orange_desc"`).

Status-LED → state mapping (high confidence, from the literal strings):

| LED | meaning |
|---|---|
| blinking green | reading the Wi-Fi QR / connecting |
| solid red | post-QR, pre-upgrade settle (15 s) |
| solid orange (≥10 min) | firmware download/prepare in progress |
| blinking orange | actively flashing firmware |
| solid orange (Wi-Fi light + nightlight) | upgrade complete, ready to continue |

This provisioning-time upgrade is driven by the **device firmware itself** once it has Wi-Fi;
the app side is the informational `config_activity_update_device` screen. The exact handshake
the device uses to fetch that firmware is on the **device↔cloud** side and is **not
statically recoverable** from the app. Confidence: **high** on the LED semantics / UX flow;
**low** on the device-side fetch protocol.

---

## 6. BLE OTA — present in SDK, NOT applicable to SCD921/923 (AC2) (confidence: confirmed)

The app bundles the full Tuya BLE/BLE-mesh OTA stack. The start-from evidence resolves to:

- `BleOtaParam { byte[] firmwareData; String productId; int type; String version; }`
  (`decompiled/jadx/sources/com/thingclips/sdk/ble/core/protocol/entity/BleOtaParam.java`).
- `OnBleUpgradeListener { onUpgrade(int progress); onSuccess(); onFail(code,msg); }`
  (`decompiled/jadx/sources/com/thingclips/smart/android/ble/api/OnBleUpgradeListener.java`).
- `BleOTABean(uuid, type, version, binPackagePath, nodeId, devId)` (+ `accessoriesPid`, `pid`)
  (`decompiled/jadx/sources/com/thingclips/smart/android/ble/bean/BleOTABean.java:6-24`).
- **Entrypoint** `startBleOta(BleOTABean, OnBleUpgradeListener)` at
  `decompiled/jadx/sources/com/thingclips/sdk/bluetooth/dqqdbqp.java:3591` (overloads `:3630`,
  `:3703`; `cancelBleOta` `:291`).
- **Transfer engine** `otaDevice(BleOtaParam, ActionOtaResponse)` at
  `decompiled/jadx/sources/com/thingclips/sdk/bluetooth/bbbdqpb.java:3429`, which builds the
  chunked data model from `type/version/firmwareData`
  (`:3431` `new …(mBleOtaParam.type, …version, …firmwareData)`), writes the OTA command frame
  carrying the `type` byte over GATT (`:4085`), and signals `onOtaSuccess(mBleOtaParam.type)`
  (`:1795`). The native backing library `libBleLib.so` is present at
  `decompiled/nativelibs/libBleLib.so`.
- Higher-level UI/use-case wrappers exist too: `BleOtaUseCase`
  (`.../com/thingclips/smart/ota/biz/usecase/BleOtaUseCase.java`),
  `NewFirmwareUpgradeBLEPresenter`, `FirmwareUpgradeBLEModel`.

**Applicability verdict for SCD921/923: NOT applicable.** Evidence (confidence **high**):

- The live device record is `category="sp"` (Tuya **Smart Camera**) with capability bitmask
  `capability=1` — only the Wi-Fi capability bit is set; the BLE capability bit is **unset**.
  (Extracted from the captured device schema; product-level fields only, no PII —
  `secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke*.json`. The exact `devId`/`meshId`
  values are **not** quoted here per the project secret rule.)
- The manifest declares BLE as **optional**:
  `decompiled/apktool/AndroidManifest.xml:26-27`
  (`android.hardware.bluetooth` / `bluetooth_le` `android:required="false"`),
  with only the legacy `BLUETOOTH` / `BLUETOOTH_ADMIN` perms (`:78,:81`) — i.e. BLE is a
  generic app capability for *other* Tuya products, not a hard requirement of this app.
- The captured SCD921 schema contains **no** BLE/blemesh/`bleDirect` keys (grep negative),
  and **no paired BLE sub-device** is present. The room-temperature reading is an integrated
  camera DP (`sensor_temperature`, see `re/environment_sensors.md`), not a BLE peripheral.

### Cloud-OTA vs BLE-OTA boundary (AC2)

| axis | Cloud OTA (this device) | BLE OTA (not this device) |
|---|---|---|
| selector | `UpgradeModeEnum.OTA(0)` | BLE-direct / mesh path |
| transport | Tuya metadata/confirm APIs + MQTT push; after confirm, firmware is fetched by the device | phone downloads and streams `firmwareData` chunks over **GATT** via `libBleLib.so` |
| current trigger | `IThingOTAService.startFirmwareUpgrade(...)` → `m.thing.firmware.upgrade.confirm` v1.0 | `startBleOta(BleOTABean, OnBleUpgradeListener)` |
| progress | `IOtaListener.onStatusChanged/onProgress` from MQTT | `OnBleUpgradeListener.onUpgrade(int)` from GATT notifications |
| applies to | Wi-Fi/IPC devices incl. **SCD921/923** | BLE / BLE-combo / BLE-mesh / mesh-sub devices |

The two are mutually exclusive per device and chosen by the device's capability bits +
`UpgradeModeEnum`; the SCD921 (Wi-Fi-only camera) takes the cloud path. Confidence: **high**.

---

## 7. Safe Rust CLI acquisition (confidence: likely)

The explicitly experimental `FirmwareWipAction`/`run_firmware_wip` CLI path delegates to
`fetch_firmware_candidates`.
That acquisition path uses `PRIMARY_ENDPOINT` and `LEGACY_ENDPOINT`; it contains no call to
either confirm action and does not define a start/cancel operation (symbol-oriented
implementation anchors:
`babymonitor/babymonitor-cli/src/main.rs` and
`babymonitor/babymonitor-cli/src/live/firmware.rs`). The read-only and confirm action
constants that this boundary mirrors are separate symbols in
`decompiled/jadx/sources/com/thingclips/sdk/device/bqqbpqb.java`.

Query and privately capture metadata without downloading package bytes:

```sh
nix-shell --run 'cargo run --manifest-path babymonitor/Cargo.toml -p babymonitor-cli --features live -- firmwareWIP info'
```

Query metadata and download every package that is currently offered by URL:

```sh
nix-shell --run 'cargo run --manifest-path babymonitor/Cargo.toml -p babymonitor-cli --features live -- firmwareWIP download'
```

Both commands require the existing owner session and the key-proven device ID from the
private LAN config. They query the captured Settings endpoint first and use the legacy v1.2
check when the primary response has no URL. Neither command calls
`m.thing.firmware.upgrade.confirm`, `thing.m.device.upgrade.confirm`, or any other OTA
mutation, so running `firmwareWIP download` does **not** instruct the camera to update.

The pre-request trust boundary fails closed:

- `SessionStore::load`, `PinnedStoreDirectory::open_read`, `validate_directory_metadata`, and
  `reject_unsafe_file_mode` in `babymonitor/babymonitor-core/src/session.rs` require, on
  Unix, an `O_NOFOLLOW`-opened regular session file with mode exactly `0600` under a real,
  non-symlink parent that is not group- or world-writable. `PinnedStoreDirectory` holds the
  validated parent descriptor through load/save/clear and performs file operations relative
  to it, closing the ancestor-swap gap between validation and use.
- `Session::needs_refresh_at` applies a two-minute buffer, and `ensure_session_fresh` rejects
  an expired or near-expiry owner session before gateway resolution, signing, or network
  work.
- `host_from_mobile_api_base` accepts only HTTPS, port 443, `/` or `/api.json`, no
  credentials/query/fragment, and an exact host from the app-evidenced gateway allowlist.
  Invalid session routing has no implicit regional fallback.
- `build_firmware_client` disables redirects. `send_atop_without_debug_capture` passes atop
  responses through `read_bounded_body`, which rejects both a declared length and an actual
  streamed body above `MAX_ATOP_RESPONSE_BYTES` (2 MiB). These are symbols in
  `babymonitor/babymonitor-cli/src/live.rs` and
  `babymonitor/babymonitor-cli/src/live/firmware.rs`.

The evidence boundary is important:

- The owner-authenticated primary and legacy **metadata** calls are live-confirmed in the
  observed no-offer state.
- Package URL handling, streamed transfer, size enforcement, and MD5/SHA-256 plumbing are
  covered by a literal-loopback fixture. No real candidate URL, CDN response, server hash,
  or package has yet exercised that path.

Private captures may contain signed URLs, hashes, signatures, and device/account correlation
data: keep the selected `<SECRETS_DIR>` gitignored and do not paste or commit it. After the
metadata query succeeds, `AcquisitionStage` and `publish_acquisition` build a unique private
staging directory (mode `0700` with mode-`0600` files on Unix). It contains
`primary-response.json`, the conditional `legacy-response.json`, `manifest.json`, and any
verified candidate. A later run cannot overwrite an earlier acquisition's
response/hash/signature provenance.

`AcquisitionManifest`, `ManifestGateway`, and `ManifestEndpoint` bind the raw responses to
the fetch time, info/download operation, validated gateway shape (`https`, host, port 443,
`/api.json`), exact action/version, read-only/session-required status, and request-field
shape (`devId`). The raw device ID is not stored in the manifest; its SHA-256 is retained
privately as `device_id_sha256`. The manifest also records legacy-query status,
`upgrade_request_sent: false`, per-channel private server metadata, expected size/MD5,
signature presence, and `signature_verified: false`. A verified artifact adds its actual
size, MD5, and SHA-256.

The manifest's `completed` and optional `failure_class` are intentionally not equivalent to
"a directory exists." URL/MD5 preflight, transport or HTTP status, size/cap, MD5 mismatch,
and storage failures after metadata capture publish `completed: false` provenance with a
bounded failure class and the raw endpoint response(s). `PartialPackage` removes the current
unverified `.part`; if a previous channel in the same run already passed size and MD5
verification, that verified sibling remains and is referenced by the failure manifest.
This behavior is covered around `AcquisitionFailureClass`, `stream_firmware_record`, and
`publish_acquisition` in `babymonitor/babymonitor-cli/src/live/firmware.rs`. A failure before
metadata querying has produced capturable provenance does not publish such an acquisition.

Public output has a narrower contract than the private manifest. `firmware_summary` reports:

- `package_url_present`: the server supplied a non-empty URL field;
- `integrity_metadata_present`: the server supplied a non-empty MD5 field, even if malformed;
- `download_eligible`: both are present, the URL passes the production HTTPS policy, and the
  MD5 is exactly 32 hexadecimal characters.

`download_eligible` is preflight information, not a promise that HTTP status, transfer,
size, or post-download digest verification will succeed. `public_firmware_version` exposes
only a short, ASCII, version-like current/offered token that does not embed the device ID or
package URL; rejected server strings become unknown/null. `stream_firmware_record` names an
artifact from only its record index and locally derived source/channel labels, never a
server-supplied version string.

Production package downloads require HTTPS and refuse redirects. HTTP is permitted only by
a test-only policy restricted to literal loopback addresses. The body is streamed with a
512 MiB cap and is retained only after optional declared-size and mandatory authenticated
MD5 checks; SHA-256 is recorded for stronger local provenance. Server `sign` presence is
recorded, but its verification remains explicitly false because the algorithm/key are
unknown.

`PinnedPrivateDirectory` retains validated parent/staging descriptors for child creation,
file writes, cleanup, verified-package installation, and publication. All names are resolved
relative to those descriptors. Publication is genuinely no-clobber only on Linux:
`PinnedPrivateDirectory::rename_noreplace` uses `renameat2(RENAME_NOREPLACE)`, after
individual file fsyncs and a staged-directory fsync, then fsyncs the held parent descriptor.
The non-Linux path returns an error, so acquisition publication fails closed instead of
claiming portable atomic no-clobber behavior. Ancestor-swap tests pin this boundary. These
protections are locally tested, but do not establish compatibility with a real Tuya CDN
response.

In the 2026-07-16 no-offer run, `firmwareWIP download` had no URL and therefore fetched no
package. The two queried endpoint models do not contain `diffOta`; do not classify any future
v1.1/v1.2 candidate as a delta without evidence from its actual metadata or package. The
server-reported current version is not an installed-image readback. With the currently
identified interfaces, exact installed bytes require device-shell access or a physical
flash/UART/SPI dump; an undiscovered archive interface remains possible.

---

## Residual unknowns (confidence: speculative)

These gaps are bounded by the captured no-offer responses and APK model surface:

- **Populated candidate response and package format.** Both live endpoints returned the
  observed no-offer shape, so URL lifetime, real CDN behavior, populated `sign` semantics,
  package container format, and payload encryption remain unproven. The `hmac`/`diffOta`
  fields belong to the separate direct-AP `FirmwareUpgradeInfoBean` model, not to the queried
  `BLEUpgradeBean` model
  (`decompiled/jadx/sources/com/thingclips/smart/device/bean/FirmwareUpgradeInfoBean.java:7-13`).
  *Unblock:* analyze a privately retained artifact if these endpoints genuinely return a
  candidate URL.
- **Archive availability and exact flash bytes.** The checked endpoints did not return an
  image for server-reported version 1.4.0, but this is not an exhaustive proof that no
  undocumented/archive API exists. *Unblock:* discover such a surface, or use device
  shell/root access, UART, or physical SPI/NAND/eMMC extraction.
- **`camera_dp_update_titile` trigger DP.** The "Upgrade Notification" string is consumed by
  the runtime-downloaded camera RN panel, not the APK; the exact DP/event that raises it was
  not located statically. *Unblock:* dump the camera panel JS bundle or capture the MQTT
  upgrade-notify message live.
- **`thing.m.camera.hardware.upgrade.get` usage.** Declared but no call site in decompiled
  Java; cannot confirm the SCD921 ever calls it. *Unblock:* live trace, or deobfuscate the
  reflective dispatch.
- **Device-side firmware fetch during provisioning.** The orange-LED forced upgrade runs on
  the device↔cloud link; not present in the app. *Unblock:* a device firmware dump or a
  capture of the unit's own cloud traffic.

## Evidence index

- Current Settings UI chain:
  `com/thingclips/smart/ipc/panelmore/presenter/CameraSettingPresenter.java:4583-4585`;
  `com/thingclips/smart/camera/base/utils/UrlRouterUtils.java:3248-3249`;
  `com/thingclips/smart/camera/base/ota/OTAManagerUtils.java:23-27`;
  `com/thingclips/smart/panel/newota/OTACheckService.java:1070-1092,1119-1170`;
  `com/thingclips/smart/ota/biz/logic/DefaultOtaLogicPlugin.java:1292,1365-1370`
- Current query/confirm business:
  `com/thingclips/sdk/device/dqqdbpp.java:2612-2626,3467-3518`;
  `com/thingclips/sdk/device/pbbqpqd.java:3080-3081`;
  `com/thingclips/sdk/device/bqqbpqb.java:35-53,1011-1023`
- Normal Wi-Fi trigger task:
  `com/thingclips/smart/ota/biz/logic/DefaultOtaLogicPlugin.java:1596-1662`;
  `com/thingclips/sdk/device/bdpqqdq.java:2063-2129,3196-3223`;
  `com/thingclips/sdk/device/dpqqpqq.java:1466-1575,1689-1706`
- Public OTA API: `com/thingclips/smart/sdk/api/IThingOta.java:5-19`,
  `IGetOtaInfoCallback.java`, `IOtaListener.java`, `IExtOtaListener.java`, `IDevOTAListener.java`
- OTA manager impl: `com/thingclips/sdk/device/ddppdbq.java:2761,2766,2838,3026,3148,3261,3266`
- Legacy and ancillary cloud OTA business:
  `com/thingclips/sdk/device/bqqbpqb.java:102,111,266,525,778,828,851,936,1027,1077`;
  `com/thingclips/smart/device/ota/DeviceOTABusiness.java:24-30,122,197`;
  `com/thingclips/smart/android/hardware/service/GwBroadcastMonitorService.java:45`;
  camera: `com/thingclips/sdk/device/pqqqbbp.java:32`
- Beans/enums: `com/thingclips/smart/android/blemesh/bean/BLEUpgradeBean.java:7-11`;
  `com/thingclips/smart/android/device/bean/UpgradeInfoBean.java:10-43`;
  `com/thingclips/smart/device/bean/FirmwareUpgradeInfoBean.java:7-13`;
  `com/thingclips/sdk/device/bean/DevUpgradeInfoBean.java:9-10`;
  `com/thingclips/sdk/device/enums/DevUpgradeStatusEnum.java:7-18`;
  `com/thingclips/sdk/device/enums/UpgradeModeEnum.java:7-8`;
  `com/thingclips/smart/device/bean/ThingDevUpgradeStatusBean.java:9-20`;
  `com/thingclips/sdk/device/bean/ProductUpgradeEventBean.java:7-13`;
  `com/thingclips/sdk/device/event/ProductUpgradeEvent.java`
- BLE OTA: `com/thingclips/sdk/ble/core/protocol/entity/BleOtaParam.java`;
  `com/thingclips/smart/android/ble/api/OnBleUpgradeListener.java`;
  `com/thingclips/smart/android/ble/bean/BleOTABean.java:6-24`;
  `com/thingclips/sdk/bluetooth/dqqdbqp.java:291,3591,3630,3703`;
  `com/thingclips/sdk/bluetooth/bbbdqpb.java:1795,3429,3431,4085`;
  `decompiled/nativelibs/libBleLib.so`
- Strings / LED / provisioning UI: `apktool/res/values/strings.xml:1123,1124,1659,2779,2780,2781,2782`;
  `apktool/res/layout/config_activity_update_device.xml:7-10`;
  `apktool/res/layout/activity_connectlost_color_led.xml:10`;
  `com/philips/ph/babymonitorplus/R.java:15720,18571`
- Manifest BLE: `apktool/AndroidManifest.xml:26-27,78,81`
- Recorded Settings check: `emulator_captures/cap3/flows.json:3561`
- Read-only CLI implementation: `babymonitor/babymonitor-cli/src/main.rs` (`FirmwareWipAction`,
  `run_firmware_wip`); `babymonitor/babymonitor-core/src/session.rs` (`SessionStore::load`,
  `Session::needs_refresh_at`, `PinnedStoreDirectory::open_read`,
  `validate_directory_metadata`);
  `babymonitor/babymonitor-cli/src/live.rs` (`host_from_mobile_api_base`,
  `read_bounded_body`, `PinnedPrivateDirectory::atomic_write`,
  `PinnedPrivateDirectory::rename_noreplace`);
  `babymonitor/babymonitor-cli/src/live/firmware.rs` (`PRIMARY_ENDPOINT`, `LEGACY_ENDPOINT`,
  `fetch_firmware_candidates`, `firmware_summary`, `public_firmware_version`,
  `stream_firmware_record`, `publish_acquisition`)
- Live device class (product-level fields only, PII not quoted):
  `secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke*.json` (`category="sp"`, `capability=1`)
