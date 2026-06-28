# Firmware OTA update path — Baby Unit (TASK-0107)

How the app checks for, triggers, and tracks a **firmware update** of the SCD921/923 baby
unit. Static RE of the decompiled Tuya device/BLE SDKs + the Philips-custom pairing strings,
cross-checked against the live (decrypted) SCD921 device record under `secrets/`. Read-only:
no firmware was pushed.

> Headline (high confidence): the SCD921/923 uses the **Tuya cloud OTA** path — a set of
> `thing.m.device.upgrade.*` mobile-API calls fronted by `IThingOta` (`getOtaInfo` →
> `startOta`/confirm) with an MQTT-pushed progress/status stream mapped onto
> `DevUpgradeStatusEnum`. The **BLE-OTA** machinery (`BleOTABean` / `OnBleUpgradeListener` /
> `BleOtaParam`, `libBleLib.so`) is generic Tuya BLE/BLE-mesh SDK code and is **NOT
> applicable** to this product: the live device is `category="sp"` (Wi-Fi smart camera) with
> capability bitmask `1` (Wi-Fi only, BLE bit unset), and there are **no paired BLE
> sub-devices/sensors** — the temp sensor is an integrated camera DP, not a BLE peripheral.
> A separate, **forced firmware self-upgrade happens at Wi-Fi-provisioning time** (the
> orange-status-LED flow), driven by the device + Philips-custom config UI, not by the
> in-app OTA check.

---

## 1. OTA manager — the public entrypoint (`IThingOta`)

The device-level OTA surface is the Tuya SDK interface `IThingOta`
(`decompiled/jadx/sources/com/thingclips/smart/sdk/api/IThingOta.java:5-19`):

```
void getOtaInfo(IGetOtaInfoCallback);          // CHECK for available firmware
void setOtaListener(IOtaListener);             // register progress/state callbacks
void startOta();                               // TRIGGER the upgrade
void cancelUpgradeFirmware(int, IResultCallback);
void changeAutoUpgradeSwitchState(int, IResultCallback);
void getAutoUpgradeSwitchState(IThingDataCallback<Integer>);
```

Concrete impl is the obfuscated device manager
`decompiled/jadx/sources/com/thingclips/sdk/device/ddppdbq.java`:
- `getOtaInfo(IGetOtaInfoCallback)` at `:2838` — the **check entrypoint** (resolves the
  `DeviceBean`, fails `11002 "device has been removed"` if unbound, otherwise queries OTA info).
- `setOtaListener(IOtaListener)` at `:3261`; `startOta()` (the **trigger**) at `:3266`.
- `cancelUpgradeFirmware` at `:2761`; `changeAutoUpgradeSwitchState` at `:2766`.
- Inbound MQTT events are translated to listener callbacks here:
  `iOtaListener.onStatusChanged(otaUpdateEventBean.getStatus(), …getFirmwareType())` at
  `:3148`, and a hard-coded `onStatusChanged(2, …)` (=UPGRADING) at `:3026/:3227/:3236`.

Confidence: **high** (interface + impl method signatures are clear despite `com.ai.ct.Tz`
anti-tamper padding around the bodies).

The check result is delivered via
`decompiled/jadx/sources/com/thingclips/smart/sdk/api/IGetOtaInfoCallback.java`
(`onSuccess(List<UpgradeInfoBean>)` / `onFailure(code,msg)`).

---

## 2. Cloud OTA — the mobile-API surface

All cloud OTA calls are built in the device SDK business class
`decompiled/jadx/sources/com/thingclips/sdk/device/bqqbpqb.java` (API-name constants at
`:35-53`) and the cleaner-named `DeviceOTABusiness`
(`decompiled/jadx/sources/com/thingclips/smart/device/ota/DeviceOTABusiness.java`).
All are `asyncRequest` POSTs over the Tuya mobile gateway with `setSessionRequire(true)`
(authenticated session — same gateway/signing as the rest of the app; see
`re/tuya_cloud_auth.md`, `re/tuya_sign.md`). Verbatim API names + version + call site:

| Purpose | API name | ver | evidence (file:line) |
|---|---|---|---|
| **Check** available firmware | `thing.m.device.upgrade.info` | 1.2 | `DeviceOTABusiness.java:27`; const `pdqppqb` `bqqbpqb.java:46` |
| **Confirm / trigger** upgrade | `thing.m.device.upgrade.confirm` | `GwBroadcastMonitorService.mVersion` | `bqqbpqb.java:851` |
| Cancel upgrade | `thing.m.device.upgrade.cancel` | 1.0 | `bqqbpqb.java:111` |
| **Report firmware version** | `thing.m.device.version.update` | 4.2 / 4.1 | `bqqbpqb.java:266` / `:1077` |
| Report OTA progress | `thing.m.device.upgrade.progress.report` | 1.0 | `bqqbpqb.java:102` |
| Update OTA status | `thing.m.device.upgrade.status.update` | 1.0 | `bqqbpqb.java:828` |
| Get upgrade process info | `thing.m.device.upgrade.process.info` | 1.1 | `bqqbpqb.java:525/1020` (const `qpppdqb`) |
| Auto-upgrade switch get / save | `thing.m.device.upgrade.auto.switch.get` / `.save` | 1.0 | `bqqbpqb.java:936` / `:1027` |
| Product-firmware confirm | `thing.m.device.product.upgrade.confirm` | — | const `qqpddqd` `bqqbpqb.java:52` |
| Local (LAN) upgrade info | `thing.m.local.device.upgrade.info` | — | const `bpbbqdb` `bqqbpqb.java:35` |
| **Camera** hardware upgrade get | `thing.m.camera.hardware.upgrade.get` | 1.0 | const `qqpdpbp` `decompiled/jadx/sources/com/thingclips/sdk/device/pqqqbbp.java:32` |
| RSSI pre-check (BLE/sub) | `thing.m.device.upgrade.rssi.info.query` | 1.1 | `bqqbpqb.java:778`; `DeviceOTABusiness.java:122` |
| Batch / family upgrade list | `m.life.device.upgrade.list` | 1.1 | `DeviceOTABusiness.java:197` |

Confidence: **high** for the names/versions/call sites (literal strings). The
camera-specific `thing.m.camera.hardware.upgrade.get` is **declared** but no call site was
found in the decompiled Java (likely invoked reflectively, gated to combo cameras, or unused
in this build) — confidence **low** on whether the SCD921 actually uses it; the generic
`thing.m.device.upgrade.*` path is the one wired through `IThingOta`.

### Firmware-version reporting (AC1)

`thing.m.device.version.update` (v4.2, `bqqbpqb.java:266`) is the version-report call. POST
body fields observed in-code: `devId`, `channel` (int), `version` (string)
(`bqqbpqb.java:267-270`, key `Names.FILE_SPEC_HEADER.VERSION`). The app reports the device's
**current** firmware version per channel; the cloud answers `thing.m.device.upgrade.info`
with the candidate new version. The current/target versions surface on the client in
`UpgradeInfoBean.currentVersion` / `.version`
(`decompiled/jadx/sources/com/thingclips/smart/android/device/bean/UpgradeInfoBean.java:24-44`,
fields `currentVersion`, `version`, `upgradeStatus`, `upgradeType`, `md5`, `sign`, `url`,
`fileSize`, `firmwareDeployTime`). Confidence: **high** (field names + call body literal).

The `thing.m.device.upgrade.info` response deserializes to `ArrayList<BLEUpgradeBean>`
(`DeviceOTABusiness.java:24,27`) and is grouped in
`DevUpgradeInfoBean { List<BLEUpgradeBean> ota; List<BLEUpgradeBean> productUpgrade; }`
(`decompiled/jadx/sources/com/thingclips/sdk/device/bean/DevUpgradeInfoBean.java:9-10`).
Note: the `BLEUpgradeBean` type name is a Tuya misnomer — it is the generic per-channel
upgrade record reused for **Wi-Fi** devices too, not BLE-specific. Confidence: **high**.

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

## 5. Provisioning-time forced firmware upgrade + status-LED semantics

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

## 6. BLE OTA — present in SDK, NOT applicable to SCD921/923 (AC2)

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
| transport | Tuya mobile API (`thing.m.device.upgrade.*`) + MQTT push; firmware fetched by the device from cloud `url`/`md5`/`sign` (`UpgradeInfoBean`) | phone streams `firmwareData` chunks to the device over **GATT** via `libBleLib.so` |
| trigger | `IThingOta.startOta()` → `thing.m.device.upgrade.confirm` | `startBleOta(BleOTABean, OnBleUpgradeListener)` |
| progress | `IOtaListener.onStatusChanged/onProgress` from MQTT | `OnBleUpgradeListener.onUpgrade(int)` from GATT notifications |
| applies to | Wi-Fi/IPC devices incl. **SCD921/923** | BLE / BLE-combo / BLE-mesh / mesh-sub devices |

The two are mutually exclusive per device and chosen by the device's capability bits +
`UpgradeModeEnum`; the SCD921 (Wi-Fi-only camera) takes the cloud path. Confidence: **high**.

---

## 7. Rust-client implications (read-only summary)

A parity Rust client does **not** need to implement firmware flashing, but to mirror the
app's UX it would:

- Call `thing.m.device.upgrade.info` (v1.2, session-signed) with the bound `devId` to learn
  whether an update exists, and parse the per-channel records (`currentVersion`, `version`,
  `upgradeStatus`, `upgradeType`, `url`, `md5`, `sign`, `fileSize`).
- Optionally report the device's running version via `thing.m.device.version.update`
  (v4.2: `devId`, `channel`, `version`).
- To trigger: `thing.m.device.upgrade.confirm`; to track: subscribe the MQTT control channel
  and map pushed status ints through `DevUpgradeStatusEnum` (0/1/2/3/4/5/6/7/13/14).
- **Do not** implement the BLE-OTA path — it is dead code for this product.
- Treat the provisioning-time forced upgrade as device-driven; the client only mirrors the
  LED-status UX (§5).

All cloud calls reuse the same session + mobile-app sign as the rest of the app
(`re/tuya_cloud_auth.md`, `re/tuya_sign.md`); no OTA-specific signing was found.

---

## Residual unknowns

- **`camera_dp_update_titile` trigger DP.** The "Upgrade Notification" string is consumed by
  the runtime-downloaded camera RN panel, not the APK; the exact DP/event that raises it was
  not located statically. *Unblock:* dump the camera panel JS bundle or capture the MQTT
  upgrade-notify message live.
- **`thing.m.device.upgrade.info` / `version.update` request+response bodies.** Field
  *names* are recovered from code; the full JSON shape (esp. the candidate-firmware record)
  was not captured. *Unblock:* a decrypted live OTA-check exchange for this device.
- **`thing.m.camera.hardware.upgrade.get` usage.** Declared but no call site in decompiled
  Java; cannot confirm the SCD921 ever calls it. *Unblock:* live trace, or deobfuscate the
  reflective dispatch.
- **Device-side firmware fetch during provisioning.** The orange-LED forced upgrade runs on
  the device↔cloud link; not present in the app. *Unblock:* a device firmware dump or a
  capture of the unit's own cloud traffic (out of scope — static app analysis only).
- **`thing.m.device.upgrade.confirm` API version** resolves to
  `GwBroadcastMonitorService.mVersion` (a runtime constant) rather than a literal — the exact
  version string was not resolved. Cosmetic.

## Evidence index

- Public OTA API: `com/thingclips/smart/sdk/api/IThingOta.java:5-19`,
  `IGetOtaInfoCallback.java`, `IOtaListener.java`, `IExtOtaListener.java`, `IDevOTAListener.java`
- OTA manager impl: `com/thingclips/sdk/device/ddppdbq.java:2761,2766,2838,3026,3148,3261,3266`
- Cloud OTA business: `com/thingclips/sdk/device/bqqbpqb.java:35-53,102,111,266,525,778,828,851,936,1020,1027,1077`;
  `com/thingclips/smart/device/ota/DeviceOTABusiness.java:24,27,122,197`;
  camera: `com/thingclips/sdk/device/pqqqbbp.java:32`
- Beans/enums: `com/thingclips/smart/android/device/bean/UpgradeInfoBean.java:10-22,24-44`;
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
- Live device class (product-level fields only, PII not quoted):
  `secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke*.json` (`category="sp"`, `capability=1`)
</content>
</invoke>
