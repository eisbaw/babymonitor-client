# Device settings & diagnostics DP family (privacy mode, volume, mic sensitivity, status light, restart, battery, wifi signal, time/zone, privacy zones)

**Scope.** This consolidates the remaining Tuya camera "device control + diagnostics" surface for
the SCD921 as exposed by the white-labeled Philips app: **privacy mode** (the baby-monitor-notable
lens/mic-off toggle + its blue-LED indicator copy), device **speaker volume**, **microphone
sensitivity**, **status/indicator-light** toggle, remote **restart**, **battery** level/reporting,
**wifi signal** (RSSI), system **time-format / timezone**, and **privacy-zone polygon** masking.
It is the diagnostics/settings companion to `re/camera_image_settings.md` (image/quality DPs),
`re/ptz_control.md`, `re/environment_sensors.md`, and `re/motion_detection.md`.

**Method.** Static analysis only of decompiled Java/Kotlin under
`decompiled/jadx/sources/com/thingclips/smart/camera/` and `.../ipc/`, plus resource strings under
`decompiled/apktool/res/values/`. The same `BaseDpOperator` mechanism documented in
`re/camera_image_settings.md` applies: each `Dp*` operator class fixes its Tuya **DP code** string
in `f()` (used as the key into the device runtime `SchemaBean` schema —
`decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/BaseDpOperator.java:31`)
and a notify `ACTION` in `g()`. The `Func*` UI classes under `ipc/panelmore/func/` are panel
wrappers that gate on a DP code via `querySupportByDPCode(...)` / `x3(<dpcode>, <type>)`. No
device-specific values, secrets, or PII appear here — these are generic Tuya schema identifiers and
English UI label strings.

**Honesty notes up front (do not gloss over):**
- The **per-DP value *type*** (boolean vs int-range vs enum-string) is carried by the Tuya runtime
  schema (`SchemaBean`), not hard-coded in these operator classes. Where a type is not provable from
  the decompiled Java it is *inferred* from the Tuya standard camera schema + the operator/Func API
  (`generateSwitchItem` ⇒ boolean, `x3(code, Boolean.TYPE)` ⇒ boolean, etc.) and marked accordingly.
- Two of the four "start-from" operator classes are **placeholders, not live DP codes**:
  `DpWifiSignal` is `@Deprecated` and `f()` returns the literal `"DpWifiSignal"` (same pattern as the
  deprecated `DpFPS` in `re/camera_image_settings.md`); the real wifi-signal value travels a
  **transfer/request channel**, not a settable schema DP (see §7). `TransferWifiSignal.f()` returns
  `""`.
- The **Philips "Privacy mode" UI** (`bm_privacy_mode` and the `bm_soilid_blue_desc`
  "Privacy mode is activated." blue-LED copy) is Philips-custom: those string resources are
  referenced only from generated `R.java`, with **no Java/JS call site recoverable statically**. The
  binding of that UI to the underlying Tuya `basic_private` DP is therefore *inferred*, not proven —
  see §4 and the residual-unknowns section.

---

## DP / entrypoint reference table

| Feature | DP code / entrypoint | Operator / Func class (file:line) | Notify ACTION | Value type | Confidence |
|---|---|---|---|---|---|
| Speaker volume | `basic_device_volume` | `DpDeviceVolume.f()` `operate/dp/DpDeviceVolume.java:14` | `VOICE_VOLUME_SETTING` (`:19`) | int range (schema) — **inferred** | HIGH (code) / MED (type) |
| Mic sensitivity | `mic_sensitivity` | `DpDeviceMicSensitivity.f()` `operate/dp/DpDeviceMicSensitivity.java:15` | `MIC_SENSITIVITY_SETTING` (`:51`) | enum/int (schema) — **inferred** | HIGH (code) / MED (type) |
| Remote restart (camera) | `device_restart` | `DpRestartDevice.f()` `operate/dp/DpRestartDevice.java:57` | `DEVICE_RESTART` (`:62`) | boolean/trigger | HIGH (code) / MED (type) |
| Remote restart (base/station) | `device_restart` | `DpRestartStationDevice.f()` `operate/dp/DpRestartStationDevice.java:169` | `STATION_DEVICE_RESTART` (`:189`) | boolean/trigger | HIGH (code) / MED (type) |
| Status / indicator light | `basic_indicator` | `DpStatusLight.f()` `operate/dp/DpStatusLight.java:156` | `INDICATOR_LIGHT` (`:161`) | boolean | HIGH |
| Status light (station) | `basic_indicator` | `DpStationIndicatorLight.f()` `operate/dp/DpStationIndicatorLight.java:83` | `STATION_INDICATOR` | boolean | HIGH |
| **Privacy mode (lens/mic off)** | `basic_private` | `DpSleep.f()` `operate/dp/DpSleep.java:15` | `SLEEP` (`:20`) | **boolean** (true = sleeping) | HIGH (DP+type) / MED (Philips UI binding) |
| Battery level | `wireless_electricity` | `DpElectric.f()` `operate/dp/DpElectric.java:15` | `ELECTRIC` (`:20`) | int 0–100 (%) — **inferred** | HIGH (code) / MED (range) |
| Battery report cap | `battery_report_cap` | `DpElectricReport.f()` `operate/dp/DpElectricReport.java:38` | `ELECTRIC_REPORT` (`:43`) | int/raw (schema) | HIGH (code) / LOW (semantics) |
| Power mode | `wireless_powermode` | `DpElectricMode.f()` `operate/dp/DpElectricMode.java:15` | `ELECTRIC_MODE` | enum (schema) | HIGH (code) / LOW (values) |
| Low-power tip | `wireless_lowpower` | `DpElectricLowPowerTip.f()` `operate/dp/DpElectricLowPowerTip.java:14` | `ELECTRIC_LOW_POWER_TIP` (`:19`) | int threshold (schema) | HIGH (code) / LOW (range) |
| Wifi signal (RSSI) | *(no schema DP)* request channel | `requestWifiSignal()` iface `devicecontrol/IThingMqttCameraDeviceManager.java:537`; impl `MqttIPCCameraDeviceManager.java:19074` | `WIFI_SIGNAL` | response int (RSSI) | HIGH (mechanism) / MED (units) |
| Wifi signal (deprecated placeholder) | `"DpWifiSignal"` (not a real DP) | `DpWifiSignal.f()` `operate/dp/DpWifiSignal.java:16` (`@Deprecated` `:7`) | `WIFI_SIGNAL` (`:53`) | n/a — placeholder | HIGH |
| Privacy-zone master switch | `ipc_privacy_zone` | `FuncPrivacyZoneSwitch` reads `x3("ipc_privacy_zone", Boolean.TYPE)` `ipc/panelmore/func/FuncPrivacyZoneSwitch.java:144`; support `:303` | n/a (panel DP) | boolean | HIGH |
| Privacy-zone polygon (single) | `ipc_privacy_polygon` | `CameraPrivacyZoneSettingModel.java:58` `querySupportByDPCode("ipc_privacy_polygon")` → `isPolygon` | boolean support flag | (gates polygon mode) | HIGH (support gate) / MED (payload) |
| Privacy-zone polygon (multi) | `multi_privacy_area` | read `x3("multi_privacy_area", JSONArray.class)` `CameraPrivacyZoneSettingModel.java:337`; publish `L3("multi_privacy_area", json, cb)` `:664` | n/a | JSON array of region beans | HIGH |
| System time format | `getSystemTimeFormat(Callback)` | RN `rnplugin/trctipcmonitormanager/TRCTIpcMonitorManager.java:754` | n/a (RN bridge) | int code 0/1/2 | HIGH (mechanism) / MED (encoding) |
| 24h model flag | `is24hoursModel(Callback)` | `TRCTIpcMonitorManager.java:970` (reads `Settings.System "time_12_24"`) | n/a (RN bridge) | "0"/"12"/24h | HIGH |
| IPC timezone id | `getIpcTimeZoneId(Callback)` | RN facade `rnplugin/trctcameramanager/TRCTCameraManager.java:1351` → impl `ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:8422` (`TimeZoneUtils.b(...).getID()`) | n/a (RN bridge) | IANA tz id string | HIGH |

> Path prefix for the operator rows is
> `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/`. Func/model rows are under
> `decompiled/jadx/sources/com/thingclips/smart/ipc/`. Full paths are given inline in the sections
> below.

---

## 1. Speaker volume — `basic_device_volume` (confidence: HIGH code / MEDIUM type)

- DP code: `DpDeviceVolume.f()` returns `"basic_device_volume"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpDeviceVolume.java:14`.
- Notify action `VOICE_VOLUME_SETTING` (`DpDeviceVolume.java:19`); enum member exists at
  `decompiled/jadx/sources/com/thingclips/smart/camera/utils/event/model/CameraNotifyModel.java:19`.
- Value type is **not** hard-coded here; the Tuya standard `basic_device_volume` schema is an
  integer value DP (device speaker loudness). Type marked MEDIUM — provable only from the device's
  runtime `SchemaBean` (`getMin/getMax/getStep`), which is not in this static evidence.

## 2. Microphone sensitivity — `mic_sensitivity` (confidence: HIGH code / MEDIUM type)

- DP code: `DpDeviceMicSensitivity.f()` returns `"mic_sensitivity"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpDeviceMicSensitivity.java:15`.
- Notify action `MIC_SENSITIVITY_SETTING` (`DpDeviceMicSensitivity.java:51`;
  `CameraNotifyModel.java:18`).
- Tuya standard `mic_sensitivity` is typically an enum (low/medium/high) **or** an int; the enum
  string set is schema-carried and not in this class. Type MEDIUM.

## 3. Status / indicator light — `basic_indicator` (confidence: HIGH)

- DP code: `DpStatusLight.f()` returns `"basic_indicator"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpStatusLight.java:156`;
  action `INDICATOR_LIGHT` (`DpStatusLight.java:161`).
- Station variant: `DpStationIndicatorLight.f()` also returns `"basic_indicator"` —
  `.../operate/dp/DpStationIndicatorLight.java:83` (action `STATION_INDICATOR`).
- The panel wrapper `FuncStatusLight` renders it as a **switch** —
  `decompiled/jadx/sources/com/thingclips/smart/ipc/panelmore/func/FuncStatusLight.java:25`
  (`DelegateUtil.generateSwitchItem(... this.a.V2())`), `getId()` →
  `CameraNotifyModel.ACTION.INDICATOR_LIGHT.name()` (`FuncStatusLight.java:62`), label
  `R.string.E1` (`:66`), `isSupport()` via `this.a.W2()` (`:82`). Switch UI ⇒ **boolean** DP, HIGH.
- UI label `ipc_basic_status_indicator` = "Indicator Light" —
  `decompiled/apktool/res/values/strings.xml:4068`.

## 4. Privacy mode — `basic_private` (the baby-monitor-notable item)

This is the privacy item the task calls out: the camera-/mic-off "sleep" control plus Philips'
blue-LED indicator copy.

### 4a. Underlying DP `basic_private` is a boolean lens/mic-off ("sleep") DP (confidence: HIGH)
- DP code: `DpSleep.f()` returns `"basic_private"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpSleep.java:15`;
  action `SLEEP` (`DpSleep.java:20`; `CameraNotifyModel.java:47`).
- **Type provably boolean** (not just inferred from schema):
  - read: `isSleeping(DeviceBean)` does
    `Intrinsics.areEqual(Boolean.TRUE, getDPCurrentValue(deviceBean, "basic_private", Boolean.TYPE))`
    — `decompiled/jadx/sources/com/thingclips/smart/camera/base/utils/DeviceExtendsKt.java:649-650`.
  - write: `DpCamera` publishes `s("basic_private", Boolean.valueOf(z), ...)` —
    `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/DpCamera.java:2014`
    (also read at `:6658`, support test `t("basic_private")` at `:14491`).
- Semantics (HIGH): `basic_private = true` ⇒ device "sleeping" / privacy = lens (and mic) disabled;
  this is the standard Tuya camera privacy/sleep DP.

### 4b. Philips "Privacy mode" UI strings (confidence: HIGH that strings exist / MEDIUM binding)
- `bm_privacy_mode` = "Privacy mode" — `decompiled/apktool/res/values/strings.xml:1419`
  (resource id `0x7f13052c`, `decompiled/apktool/res/values/public.xml:18322`).
- Blue-LED indicator copy: `bm_soilid_blue` = "Solid blue"
  (`strings.xml:1501`) and `bm_soilid_blue_desc` = "Privacy mode is activated." (`strings.xml:1502`).
- **Honesty:** these `bm_*` strings are Philips-custom and are referenced **only** from generated
  `R.java` (`grep` found no Java/JS call site; the `js/assets/kit_js/*` bundles contain no
  `basic_private`/`bm_privacy` reference). The wiring of the "Privacy mode" toggle to the
  `basic_private` DP, and the mapping "privacy active ⇒ solid-blue LED", are therefore **inferred**
  from the standard Tuya privacy/sleep DP + the label text, not statically proven. Confidence MEDIUM
  for the binding. What would unblock: the Philips RN panel JS that owns `bm_privacy_mode` (not in
  the extracted `js/` bundle), or a live DP capture toggling the privacy switch.

## 5. Remote restart — `device_restart` (confidence: HIGH code / MEDIUM type)

- Camera: `DpRestartDevice.f()` returns `"device_restart"` —
  `.../operate/dp/DpRestartDevice.java:57`; action `DEVICE_RESTART` (`:62`; `CameraNotifyModel.java:85`).
- Base/station: `DpRestartStationDevice.f()` also returns `"device_restart"` —
  `.../operate/dp/DpRestartStationDevice.java:169`; action `STATION_DEVICE_RESTART` (`:189`;
  `CameraNotifyModel.java:130`).
- Standard Tuya `device_restart` is a boolean/trigger DP (write `true` ⇒ reboot). Type MEDIUM
  (schema-carried). Two distinct operator classes share the same DP code but emit different notify
  actions (camera vs. station) — both rows kept for completeness.

## 6. Battery level & power — `wireless_electricity` / `battery_report_cap` / `wireless_powermode` / `wireless_lowpower`

- Battery level: `DpElectric.f()` returns `"wireless_electricity"` —
  `.../operate/dp/DpElectric.java:15`; action `ELECTRIC` (`:20`; `CameraNotifyModel.java:67`). Tuya
  standard `wireless_electricity` is an int **0–100 percentage**; range inferred (MEDIUM). The UI
  copy backing this is `ipc_panel_baterrylevel` = "Battery remaining: %s%%" —
  `decompiled/apktool/res/values/strings.xml:4616`.
- Battery report cap: `DpElectricReport.f()` returns `"battery_report_cap"` —
  `.../operate/dp/DpElectricReport.java:38`; action `ELECTRIC_REPORT` (`:43`). Semantics LOW.
- Power mode: `DpElectricMode.f()` returns `"wireless_powermode"` — `.../operate/dp/DpElectricMode.java:15`
  (action `ELECTRIC_MODE`). Enum values schema-carried; LOW.
- Low-power tip/threshold: `DpElectricLowPowerTip.f()` returns `"wireless_lowpower"` —
  `.../operate/dp/DpElectricLowPowerTip.java:14`; action `ELECTRIC_LOW_POWER_TIP` (`:19`). Backing UI
  `ipc_electric_lowpower_level`/`ipc_electric_lowpower_tip` (`strings.xml:4369-4370`).

> **Note (the task's `battery_percentage`):** the task brief names `battery_percentage`. That exact
> DP code is **not** used by the camera modules — the only `battery_percentage` hit in the whole
> tree is in an unrelated audio module
> (`decompiled/jadx/sources/com/thingclips/smart/audio/api/util/ODAudioUIDPSet.java`). For the
> SCD921 camera, battery level is `wireless_electricity` (above). Flagged so this isn't mistaken for
> the live DP. Confidence HIGH that `battery_percentage` is not the camera battery DP here.

## 7. Wifi signal / RSSI — request channel, not a settable DP (confidence: HIGH mechanism / MEDIUM units)

- `DpWifiSignal` is a **deprecated placeholder**: `@Deprecated`
  (`.../operate/dp/DpWifiSignal.java:7`) and `f()` returns the literal `"DpWifiSignal"`
  (`:16`) — **not** a real schema DP code (same anti-pattern as the deprecated `DpFPS` in
  `re/camera_image_settings.md`). It still declares the `WIFI_SIGNAL` notify action (`:53`).
- `TransferWifiSignal` (implements `IDpOperator`, not `BaseDpOperator`) has `f()` return `""`
  (`.../operate/dp/TransferWifiSignal.java:148`) and forwards results via `CameraEventSender`
  with `ACTION.WIFI_SIGNAL` (`TransferWifiSignal.java:302`, `:369`).
- The **live path** is a request/response over the MQTT/transfer control channel:
  `IThingMqttCameraDeviceManager.requestWifiSignal()` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/IThingMqttCameraDeviceManager.java:537`;
  impl `MqttIPCCameraDeviceManager.requestWifiSignal()` calls `controller.T4(m())` —
  `.../devicecontrol/MqttIPCCameraDeviceManager.java:19074`. The result is delivered to panels as
  `ACTION.WIFI_SIGNAL` (`CameraNotifyModel.java:58`), consumed in
  `camera/blackpanel/model/CameraPanelModel.java:2210`/`:74` and
  `camera/whitepanel/model/ThingCameraPanelModel.java:152`. So wifi RSSI is **pulled on demand**,
  not a writable DP. Units (dBm vs. 0–4 bars vs. 0–100) are not provable statically (MEDIUM).

## 8. System time format & timezone (React-Native bridge) (confidence: HIGH mechanism)

These are RN bridge methods, not Tuya DPs:
- `getSystemTimeFormat(Callback)` —
  `decompiled/jadx/sources/com/thingclips/smart/rnplugin/trctipcmonitormanager/TRCTIpcMonitorManager.java:754`.
  It probes the **device locale** date format (formats a fixed date, year≈2023/month=Dec/day=20)
  and returns an int code: `0` when the formatted string starts with the year (year-first,
  `yyyy/MM/dd`), `1` when it starts with `12` (month-first, `MM/dd/yyyy`), else `2` (day-first,
  `dd/MM/yyyy`) — `TRCTIpcMonitorManager.java:799-804`. Mechanism HIGH; the exact 0/1/2 ⇒ ordering
  mapping is read off the if/else and marked MEDIUM (the formatted-string heuristic).
- `is24hoursModel(Callback)` reads `Settings.System "time_12_24"` (falling back to
  `DateFormat.is24HourFormat`) — `TRCTIpcMonitorManager.java:970`, `:1026-1028`.
- `getIpcTimeZoneId(Callback)` — RN facade
  `.../rnplugin/trctcameramanager/TRCTCameraManager.java:1351` delegates to the concrete
  `.../ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:8422`, which returns
  `TimeZoneUtils.b(ctx, devId).getID()` — i.e. the **IANA timezone id string** for the device.
  (Interface declared at `.../ipc/camera/rnpanel/api/ICameraManager.java:51`.)

## 9. Privacy-zone polygon masking (confidence: HIGH gates / MEDIUM payload)

Three DP codes form the privacy-zone family, all gated through `querySupportByDPCode` / `x3`:

- **Master switch** `ipc_privacy_zone` (boolean): read in the panel toggle
  `FuncPrivacyZoneSwitch` via
  `x3("ipc_privacy_zone", Boolean.TYPE)` —
  `decompiled/jadx/sources/com/thingclips/smart/ipc/panelmore/func/FuncPrivacyZoneSwitch.java:144`;
  support `querySupportByDPCode("ipc_privacy_zone")` (`:303`); UI id literal `"FuncPrivacyZoneSwitch"`
  (`:251`). Also gated by `FuncBasePrivacyZone.isSupport()` (`querySupportByDPCode("ipc_privacy_zone")`
  — `.../func/FuncBasePrivacyZone.java:231`, label `R.string.t5` `:143`).
- **Polygon editor entrypoint** `FuncPrivacyPolygonSetting`: `isSupport()` gates on
  `x3("ipc_privacy_zone", Boolean.TYPE)` —
  `.../func/FuncPrivacyPolygonSetting.java:351`; UI id literal `"FuncPrivacyPolygonSetting"` (`:332`);
  `onOperate(... CLICK ...)` merely opens the editor via `handler.sendEmptyMessage(1688)`
  (`FuncPrivacyPolygonSetting.java:374-378`) — it does **not** itself publish the polygon.
- **Polygon payload DPs** (in `CameraPrivacyZoneSettingModel`):
  - `ipc_privacy_polygon` (single-polygon support flag) → sets `isPolygon` —
    `.../ipc/panelmore/model/CameraPrivacyZoneSettingModel.java:58`.
  - `multi_privacy_area` (multi-zone payload): read as a `JSONArray`
    (`x3("multi_privacy_area", JSONArray.class)` `:337`), parsed into `CameraMotionRegionBean`
    objects (`:346`), and **published** with
    `L3("multi_privacy_area", jSONArray.toString(), IPublishDpsCallback)` (`:664`); support gate
    `querySupportByDPCode("multi_privacy_area")` (`:331`, `:650`).
  - Region payload shape: `CameraMotionRegionBean` carries `ispoly` (int polygon flag), `points`
    (`Integer[]`), and `pointList` (`List<AnchorPoint>` of normalized float `x`,`y`) —
    `decompiled/jadx/sources/.../CameraMotionRegionBean.java:351,390,398,438,444` (the same region
    bean reused by motion regions; cross-ref `re/motion_detection.md`). The on-wire JSON field names
    derive from this bean via `JSON.toJSONString` (`CameraPrivacyZoneSettingModel.java:658`); exact
    serialized keys/coordinate normalization are MEDIUM (would be confirmed by a captured
    `multi_privacy_area` DP value).
- UI strings: `ipc_multiple_privacy_zone` = "Privacy zone" (`strings.xml:4554`),
  `ipc_privacy_zone_set` (`:4702`), `ipc_monitor_privacy_zone` (`:4508`).

---

## Residual unknowns (what static analysis cannot settle here)

1. **Per-DP value types/ranges** for `basic_device_volume`, `mic_sensitivity`, `device_restart`,
   `wireless_electricity`, `battery_report_cap`, `wireless_powermode`, `wireless_lowpower` are
   carried by the device's runtime `SchemaBean`, which is fetched from cloud/device at runtime and
   is not in the decompiled classes. Unblock: dump the SCD921 DP schema (cloud device-detail or a
   live MQTT DP report) — see `re/tuya_cloud_auth.md` for the device-list path.
2. **Philips "Privacy mode" → `basic_private` binding** is inferred, not proven (§4b). The
   `bm_privacy_mode`/`bm_soilid_blue_desc` strings have no recoverable call site; the owning Philips
   React-Native panel JS is not in the extracted `js/assets/kit_js/*` bundle. Unblock: that panel's
   JS bundle, or a live DP capture while toggling Privacy mode in the app.
3. **Wifi-signal units** (dBm vs. bars vs. 0–100) and the exact transfer-frame body of
   `requestWifiSignal()`/`controller.T4(...)` are not resolved (§7). Unblock: a captured
   `WIFI_SIGNAL` response frame.
4. **`multi_privacy_area` / `ipc_privacy_polygon` serialized JSON** (exact field names and whether
   coordinates are normalized 0–1 or pixel) is inferred from `CameraMotionRegionBean`; the live key
   set is MEDIUM. Unblock: a captured `multi_privacy_area` DP value (anonymized before any commit).
5. **`getSystemTimeFormat` 0/1/2 encoding** is read off the locale-heuristic if/else; the precise
   semantic each int maps to in the RN panel is MEDIUM. Unblock: the RN panel consumer of that
   callback.
6. **Which subset the SCD921 actually publishes** — e.g. camera vs. station restart, wireless/battery
   DPs (the SCD921 may be mains-powered, in which case `wireless_*` may be unwired) — depends on the
   device schema. Generic-Tuya rows that may be **present-in-code but unwired on this hardware** are
   the battery/power family (`wireless_electricity`, `battery_report_cap`, `wireless_powermode`,
   `wireless_lowpower`), the station variants (`DpRestartStationDevice`, `DpStationIndicatorLight`),
   and the deprecated `DpWifiSignal` placeholder. Unblock: the runtime schema (item 1).
