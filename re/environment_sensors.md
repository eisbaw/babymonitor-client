# Environmental sensors — room temperature & humidity (TASK-0098)

How the app models the room **temperature** and **humidity** readings, the value
scaling/units, the Celsius/Fahrenheit unit setting, the humidity comfort banding, and
the **alert-threshold** path. Static RE of the decompiled Tuya camera SDK + the live
(decrypted) SCD921 device schema captured under `secrets/`.

> Headline (high confidence): the **SCD921 exposes a temperature DP but NOT a humidity
> DP**. `sensor_temperature` (dpId 207) is present in the device's own schema; there is
> **no** `sensor_humidity` entry. `DpHumidity` exists only as generic Tuya-camera-SDK
> code that this product never provisions. The temperature **alert** is implemented with
> dedicated device DPs (`temp_max_switch` / `temp_min_switch` / `temp_max_cvalue` /
> `temp_min_cvalue` + Fahrenheit string twins), not a generic cloud scene.

---

## 1. DP operators in the APK (generic Tuya camera SDK)

Both sensors are `BaseDpOperator` subclasses. `f()` returns the DP **code** (looked up in
the device `SchemaBean` map to resolve the numeric dpId + value type), and `g()` returns
the camera event `ACTION` raised when the DP changes. (The bodies are padded with
`com.ai.ct.Tz` no-op anti-tamper calls — the only load-bearing lines are the returns.)

| operator | DP code (`f()`) | event ACTION (`g()`) | evidence |
|---|---|---|---|
| `DpTemperature` | `sensor_temperature` | `TEMPERATURE_SIGNAL` | `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpTemperature.java:15` (code), `:49` (action) |
| `DpHumidity` | `sensor_humidity` | `HUMIDITY_SIGNAL` | `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpHumidity.java:148` (code), `:153` (action) |

- The `ACTION` enum constants exist at
  `decompiled/jadx/sources/com/thingclips/smart/camera/utils/event/model/CameraNotifyModel.java:60` (`TEMPERATURE_SIGNAL`)
  and `:61` (`HUMIDITY_SIGNAL`). Confidence: **high**.
- `BaseDpOperator` resolves the code → schema → dpId/value-type at construction
  (`BaseDpOperator.java:31-61`). If the device schema has no entry for the code, the
  operator is marked unsupported (`this.b = false`, returned by `isSupport()`,
  `BaseDpOperator.java:37-41`, `:841`). This is exactly what happens for humidity on the
  SCD921 (see §3). Confidence: **high**.

These operators carry **no hard-coded scaling**. Scaling/units come entirely from the
per-device DP schema (`ValueSchemaBean`), downloaded from the cloud — see §2/§4.

---

## 2. Value scaling & units — driven by the device schema, not the APK

For `value`-type DPs the operator wraps a `ValueDpOperateBean`, which copies the
schema's bounds into local fields:

```
this.max      = valueSchemaBean.getMax();
this.min      = valueSchemaBean.getMin();
this.step     = valueSchemaBean.getStep();
this.unit     = valueSchemaBean.getUnit();
this.multiple = valueSchemaBean.getScale();   // "multiple" == decimal scale
```
`decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/bean/ValueDpOperateBean.java` (constructor). Confidence: **high**.

- The DP transport carries **raw integers**. `BaseDpOperator.b()` returns the raw
  `curDpValue` unscaled (`BaseDpOperator.java:200,244`); `DpOperateBean.getMultiple()`
  just exposes the scale (`DpOperateBean.java:16,148`). The Tuya convention is
  `display = raw / 10^scale`. The actual division happens in the IPC display / React
  Native panel layer (fetched at runtime — see Residual unknowns), **not** in this Java
  bean. Confidence on the convention: **high**; on the exact division site: **medium**.

### Concrete scaling, from the live SCD921 schema

The device's own schema was captured (decrypted) at
`secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke.json:339` (mirror:
`...invoke_3.json:339`); the dpId map is at `...invoke_1.json:281` / `...invoke_2.json:281`.
These are the **product capability definitions** (codes/ids/scale/units), not per-device
secrets. Relevant entries (verbatim DP metadata, no PII):

| DP code | dpId | mode | type | unit | min | max | scale | step | meaning |
|---|---|---|---|---|---|---|---|---|---|
| `sensor_temperature` | 207 | ro | value | `C` | 0 | 5000 | 2 | 1 | room temperature |
| `temp_report` | 208 | ro | value | `` | 0 | 500 | 2 | 1 | device-side "Temperature F" reading |

- **`sensor_temperature` scaling:** `display_°C = raw / 10^scale = raw / 100`. Range
  `0.00 … 50.00 °C`; one raw LSB = `0.01 °C`. Example: raw `2350` → `23.50 °C`. Unit field
  is `C` (Celsius is the device-native unit). Confidence: **high** (scale/unit read from
  the live schema; division convention is standard Tuya).
- `temp_report` (id 208) is a second, device-computed reading labelled "Temperature F".
  Its `max 500 / scale 2` (→ 5.00) is inconsistent with a Fahrenheit room temperature, so
  its exact encoding is **unverified** — flagged in Residual unknowns. The app's primary
  reading is `sensor_temperature`.

---

## 3. Humidity: present in SDK code, ABSENT on this hardware

The captured SCD921 schema (the full DP list at `...invoke.json:339`) contains **no**
`sensor_humidity` entry and **no** other `humid*` DP code — verified by grep returning
zero `humid` matches across all decrypted captures. Therefore:

- `DpHumidity` (`sensor_humidity` / `HUMIDITY_SIGNAL`) is **dead capability** on the
  SCD921: `BaseDpOperator` finds no schema entry and reports `isSupport() == false`. The
  app never receives a humidity reading from this camera. Confidence: **high** (entire
  device schema captured; no humidity DP).
- Consequently the **humidity comfort banding is generic Tuya scene UI**, not a SCD921
  feature. The band thresholds are a string resource:
  `apktool/res/values/strings.xml:7460` — `scene_humidity_tip` =
  `"Dry (0%-40%), Comfortable (40%-70%), Moist (70%-100%)"`. So the Tuya humidity bands
  are **Dry 0–40 %, Comfortable 40–70 %, Moist 70–100 %**. This string lives in the
  Tuya home/scene module (`decompiled/jadx/sources/com/thingclips/smart/home/service/R.java:8135`).
  It documents the banding the task asked for, but it is **not** wired to this device.
  Confidence: banding values **high** (literal string); device linkage **high** that it is
  NOT linked (no humidity DP).

---

## 4. Temperature alert threshold mechanism — device-native DPs

The alert is **not** a generic cloud automation; the product ships dedicated threshold
DPs (same live schema, `...invoke.json:339`). Verbatim, no PII:

| DP code | dpId | mode | type | unit | min | max | scale | step | name |
|---|---|---|---|---|---|---|---|---|---|
| `temp_max_switch` | 231 | rw | bool | – | – | – | – | – | "High temp. alert on" |
| `temp_min_switch` | 232 | rw | bool | – | – | – | – | – | "Low temp. alert on" |
| `temp_max_cvalue` | 233 | rw | value | `` | 0 | 4000 | 2 | 100 | "High temp. value" |
| `temp_min_cvalue` | 234 | rw | value | `` | 0 | 4000 | 2 | 100 | "Low temp. value" |
| `temp_max_fvalue` | 235 | rw | string | – | – | – | – | – | "High temp. value F" |
| `temp_min_fvalue` | 236 | rw | string | – | – | – | – | – | "Low temp. value F" |

Reading of the alert path (confidence **high** for the DP shapes; **medium** for the
device-side firing behaviour, which is inferred from the DP semantics):

- Enable a bound by writing its boolean switch (`temp_max_switch` / `temp_min_switch`).
- Set the threshold in **centi-°C** via `temp_max_cvalue` / `temp_min_cvalue`:
  `raw = °C * 100`, range `0.00 … 40.00 °C`, step `100 raw = 1.00 °C`. So the configurable
  alert range is **0–40 °C in 1 °C increments**.
- `temp_max_fvalue` / `temp_min_fvalue` are **string twins** holding the Fahrenheit form
  of the same thresholds (so the device/app keep both unit representations; which one is
  authoritative for display follows the user's unit setting — §5).
- When `sensor_temperature` crosses an enabled bound the device raises an alert
  (push/notification). The notification payload is **not** statically recoverable here
  (Residual unknowns).

### Generic Tuya scene surface (the other path)

Separately, Tuya's scene/automation framework can use `sensor_temperature` as a
condition. The labels the task referenced are scene/IPC-panel strings:
`apktool/res/values/strings.xml:7838` `temperature_alarm` = "Temperature alarm" and
`:7839` `temperature_detection` = "Temperature detection". These are **not** referenced
from smali (no `smali_*` hit) — they are surfaced by the runtime-fetched RN panel / scene
builder, so their exact wiring is **medium** confidence. A Philips-custom "Night Owl"
activity also references a temperature-detection layout
(`decompiled/jadx/sources/com/philips/ph/babymonitorplus/R.java:16285`,
`nightowl2_activity_temperature_detection`) — layout id only, no logic examined
(**low** confidence on its behaviour).

---

## 5. Temperature unit (Celsius / Fahrenheit) setting

There are **two distinct unit encodings** — do not conflate them:

### (a) Camera RN bridge — `getTempUnit` → 0 = Celsius, 1 = Fahrenheit

`TRCTCameraManager.getTempUnit(Callback)` forwards to the camera impl
(`decompiled/jadx/sources/com/thingclips/smart/rnplugin/trctcameramanager/TRCTCameraManager.java:1545,1583`),
whose concrete body returns `q0()`:
`decompiled/jadx/sources/com/thingclips/smart/ka/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:10800-10806`
(`callback.invoke(Integer.valueOf(q0()))`).

`q0()` (`...cameramanager/TRCTCameraManager.java:5500`):
- reads the `"tempUnit"` shared-preference string (`PreferencesUtil.getString`);
- if **empty** → country default via `CountryUtils`: if the dialing/country code is in
  `{"1","1242", <ConfigErrorCode.STATUS_DEV_DEVICE_ALREADY_BIND>, "1345","680"}` →
  `return 1` (Fahrenheit, e.g. US = "1"); otherwise `return 0` (Celsius) — lines
  `5506-5595`;
- if **non-empty** → `"℉".equals(string)` ? `return 1` : `return 0` (lines `5597-5611`).

So the **RN encoding is 0 = Celsius, 1 = Fahrenheit**, default Celsius except for a small
Fahrenheit-by-default country list. Confidence: **high**.

### (b) Account user profile — `User.getTempUnit()` → 1 = Celsius, 2 = Fahrenheit

The Tuya account-level unit uses a *different* numbering:
`TemperatureProxy.a(User)` maps `getTempUnit()==1 → "℃"`, `==2 → "℉"`
(`decompiled/jadx/sources/com/thingclips/smart/login/core/proxy/TemperatureProxy.java:86-94`);
`TRCTPublicManager` computes `celsius = (user.getTempUnit() != 2)`
(`.../trctpublicmanager/TRCTPublicManager.java:2370`); the settings cell uses the same
`==1`/`==2` (`.../personal/setting/plug/cell/UnitCell.java:364-367`). Confidence: **high**.

Net: the **device** stores its readings in Celsius (`sensor_temperature` unit `C`) and
keeps both C and F threshold twins; the **unit setting is presentation only** plus a
selector for which threshold twin (`*_cvalue` vs `*_fvalue`) the UI writes/reads.

---

## 6. Rust-client implications (summary)

- Read `sensor_temperature` (dpId 207) as an int; display `value / 100.0` °C. Convert to
  °F for display only (`°C * 9/5 + 32`) when the user prefers Fahrenheit.
- Do **not** expect humidity from the SCD921 — treat `sensor_humidity` as unsupported.
- To configure the high-temp alert: write `temp_max_switch=true` (dpId 231) and
  `temp_max_cvalue = round(°C * 100)` (dpId 233, 0–4000, multiple of 100). Low-temp alert
  mirrors with 232/234. Keep the `*_fvalue` string twins in sync if the account unit is
  Fahrenheit.
- The DP **codes/ids/scales above are the SCD921 product's own schema**; a Rust client
  should still fetch and honour the live `schema` for the bound device rather than
  hard-coding, since scale/range are schema-driven (§2).

---

## Residual unknowns

- **Exact raw→display division site** for `sensor_temperature`: the IPC React-Native panel
  bundle is downloaded at runtime and is not in the APK, so the literal `/10^scale` call
  was not located in decompiled Java. The scale **value** (2) is known from the live
  schema; the convention is standard Tuya. *Unblock:* dump the runtime RN bundle or trace
  the panel JS.
- **Alert notification payload/format** emitted when a threshold is crossed: not statically
  recoverable. *Unblock:* a live capture of a temperature-alert push for this device.
- **`temp_report` (id 208) encoding:** its `max 500 / scale 2` is inconsistent with a
  Fahrenheit room temperature; semantics unverified. *Unblock:* observe live `temp_report`
  values alongside `sensor_temperature`.
- **Is humidity ever provisioned?** The captured schema shows none; cannot prove the
  firmware never adds it. *Unblock:* a device/firmware that reports `sensor_humidity`, or a
  firmware dump.
- **`q0()` country list:** `ConfigErrorCode.STATUS_DEV_DEVICE_ALREADY_BIND` is used as a
  country-code string; its numeric value was not resolved here (cosmetic — only affects the
  Fahrenheit-default country set).

## Evidence index

- DP operators: `.../operate/dp/DpTemperature.java:15,49`, `.../operate/dp/DpHumidity.java:148,153`,
  `.../operate/dp/BaseDpOperator.java:31-61,200,841`,
  `.../operate/dp/bean/ValueDpOperateBean.java` (ctor), `.../operate/dp/bean/DpOperateBean.java:16,148`
- Event enum: `.../camera/utils/event/model/CameraNotifyModel.java:60-61`
- Live SCD921 schema (codes/ids/scale only; PII not quoted):
  `secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke.json:339`,
  `...invoke_3.json:339`, dpId map `...invoke_1.json:281` / `...invoke_2.json:281`
- Unit setting: `.../rnplugin/trctcameramanager/TRCTCameraManager.java:1545,1583`,
  `.../ka/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:5500-5611,10800-10806`,
  `.../login/core/proxy/TemperatureProxy.java:86-94`,
  `.../rnplugin/trctpublicmanager/TRCTPublicManager.java:2370`,
  `.../personal/setting/plug/cell/UnitCell.java:364-367`
- Strings: `apktool/res/values/strings.xml:7460` (scene_humidity_tip), `:7838` (temperature_alarm),
  `:7839` (temperature_detection); `.../home/service/R.java:8135`;
  `.../philips/ph/babymonitorplus/R.java:16285`
