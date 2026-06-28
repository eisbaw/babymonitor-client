# Local SD-card Recording — switch/loop/format/storage + record modes (event/continuous/timing/AOV) (TASK-0103)

Static RE of the **local SD-card recording / on-device record-mode stack** of
`com.philips.ph.babymonitorplus` (Tuya-reskin SCD921/923). Goal: map the SD-card
control-plane DPs (record on/off, loop-overwrite, format, eject, storage/status),
the `record_mode` enum (EVENT / CONTINUOUS_RECORD / TIMING) and its scheduled
sub-page, and the **AOV** (Always-On-Video, ultra-low-frame-rate) time-lapse mode
(record 1 frame every N seconds) — each DP code + value mapping with `file:line`
evidence, and an honest assessment of whether the SCD921 actually exposes any of it.

> **Method / citation note.** Evidence is grep of the jadx Java tree under
> `decompiled/jadx/sources/` (regenerable via `just decompile`, gitignored) plus the
> apktool resource tree under `decompiled/apktool/`. Cites name a **symbol** (class /
> DP-code string / resource name) plus a `File.java:NN` hint — jadx line numbers
> drift across re-decompiles, so grep the symbol, not the bare line. Every DP-code
> string (`"record_switch"`, `"sd_storge"`, …) is a Tuya **schema identifier**, not a
> device secret. UI label resource ids (`R.string.F6` etc.) are jadx-synthetic; they
> were resolved to real resource names by mapping the integer id in
> `…/ipc/camera/ui/R.java` → `decompiled/apktool/res/values/public.xml` (string type
> `0x7f13xxxx`) → `…/res/values/strings.xml`. The interleaved `Tz.a()/Tz.b(0)`
> no-ops are `com.ai.ct.Tz` control-flow-flattening obfuscation — ignore them; the
> `return "<dpcode>"` / `return ACTION.X` lines are the real bodies. No
> localKey/devId/uid/token/PII is referenced here; the captured device schema is
> cited by path + line only.
>
> **Headline (confidence: high).** Every DP and UI surface below is **generic Tuya
> camera-SDK code**. The **live SCD921 device schema** (43 DP codes, captured
> decrypted under `secrets/`) advertises **none** of the SD-card / record-mode DP
> codes — so on this hardware the whole feature group is **dormant**: every
> `FuncSDCard*` / `FuncChangeRecordModel` / `FuncAOVRecordModel` gate
> (`querySupportByDPCode(...)`) returns false and the rows never render. See §5.

---

## TL;DR DP map

| DP code | Operator class | ACTION / SUB_ACTION | Type | Role |
|---|---|---|---|---|
| `record_switch` | `DpSDCardRecordSwitch` | `SDCARD_RECORD_SWITCH` | Boolean | **Master** SD-record on/off |
| `record_loop` | `DpSDCardRecordLoopSwitch` | `SDCARD_RECORD_LOOP_SWITCH` | Boolean | **Loop / overwrite-when-full** |
| `ipc_mute_record` | `DpSDCardRecordMuteSwitch` | `SDCARD_RECORD_MUTE_SWITCH` | Boolean | Record video **without audio** |
| `record_mode` | `DpRecordModel` (`EnumDpOperator`) | `RECORD_MODEL` | enum string | **EVENT `"1"` / CONTINUOUS `"2"` / TIMING `"3"`** |
| `record_timing_set` | (`CameraRecordModeTimingSettingModel`) | — | String (schedule) | Schedule used when `record_mode="3"` |
| `record_mode_aov_switch` | (`FuncAOVRecordModel`) | — | Boolean | **AOV master** ("Intelligent full-time recording") |
| `record_aov_mode` | `DpAovModel` (`EnumDpOperator`) | `RECORD_AOV_MODEL` | enum string | AOV preset: `"1"`=1 frame/5 s, `"2"`=1 frame/2 s, `"3"`=custom |
| `record_aov_mode_customize` | `DpAovCustomizeFrameModel` (`EnumDpOperator`) | `RECORD_AOV_CUSTOMIZE_FRAME` | enum string (seconds) | Custom AOV interval, default `"5"` |
| `sd_format` | `DpSDFormat` | `SDCARD` / `FORMAT` | Boolean (trigger) | Format the card |
| `sd_format_state` | `DpSDFormatStatus` | `SDCARD` / `PROGRESS` | status | Format progress |
| `sd_storge` *(sic)* | `DpSDStorage` | `SDCARD` / `REQUEST_STORAGE` | String `total\|video\|free` | Capacity report |
| `sd_status` | `DpSDStatus` | `SDCARD` / `SDCARD_STATUS` | status enum | Card present / abnormal |
| `sd_umount` | `DpSDUmount` | `SDCARD` | Boolean (trigger) | Safe-eject |
| `sd_encryption` | `DpSDEncryption` | `SDCARD` | — | Card encryption |

All operator classes live under
`decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/`.
The DP-code strings are registered/dispatched in `…/operate/DpCamera.java` (grep the
literal; e.g. `record_switch` at `DpCamera.java:11614/12266/15346`, `record_mode` at
`:1513/2698/8909`, `sd_storge` at `:2618/16585/17549`, `sd_format` at
`:4535/8790`, `sd_status` at `:8125/9392/11089`, `sd_format_state` at `:9219`).
The `ACTION` constants are inner-enum members of `CameraNotifyModel`
(`…/camera/utils/event/model/CameraNotifyModel.java`): `SDCARD` `:45`,
`SDCARD_RECORD_SWITCH` `:72`, `RECORD_MODEL` `:73`, `SDCARD_RECORD_MUTE_SWITCH`
`:104`, `SDCARD_RECORD_LOOP_SWITCH` `:105`, `RECORD_AOV_MODEL` `:160`,
`RECORD_AOV_CUSTOMIZE_FRAME` `:161`; SUB_ACTION `SDCARD_STATUS` `:264`.

---

## 1. SD record switch / loop / mute (confidence: high)

**`record_switch`** — master "store video to the card" toggle. `DpSDCardRecordSwitch`
extends `BaseDpOperator` (Boolean, no enum): `f() → "record_switch"`
(`DpSDCardRecordSwitch.java:97`), `g() → ACTION.SDCARD_RECORD_SWITCH` (`:132`). The
settings row `FuncSDCardRecordSwitch` (`ipc/panelmore/func/FuncSDCardRecordSwitch.java`)
publishes it: `onOperate(...) → a.L3("record_switch", Boolean.valueOf(status), …)`
(`:242`); its label is `R.string.H6` = **`ipc_sdcard_record_switch`** ("SD card
recording on/off switch", resolved at `:74-75` where jadx even left the comment), and
`isSupport()` gates on `querySupportByDPCode("record_switch")` (decompiler note at
`:195`).

**`record_loop`** — loop/overwrite-when-full. `DpSDCardRecordLoopSwitch` (Boolean):
`f() → "record_loop"` (`DpSDCardRecordLoopSwitch.java:100`), `g() →
ACTION.SDCARD_RECORD_LOOP_SWITCH` (`:105`). Row `FuncSDCardRecordLoopSwitch`
publishes `L3("record_loop", Boolean…, …)` (`:322`) and is **gated on BOTH**
`querySupportByDPCode("record_loop")` AND `querySupportByDPCode("record_switch")`
(`:272-274`) — i.e. loop is a sub-option of recording. Label `R.string.y8` =
**`ipc_settings_sd_record_loop`** ("Loop recording").

**`ipc_mute_record`** — record video with audio muted. `DpSDCardRecordMuteSwitch`
(Boolean): `f() → "ipc_mute_record"`, `g() → ACTION.SDCARD_RECORD_MUTE_SWITCH`.

---

## 2. `record_mode` enum — EVENT / CONTINUOUS_RECORD / TIMING (confidence: high)

**`RecordMode`** value enum (`…/devicecontrol/mode/RecordMode.java:7-8`):
```
EVENT("1"), CONTINUOUS_RECORD("2");
```
`getDpValue()` returns the wire string `"1"`/`"2"` (`:185-242`). The DP operator is
**`DpRecordModel`** (`EnumDpOperator`): `f() → "record_mode"`
(`DpRecordModel.java:17`), `g() → ACTION.RECORD_MODEL` (`:51`), `j(Object)` casts the
value to `RecordMode` and emits `getDpValue()` (`:69-78`).

**But the UI exposes a THIRD value `"3"` = "Timed recording", which is NOT in the
`RecordMode` enum.** `FuncChangeRecordModel` (`ipc/panelmore/func/FuncChangeRecordModel.java`)
builds its label table from the device's own `record_mode` enum range
(`G2("record_mode", EnumSchemaExBean.class).range`, `:168`) and maps each raw value
string to a label (`modeMap`, `:116`) — resolved via R.java→public.xml:

| `record_mode` value | label resource | English text |
|---|---|---|
| `"1"` | `ipc_sdcard_record_mode_event` (`F6`) | "Event Recording" — any detected motion is recorded |
| `"2"` | `ipc_sdcard_record_mode_ctns` (`E6`) | "Non-stop recording" — always-on continuous |
| `"3"` | `ipc_record_mode_timing` (`O5`) | "Timed recording" — schedule-driven |

When the current value is `"3"`, the func appends a click row
`…+"record_mode_timing_setting"` labelled `ipc_record_mode_timing_setting` (`P5`,
"Timed recording setting") (`FuncChangeRecordModel.java:179-182`) that opens a
schedule sub-page. Selecting a mode publishes the **raw string**:
`L3("record_mode", substring, …)` (`:289`). So a Rust client must publish
`"1"`/`"2"`/`"3"` (string), not a typed enum — and `"3"` is valid even though the
APK's `RecordMode` enum omits it (a latent SDK gap, handled by the raw-string path).

**Timed-recording schedule** — `CameraRecordModeTimingSettingModel`
(`ipc/panelmore/model/CameraRecordModeTimingSettingModel.java`) reads/writes a
separate DP **`record_timing_set`**: `x3("record_timing_set", String.class)` (`:87`)
to load, `L3("record_timing_set", data, callback)` (`:158`) to save. The schedule
payload (`data`) is an opaque String built by the timing UI; its exact grammar
(weekday-mask + time-windows) was not enumerated here — see Residual unknowns.

---

## 3. AOV — ultra-low-frame-rate time-lapse "record 1 frame / N s" (confidence: high)

AOV ("Always-On-Video") is the baby-monitor-relevant low-power mode: instead of full
video it stores **one frame every few seconds**, giving all-day coverage in tiny
storage. Three DPs, all driven by `FuncAOVRecordModel`
(`ipc/panelmore/func/FuncAOVRecordModel.java`):

1. **`record_mode_aov_switch`** (Boolean) — AOV master. Read via
   `x3("record_mode_aov_switch", Boolean.TYPE)` (`:284`); toggled via
   `L3("record_mode_aov_switch", Boolean…, …)` when the row id ends with
   `"record_mode_aov_setting"` (`:571-572`). Switch label `R.string.Xa` =
   **`record_mode_aov_switch`** ("Intelligent full-time recording"); subtitle
   `R.string.D6` = **`ipc_sdcard_record_mode_aov_subtitle`** ("Ultra-low frame rate
   all-day continuous recording (AOV), full-time recording with smaller storage
   space"). `isSupport()` gates on `querySupportByDPCode("record_mode_aov_switch")`
   (`:518-519`).

2. **`record_aov_mode`** (enum string) — which AOV preset. Operator `DpAovModel`:
   `f() → "record_aov_mode"` (`DpAovModel.java:63`), `g() → ACTION.RECORD_AOV_MODEL`
   (`:68`). The func reads the device enum range
   (`G2("record_aov_mode", EnumSchemaExBean.class).range`, `:316`) and maps each raw
   value via `modeMap` (`:116`). **Value mapping (as displayed; resolved
   R.java→public.xml):**

   | `record_aov_mode` value | displayed title | displayed subtitle (literal) |
   |---|---|---|
   | `"1"` | `…aov_mode_power_saving` (`B6`) "Energy-saving long recording mode" | `…aov_mode_all_time_tips` (`z6`) **"Record 1 frame every 5 seconds"** |
   | `"2"` | `…aov_mode_all_time` (`y6`) "Efficient fast recording mode" | `…aov_mode_power_saving_tips` (`C6`) **"Record 1 frame every 2 seconds"** |
   | `"3"` | `…aov_customize` (`w6`) "Custom frame interval mode" | (empty) |

   Selecting a preset publishes the **raw string**:
   `L3("record_aov_mode", substring, …)` (`FuncAOVRecordModel.java:710`).

   > **Gotcha (confidence: high).** The displayed *subtitle* literally states the
   > frame interval ("…every 5 seconds" / "…every 2 seconds"), so the value→interval
   > mapping is solid. But Tuya's resource *names* are crossed relative to the
   > pairing: value `"1"` pairs the `power_saving` **title** with the `all_time`
   > **tips** string, and value `"2"` does the reverse (see `modeMap` at `:116`:
   > `B6,z6` / `y6,C6`). Trust the value→interval mapping (1 frame / 5 s for `"1"`,
   > 1 frame / 2 s for `"2"`), not the resource-name labels.
   >
   > **Latent SDK gap.** `DpAovModel.j(Object)` casts the value to `RecordMode`
   > (`DpAovModel.java:173-174`), which only knows `"1"`/`"2"` — so AOV value `"3"`
   > (customize) is unrepresentable via that typed path. The actual UI publish uses
   > the raw `substring`, so it works; the typed `DpAovModel` API is just incomplete.

3. **`record_aov_mode_customize`** (enum string, seconds) — the custom interval used
   when `record_aov_mode == "3"`. Operator `DpAovCustomizeFrameModel`:
   `f() → "record_aov_mode_customize"` (`DpAovCustomizeFrameModel.java:20`), `g() →
   ACTION.RECORD_AOV_CUSTOMIZE_FRAME` (`:103`). The func renders a click row only when
   current AOV mode is `"3"` and the DP is supported (`:327-329`), reads the enum
   range + current value (`:361-364`), **defaults the value to `"5"` if empty**
   (`:365-367`), and shows it as `"<n> <R.string.A6>"` where `A6` =
   **`ipc_sdcard_record_mode_aov_mode_frame`** = "seconds"
   (`:368`) — i.e. the customize value is an **interval in seconds**. Writing it:
   `L3("record_aov_mode_customize", value, …)` (`FuncAOVRecordModel.d(...)`, `:191`).

The two record-mode groups are aggregated by `CameraRecordModeModel`
(`ipc/panelmore/model/CameraRecordModeModel.java:50-51`), which adds
`FuncChangeRecordModel` (event/continuous/timing) **and** `FuncAOVRecordModel` (AOV)
to one "Recording Mode" page, but only if `FuncChangeRecordModel.isSupport()` is true
(`m7()`, `:189`). `FuncAOVRecordModel.isSupport()` additionally requires a cloud
service status of `10010` or a frame value of `5` (`getIsSupport()` decompiled body,
`:512-549`) — i.e. AOV is partly cloud-gated.

---

## 4. Format / storage / status / eject (confidence: high)

- **`sd_format`** — `DpSDFormat`: `f() → "sd_format"` (`DpSDFormat.java:83`), `g() →
  ACTION.SDCARD` (`:170`), `h() → SUB_ACTION.FORMAT` (`:180`). A write triggers a
  card format; `DpCamera.java:4535` issues `s("sd_format", Boolean.TRUE, …)`. Label
  `ipc_sdcard_format` ("Format memory card"). Func `FuncSDCardFormat`.
- **`sd_format_state`** — `DpSDFormatStatus`: `f() → "sd_format_state"`
  (`DpSDFormatStatus.java:95`), `g() → SDCARD` (`:100`), `h() → SUB_ACTION.PROGRESS`
  (`:127`). Reports format progress.
- **`sd_storge`** *(spelled without the second 'a' in the Tuya schema)* —
  `DpSDStorage`: `f() → "sd_storge"` (`DpSDStorage.java:145`), `g() → SDCARD`
  (`:150`), `h() → SUB_ACTION.REQUEST_STORAGE` (`:216`). The value is a
  **pipe-delimited string `total|video|free`**, parsed in `j(int,String)`:
  `str.split("\\|")` must yield length 3, then `CameraSDInfoBean.setTotalSpace`,
  `setVideoSpace`, `setFreeSpace` (`:36-43`), with `setStatus(...)` taken from the
  current DP value (`:44`); malformed → error `"11011"`
  (`CameraConstant.ERROR_MSG_DATA_BROKEN`, `:38`). UI labels `ipc_sdcard_capacity*`
  ("SD card capacity / Total Capacity / Used / Remaining capacity").
- **`sd_status`** — `DpSDStatus`: `f() → "sd_status"` (`DpSDStatus.java:64`), `g() →
  SDCARD` (`:69`), `h() → SUB_ACTION.SDCARD_STATUS` (`:75`). Card present/abnormal/
  insufficient state (drives "no SD card inserted" / "reformat needed" strings). The
  concrete status-int → state enum table was not enumerated here (firmware-defined).
- **`sd_umount`** — `DpSDUmount`: `f() → "sd_umount"`. Safe-eject trigger
  (`ipc_sdcard_remove`, "Remove memory card"). Func `FuncSDCardUMount`.
- **`sd_encryption`** — `DpSDEncryption`: `f() → "sd_encryption"`. Card-encryption
  capability.

---

## 5. Does the SCD921/923 actually expose SD recording? — NO (confidence: high)

**It does not.** The same decrypted **live SCD921 device schema** used by
`re/environment_sensors.md` (the device's own DP list, captured at
`secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke.json:339`) declares **43 DP
codes**, and **none** of the SD-card / record-mode codes appear in it. Grep of that
schema file for each code returns **zero** matches for:
`record_switch`, `record_loop`, `record_mode`, `record_aov_mode`,
`record_aov_mode_customize`, `record_mode_aov_switch`, `record_timing_set`,
`ipc_mute_record`, `sd_format`, `sd_format_state`, `sd_storge`, `sd_status`,
`sd_umount`, `sd_encryption`.

The 43 codes the SCD921 **does** advertise are camera/baby-monitor controls only —
`monitor_sensitivity`, `motion_detection`, `motion_switch`, `motion_sensitivity`,
`motion_area*`, `sensor_temperature`, `temp_*`, `decibel_*` (cry/sound),
`lullaby_*`/`play*` (lullaby playback), `nightlight_*`, `floodlight_lightness`,
`bulb_switch`, `privacy_switch`, `app_talking`/`pu_talking` (two-way audio),
`ipc_flip`, `background_mode`, `power_status`/`device_poweroff`, etc. (full list
derivable from the same schema, schema names only — no PII).

**Why dormant, not removed.** Every SD/record surface is gated at runtime by
`querySupportByDPCode(...)` against this schema:
`FuncSDCardRecordSwitch` (`record_switch`), `FuncSDCardRecordLoopSwitch`
(`record_loop` AND `record_switch`), `FuncChangeRecordModel` (`record_mode`),
`FuncAOVRecordModel` (`record_mode_aov_switch`). With the codes absent,
`BaseDpOperator` finds no schema entry (`BaseDpOperator.java` resolves
code→schema→dpId at construction; see `re/environment_sensors.md §1`), `isSupport()`
returns false, and the rows never render. This is the **identical pattern** to the
humidity finding (`DpHumidity` exists in the SDK but `sensor_humidity` is absent from
the SCD921 schema — `re/environment_sensors.md`). The SD-record DP operators,
`Func*` rows, `RecordMode`/`record_mode`/AOV enums, and all `ipc_sdcard_*` /
`ipc_sdcard_record_mode_aov_*` strings are **generic Tuya camera-SDK baggage**
shipped in the white-labeled app, **not wired on this hardware**. (Consistent with the
SCD921 being a slot-less, cloud/live-stream baby monitor; the app even ships generic
"Your camera has no SD card inserted" / "did not detect a storage device" strings.)

**Honest caveat.** This conclusion rests on **one** captured schema snapshot for the
user's SCD921 (productId class referenced in `MEMORY.md`). It is a single device at a
single firmware/cloud-config point. A different firmware, the SCD923 variant, or a
future cloud schema push could in principle enable some of these DPs. Nothing in the
**static app** can decide that — the support set is a server-delivered schema, not an
APK constant. (confidence that the *captured* schema lacks these: high; confidence
that *no* SCD921/923 firmware anywhere exposes them: medium.)

---

## Residual unknowns / what would unblock them

1. **`record_timing_set` schedule grammar (confidence: low).** The timed-recording
   payload is an opaque String (`CameraRecordModeTimingSettingModel.java:87/158`); its
   weekday-mask + time-window encoding was not decoded here. *Unblock:* read
   `CameraRecordModeTimingSettingPresenter` / `TimePieceBean` and/or capture one
   `record_timing_set` publish from a device that supports it.
2. **`sd_status` status-int → state enum (confidence: low).** The mapping from the
   numeric `sd_status` value to "none / normal / abnormal / formatting / full" is
   firmware-defined and was not enumerated. *Unblock:* read the `sd_status`-consuming
   presenter, or a live capture from an SD-capable Tuya cam.
3. **AOV cloud gating (`mCloudServiceStatus == 10010`).** `FuncAOVRecordModel.isSupport()`
   couples AOV availability to a cloud-service status code (`:512-549`); the meaning of
   `10010` (cloud-storage subscription state?) is not pinned. *Unblock:* the cloud
   `service status` API response. Moot for the SCD921 (AOV DP absent anyway).
4. **Whether ANY SCD921/923 firmware enables SD recording (confidence: medium it does
   not).** Decided by the server-pushed device schema, not the APK. *Unblock:* capture
   the device schema from an SCD923 and/or after a firmware update; compare DP lists.
5. **On-device record engine.** Even with the DPs present, the actual segmenting,
   H.264 muxing to the card, loop-overwrite, AOV frame-dropping, and event-trigger
   wiring run in **device firmware**, out of app-side static reach. *Unblock:* SCD921
   firmware dump (out of scope for this app RE).
</content>
</invoke>
