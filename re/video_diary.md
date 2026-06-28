# Video Diary / "Moments" — event-triggered recording + activity log (TASK-0104)

Static RE of the Philips Avent Baby Monitor+ **"Moments"** feature (internal name
*Video Diary*) of `com.philips.ph.babymonitorplus` (Tuya-reskin SCD921). Goal: map
the per-event-type recording triggers (sound / motion / cry / baby-awake /
baby-asleep) and their enable settings, the sensitivity controls, and where the
diary state and the recorded clips persist (local DB vs Tuya cloud).

> **Method / citation note.** All evidence is grep of the jadx Java tree under
> `decompiled/jadx/sources/` and the apktool resources under `decompiled/apktool/`
> (both regenerable via `just decompile`, gitignored). Cites name a **symbol**
> (class / method / DP-code string / view id) plus a `File.java:NN` hint — jadx line
> numbers drift across re-decompiles, so grep the symbol/string, not the bare line.
> Every DP-code string (`"ext_functions"` etc.) is a Tuya **schema identifier**, not a
> device secret; no localKey/devId/uid/token/PII is referenced here (`mDevId` is only
> ever a variable name). The `Tz.a()/Tz.b(0)` no-ops interleaved in every method are
> the app's control-flow-flattening obfuscation (`com.ai.ct.Tz`); ignore them — the
> `return …` / `publishDps(…)` lines are the real bodies.
>
> **Static-only honesty caveat.** This documents the **client→cloud DP control plane**
> (which event types the app *arms* for diary recording, and the sensitivity it sets).
> The actual event *detection* and the *clip cutting/upload* run on-device firmware +
> Tuya cloud and are out of static reach. No live Moments-event capture exists in the
> reviewed `emulator_captures/`, so the inbound "a Moment was recorded" notification
> and the cloud clip-list wire shape are **inferred, not captured** (see Residual
> unknowns).

---

## TL;DR — the event-type trigger bitmask

The "Moments" settings screen does **not** use one DP per event type. All five
per-event-type enable toggles are packed into the **bits of a single integer Tuya
DP `ext_functions`** (DpCode `EXT_FUNCTIONS`, dpId `21`). The app reads the int,
flips one bit per toggle, and republishes the whole int.

| Bit | Event type | UI string | Read helper | Write helper | Switch (binding field / view id) |
|-----|-----------|-----------|-------------|--------------|----------------------------------|
| 0 | **Sound** | `bm_diary_sound` | `ExtFunctionUtils.g()` | `ExtFunctionUtils.l(i,z)` | `s` = `sb_sound_subtitle` |
| 1 | **Motion** | `bm_diary_motion` | `ExtFunctionUtils.f()` | `ExtFunctionUtils.k(i,z)` | `q` = `sb_motion_subtitle` |
| 2 | **Cry** | `bm_diary_cry` | `ExtFunctionUtils.e()` | `ExtFunctionUtils.j(i,z)` | `o` = `sb_cry_subtitle` |
| 3 | **Baby awake** | `bm_diary_baby_awake` | `ExtFunctionUtils.c()` | `ExtFunctionUtils.i(i,z)` | `n` = `sb_awake_subtitle` |
| 4 | **Baby asleep** | `bm_diary_baby_asleep` | `ExtFunctionUtils.b()` | `ExtFunctionUtils.h(i,z)` | `m` = `sb_asleep_subtitle` |

Page title `bm_video_diary` = **"Moments"**; subtitle `bm_video_diary_desc` =
*"Control which events record videos and fine-tune motion or sound sensitivity.
These settings do not affect your notifications."* (`strings.xml:1546-1547`).

---

## 1. Event-type triggers + enable settings (confidence: high)

### 1a. The packed-bitmask helpers — exact bit positions

`com/thingclips/bm/camera/panel/ui/utils/ExtFunctionUtils.java` is a pure
bit-manipulation utility (log tag `"VideoDiarySettingActivity Utils"`):

- Core primitives:
  - `private a(int i, boolean z, int i2)` — set/clear bit `i2`:
    `z ? i | (1<<i2) : i & (~(1<<i2))` (`ExtFunctionUtils.java:8-14`).
  - `private d(int i, int i2)` — test bit `i2`: `(i & (1<<i2)) != 0`
    (`…:28-30`).
- Per-event **read** (decode bit → boolean):
  - `g(i) → d(i,0)` "getSoundStatus" (`…:275`) — **bit 0 = Sound**
  - `f(i) → d(i,1)` "getMotionStatus" (`…:181`) — **bit 1 = Motion**
  - `e(i) → d(i,2)` "getCryStatus" (`…:94`) — **bit 2 = Cry**
  - `c(i) → d(i,3)` "getAwakeStatus" (`…:23`) — **bit 3 = Awake**
  - `b(i) → d(i,4)` "getAsleepStatus" (`…:17`) — **bit 4 = Asleep**
- Per-event **write** (set/clear bit, return new int):
  - `l(i,z) → a(i,z,0)` "switchSound" (`…:598`)
  - `k(i,z) → a(i,z,1)` "switchMotion" (`…:552`)
  - `j(i,z) → a(i,z,2)` "switchCry" (`…:546`)
  - `i(i,z) → a(i,z,3)` "switchAwake" (`…:448`)
  - `h(i,z) → a(i,z,4)` "switchAsleep" (`…:350`)

### 1b. Load: decode `ext_functions` → five booleans

`VideoDiaryViewModel.J()` (`VideoDiaryViewModel.java:370-403`) reads the int and
decodes it, gated by device support:

```
int l = DeviceDpUtil.l(mDevId);          // current ext_functions int
motionStatus = ExtFunctionUtils.f(l);    // bit1
soundStatus  = ExtFunctionUtils.g(l);    // bit0
if (DeviceDpUtil.C(mDevId)) cryStatus    = ExtFunctionUtils.e(l);   // bit2, supportCry
if (DeviceDpUtil.D(mDevId)) {            // supportSleepIQ
    awakeStatus  = ExtFunctionUtils.c(l);   // bit3
    asleepStatus = ExtFunctionUtils.b(l);   // bit4
}
```

The five booleans are surfaced to the activity through getters
`H()`=motion, `I()`=sound, `getCryStatus()/G()`=cry, `F()`=awake, `E()`=asleep
(`VideoDiaryViewModel.java:53-368`), and pushed into the switches in
`VideoDiarySettingActivity.Pa()` (`…:961-965`):
`Ma().o`=cry, `Ma().n`=awake, `Ma().m`=asleep, `Ma().q`=motion, `Ma().s`=sound
(`setCheckedImmediatelyNoEvent(...)`).

### 1c. Save: flip one bit → republish `ext_functions`

`VideoDiarySettingActivity.onCheckedChanged()` (`…:1988-2092`) is the single
`CompoundButton.OnCheckedChangeListener` for all five switches. For each switch it
re-reads the current int (`int l = DeviceDpUtil.l(mDevId)`), flips the matching bit
via `ExtFunctionUtils.{k,l,j,i,h}(l, isChecked)`, then writes the whole int back via
`DeviceDpUtil.J(mDevId, newInt)`:

- `Ma().q` (motion) → `k(l,z)` → `J(...)` (`…:2039-2049`)
- `Ma().s` (sound) → `l(l,z)` → `J(...)` (`…:2051-2061`)
- `Ma().o` (cry) → `j(l,z)` → `J(...)` (`…:2063-2068`)
- `Ma().m` (asleep) → `h(l,z)` → `J(...)` (`…:2071-2076`)
- `Ma().n` (awake) → SenseIQ-gated (see §3), else `i(l,z)` → `J(...)` (`…:2080-2091`)

Switch visibility is gated in `initView()` (`…:1928-1953`): cry row
(`Ma().h/e/o`) shown only if `DeviceDpUtil.C(mDevId)`; awake+asleep rows
(`Ma().d/g/u/n/m`) shown only if `DeviceDpUtil.D(mDevId)`. The string→view binding
is confirmed in `activity_video_diary_setting_layout.xml` (motion `:47-111`, sound
`:126-190`, cry `:207-223`, awake `:246-280`, asleep `:297-313`) and the field
letters in `ActivityVideoDiarySettingLayoutBinding.java:57-84` (fields are assigned
alphabetically by view-id, which is how `m/n/o/q/s` map to
asleep/awake/cry/motion/sound).

---

## 2. The two sensitivity sliders reuse the detection-sensitivity DPs (confidence: high for motion, medium-high for sound)

The Moments screen also exposes a 3-step **Motion** and **Sound** sensitivity slider
(low/mid/high) — the "fine-tune motion or sound sensitivity" of the subtitle. These
are **not** part of `ext_functions`; they drive the same camera-detection sensitivity
DPs documented elsewhere, via `NightowlMQTTCameraModel`:

- **Motion slider** (`Ma().p` = `sb_motion`): reads `mNightowlMQTTCameraModel.s7()`
  and writes `…E7(MotionMonitorSensitivityMode.LOW/MIDDLE/HIGH)`
  (`VideoDiarySettingActivity.java:1414-1469`). `MotionMonitorSensitivityMode` is the
  `motion_sensitivity` DP enum (`"0"/"1"/"2"`) — cross-ref `re/motion_detection.md`.
- **Sound slider** (`Ma().r` = `sb_sound`): reads `mNightowlMQTTCameraModel.w7()` and
  writes `…G7(SoundSensitivityMode.LOW/MID/HIGH)`
  (`VideoDiarySettingActivity.java:1626-1677`). `SoundSensitivityMode` maps to the
  `decibel_sensitivity` DP enum — cross-ref `re/sound_detection.md` (medium-high:
  the slider→mode binding is direct; the mode→`decibel_sensitivity` DP link is the
  cross-doc mapping, not re-proven here).

The slider descriptions are `bm_diary_motion_desc_{low,mid,high}` and
`bm_diary_sound_desc_{low,mid,high}` (`strings.xml:1228-1235`). Slider enable/disable
mirrors the switch state via `Ra()` (`…:985-1079`).

**Consequence for a Rust client:** toggling a Moments event type writes the
`ext_functions` bitmask DP; dragging a sensitivity slider writes the *shared*
`motion_sensitivity` / `decibel_sensitivity` DP — i.e. the Moments sliders and the
main motion/sound detection settings are the **same** underlying DPs, so changing one
changes the other.

---

## 3. Device-support and SenseIQ-enable gates (confidence: high)

Three `DeviceDpUtil` predicates gate which event types appear and whether "Baby
awake" can be armed:

- `C(devId)` — **cry supported**: `querySupportByDPCode("cry_trans_switch")`
  (`DeviceDpUtil.java:682-710`, DpCode `DP_CRY_TRANS_SWITCH` `:73`).
- `D(devId)` — **SleepIQ/SenseIQ supported**: `querySupportByDPCode("sleepiq_switch")`
  (`DeviceDpUtil.java:713-800`, DpCode `DP_SLEEPIQ_SWITCH` `:63`).
- `B(devId)` — **SleepIQ currently enabled**: reads current value of
  `"sleepiq_switch"` (Boolean) (`DeviceDpUtil.java:571-…:640`).

The "Baby awake" toggle requires SenseIQ to be *active*: in `onCheckedChanged`, if the
awake switch is turned on while `B(devId)==false`, the app reverts the switch and pops
the **SenseIQ-required** dialog `Ua()` (`…:1208-1268`, strings
`bm_diary_require_senseiq` / `bm_diary_require_senseiq_content` `strings.xml:1231-1232`),
which routes to `WelcomeToSenseIqActivity` (`…:1308-1313`). After SenseIQ setup,
`onNewIntent` re-checks `senseIqDone && B(devId)` and auto-enables the awake switch
(`…:2187-2203`). (confidence: high.)

---

## 4. Persistence / sync path — Tuya cloud, not a local DB (confidence: high for settings; medium-high for the clips)

### 4a. The diary *settings* (which events record) persist as a Tuya cloud DP

`DeviceDpUtil.l()` / `J()` are thin wrappers over the Tuya IPC DP helper
`ThingIPCSdk.createIPCDpHelper(devId)`:

- **Read** `l(devId)` (`DeviceDpUtil.java:2505-2576`):
  `createIPCDpHelper.getCurrentValue(DpCode.EXT_FUNCTIONS.getDpCode(), Integer.TYPE)`
  → the `ext_functions` integer.
- **Write** `J(devId, value)` (`DeviceDpUtil.java:1239-1319`):
  reads the DP's `ValueSchemaBean`, then
  `createIPCDpHelper.publishDps("ext_functions", Double.valueOf(value * 10^scale), resultCallback)`.

`publishDps` is the Tuya device-DP publish path (cloud/MQTT round-trip to the device's
data-point store), **not** a local SQLite write. So the per-event-type enable state is
**device/cloud DP state** (`ext_functions`, dpId 21), shared across all the user's app
instances and surviving reinstall. There is **no local-DB persistence** of these
toggles in the app. (confidence: high — direct `publishDps`/`getCurrentValue` evidence.)

DpCode table for cross-reference: `DeviceDpUtil$DpCode` enumerates every DP this module
touches, including `EXT_FUNCTIONS("ext_functions", 21)` (`DeviceDpUtil.java:81`) and the
detection DPs `MOTION_SENSITIVITY("motion_sensitivity",106)`,
`DP_DECIBEL_SENSITIVITY("decibel_sensitivity",140)`,
`DP_SLEEPIQ_SWITCH("sleepiq_switch",1)`, `DP_CRY_TRANS_SWITCH("cry_trans_switch",2)`
(`…:54-81`).

### 4b. The recorded *clips* ("Moments") are Tuya Cloud Storage

The settings screen lives in the panel package
`com.thingclips.bm.camera.panel.ui.cloud.activity`, whose only sibling is
`BmCameraCloudActivity` (`BmCameraCloudActivity.java`), the camera **cloud-storage**
panel host. Both are registered as routes in `BmCameraPanelApp` (`BmCameraPanelApp.java:76-79`):
`"bm_camera_cloud_panel" → BmCameraCloudActivity`, `"video_diary_setting" →
VideoDiarySettingActivity`; the routes are declared together in
`apktool/assets/module_app.json` (`…BmCameraPanelApp":["bm_camera_cloud_panel","video_diary_setting"]`).
The clip-delete copy `bm_diary_delete_video_tip` ("The video will be deleted
permanently and cannot be restored", `strings.xml:1224`) and the subscription gating
strings (`bm_diary_have_subs*`, `…:1225-1226`) confirm the recorded Moments are
**subscription-backed Tuya cloud clips**, not local recordings. The clips are indexed
by the same event taxonomy (sound/motion/cry/awake/asleep) that `ext_functions` arms;
the on-screen "Drag timeline segments to preview event videos" timeline string
(`ipc_sdcard_empty_not_support_record`, `strings.xml:4821`) belongs to the generic
Tuya cloud/SD playback UI. (confidence: medium-high — package/route/string evidence is
strong; the exact cloud clip-list API and per-clip event-type tag field were not
captured, see Residual unknowns.)

### 4c. Honest correction: there is no manual-entry "journal"

The task framing mentions an "activity diary/log … manual entries". Statically there
is **no user-authored journal / manual-entry feature** in this app: the only "diary"
is the *Video Diary = Moments* = automatic event-triggered cloud clips. The
`feeding`/`diaper` strings that surface in search are part of the **cry-translation**
advice content (`mty_cry_*`, e.g. `strings.xml:6027-6147`), unrelated to a diary log.
The "activity log (cry/motion/sleep/awake)" is realised as the **event-tagged cloud
clip list** of §4b, not a separate logging subsystem. (confidence: high — exhaustive
grep for journal/manual/note/feeding/diaper diary classes returns nothing.)

---

## 5. Entry point + routing (confidence: high)

- Route name **`video_diary_setting`** → `VideoDiarySettingActivity`
  (`BmCameraPanelApp.java:78`).
- Launched from `SenseIQDoneActivity` via
  `UrlRouter.d(new UrlBuilder(this, "video_diary_setting").b(bundle))`
  (`SenseIQDoneActivity.java:485`) — i.e. the Moments setup is offered right after the
  SenseIQ onboarding completes (which is also why "Baby awake" depends on SenseIQ).
- The activity carries the device id via `BaseCameraActivity.a` (`mDevId`); the
  ViewModel is built from it through `ViewModelFactory(mDevId)`
  (`VideoDiarySettingActivity.java:279-281`).

---

## Residual unknowns / what would unblock them

1. **`ext_functions` value semantics beyond bits 0-4 (confidence of completeness:
   medium).** The app only reads/writes bits 0-4. Whether the firmware uses higher
   bits (or the `scale` multiplier in `J()`) for anything else is not statically
   determinable. *Unblock:* the live DP schema for product `kzm54lhabeeucq5a`
   (`ValueSchemaBean` for `ext_functions`: min/max/scale), via a device
   `device.dp.publish` capability query.
2. **Inbound "Moment recorded" notification + cloud clip-list API (low).** The
   detection→cut→upload happens in firmware/cloud; the app side that *lists* recorded
   Moments and tags each clip with its triggering event type lives in the Tuya
   cloud-storage panel (`BmCameraCloudActivity`, a near-empty host that loads the cloud
   panel) and the message-center, neither captured here. *Unblock:* trigger each event
   type on the live SCD921 with the emulator-capture pipeline running and grab the
   cloud clip-list REST/MQTT payload (no such capture in the reviewed
   `emulator_captures/`).
3. **Detection algorithm + clip duration/pre-roll (firmware, out of static reach).**
   The thresholds behind cry/awake/asleep classification and the recorded segment
   length are device-side. *Unblock:* SCD921 firmware dump (out of scope for app-side
   static RE).
4. **`SoundSensitivityMode → decibel_sensitivity` link (medium-high).** Confirmed here
   only that the Moments sound slider writes `SoundSensitivityMode`; the mode→DP code
   binding is taken from `re/sound_detection.md`. *Unblock:* read
   `NightowlMQTTCameraModel.G7()`/`w7()` bodies to re-prove the DP code locally (cheap
   follow-up).
