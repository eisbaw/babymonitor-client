# Motion Detection — sensitivity, recording trigger, IVA outline, motion tracking, PIR (TASK-0096)

Static RE of the **motion-detection stack** of `com.philips.ph.babymonitorplus`
(Tuya-reskin SCD921) as a **recording / notification / siren trigger**. Goal: map
the video-motion sensitivity DP and its value enum, the master motion on/off
switch, the recording trigger, the object-outline / cross-line IVA overlay
(native `enableIVA`), PTZ motion-tracking auto-follow, the PIR sensor DPs, and the
event ACTION path that the DP-change notifications travel.

> **Method / citation note.** All evidence is grep of the jadx Java tree under
> `decompiled/jadx/sources/` (regenerable via `just decompile`, gitignored). Cites
> name a **symbol** (class / enum / DP-code string) plus a `File.java:NN` hint —
> jadx line numbers drift across re-decompiles, so grep the symbol/string, not the
> bare line. Every DP-code string (`"motion_sensitivity"` etc.) is a Tuya **schema
> identifier**, not a device secret. No localKey/devId/uid/token/PII is referenced
> here. The `Tz.a()/Tz.b(0)` no-ops interleaved in every method are the app's
> control-flow-flattening obfuscation (`com.ai.ct.Tz`); ignore them — the
> `return "<dpcode>"` / `return ACTION.X` lines are the real bodies.
>
> **Static-only honesty caveat.** This documents the **client→cloud DP control
> plane** (how the app *configures* detection) and the **client-side overlay
> rendering**. The actual motion/PIR *detection algorithm* runs on-device
> (firmware) and is out of static reach. There is **no live motion-event capture**
> in `emulator_captures/` reviewed for this task, so the inbound "motion detected"
> push-notification wire shape is **inferred, not captured** (see Residual
> unknowns).

---

## TL;DR DP map

| DP code | Operator class | ACTION / SUB_ACTION | Value type | Role |
|---|---|---|---|---|
| `motion_switch` | `DpMotionMonitorSwitch` | `MOTION_MONITOR` / `SWITCH` | Boolean | **Master** video-motion on/off |
| `motion_sensitivity` | `DpMotionMonitorSensitivity` | `MOTION_MONITOR` / `SENSITIVITY` | enum `MotionMonitorSensitivityMode` LOW`"0"`/MIDDLE`"1"`/HIGH`"2"` | Detection sensitivity |
| `motion_record` | `DpMotionMonitorRecordSwitch` | `MOTION_MONITOR` / `RECORD_NATIVE` | Boolean | **Record clip on motion** (the recording trigger) |
| `ipc_auto_siren` | `DpMotionMonitorTriggerSiren` | `TRIGGER_SIREN` | Boolean | Sound siren on motion |
| `ipc_alarm_ind` | `DpMotionMonitorLinkSupport` | `MOTION_MONITOR_LINKED` | Boolean | Alarm-linkage indicator |
| `motion_interval` | `DpMotionMonitorSeparation` | `MOTION_MONITOR` / `SEPARATION` | enum | Min interval between motion alerts |
| `motion_timer_switch` | `DpMotionMonitorOpenAllTime` | `MOTION_MONITOR` / `ALL_TIME` | Boolean | Detect 24/7 vs scheduled |
| `motion_timer_setting` | `DpMotionMonitorOpenTimePiece` | `MOTION_MONITOR` / `TIME_PIECE` | (schedule) | Active-window schedule |
| `motion_area_switch` | (queried in `FuncBaseMotionMonitor`) | — | Boolean | Detection-zone masking enable |
| `ipc_object_outline` | `DpMotionMonitorObjectOutline` | `OBJECT_OUTLINE` | Boolean | Draw moving-object outline (drives native IVA) |
| `out_off_bounds` | (read in IVA builder) | — | Boolean | Cross-line / area-crossing IVA |
| `motion_tracking` | `FuncMotionTracking` (`PTZDPModel.DP_MOTION_TRACKING`) | — | Boolean | **PTZ auto-follow** (camera pans to subject) |
| `pir_switch` | `DpPIR` | `PIR` | enum `PIRMode` CLOSE`"0"`/LOW`"1"`/MID`"2"`/HIGH`"3"`/OPEN`"4"` | PIR sensitivity/mode (5-step) |
| `ipc_pir_switch` | `DpIpcPIR` | `IPC_PIR` | Boolean | PIR on/off (IPC variant) |
| `ipc_pir_sensitivity` | `DpIpcPIRSensitivity` | `IPC_PIR_SENSITIVITY` | (sensitivity) | PIR sensitivity (IPC variant) |

All operator classes are under
`decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/`
and are registered in `.../operate/DpCamera.java` (each DP-code string appears
there; grep `DpCamera.java` for the literal).

---

## 1. Motion sensitivity DP + value mapping (confidence: high)

**DP code `"motion_sensitivity"`.** `DpMotionMonitorSensitivity` extends
`EnumDpOperator`; its `f()` returns the DP code and `g()`/`h()` return the event
ACTION/SUB_ACTION:

- `f() → "motion_sensitivity"` —
  `operate/dp/DpMotionMonitorSensitivity.java:105`
- `g() → CameraNotifyModel.ACTION.MOTION_MONITOR` — `…:193`
- `h() → CameraNotifyModel.SUB_ACTION.SENSITIVITY` — `…:199`
- `j(Object) `casts the value to `MotionMonitorSensitivityMode` and emits
  `getDpValue()` — `…:204-206`

**Value enum** `MotionMonitorSensitivityMode`
(`…/devicecontrol/mode/MotionMonitorSensitivityMode.java:6-9`):

- `HIGH("2")`, `MIDDLE("1")`, `LOW("0")` — i.e. the wire DP value is the **string**
  `"0"`/`"1"`/`"2"`, exposed via `getDpValue()` (`…:261-263`). Mapping is
  monotonic: higher string = more sensitive.

**Master on/off switch DP `"motion_switch"`** — `DpMotionMonitorSwitch`
(`operate/dp/DpMotionMonitorSwitch.java`):

- `f() → "motion_switch"` — `…:15`
- `g() → ACTION.MOTION_MONITOR` — `…:37`
- sub-action `SUB_ACTION.SWITCH` — `…:57`
- Boolean DP (extends `BaseDpOperator`, no enum mapping).

The settings-screen aggregator `FuncBaseMotionMonitor`
(`ipc/panelmore/func/FuncBaseMotionMonitor.java`) is the "Motion detection" row:
`dynamicTypeName() → DynamicSettingItemName.DETECT` (`:28`) and `isSupport()`
(`:106-107`) returns true if the device advertises any of the motion capabilities,
explicitly probing `querySupportByDPCode("motion_area_switch")` and
`PTZDPModel.DP_MOTION_TRACKING` among others — confirming these DP codes are the
gate for the whole feature group.

**Recording trigger relation (confidence: high).** The "record on motion" toggle is
a **separate** DP `"motion_record"` (`DpMotionMonitorRecordSwitch.java:176`,
ACTION `MOTION_MONITOR`, SUB_ACTION `RECORD_NATIVE` at `:181/:270`). So the
trigger chain the app configures is: `motion_switch` (arm) → `motion_sensitivity`
(threshold) → on detection the device fires the linkage(s): `motion_record`
(record clip / `RECORD_NATIVE`), `ipc_auto_siren` (`TRIGGER_SIREN`), push
notification, gated by `motion_timer_switch`/`motion_timer_setting` schedule and
rate-limited by `motion_interval` (`SEPARATION`). The detection→record decision
itself executes in device firmware; the app only sets these DPs.

---

## 2. IVA / object-outline overlay + native `enableIVA`, PTZ motion-tracking, PIR (confidence: high, with one naming correction)

### 2a. `enableIVA` native call and the object-outline DP

**Native declaration** —
`camera/nativeapi/ThingCameraNative.java:57`:
```
public static native int enableIVA(long j, boolean z);
```
Interface contract `ThingCameraInterface.java:59` (`int enableIVA(boolean z)`).

**Call chain (client overlay rendering):**
`ThingSmartCameraP2PSync.setSdkEnableIVA(z)` (`:3256-3259`) →
`iCameraP2P.setEnableIVA(z)` → `IPCThingP2PCamera.setEnableIVA(z)` (`:12149`) →
`this.thingCamera.enableIVA(z)` (`IPCThingP2PCamera.java:12193`) →
`ThingCameraNative.enableIVA(long,boolean)` (JNI).

**What gates it** — `ThingSmartCameraP2PSync.getEnableIVA()` (`:2464-2483`):
```
return (TRUE.equals(DpStaticHelper.getCurrentValue(devId, "ipc_object_outline", Boolean)) && sp(SPU_CAMERA_MOTION_IVA, true))
       || sp(SPU_CAMERA_MOTION_CROSS_LINE_IVA, false);
```
So native IVA is enabled when the **`ipc_object_outline`** DP is TRUE (and a local
SharedPreferences toggle is on), OR the cross-line IVA SP toggle is on.
`ipc_object_outline` is owned by `DpMotionMonitorObjectOutline`
(`operate/dp/DpMotionMonitorObjectOutline.java`): `f() → "ipc_object_outline"`
(`:14`), `g() → ACTION.OBJECT_OUTLINE` (`:19`).

**The overlay descriptor** — `setSmartRectFeatures()` builder
(`ThingSmartCameraP2PSync.java:7917-7977`) builds a `SmartRectFeature` JSON array
the SDK renders on top of the video. For object-outline (`ipc_object_outline`
TRUE) it encodes line **width** (`wide=2/middle=1/thin=0`, default `"thin"`),
**color** (`red=0xFF0000`, `blue/yellow/green/black/white/purple`, default
`"red"`), **fps**, and **style** (`full=0/horn=1`, default `"horn"`) — all from SP
keys `SPU_CAMERA_MOTION_IVA_*`. For cross-line it reads the **`out_off_bounds`** DP
plus `SPU_CAMERA_MOTION_CROSS_LINE_*`, emitting up to 4 line segments
(`:7949-7967`). The numeric color/width tables here are UI constants, not secrets.

**Honest correction to the task framing.** The task labels `enableIVA` as
"motion-tracking / IVA auto-follow". Statically that is **not** what `enableIVA`
does: `enableIVA` toggles **client-side IVA overlay drawing** (the moving-object
outline box and cross-line markers rendered over the decoded video), gated by the
`ipc_object_outline` / `out_off_bounds` DPs. It does **not** move the camera. It is
a *visualization* of what the on-device detector found, not a tracker. (confidence:
high — the entire `getEnableIVA()`/`setSmartRectFeatures` evidence is overlay
geometry, never PTZ commands.)

### 2b. PTZ motion-tracking auto-follow (the real "follow") — `motion_tracking` DP

The physical auto-follow ("camera pans to keep the subject in frame") is a
**different** mechanism: the boolean DP `motion_tracking`
(`PTZDPModel.DP_MOTION_TRACKING = "motion_tracking"`,
`…/android/camera/sdk/constant/PTZDPModel.java:14`), driven by
`FuncMotionTracking` (`ipc/panelmore/func/FuncMotionTracking.java`):

- `getId() → "FuncMotionTracking"` (`:33`); rendered as a switch item bound to the
  current `DP_MOTION_TRACKING` boolean (`:25`).
- `onOperate(...)` publishes the toggle:
  `I3().publishDps(PTZDPModel.DP_MOTION_TRACKING, Boolean.valueOf(z), …)`
  (`:205`).
- `isSupport()` gates on `querySupportByDPCode(DP_MOTION_TRACKING)` (`:168`).

So: **`motion_tracking` (PTZ DP) = auto-follow; `enableIVA`/`ipc_object_outline` =
on-screen outline overlay.** They are distinct and should not be conflated in the
Rust client.

### 2c. PIR sensor DPs (confidence: high)

Three related DP operators exist; the **`PIRMode 0-4`** enum from the task is the
graduated PIR mode and is consumed by **`DpPIR`**, not by `DpIpcPIR`:

- **`pir_switch`** — `DpPIR extends EnumDpOperator`
  (`operate/dp/DpPIR.java:17`), `g() → ACTION.PIR` (`:22`),
  `j()` casts to `PIRMode` and emits `getDpValue()` (`:40-41`). Value enum
  `PIRMode` (`…/devicecontrol/mode/PIRMode.java:6-11`):
  `CLOSE("0")`, `LOW("1")`, `MID("2")`, `HIGH("3")`, `OPEN("4")` — a 5-step
  off→low/mid/high→always scale (this is the "PIRMode 0-4" the task names).
- **`ipc_pir_switch`** — `DpIpcPIR extends BaseDpOperator`
  (`operate/dp/DpIpcPIR.java:85`), `g() → ACTION.IPC_PIR` (`:90`). Boolean on/off
  PIR enable for the IPC product variant (no enum mapping → simple switch).
- **`ipc_pir_sensitivity`** — `DpIpcPIRSensitivity`
  (`operate/dp/DpIpcPIRSensitivity.java:17`), `g() → ACTION.IPC_PIR_SENSITIVITY`
  (`:81`). Separate PIR sensitivity DP for the IPC variant.

`PIRMode` is consumed by the PIR settings UI: `ipc/panelmore/func/FuncPIRSetting.java`,
`FuncPIRChoose.java`, `presenter/CameraIPCPIRPresenter.java`,
`presenter/CameraPIRPresenter.java`, and the device-control facade
`MqttIPCCameraDeviceManager.java` (grep `PIRMode`).

**PIR ↔ recording trigger relation (confidence: medium).** PIR is an *alternative*
trigger source to video motion: enabling `pir_switch`/`ipc_pir_switch` arms the
passive-infrared sensor so a heat-motion event can fire the same linkage set
(record / siren / push). The app exposes PIR and video-motion as parallel toggles
in the same settings group; the firmware fuses both into the alarm pipeline. The
exact fusion ("PIR AND video" vs "PIR OR video") is **not statically determinable**
— it is a firmware decision. (See Residual unknowns.)

---

## 3. The DP-change event ACTION path — and why there is no `ACTION.MOTION_SIGNAL` (confidence: high)

The task asks for "the `ACTION.MOTION_SIGNAL` event path". **There is no
`MOTION_SIGNAL` symbol anywhere in the jadx tree** —
`grep -rc 'MOTION_SIGNAL' decompiled/jadx/sources` returns zero hits. Stating this
honestly rather than inventing it.

The real event vehicle is **`CameraNotifyModel`**
(`…/camera/utils/event/model/CameraNotifyModel.java`), whose inner enums `ACTION`
and `SUB_ACTION` are the dispatch keys. Each motion DP operator's `g()`/`h()`
returns the `(ACTION, SUB_ACTION)` pair that a DP-value change is published under,
so the panel/presenter can route the updated value to the right UI control:

- `ACTION.MOTION_MONITOR` (`CameraNotifyModel.java:53`) is the umbrella ACTION for
  the whole motion group; it is sub-keyed by `SUB_ACTION`:
  `SWITCH` (`:280` master `MOTION_SWITCH` also present), `SENSITIVITY` (`:268`),
  `RECORD_NATIVE`, `SEPARATION`, `ALL_TIME`, `TIME_PIECE` (`:260-281`).
- `ACTION.OBJECT_OUTLINE` (`:112`) — object-outline DP change.
- `ACTION.IPC_PIR` (`:148`), `ACTION.IPC_PIR_SENSITIVITY` (`:149`),
  `ACTION.PIR` (`:76`) — PIR DP changes.
- `ACTION.MOTION_MONITOR_LINKED` (`:147`), `ACTION.TRIGGER_SIREN` — linkage/siren.

These ACTIONs carry **DP-state echoes** (the app confirming a setting changed),
*not* the inbound "motion just happened" alarm. The inbound motion **alert** to the
app is a Tuya **cloud push notification / message-center event** (and an MQTT DP
report for the trigger DPs), which is a different subsystem from
`CameraNotifyModel`. That inbound alarm path was not captured for this task — see
Residual unknowns.

---

## Residual unknowns / what would unblock them

1. **Inbound "motion detected" alert wire shape (confidence of mapping: low).**
   `CameraNotifyModel.ACTION.*` are *outbound DP-config echoes*, not the alarm. The
   real-time motion alarm reaches the app as a Tuya push notification / message-
   center record and/or an MQTT DP report. *Unblock:* trigger motion on the live
   SCD921 with the emulator-capture pipeline running and grab the FCM/MQTT payload
   (no such capture exists in the reviewed `emulator_captures/`).
2. **Detection algorithm + PIR/video fusion (firmware, out of static reach).** The
   sensitivity thresholds, the motion-region math behind `motion_area_switch`, and
   whether PIR and video-motion are AND/OR-fused live in device firmware.
   *Unblock:* firmware dump of the SCD921, out of scope for app-side static RE.
3. **`enableIVA(long handle, …)` first arg.** The native takes a `long` session
   handle; its exact provenance (P2P session pointer) is JNI-side. *Unblock:*
   Ghidra on `libThingCameraSDK.so` for the `enableIVA` export (not done here; this
   task was Java-tree only).
4. **`ipc_object_outline` vs `out_off_bounds` device support.** Whether the SCD921
   advertises the cross-line (`out_off_bounds`) capability is device-specific and
   needs the live `skill`/DP-schema for this product (`kzm54lhabeeucq5a`).
   *Unblock:* the device DP schema from a live `device.dp.publish` capability query.
5. **`motion_interval` enum values.** It is an `EnumDpOperator`
   (`DpMotionMonitorSeparation`) but its concrete value enum was not enumerated
   here. *Unblock:* read its `j()`/value-enum class (cheap follow-up).
