# PTZ pan/tilt motor control (TASK-0094)

Static RE of the camera pan/tilt ("PTZ") motor-control path in the Tuya camera stack that the
Philips Avent Baby Monitor+ app reskins. Goal: document the `PTZDirection` enum, the
`IThingIPCPTZ` API, the `PTZControlView` / `NewUIPTZControlView` UI wiring, the exact DP code +
payload published to move the motor, the stop semantics, and whether the SCD921/SCD923 actually
exposes a motor at all.

All paths below are under `decompiled/jadx/sources/` unless noted. The jadx output is
control-flow-obfuscated with `com.ai.ct.Tz` no-op calls (`Tz.a()` / `Tz.b(0)`); these are dead
instrumentation and carry no logic — ignore them. Enum string values were re-verified against the
unobfuscated smali constructor.

---

## 1. The PTZ direction enum and its DP values — **HIGH**

There are two parallel `PTZDirection` enums (the app embeds both the camera-base SDK copy and the
UI/devicecontrol copy). Both carry the **same string DP value per direction**.

`com/thingclips/camera/devicecontrol/model/PTZDirection.java:9-20` (the camera SDK copy):

| Constant      | DP value (`getDpValue()`) | Source |
|---------------|---------------------------|--------|
| `UP`          | `"0"`                     | literal |
| `RIGHT_UP`    | `"1"`                     | literal |
| `RIGHT`       | `"2"`                     | literal |
| `RIGHT_DOWN`  | `"3"`                     | literal |
| `DOWN`        | `"4"`                     | literal |
| `LEFT_DOWN`   | `"5"`                     | literal |
| `LEFT`        | `"6"`                     | literal |
| `LEFT_UP`     | `"7"`                     | literal |
| `ROTATE`      | `"8"`                     | `ThingIPCConstant.THING_PTZ_ROTATE` |
| `CALIBRATING` | `"9"`                     | `ThingIPCConstant.THING_PTZ_CALIBRATING` |

The constants are defined in
`com/thingclips/smart/android/camera/sdk/constant/ThingIPCConstant.java:24-33`
(`THING_PTZ_UP="0"` … `THING_PTZ_LEFT_UP="7"`, `THING_PTZ_ROTATE="8"`, `THING_PTZ_CALIBRATING="9"`).

The second copy `com/thingclips/smart/camera/devicecontrol/mode/PTZDirection.java:9-21` is identical
but `@Keep`-annotated and adds one sentinel `UNKNOW("-1")`; its field is the public
`String dpValue`. This is the enum referenced by the RN/UI control paths
(`...smart.camera.devicecontrol.mode.PTZDirection`). The SDK copy
(`...camera.devicecontrol.model.PTZDirection`) exposes `getDpValue()` and a `getDirection()`
bridge that maps one enum to the other.

Smali corroboration (unobfuscated):
`decompiled/apktool/smali_classes8/com/thingclips/camera/devicecontrol/model/PTZDirection.smali:216-409`
shows `const-string … "UP"` paired with `const-string … "0"`, `"RIGHT_UP"`/`"1"`, … `"LEFT_UP"`/`"7"`,
`"ROTATE"`/`"8"` — byte-for-byte matching the table.

> Encoding summary: a PTZ direction is sent as the **single-character decimal string** of its
> ordinal in clockwise order starting at UP=0 (UP, RIGHT_UP, RIGHT, RIGHT_DOWN, DOWN, LEFT_DOWN,
> LEFT, LEFT_UP), with `8`=continuous rotate and `9`=calibrate.

---

## 2. The control API and the DP codes — **HIGH**

The motor is driven entirely through Tuya **DP (datapoint) writes** on the device's standard MQTT
control plane — there is no dedicated PTZ wire protocol and PTZ is **not** carried over the WebRTC
media path (cross-ref `re/webrtc_session.md:598-602`).

API surface: `com/thingclips/smart/android/camera/sdk/api/IThingIPCPTZ.java`
- `:29` `void publishDps(@NonNull String str, @NonNull Object obj, IResultCallback iResultCallback);`
  — the generic DP-write used for every PTZ action (`str` = DP code, `obj` = payload).
- `:31` `boolean querySupportByDPCode(String str);` — capability gate (see §5).
- Plus cruise/collection-point methods (`setCruiseMode`, `addCollectionPoint`, …) — out of scope.

Listener: `com/thingclips/smart/android/camera/sdk/callback/IThingIPCPTZListener.java:5`
`void onPTZDeviceDpUpdate(String str)` — fires when the device reports a PTZ DP change.

DP codes: `com/thingclips/smart/android/camera/sdk/constant/PTZDPModel.java:16-17`
- `DP_PTZ_CONTROL = "ptz_control"` — **enum DP**, payload is the direction string `"0"`..`"9"`.
- `DP_PTZ_STOP   = "ptz_stop"`   — **bool DP**, payload is `Boolean.TRUE`.

(Same file `:8-19` also lists the adjacent motor DPs: `cruise_*`, `zoom_control`/`zoom_stop`,
`ipc_preset_set`, `memory_point_set`, `motion_tracking` — none are in scope here, but they share the
same publish mechanism.)

---

## 3. The exact publish calls per direction — **HIGH**

**Move (start motion in a direction):**

```java
// generic, takes any PTZDirection
iThingIPCDpHelper.publishDps(PTZDPModel.DP_PTZ_CONTROL, ptzDirection.dpValue, null);
```
`com/thingclips/smart/ipc/camera/rnpanel/cameraplayer/DpHelperExtendKt.java:138`
(also `RNThingCameraManager.java:659` using `getDpValue()`, `multicamera/RNCameraLinker.java:364`).

The fixed-direction RN bridge methods publish the corresponding enum constant directly
(`com/thingclips/smart/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java`):
- `:14665` `startPtzDown()`  → `publishDps("ptz_control", PTZDirection.DOWN.getDpValue() /* "4" */, null)`
- `:14698` `startPtzLeft()`  → `publishDps("ptz_control", PTZDirection.LEFT.getDpValue() /* "6" */, null)`
- `:14763` `startPtzRight()` → `publishDps("ptz_control", PTZDirection.RIGHT.getDpValue() /* "2" */, null)`
- `:14807` `startPtzUp()`    → `publishDps("ptz_control", PTZDirection.UP.getDpValue() /* "0" */, null)`

**Stop (halt motion):**

```java
iThingIPCDpHelper.publishDps(PTZDPModel.DP_PTZ_STOP, Boolean.TRUE, null);
```
Seen identically in `DpHelperExtendKt.java:213` (`stopPtz`), `RNThingCameraManager.java:829`,
`cameramanager/TRCTCameraManager.java:15707` (`stopPtz()`), `multicamera/RNCameraLinker.java:431`,
`camera/blackpanel/model/CloudPlatformModel.java:4786`,
`camera/blackpanel/model/CameraPanelModel.java:5802`,
`camera/whitepanel/model/ThingCameraPanelModel.java:3437`,
`camera/panelimpl/screen/ScreenCameraViewModel.java:4046`,
`ipc/presetpoint/model/CameraPresetPointPreviewModel.java:1991`. The payload is always
`Boolean.TRUE`; the DP code `ptz_stop` carries the semantics, the value is a no-op flag.

**Wire encoding for each action (the deliverable):**

| Action            | DP code       | Payload (`Object`) | JSON DP map shape* |
|-------------------|---------------|--------------------|--------------------|
| Pan/tilt UP       | `ptz_control` | `"0"` (String)     | `{"<ptz_control dpId>":"0"}` |
| RIGHT_UP          | `ptz_control` | `"1"`              | …`:"1"` |
| RIGHT             | `ptz_control` | `"2"`              | …`:"2"` |
| RIGHT_DOWN        | `ptz_control` | `"3"`              | …`:"3"` |
| DOWN              | `ptz_control` | `"4"`              | …`:"4"` |
| LEFT_DOWN         | `ptz_control` | `"5"`              | …`:"5"` |
| LEFT              | `ptz_control` | `"6"`              | …`:"6"` |
| LEFT_UP           | `ptz_control` | `"7"`              | …`:"7"` |
| ROTATE (cruise)   | `ptz_control` | `"8"`              | …`:"8"` |
| CALIBRATE         | `ptz_control` | `"9"`              | …`:"9"` |
| STOP              | `ptz_stop`    | `Boolean.TRUE`     | `{"<ptz_stop dpId>":true}` |

\* The DP *code* (`ptz_control`) is resolved to the device's numeric DP id from its schema before
the MQTT publish; the resolved id is device-specific and not reproduced here. The Tuya DP-write
transport (MQTT 2.x publish over the device's control channel, AES-ECB/localKey) is documented in
`re/mqtt_signaling.md` / `re/js_bundle_map.md` (`TUNIMQTTManager`); PTZ is just one more DP on it.

---

## 4. Start / continuous / stop semantics — **HIGH**

PTZ is **press-and-hold continuous motion**, not step-per-tap. The UI sends exactly one
`ptz_control` write on touch-down and one `ptz_stop` write on touch-up; the motor runs continuously
in between (the device keeps moving until it receives `ptz_stop`).

`com/thingclips/smart/camera/uiview/view/PTZControlView.java:1078-1101` `onTouchEvent`:
- `ACTION_DOWN` (`action == 0`): `whichSector(...)` picks a quadrant and calls
  `onLeft()` / `onRight()` / `onUp()` / `onDown()` (`:1087-1093`).
- `ACTION_UP` (`action == 1`): calls `onTouchEventUp()` (`:1098`).

`com/thingclips/smart/camera/uiview/view/NewUIPTZControlView.java:1185` `onTouchEvent` is the same
shape: `onLeft()`/`onRight()`/`onUp()`/`onDown()` at `:1380/1464/1489/1539` and `onTouchEventUp()` at
`:1544`. The callback contract is `OnPTZTouchLisenter { onUp/onDown/onLeft/onRight + onTouchEventUp }`
(`PTZControlView.java:59-67`, `NewUIPTZControlView.java:64-72`).

Wiring: the view's `onUp/onDown/onLeft/onRight` callbacks invoke the `startPtz*` bridge (→ `ptz_control`
move write) and `onTouchEventUp` invokes `stopPtz` (→ `ptz_stop` write). So the lifecycle is:

```
finger down on a sector → publishDps("ptz_control","<dir>")   // motor starts, runs continuously
finger up               → publishDps("ptz_stop", true)        // motor stops
```

The React-Native bridge exposes the same lifecycle as discrete JS methods
(`com/thingclips/smart/rnplugin/trctcameramanager/TRCTCameraManager.java`): `startPtzDown()` `:5446`,
`startPtzLeft()` `:5454`, `startPtzRight()` `:5462`, `startPtzUp()` `:5487`, `stopPtz()` `:6024`,
each delegating to `ICameraManager` (`rnplugin/.../api/ICameraManager.java`) → the
`cameramanager/TRCTCameraManager` impl publishes the DP. JS callers therefore call
`startPtzUp` then `stopPtz` to bracket a move.

**Diagonals are blocked in the RN/move path:** the move guards only allow the 4 cardinal directions.
`RNThingCameraManager.java:47-59` builds `$SwitchMap$…$PTZDirection` mapping only
`LEFT→1, UP→2, RIGHT→3, DOWN→4`, and the move guard at `:659` (and `DpHelperExtendKt.java:138`,
`RNCameraLinker.java:364`) is `… && (i == 1 || i == 2 || i == 3 || i == 4)`. Diagonal values
(`1,3,5,7`), `ROTATE` (`8`) and `CALIBRATING` (`9`) are part of the enum/DP vocabulary but are not
issued by these continuous-move call sites; they would be reached by other features (cruise /
calibration / collection-point flows) rather than the directional pad. **MEDIUM** that diagonal DP
values are never sent by any path — the DP enum accepts them, but I found no live call site that
sends `1/3/5/7` for manual move.

---

## 5. Does the SCD921/SCD923 actually have a motor? — **MEDIUM (assessed: NO motor)**

Every move/stop call is gated by `querySupportByDPCode(PTZDPModel.DP_PTZ_CONTROL)` before it
publishes (`RNThingCameraManager.java:658`, `DpHelperExtendKt.java:138`,
`camera/blackpanel/model/CameraPanelModel.java:3510`,
`camera/panelimpl/screen/ScreenCameraViewModel.java:619`, etc.). The whole PTZ feature — UI
visibility and DP writes — is therefore driven by whether the device's DP schema declares
`ptz_control`. The PTZ drawables/layouts present in the APK
(`decompiled/apktool/res/layout/camera_platform_ptz_control.xml`, `screen_cam_ptz_*` webp, etc.) are
**generic Tuya camera-skin assets** shipped for all camera models and are *not* evidence that this
particular device has a motor.

The authoritative signal is the **captured cloud DP schema for the real paired SCD921**. The
decrypted device function/schema (`secrets/cap1_rtc_decrypted/smartlife.m.api.batch.invoke*.json`,
gitignored — values not reproduced here) lists these DP/function tokens:

`basic_indicator`, `decibel_sensitivity`, `decibel_switch`, `decibel_upload`,
`floodlight_lightness`, `ipc_flip`, `motion_area`, `motion_area_switch`, `motion_sensitivity`,
`motion_switch`, `sensor_temperature`.

There is **no** `ptz_control`, `ptz_stop`, `cruise_*`, `zoom_control`, `ipc_preset_set`,
`memory_point_set`, `motion_tracking`, `pan`, or `tilt` DP in that schema. `ipc_flip` is a *digital*
image flip (software 180° rotate), not a motor. Conclusion: for this device
`querySupportByDPCode("ptz_control")` returns **false**, the PTZ pad is hidden/disabled, and the
SCD921 has **no motorized pan/tilt** — it is a fixed camera (sound/motion/temperature/floodlight
sensors only). This matches the product class (a fixed baby-monitor camera).

Confidence is **MEDIUM** rather than high because the assessment rests on *absence* in a single
device-schema capture: absence-of-evidence is not proof, and the batch-invoke capture may not be the
complete schema query. It is corroborated by the device feature set (no motor-adjacent DP at all)
and the product being a known fixed unit.

---

## Residual unknowns / what would raise confidence

- **Definitive motor verdict — LOW→HIGH unblock.** A capture of the device's full schema/spec
  response (e.g. `…device.dp.publish` spec or the panel's `getSchema`/`dpCodes` list) for the
  SCD921, or simply confirming `querySupportByDPCode("ptz_control")` at runtime, would turn the
  MEDIUM "no motor" into HIGH. Physically inspecting the unit for a motor is the ground truth.
- **Whether the move write repeats while held.** Static evidence shows one `ptz_control` on
  touch-down and one `ptz_stop` on release (no timer/loop found in `PTZControlView` /
  `NewUIPTZControlView`), implying the device self-continues until stop. Not 100% confirmed that no
  higher layer re-sends on `ACTION_MOVE` — a capture of a held-drag PTZ session would confirm.
- **Diagonal / ROTATE / CALIBRATING usage.** The enum and `ptz_control` DP accept `1/3/5/7/8/9`,
  but no manual-move call site issues them. Which feature (cruise, auto-calibration, collection
  points) emits `8`/`9` and whether any UI sends diagonals was not traced — out of this task's scope.
- **DP id resolution.** The numeric DP id that `ptz_control`/`ptz_stop` map to is device-schema
  specific and intentionally not reproduced here; a re-implementer must resolve it from the device's
  schema at runtime (same mechanism as every other DP write).
