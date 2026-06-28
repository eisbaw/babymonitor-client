# Camera image / video-quality DP family (night vision, clarity, FPS, flip, brightness, WDR, anti-flicker, watermark)

**Scope.** This consolidates the Tuya camera "image / picture quality" control surface for the
SCD921 as exposed by the white-labeled Philips app. It covers the night-vision modes (the
baby-monitor-essential feature), the video clarity/resolution get/set path, frame rate, image
flip/mirror/rotate, display brightness/contrast/sharpness, WDR, anti-flicker, and the OSD
watermark.

**Method.** Static analysis only of decompiled Java under
`decompiled/jadx/sources/com/thingclips/smart/camera/`. Each DP operator class fixes a Tuya **DP
code** string in its `f()` method and a notification `ACTION` in `g()`; `f()` is provably the DP
code because `BaseDpOperator` uses it as the key into the device's runtime DP schema
(`SchemaBean schemaBean = schemaMap.get(f)` —
`decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/BaseDpOperator.java:31`).
Enum value strings come from the `mode/*.java` enums. No device-specific values, secrets, or PII
are involved — these are generic Tuya schema identifiers.

**Honesty notes up front (do not gloss over):**
- The **per-DP value *type*** (boolean vs integer-range vs enum-string) is carried by the Tuya
  *runtime schema* (`SchemaBean`), not hard-coded in these operator classes. For boolean/int DPs
  below the type is *inferred* from the Tuya standard camera schema + the operator base class API
  (`getMin/getMax/getStep`), and is marked medium confidence. Enum DPs are high confidence because
  the value strings are literally compiled into the `mode/*.java` enums.
- `DpFPS` is `@Deprecated` and its `f()` returns the literal placeholder `"DpFPS"`, **not** a real
  Tuya DP code (see below) — so the live FPS DP code is *not* statically resolvable from this app.
- There is **no LD / low-definition clarity constant** in this build; only SD/HD/UHD exist
  (see clarity section). The task's "LD" is unconfirmed.

---

## 1. Night vision (baby-monitor essential)

Two distinct DPs control night behaviour, plus a "full colour / starlight" toggle:

### 1a. `nightvision_mode` — the rich IR/colour mode enum (**confidence: HIGH**)
- DP code: `DpNightVisionMode.f()` returns `"nightvision_mode"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpNightVisionMode.java:43`.
- Notify action `NIGHT_VISION_MODE` (`DpNightVisionMode.java:48`); value converted from the
  `NightVisionMode` enum (`DpNightVisionMode.java:124`).
- Enum value strings —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/mode/NightVisionMode.java:7-11`:

| enum constant | DP string |
|---|---|
| `AUTO` | `auto` |
| `IR` | `ir_mode` |
| `COLOR` | `color_mode` |
| `TRUE_COLOR` | `true_color_mode` |
| `BLACK_COLOR` | `black_color_mode` |

### 1b. `basic_nightvision` — legacy IR on/off/auto enum (**confidence: HIGH**)
- DP code: `DpNightMode.f()` returns `"basic_nightvision"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpNightMode.java:32`;
  action `IR_NIGHT_VISION_MODE` (`DpNightMode.java:37`); enum is `NightStatusMode`
  (`DpNightMode.java:119`).
- Enum value strings —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/mode/NightStatusMode.java:7-9`:
  `AUTO="0"`, `CLOSE="1"`, `OPEN="2"`.

### 1c. `basic_shimmer` — full-colour / starlight toggle (**confidence: MEDIUM**)
- DP code: `DpFullColor.f()` returns `"basic_shimmer"` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpFullColor.java:15`;
  action `LLL_FULL_COLOR` (`DpFullColor.java:40`). Boolean type inferred from Tuya standard schema
  (no enum class), hence medium.

> Which of `nightvision_mode` vs `basic_nightvision` the SCD921 actually publishes depends on its
> runtime schema (not statically known here). `nightvision_mode` is the modern superset (adds
> `true_color_mode` / `black_color_mode`); `basic_nightvision` is the older tri-state IR DP.

---

## 2. Video clarity / resolution get-set path (**confidence: HIGH for the path; clarity values HIGH**)

Clarity/resolution is **not** a DP-schema string — it is an integer set through the native P2P SDK:

- Native JNI:
  `getVideoClarity(long, ThingBaseCallback)` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/nativeapi/ThingCameraNative.java:79`;
  `setVideoClarity(long, int, ThingBaseCallback)` — `ThingCameraNative.java:151`.
- High-level interface:
  `getVideoClarity(OperationDelegateCallBack)` —
  `decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/p2p/ICameraP2P.java:508`;
  `setVideoClarity(int, OperationDelegateCallBack)` — `ICameraP2P.java:588`.
- Clarity integer constants — `ICameraP2P.java:22-34`:

| constant | int | meaning |
|---|---|---|
| `STANDEND` | `2` | SD / standard definition |
| `HD` | `4` | high definition |
| `UHD` | `8` | ultra-HD |
| `AUDIO_ONLY` | `65535` | audio-only (no video) |

  No `LD`/low-definition constant exists in this build (grep over `ICameraP2P.java` and the camera
  tree found none) — so the task's "LD" is **unconfirmed (confidence: cannot determine statically)**.
- Device-advertised capability:
  `DeviceAbilityBean.vedioClarity` (int, current) and `vedioClaritys` (`List<Integer>`, supported
  set) —
  `decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/bean/DeviceAbilityBean.java:10-11`,
  getters at `:217` / `:221`. The device returns which of the `{2,4,8}` clarities it supports;
  the SCD921's actual advertised list is a runtime value, not statically known.

---

## 3. Consolidated DP table (one row per control)

Value type legend: **enum** = compiled enum string (high conf); **bool** = boolean DP (type
inferred from Tuya schema, medium); **int** = integer-range DP, range/step from runtime schema via
`BaseDpOperator.getMin/getMax/getStep`
(`.../operate/dp/BaseDpOperator.java:504/397/724`) (type inferred, medium); **native-int** = not a
DP, set via P2P SDK int.

| DP code / API | values → meaning | type | source (file:line) | confidence |
|---|---|---|---|---|
| `nightvision_mode` | `auto`/`ir_mode`/`color_mode`/`true_color_mode`/`black_color_mode` → IR-cut night-vision mode | enum | DpNightVisionMode.java:43 ; NightVisionMode.java:7-11 | HIGH |
| `basic_nightvision` | `0`=auto, `1`=close(off), `2`=open(force IR) → legacy night mode | enum | DpNightMode.java:32 ; NightStatusMode.java:7-9 | HIGH |
| `basic_shimmer` | bool → full-colour / starlight ("shimmer") night view | bool | DpFullColor.java:15 | MEDIUM |
| `getVideoClarity` / `setVideoClarity` | int `2`=SD, `4`=HD, `8`=UHD, `65535`=audio-only → stream resolution | native-int | ThingCameraNative.java:79,151 ; ICameraP2P.java:22-34,508,588 | HIGH |
| `ipc_flip` | `flip_none`/`flip_horizontal_mirror`/`flip_vertical_mirror`/`flip_rotate_90`/`flip_rotate_180`/`flip_rotate_270` → image flip+rotate | enum | DpFlip.java:21 ; CameraFlipMode.java:7-12 | HIGH |
| `basic_flip` | bool → legacy vertical mirror ("flip") toggle | bool | DpMirror.java:15 | MEDIUM |
| `basic_anti_flicker` | `0`=close, `1`=50 Hz, `2`=60 Hz → mains anti-flicker | enum | DpAntiFlicker.java:47 ; AntiFlickerMode.java:7-9 | HIGH |
| `ipc_bright` | int (range/step from schema) → display brightness | int | DpDisplayAdjustBright.java:15 | MEDIUM (code HIGH) |
| `ipc_contrast` | int (range/step from schema) → display contrast | int | DpDisplayAdjustContrast.java:106 | MEDIUM (code HIGH) |
| `ipc_sharp` | int (range/step from schema) → display sharpness | int | DpDisplayAdjustSharpness.java:64 | MEDIUM (code HIGH) |
| `basic_wdr` | bool → wide dynamic range on/off | bool | DpWDR.java:60 | MEDIUM (code HIGH) |
| `basic_osd` | bool → on-screen-display watermark (timestamp/logo) on/off | bool | DpWaterMark.java:16 | MEDIUM (code HIGH) |
| `"DpFPS"` (placeholder) | `FPSMode`: `0`=60 fps, `1`=45 fps, `2`=30 fps | enum (deprecated) | DpFPS.java:8,79 ; FPSMode.java:7-9 | LOW for DP code, HIGH for enum mapping |

All file paths are under `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/`
(`operate/dp/*` for the `Dp*` classes, `mode/*` for the enums) except the clarity classes noted in
§2.

---

## 4. FPS — important caveat (**confidence: enum HIGH, DP code LOW/cannot-determine**)
- `FPSMode` enum maps frame rates —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/mode/FPSMode.java:7-9`:
  `FPS_60="0"`, `FPS_45="1"`, `FPS_30="2"`.
- But `DpFPS` is annotated `@Deprecated`
  (`.../operate/dp/DpFPS.java:8`) and its `f()` returns the literal string `"DpFPS"`
  (`DpFPS.java:79`) — a class name, **not** a Tuya DP code. So the operator does not expose a usable
  FPS DP code in this build. The action is `FPS` (`DpFPS.java:104`).
- UI string resources `ipc_frame_fps` / `ipc_frame_fps_fast` / `fps_text` exist in
  `decompiled/apktool/res` (labels only, not DP codes). The real wire DP code for FPS could not be
  determined statically.

---

## 5. Residual unknowns / what would unblock them
- **Exact value type + numeric range** of `ipc_bright` / `ipc_contrast` / `ipc_sharp`, and the
  boolean encoding of `basic_osd` / `basic_wdr` / `basic_shimmer` / `basic_flip`: these come from
  the SCD921's runtime DP **schema** (`SchemaBean` min/max/step/type), which is fetched per device
  and not present in the static code. **Unblock:** a captured `schema`/`dps` JSON from a live device
  bind/query (anonymized) or the device's published Tuya product schema.
- **Which night-vision DP the SCD921 actually uses** (`nightvision_mode` vs `basic_nightvision`) and
  whether `basic_shimmer` is supported: requires the device schema / a live DP dump.
- **Live FPS DP code:** not resolvable from the deprecated `DpFPS`; would need a live DP report or
  the product schema showing an `fps`-family code.
- **Clarity values the SCD921 advertises** (`vedioClaritys`): subset of `{2,4,8}` is device-runtime
  (`DeviceAbilityBean.getVedioClaritys()`), unblocked by a live `getCameraAbilitys`/ability JSON.
- **`LD` / low-definition:** no constant in this build; if a 4th clarity exists it is not in
  `ICameraP2P`. Unblock: live ability list or a newer SDK build.
