# PTZ Presets, Cruise/Patrol & Panorama Stitching (TASK-0095)

Static-RE of the higher-level PTZ automation surface of the Tuya IPC stack that the
Philips Avent Baby Monitor+ (SCD921/SCD923) reskins: **collection (preset) points**,
**auto-cruise/patrol**, and **PTZ-driven panorama stitching**. This documents the
DP/API/JNI entrypoints only — no implementation.

> Scope caveat (confidence: high): every entrypoint below is **gated on the camera
> actually having a motorized pan/tilt head**. The SCD921 is a fixed-lens cot camera;
> whether its firmware advertises the PTZ DPs (`ptz_control`, `cruise_*`, `memory_point_set`,
> `ipc_preset_set`) is a *device-schema* question not answerable from the app APK alone
> (the app is the generic Tuya white-label and ships the whole PTZ UI regardless). See
> "Residual unknowns". The code paths are real and present in the shipped APK; their
> *applicability to this specific camera* is unconfirmed.

> Citation note (symbol-anchored, per `re/native_libs.md`): native evidence is anchored on
> the lib **SONAME** + **demangled/JNI symbol name** (stable handles). Offsets are from a
> local `nm -D` of `decompiled/nativelibs/libIPCStitch.so`, which is **gitignored** and
> resolves only after `just decompile`; the symbol *names* are authoritative, the hex
> offsets are convenience. Java `file:line` citations are jadx output, also under the
> gitignored `decompiled/` tree.

---

## 1. DP model — the canonical PTZ datapoint codes (confidence: high)

`decompiled/jadx/sources/com/thingclips/smart/android/camera/sdk/constant/PTZDPModel.java:8-19`
declares every PTZ DP code as a string constant:

| Constant | DP code | Role |
|---|---|---|
| `DP_PTZ_CONTROL` | `ptz_control` | directional pan/tilt step (enum direction) |
| `DP_PTZ_STOP` | `ptz_stop` | stop motor |
| `DP_ZOOM_CONTROL` / `DP_ZOOM_STOP` | `zoom_control` / `zoom_stop` | optical/digital zoom |
| `DP_PRESET_POINT` | `ipc_preset_set` | preset-point set (legacy/simple presets) |
| `DP_MEMORY_POINT_SET` | `memory_point_set` | **collection-point CRUD transport** (add/del/view) |
| `DP_CRUISE_SWITCH` | `cruise_switch` | cruise on/off |
| `DP_CRUISE_MODE` | `cruise_mode` | cruise type: full-pan vs memory-point |
| `DP_CRUISE_STATUS` | `cruise_status` | reported cruise state (read) |
| `DP_CRUISE_TIME` | `cruise_time` | cruise schedule window (JSON) |
| `DP_CRUISE_TIME_MODE` | `cruise_time_mode` | all-day vs scheduled |
| `DP_MOTION_TRACKING` | `motion_tracking` | auto-follow motion (adjacent feature) |

These DP names match Tuya's public IPC PTZ schema; values are device-defined. Confidence
high — they are literal compile-time constants.

---

## 2. Preset / collection points — `IThingIPCPTZ` (confidence: high)

Public SDK interface:
`decompiled/jadx/sources/com/thingclips/smart/android/camera/sdk/api/IThingIPCPTZ.java`

```
addCollectionPoint(String name, IResultCallback)                              // :15
deleteCollectionPoints(List<CollectionPointBean>, IResultCallback)            // :19
modifyCollectionPoint(CollectionPointBean, String newTitle, IResultCallback)  // :27
viewCollectionPoint(CollectionPointBean, IResultCallback)                     // :41
requestCollectionPointList(IThingResultCallback<List<CollectionPointBean>>)   // :35
setCruiseMode(String mode, IResultCallback)                                   // :37
setCruiseTiming(String start, String end, IResultCallback)                    // :39
addPTZListener / removePTZListener(IThingIPCPTZListener)                      // :17/:33
publishDps(String dpCode, Object value, IResultCallback)                      // :29
```

Two error codes are declared at `IThingIPCPTZ.java:12-13`:
`TYPTZERROR_COLLPOINT_CRUISING = "-1431"`, `TYPTZERROR_COLLPOINT_INSUFFICIENT = "-1432"`.

**`CollectionPointBean`** (`.../android/camera/sdk/bean/CollectionPointBean.java`) carries:
`devId, id, mpId, name, pic, pos, encryption`. `mpId` is the device-side memory-point id;
`pos` is the (opaque) motor position blob; `pic` a thumbnail URL; `encryption` an optional
wrapper object. (Getters are heavily larded with `com.ai.ct.Tz` no-op anti-RE calls but
return the plain fields.)

### 2.1 Concrete implementation `bqdbdbd` (confidence: high)

The only shipped impl is the obfuscated
`decompiled/jadx/sources/com/thingclips/smart/camera/middleware/bqdbdbd.java`
(`implements IThingIPCPTZ`). It splits the surface across **two transports**: device DPs
(via `DpHelper.publishDps`) and **cloud HTTP API** (`ApiParams` → `asyncRequest`).

**add** — `bqdbdbd.java:508-619`. Guards on `cruise_status` ∈ {"0","1"} → rejects with
`-1431` ("Cannot add collection points in panoramic cruise and favorite point cruise").
Otherwise publishes DP `memory_point_set` with payload shape:
```
{"type": 1, "data": {"name": "<newTitle>"}}            // type 1 = add
```
(`:595-603`)

**delete** — `bqdbdbd.java:676-727`. Publishes `memory_point_set`:
```
{"type": 2, "data": {"num": <count>,
                     "sets": [ {"devId": "<bean.id>", "mpId": "<bean.mpId>"}, ... ]}}
```
(`:687-703`) — note: the `"devId"` field is populated from `bean.getId()`, not `getDevId()`
(a quirk in Tuya's own code; reproduce as-is for parity).

**view (recall)** — `bqdbdbd.java:1609-1664`. Publishes `memory_point_set`:
```
{"type": 3, "data": {"mpId": "<bean.mpId>"}}           // type 3 = goto/preview
```
(`:1655-1663`). So `memory_point_set` is a **multiplexed CRUD DP** keyed by `type`
(1=add, 2=delete, 3=view); the `mpId`/`pos` round-trip is the camera firmware's job.

**modify (rename)** — `bqdbdbd.java:918-968`. **Not a DP** — a cloud API call:
`ApiParams("thing.m.ipc.memory.point.rename", "1.0")` with post data `id`, `name`
(`:964-967`).

**list** — `bqdbdbd.java:1515-1535`. Also cloud, not DP:
`ApiParams("thing.m.ipc.memory.point.list", "2.0")` with post data `devId`, decoded into
`List<CollectionPointBean>` (`:1522-1524`).

**listener** — `IThingIPCPTZListener.onPTZDeviceDpUpdate(String)`
(`.../sdk/callback/IThingIPCPTZListener.java`) fans out device DP updates;
`bqdbdbd.onDeviceDpUpdate` at `:970-975` iterates registered listeners.

> Parity takeaway: preset CRUD is a **hybrid** — *add/delete/recall* go over the device DP
> channel (`memory_point_set`, type-multiplexed JSON), while *rename/list* go over the Tuya
> mobile cloud API (`thing.m.ipc.memory.point.*`). A Rust client must implement both transports.

### 2.2 Preset UI (confidence: medium — UI only, thin)

`decompiled/jadx/sources/com/thingclips/smart/ipc/presetpoint/activity/CameraPresetPointActivity.java`
is the MVP view (`:24` `implements CameraPresetPointContract.ICameraPresetPointView`) driven by
`...presetpoint/present/CameraPresetPointPresenter` and `...presetpoint/adapter/CameraPresetPointAdapter`
(`:15-17`). It is a thin list/rename/delete UI over §2.1; no new wire protocol lives here.

---

## 3. Auto-cruise / patrol (confidence: high)

**setCruiseMode** — `bqdbdbd.java:1538-1591`. Branches on `mode`:
- `mode != "1"` (i.e. full/panoramic cruise) → publishes DP `cruise_mode` = `mode` directly
  (`:1589`).
- `mode == "1"` (memory-point cruise) → first calls `requestCollectionPointList(...)`; the
  inner callback `qddqppb` (`bqdbdbd.java:~420-440`) requires **≥ 2** stored points, then
  publishes DP `cruise_mode` = `"1"`; otherwise errors with `-1432`
  ("Collection points are less than 2, unable to open the collection point cruise").

Mode values come from the enum
`decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/mode/MemoryCruiseMode.java`:
`FULL_CURISE("0")`, `MEMORY_CURISE("1")` (`getDpValue()` returns the DP string).

**setCruiseTiming** — `bqdbdbd.java:1594-1606`. Two DP writes:
1. DP `cruise_time_mode` = `"1"` (switch to scheduled) (`:1598`).
2. DP `cruise_time` = `{"t_start":"<start>","t_end":"<end>"}` (`:1599-1605`).

Schedule-mode values: `decompiled/.../devicecontrol/mode/MemoryTimeCruiseMode.java`:
`ALL_DAY("0")`, `SCHEDULE("1")`.

**Panel button** — the `ipc_panel_button_cruise` panel action referenced in the task is the
RN/panel surface for the cruise toggle; the underlying writes are the `cruise_switch` /
`cruise_mode` DPs above. The blackpanel MVP triad backs the UI:
`decompiled/jadx/sources/com/thingclips/smart/camera/blackpanel/{view,presenter,fragment}/`
— `ICameraCruiseModeView` / `ICameraCloudPlatformView` / `ICameraCruiseTimeView`,
`CameraCruiseTimePresenter` / `CameraCruiseModelPresenter` / `CameraCloudPlatformPresenter`,
and `CameraCruiseModelFragment` / `CameraCruiseTimeFragment` / `CameraCloudPlatformFragment`.
These are view glue; no extra wire protocol. (Confidence high for the DP writes; medium that
`ipc_panel_button_cruise` maps exactly to `cruise_switch` vs `cruise_mode` — the RN button id
to DP binding was not traced end-to-end.)

---

## 4. PTZ-driven panorama stitching (confidence: medium-high)

This is a **multi-stage capture+download+local-stitch+upload** pipeline, NOT a single DP.

### 4.1 RN entrypoint (confidence: high)

`startStitchingPTZPanorama(Callback, Callback)` is a React-Native `@ReactMethod`:
- declared on the bridge interface
  `decompiled/jadx/sources/com/thingclips/smart/ka/ipc/camera/rnpanel/api/ICameraManager.java:211`
  (siblings: `cancelStitchingPTZPanorama` `:15`, `isSupportStitchingPanorama` `:129`);
- the apktool ReactMethod stubs are in
  `decompiled/apktool/smali_classes3/com/thingclips/smart/rnplugin/trctcameramanager/TRCTCameraManager.smali:27069`
  (`start`), `:1184` (`cancel`), `:15166` (`isSupport`), each delegating to the bound
  `ICameraManager` impl.

**Real impl**:
`decompiled/jadx/sources/com/thingclips/smart/ka/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:18429-18453`.
It needs a `devId` + a live `IThingSmartCameraP2P` handle, then constructs a
`DeviceAlbumManager(devId, p2pCamera)` and invokes its obfuscated method `n(success, failure)`
(= `startStitchingPanorama`, per the inner-class metadata name).

`isSupportStitchingPanorama` (`TRCTCameraManager.java:13279-...`) is **only a runtime
permission check** for `WRITE_EXTERNAL_STORAGE` — it is *not* a device-capability gate. So the
RN "is supported" answer says nothing about whether the camera has a PTZ head. (Important
honesty point.)

### 4.2 Capture → download → stitch → upload (confidence: medium)

`decompiled/jadx/sources/com/thingclips/smart/ipc/localphotovideo/utils/DeviceAlbumManager.java`:
1. `queryAlbumFileIndex("ipc_panorama_tmp", ...)` (`:2530`) — the **device** has already
   swept its PTZ head and stored the panorama frame set in an on-device album named
   `ipc_panorama_tmp`. (The command that *triggers* the device-side sweep was not pinned down
   — see Residual unknowns.)
2. `mP2PCamera.startDownloadAlbumFile("ipc_panorama_tmp", <localDir>, <DownloadAlbumFiledBean2 json>, false, cb)`
   (`:1131`) — pulls the frames over the P2P/album channel to a local temp dir.
3. On download finish, `ThingIPCStitchManager.INSTANCE.startStitchPanorama(srcDir, outPath, progress, success, failure)`
   (`:1381`,`:1559`) does the **local** stitch via JNI (§4.3).
4. `PanoramaUploadBusiness` (`:26`,`:1775+`,`:2013+ uploadPanoramaInfo`) uploads the stitched
   result + metadata back to the Tuya cloud.

So the app's role in "panorama" is: trigger, **download** the device-captured frame burst over
P2P, **stitch locally in native code**, then upload. The pan/tilt motion itself is performed by
the camera firmware.

### 4.3 `libIPCStitch.so` JNI surface (confidence: high)

JNI bridge class:
`decompiled/jadx/sources/com/thingclips/smart/camera/stitch/ThingIPCStitch.java`
(`System.loadLibrary("IPCStitch")` at `:66`). Native methods + matching exports in
`decompiled/nativelibs/libIPCStitch.so` (`nm -D`):

| Java native (`ThingIPCStitch.*`) | JNI export (offset) |
|---|---|
| `getVersion()` | `Java_..._ThingIPCStitch_getVersion` (0x4b5b8) |
| `stitchInit(...)` | `..._stitchInit` (0x4b5bc) |
| `stitchAddMem(...)` | `..._stitchAddMem` (0x4b6a8) |
| `stitchFromMemory(...)` | `..._stitchFromMemory` (0x4b728) |
| `StitchProc(w,h,n,4,6,0,0,0, ByteBuffer[])` | `..._StitchProc` (0x4bc48) |
| `StitchStop()` | `..._StitchStop` (0x4bdc0) |
| `stitchDeinit()` | `..._stitchDeinit` (0x4b7fc) |
| `decodeJpegToRGB888 / encodeRGB888ToJpeg / ...File` | `..._decodeJpegToRGB888` (0x4b800) etc. |
| (entry) | `JNI_OnLoad` (0x4b558) |

`ThingIPCStitch.java` also declares the pixel-format / dtype / mode constants used as
`StitchProc` args: `IMG_TYPE_{Y,YUV,UYUV,RGB888=4,ARBG1555,JPEG=6}` (`:8-13`),
`THING_STITCH_{PANO=0,HALF_PANO=1,GRIDVIEW=2}`, `THING_STITCH_{CPU=0,OPENCL=1,GPU=2}`
(`:30-37`), and error codes `OPRT_IMG_PROC_*` (`-1201..-1209`, `:14-22`). The actual call in
`ThingIPCStitchManager.startStitchPanorama` (`.../camera/stitch/ThingIPCStitchManager.java:817`)
is `StitchProc(width, height, imageCount, 4 /*RGB888 in*/, 6 /*JPEG out*/, 0, 0, 0, byteBuffers)`.
(Confidence medium on the *meaning* of the 4/6 args — inferred from the `IMG_TYPE_*` constants,
not from native disassembly.)

Native results return up via `ThingIPCStitch.onStitchCallback(int,int,int,int,String,ByteBuffer)`
→ `StitchListener.onResult(...)` (`ThingIPCStitch.java:82-89`).

### 4.4 Native stitch engine identity (confidence: high)

Demangled C++ symbols in `libIPCStitch.so` show two layers:
- a thin wrapper class `ThingSmartIPCStitch` (`InitStitch`, `StitchProc`, `StitchStop`,
  `DeinitStitch`, `StitchFromMemory`, `AddMem`, `DecodeJpgToRGB888`, `EncodeRGB888toJpeg[File]`);
- a real **Tuya IMM panorama-stitch core** in namespace `imm_pano_stitch`:
  `Imm_Stitch_Dispatcher` (`start`/`stitch_add`/`stitch_stop`/`stitch`), `Imm_Stitcher`,
  `Imm_ImageRef`, and `Imm_Camera` with classic photogrammetry methods —
  `estimate_focal`, `angle_to_rotation`, `rotation_to_angle`, `straighten`,
  plus `Imm_Homography_Mat`, `Imm_Match_Info`, `imm_mat_crop`, `cvt_uc2f_uchar`. This is a
  feature-match → focal/rotation-estimate → bundle-adjust → warp/blend panorama pipeline
  (OpenCV-stitching-style). The `Imm_*`/`STITCH_STATUS_CB_ENUM` lineage matches the **IMM**
  family already identified in the media path (`re/native_libs.md`, `re/media_decode_spec.md`).
  Plain-C entrypoints `Imm_Ipc_Stitch*` operate over an `_IMM_IMG_STITCH_PARA` struct.

This is purely **local image processing** — no network protocol. A Rust reimplementation would
either FFI this `.so` or substitute an open-source stitcher; it does not require RE of the
internal algorithm for protocol parity.

---

## 5. Residual unknowns / what would unblock

- **Device-schema applicability (confidence: unknown).** Whether SCD921/SCD923 firmware
  actually exposes `ptz_control`/`cruise_*`/`memory_point_set`/`ipc_preset_set` is not derivable
  from the generic Tuya app. *Unblock:* the device DP schema (`thing.m.device.dp.get` /
  `getDataPointList`) for this productId, or a live capture of the panel querying it. (No DP
  values are reproduced here — see `secrets/` for any captured device JSON.)
- **`memory_point_set` `type` enum completeness (medium).** Only 1=add, 2=delete, 3=view are
  used by the app. Whether the firmware defines other `type`s (e.g. update-in-place) is
  unconfirmed. *Unblock:* device firmware or Tuya IPC DP spec.
- **`pos` / `encryption` field format (low).** `CollectionPointBean.pos` (motor coordinates)
  and `encryption` are opaque round-trip blobs in the app. *Unblock:* a captured
  `memory.point.list` response or device-side decode.
- **Panorama sweep trigger (medium).** The app *downloads* `ipc_panorama_tmp` and queries its
  index, but the command that makes the camera perform the PTZ sweep + capture into that album
  was not located (likely a P2P transparent/IPC command or a DP issued elsewhere in the RN
  panel). *Unblock:* trace the RN call just before `queryAlbumFileIndex`, or a live P2P capture.
- **`StitchProc` argument semantics (medium).** The 8 ints are inferred from `IMG_TYPE_*` /
  `THING_STITCH_*` constants, not from native disassembly. *Unblock:* Ghidra decomp of
  `Java_..._StitchProc` (0x4bc48) → `ThingSmartIPCStitch::StitchProc`.
- **`ipc_panel_button_cruise` → DP binding (medium).** The RN panel button id was not traced to
  its exact DP write (`cruise_switch` vs `cruise_mode`). *Unblock:* grep the RN panel JS bundle
  (`re/js_bundle_map.md`) for the button id.

---

## 6. Parity checklist for a Rust client

1. PTZ jog: write DPs `ptz_control` / `ptz_stop` (+ `zoom_control`/`zoom_stop`).
2. Presets: `memory_point_set` type-1/2/3 JSON over the device DP channel; rename/list via
   mobile cloud API `thing.m.ipc.memory.point.rename`(v1.0) / `.list`(v2.0).
3. Cruise: `cruise_mode` ("0" full / "1" memory, requires ≥2 presets); schedule via
   `cruise_time_mode="1"` + `cruise_time={t_start,t_end}`; toggle via `cruise_switch`.
4. Panorama: out of scope for the live stream — it is camera-side sweep + P2P album download +
   local native stitch (`libIPCStitch.so` / `imm_pano_stitch`) + cloud upload. Lowest priority
   for the baby-monitor use case.

All DP/API/JNI handles above are present in the shipped APK; the binding gap is the
device-schema question in §5, which only a device-side artifact can close.
