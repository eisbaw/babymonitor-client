# Sound Detection — `decibel_switch` / `decibel_sensitivity` DPs + sound-level indicator (TASK-0097)

How the Philips Avent Baby Monitor+ (SCD921, Tuya reskin) does audio-event
detection: the **sound-detection on/off** switch, the **sound-sensitivity**
(high/mid/low) selector, and the real-time **"sound level indicator"** that the
app advertises as visible "while muted". Static analysis only.

> Citation note: cites name a **symbol** (class/method/enum/DP code) plus a
> `File.java:NN` line that is an approximate hint for the current
> `just decompile` jadx tree (line numbers drift across rebuilds — grep the
> symbol if a line is stale). `decompiled/jadx/sources/...` and
> `decompiled/apktool/...` paths resolve only after a local `just decompile`
> (gitignored). No secrets/PII here: DP codes and string-resource names are
> protocol/UI identifiers, not credentials.

---

## VERDICT

- **Sound detection on/off = DP code `decibel_switch` (boolean, dpId 139).**
  (confidence: high — three independent decompiled sources agree.)
- **Sound sensitivity = DP code `decibel_sensitivity` (string-enum, dpId 140).**
  Value is a stringified level index published to the device. (confidence: high
  for the code/id; medium for the *number of levels* — see the two-enum
  discrepancy below.)
- **The "sound level indicator" is NOT sourced from the `trctaudiospectrumanager`
  RN module.** That module is a *local* audio (phone microphone + local music
  files) FFT visualizer, not the nursery feed. (confidence: high.)
- **The live nursery level most plausibly derives from the decoded stream PCM**
  delivered by the camera SDK callback `IRegistorIOTCListener.receivePCMData(...)`,
  because muting (`setMute`) gates only local speaker rendering, not PCM delivery —
  consistent with the UI tip "See sound activity while muted". (confidence: medium
  — the exact amplitude→UI wiring lives in a runtime-downloaded RN panel bundle
  that is **not** in this static tree; see *Residual unknowns*.)

---

## 1. The two DP codes (AC #1)

### 1a. `decibel_switch` — sound detection on/off (boolean)

- DP operator: `DpSoundCheck.f()` returns the literal DP code.
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpSoundCheck.java:41`
  (`return "decibel_switch";`), and its notify action is `ACTION.SOUND_SWITCH`
  (`DpSoundCheck.java:46`). (confidence: high)
- Settings-row feature `FuncBaseSoundCheck` (dynamic type `SOUND_DETECTED`,
  line 24):
  - support gate: `querySupportByDPCode("decibel_switch")`
    (`.../ipc/panelmore/func/FuncBaseSoundCheck.java:285`)
  - read current state as **Boolean**:
    `x3("decibel_switch", Boolean.class) == Boolean.TRUE`
    (`FuncBaseSoundCheck.java:29`)
  - write on toggle: `L3("decibel_switch", Boolean.valueOf(z), ...)`
    (`FuncBaseSoundCheck.java:321`). (confidence: high)
- Numeric DP id binding: `DeviceDpUtil$DpCode.DP_DECIBEL_SWITCH =
  new DpCode("DP_DECIBEL_SWITCH", 1, "decibel_switch", 139)` →
  `dpCode="decibel_switch"`, `dpId=139` (constructor assigns
  `this.dpCode = str2; this.dpId = i2;`,
  `.../ka/panel/camera/details/camera/utils/DeviceDpUtil.java:84-86`; entry at
  `DeviceDpUtil.java:55`). (confidence: high)

### 1b. `decibel_sensitivity` — sound sensitivity (string-enum)

- DP operator: `DpSoundSensitivity.f()` returns the DP code
  (`.../devicecontrol/operate/dp/DpSoundSensitivity.java:51`,
  `return "decibel_sensitivity";`), notify action `ACTION.SOUND_SENSITIVITY`
  (`DpSoundSensitivity.java:56`). The write path maps an enum to a DP string:
  `this.a.getDps(((SoundSensitivityMode) obj).getDpValue())`
  (`DpSoundSensitivity.java:16`). (confidence: high)
- Settings-row feature `FuncBaseSoundSensitivity`:
  - support gate + read: `querySupportByDPCode("decibel_sensitivity")` then
    `x3("decibel_sensitivity", String.class)`
    (`.../ipc/panelmore/func/FuncBaseSoundSensitivity.java:112-113`); also gated
    against `ipc_alarm_ind` / `decibel_switch` at `FuncBaseSoundSensitivity.java:225,248`.
    (confidence: high)
- Numeric DP id binding: `DP_DECIBEL_SENSITIVITY =
  new DpCode("DP_DECIBEL_SENSITIVITY", 2, "decibel_sensitivity", 140)` →
  `dpId=140` (`DeviceDpUtil.java:56`). (confidence: high)
- Write helper (newer "nightowl-camera-setting" baby-monitor module):
  `DeviceDpUtil.N(devId, SoundSensitivityMode mode)` publishes
  `DpCode.DP_DECIBEL_SENSITIVITY.getDpCode()` with value `mode.dpValue`
  (`DeviceDpUtil.java:1575-1580`). (confidence: high)

### 1c. Value mapping — **two enums disagree on the level count**

There are two `SoundSensitivityMode` enums in the APK and they map levels
differently. This is the one honest ambiguity in AC #1:

| Enum (class) | Values → DP string | Used by |
|---|---|---|
| `com.thingclips.smart.camera.devicecontrol.mode.SoundSensitivityMode` | `LOW("0")`, `HIGH("1")` | legacy IPC panel `FuncBaseSoundSensitivity` |
| `com.thingclips.smart.ka.panel.camera.details.camera.model.SoundSensitivityMode` | `LOW("0")`, `MID("1")`, `HIGH("2")` | newer baby-monitor module (`nightowl-camera-setting`) `DeviceDpUtil` |

- Legacy 2-level enum: `LOW("0"), HIGH("1")`
  (`.../camera/devicecontrol/mode/SoundSensitivityMode.java:7-8`); the legacy panel
  builds its option array as `{HIGH, LOW}`
  (`FuncBaseSoundSensitivity.java:111`) and matches the stored DP string by
  `getDpValue().endsWith(str)` (`FuncBaseSoundSensitivity.java:119`).
- Newer 3-level enum (matches the task's **high/mid/low**):
  `LOW("0"), MID("1"), HIGH("2")`
  (`.../ka/panel/camera/details/camera/model/SoundSensitivityMode.java:7-9`),
  field `dpValue` set in the ctor (`:140-142`); published verbatim by
  `DeviceDpUtil.N()` (`:1579`).

**Interpretation (confidence: medium).** The DP `decibel_sensitivity` carries a
stringified level index. The *dedicated baby-monitor settings module*
(`nightowl-camera-setting`) is the 3-level path (`"0"`=low, `"1"`=mid, `"2"`=high)
and is the one matching the task's high/mid/low UI. The legacy generic-IPC panel
only exposes 2 levels (`"0"`=low, `"1"`=high). Which one the SCD921 actually
renders depends on which panel module is mounted for this product; that cannot be
decided from code alone — see *Residual unknowns*. The on-device accepted value
**set** (whether the device firmware accepts `"2"`) is governed by the device DP
schema, not the app.

### 1d. UI strings (corroborating, AC #1)

- `ipc_sound_detect_switch` = "Sound detection"
  (`decompiled/apktool/res/values/strings.xml:5037`);
  `ipc_sound_detect_settings` = "Sound detection setting" (`:5036`);
  `ipc_sound_detected_switch_settings` = "Sound detection alarm" (`:5038`).
- `mty_sound_detection` / `..._tip` (`:6546-6547`) and `sound_detection` /
  `sound_detection_tips` (`:7755-7756`) phrase the feature as "notified when sound
  is detected based on your preferred sensitivity level" — i.e. `decibel_switch`
  gated by `decibel_sensitivity`. (confidence: high that these strings describe
  this DP pair; the string↔DP link is by semantics, not a code reference.)

### 1e. Not to be conflated: cry detection is a *separate* DP

Cry detection is distinct from generic sound detection: `cry_det_switch`
(dpId 12) and `cry_trans_switch` (dpId 2)
(`DeviceDpUtil.java:72-73`, `FuncCrySoundSwitch`), with string
`ipc_cry_sound_detected_switch_settings` = "Detect Baby Crying"
(`strings.xml:4276`). Documented here only to prevent conflation; cry detection is
out of this task's scope. (confidence: high)

---

## 2. Sound-level-indicator data source (AC #2)

### 2a. The strings

- `bm_sound_level_indicator` = "Sound level indicator"
  (`decompiled/apktool/res/values/strings.xml:1512`; public id `0x7f130567`,
  `decompiled/apktool/res/values/public.xml:18381`).
- `bm_sound_level_indicator_tip` = "See sound activity while muted"
  (`strings.xml:1513`). The `bm_` prefix marks this as a **custom Philips
  baby-monitor** panel string (not stock Tuya). (confidence: high)

### 2b. `trctaudiospectrumanager` is a LOCAL-audio visualizer — RULED OUT as the live source

The task named `trctaudiospectrumanager` as a candidate; the code shows it is a
*local* audio FFT spectrum module, **not** the nursery feed
(`.../rnplugin/trctaudiospectrumanager/TRCTAudioSpectruManager.java`):

- RN module name `"TYRCTAudioSpectruManager"` (`:627-628`).
- Requests **`RECORD_AUDIO` / `MODIFY_AUDIO_SETTINGS` / `READ_MEDIA_AUDIO`(or
  `READ_EXTERNAL_STORAGE`)** (`:134`) — phone microphone + local file access.
- `getLocalMediaLibrary(...)` enumerates the phone's local `Song` list
  (`:571-624`) via `LocalMusicHelper`.
- `audioPlay(filePath, ...)` plays a **local file path** through
  `AbsAudioSpectrumService.n0(ctx, path)` → `IAudioSpectrumInstance`
  (`:333-336`); the instance is a media-player-style FFT (play/pause/stop/release,
  `IAudioSpectrumInstance.java:5-19`).
- FFT samples flow `onFftDataCapture(byte[])` → `onSpectruData(map)` →
  `emit("onSpectruData", ...)` to JS (`:694-703`, `:875-883`).

So this module animates the **lullaby / local-audio** spectrum, gated on the
microphone permission — it is unrelated to streaming nursery audio.
(confidence: high.)

The camera-package counterparts
`com.thingclips.smart.rnplugin.rctvideomanager.RCTAudioSpectruManager` and
`...rctvideomanager.OnAudioSpectrumDataListener` exist but are **empty stubs** in
this build (`RCTAudioSpectruManager.java:1-5`,
`OnAudioSpectrumDataListener.java:1-5`) — the naming hints at an intended
stream-audio spectrum path, but no implementation is present statically.
(confidence: high that they are stubs; low on what they were meant to do.)

### 2c. Most plausible live source: decoded stream PCM, gated by speaker mute only

- The camera SDK delivers decoded audio frames via
  `IRegistorIOTCListener.receivePCMData(int, ByteBuffer, ThingAudioFrameInfo, Object)`
  (`.../camera/camerasdk/thingplayer/callback/IRegistorIOTCListener.java:17`),
  alongside `receiveFrameYUVData(...)` for video. This is the only live audio
  data tap in the static tree. (confidence: high that this is the stream-audio
  callback.)
- Mute affects only **local rendering**: `TRCTCameraManager.enableMute(...)` calls
  `p2PCamera.setMute(PLAYMODE.LIVE, ...)`
  (`.../ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:7873-7896`). Setting
  the speaker mute does not stop `receivePCMData` delivery — which is exactly what
  the tip "See sound activity while muted" requires. (confidence: medium —
  inferred from the API split; no static line computes a level from the PCM.)
- **Conclusion:** the "sound level indicator" is best explained as a Philips panel
  computing an amplitude/level from the live-stream PCM (`receivePCMData`) rather
  than from a DP or from `trctaudiospectrumanager`. The exact computation and the
  JS event name are **not** in this static tree (the panel that references
  `bm_sound_level_indicator` is a runtime-downloaded React-Native bundle — the
  string name appears only in localized `res/values-*/strings.xml`, with **no**
  Java/smali/JS code reference in the decompiled output). (confidence: medium.)

### 2d. Not a DP

No status/report DP for an instantaneous sound *level* exists in
`com/thingclips/smart/camera/devicecontrol/` — the only sound DPs are the two
control DPs in §1 (`decibel_switch`, `decibel_sensitivity`). Detected-sound
*alarms* (string `ipc_alarm_type_sound_detected_txt` = "Sound Alert",
`strings.xml:3983`) are event/push notifications, not a continuous level feed. So
the live indicator is client-side stream telemetry, not a DP read. (confidence:
medium — based on absence of a level DP in the devicecontrol package.)

---

## Residual unknowns / what would unblock

1. **Level count actually used by SCD921** (2 vs 3 sensitivity levels). The two
   enums disagree (§1c). Unblock: a device DP-schema dump for productId
   (see `secrets/` device records / `re/identity_enumeration.md`) or a live read of
   `decibel_sensitivity` value range. Static code alone can't decide which panel
   mounts.
2. **Exact `bm_sound_level_indicator` wiring.** The rendering panel is a
   runtime-fetched RN bundle absent from this APK (only its string resource ships).
   Unblock: capture the downloaded Hermes/JS panel bundle, or a live Frida trace of
   the RN bridge to see whether the level is emitted from a `receivePCMData`-derived
   value, a native audio-spectrum listener, or elsewhere. This is what turns the
   §2c claim from medium to confirmed.
3. **Whether the stubbed `rctvideomanager` audio-spectrum classes are live in
   another build.** They are empty here. Unblock: diff against a newer APK or the
   obfuscated native lib symbol table.
4. **Sound-alarm transport.** Whether a detected-sound event is pushed via the
   message center vs an MQTT report DP is not established here (only the alarm
   *string* was found). Unblock: message-center / push analysis (separate task).
