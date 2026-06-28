# Soothing features — nightlight, lullabies/music, soothing sounds, voice messages (TASK-0093)

Static-RE map of the Philips "Soothing features" cluster for the SCD921 baby unit:
**nightlight LED, lullaby/music library, soothing sounds, and parent voice
messages**. The app groups these under one marketing label (`bm_soothing_features`
= "Soothing features", `decompiled/apktool/res/values/strings.xml:1511`) whose
content string is literally *"Nightlight, soothing sounds, lullabies, true
talk-back, voice recording"* (e.g. `strings.xml:1252,1268,1383,1392`).

Every claim carries a confidence level (high/medium/low) and cites
`file:line` (paths under `decompiled/…` resolve only after a local `just
decompile`; the trees are gitignored). No DP value, device id, key, or PII is
inlined — none was recoverable that would need redaction (see "Residual unknowns").

> **Headline honesty caveat (read first).** The two Tuya modules named in the task
> brief — `TRCTMusicManager` and `TRCTAudioPlayerManager` — are **generic Tuya RN
> modules**, not the SCD921 lullaby/nightlight control surface. `TRCTMusicManager`
> is Tuya's **"Light-Music"** feature (the phone plays *local phone* music, runs an
> FFT, and drives an **RGB smart-bulb** DP so the bulb pulses to the beat). The
> SCD921's *device-side* nightlight/lullaby/soothing-sound playback is driven by
> **per-product Tuya DPs** issued from a **cloud-delivered Philips RN panel** that
> is **not in the APK**. So the *control path shape* (DP publish) is recoverable
> statically; the *specific DP codes* are not. This doc states which is which.

---

## 0. Architecture at a glance (confidence: high)

```
Soothing UI (Philips RN panel, cloud-delivered — NOT in APK)
   │
   ├─ Nightlight on/off + colour ───────┐
   ├─ Lullaby / soothing-sound select ──┤ publishDps({dpCode: value})
   ├─ Volume ───────────────────────────┘ → TUNIIPCCameraManager.publishDps
   │                                        (TUNIIPCCameraManager.java:3049)
   │                                      → MQTT DP publish (AES-ECB/localKey)
   │                                        [see re/webrtc_session.md, streaming docs]
   │   dpCodes for these features = UNKNOWN statically (cloud schema/panel)
   │
   └─ Voice message
        record (mic, RECORD_AUDIO) ─ panel/native ─ upload to cloud storage
            (generic TUNICloudStorageSignatureManager.generateSignedUrl path)
        playback of a stored message clip:
            native ThingCameraNative.playAudioMessage(handle, path, i, key, cb)
            (ThingCameraNative.java:103) via IThingCloudVideo.playAudio
            (bbppbbd.java:2112) → frame info to panel as
            TUNIDLIPCManager.onPlayMessageAudioInfo (TUNIDLIPCManager.java:16)
        in-app audio preview / TTS:
            TRCTAudioPlayerManager.audioPlay(url) / textSpeechPlay(text,…)
```

Two distinct, easily-conflated "audio" subsystems exist; keep them apart:

| Subsystem | Java module / native | What it actually does | Used by soothing UI? |
|---|---|---|---|
| **Light-Music** | `TRCTMusicManager` + `LightMusicPresenter` (`TYRCTMusicManager`); GZL twin `TUNIMusicManager` | phone-local music → FFT → **RGB bulb** DP | **Probably not** for SCD921 (medium) |
| **Device DP control** | `TUNIIPCCameraManager.publishDps` / `TUNIDeviceControlManager.publishDps` | issue device DPs over MQTT | **Yes** — the real nightlight/lullaby path (high) |
| **Camera message player** | `ThingCameraNative.playAudioMessage` / `IThingCloudVideo` | play a stored (cloud) audio/video **message** clip | **Yes** — voice-message playback (high) |
| **In-app audio/TTS** | `TRCTAudioPlayerManager` (`TYRCTAudioPlayerManager`) + `AudioPlayer` / `TextToSpeechManager` | play a URL/file in-app; text-to-speech | preview / TTS only (medium) |

---

## 1. Nightlight LED

### 1.1 What is statically certain (confidence: high)
The SCD921 has a **physical nightlight LED below the camera** with a dedicated
hardware **NIGHTLIGHT button** (paired with a **LULLABY button**):

- `strings.xml:1089` `bm_activator_step2_1` — *"Press and hold the NIGHTLIGHT and
  LULLABY buttons together for 3 seconds."*
- `strings.xml:1090` `bm_activator_step2_2` — *"When the nightlight (below the
  camera) pulses soft orange press Next to proceed."*
- `strings.xml:8066-8067` `thing_activator_init_step1/2` — same NIGHTLIGHT+LULLABY
  hold + *"Check the nightlight softly blinks"*.
- Pairing/firmware screens also use the nightlight colour as a status indicator
  (`firmware_upgrade_process_4` `strings.xml:2782`, `firmware_version_confirm`
  `strings.xml:2792`).

So "nightlight" is a first-class device LED, used both as a soothing light and as a
pairing/status indicator.

### 1.2 The app-side control path (confidence: high for shape; the DP code is UNKNOWN)
Toggling the nightlight from the app is an ordinary **Tuya DP write**, not a
bespoke API. The static evidence for the generic write path:

- `com/thingclips/smart/plugin/tuniipccameramanager/TUNIIPCCameraManager.java:3049`
  — `public void publishDps(@NonNull DpsPublish dpsPublish, …)`. The IPC panel
  publishes DPs through this bridge (the `publishDps` verb is also listed in the
  manifest `decompiled/js/assets/thing_uni_plugins/TUNIIPCCameraManager.json`, see
  `re/js_bundle_map.md`).
- `com/thingclips/smart/plugin/tunidevicecontrolmanager/TUNIDeviceControlManager.java`
  also exposes `publishDps` (generic device DP control). DP publishes ride the
  MQTT control plane (AES-ECB/localKey) per `re/webrtc_session.md` /
  `re/streaming_mode.md`.

**The specific nightlight DP code/id is NOT in the static APK** (see §5). What we
have is: nightlight = `publishDps({<nightlight_dp>: on/off | colour})`.

### 1.3 Why `TRCTMusicManager`'s RGB output is *not* the camera nightlight (confidence: medium-high)
The only RGB-LED code in the APK is Tuya's generic Light-Music sync (see §2.4),
which computes `(R,G,B,W,C,brightness,index)` from a phone-music FFT and emits it
toward a **smart-light DP** — there is no camera handle and no camera DP in that
path. It is the "bulb dances to music" feature, reused verbatim from Tuya, and
almost certainly not wired to the SCD921 nightlight. Evidence it is bulb-oriented:
`LightMusicPresenter` drives `IMusicRgbListener.a(R,G,B,W,C,dB,index)`
(`LightMusicPresenter.java:71-72`) and the GZL manifest calls it
`getRGBAudioManager` (`TUNIMusicManager.json`).

---

## 2. Lullaby / music library (the `TRCTMusicManager` cluster)

This is the cluster named in the task brief. **Verdict: it is Tuya's generic
Light-Music module, whose track list is the *phone's local* audio library and
whose output is an *RGB-bulb* colour stream — not the camera's on-board lullaby
library.** Documented here because it is the literal `playMusic/getMusicList/…`
surface the brief points at, with the honest caveat above.

### 2.1 The RN module surface (confidence: high)
`com/thingclips/smart/rnplugin/trctmusicmanager/TRCTMusicManager.java`,
registered as **`TYRCTMusicManager`** (`getName()`, line 466). `@ReactMethod`s:

| JS method | Delegates to `LightMusicPresenter` | Note |
|---|---|---|
| `getMusicList(cb,cb2)` (231) | `checkMusicRecordListPermission` → `p0` | builds the list |
| `playMusic(map,cb,cb2)` (990) | `w0(map.getInt("itemIndex"), …)` (1025) | 1-based index |
| `pauseMusic` (848) | `u0` (914) | |
| `resumeMusic` (1029) | `v0` (1059) | |
| `stopMusic` (1220) | `z0` (1266) | |
| `musicThreshold(map)` (475) | `x0(map.getDouble("threshold"))` (506) | RGB-trigger sensitivity |
| `startVoice/stopVoice` (1142/1353) | `y0` / `A0` | mic capture for RGB sync (NOT a voice message) |
| `customOperation` (158) | — | obfuscated no-op stub |

`playMusic` takes `{"itemIndex": int}` (`TRCTMusicManager.java:1025`); `musicThreshold`
takes `{"threshold": double}` (line 506).

### 2.2 Track-list source = the phone's LOCAL audio library (confidence: high)
`getMusicList` first demands **mic + media-read permissions**, which only makes
sense for scanning on-device audio:

- `checkMusicRecordListPermission` requests `RECORD_AUDIO` **and**
  `READ_MEDIA_AUDIO` (API ≥ 33) / `READ_EXTERNAL_STORAGE`
  (`TRCTMusicManager.java:131-143`).

The list itself comes from a local Android **`MusicPlayService`**:

- `LightMusicPresenter.p0` binds `MusicPlayService` and reads
  `musicPlayService.g()` (`LightMusicPresenter.java:2007`, also `:476`), producing
  a `List<Song>`; each entry maps to `MusicBean{name=song.getMusicName(),
  author=song.getArtist()}` (`LightMusicPresenter.java:1639-1646`) returned to JS
  under key `"data"`.
- `MusicPlayService` is `com.thingclips.stencil.component.media.MusicPlayService`
  with `Song` beans (`LightMusicPresenter.java:14-16`) — a phone media player.

**So: track list = local phone storage. It is NOT a cloud playlist and NOT the
camera's built-in lullaby set.** (confidence: high)

### 2.3 Play/volume command path for this module (confidence: high)
Playback is local Android `MusicPlayService`, not a device command:

- `w0(index)` → `musicPlayService.o(index-1)` (`LightMusicPresenter.java:2240`)
- `u0` pause → `musicPlayService.k()` (`:2159`)
- `v0` resume → `musicPlayService.s()` (`:2220`)
- `z0` stop → `musicPlayService.u()` (`:2507`)

There is **no volume DP** here; `musicThreshold` (`x0`, `:2267`) only sets the RGB
trigger gap: `this.n.b((long)(d * v))` with `v = 600` (`:2350-2351`, `:744`).

### 2.4 What this module is really for: RGB-light music sync (confidence: high)
`MusicPlayService.IMusicFFTListener.a(byte[] fft, int)` →
`MusicUtils.e(fft)` amplitude (clamped 0–99) → `MusicUtils.d(e)` → `int[] rgb`
(`LightMusicPresenter.java:63-70`); then
`IMusicRgbListener.a(rgb[0..4], brightness=e, index=e/10)`
(`LightMusicPresenter.java:71-72`), surfaced to JS as the `audioRgbChange` event
(`TRCTMusicManager.java:86-92`). `startVoice` swaps the music source for a live
mic via `LightRecorder` (`LightMusicPresenter.y0`, `:2430-2437`) — still feeding
the same RGB pipeline. This is a smart-**bulb** effect.

### 2.5 GZL/uni twin (corroboration) (confidence: high)
A second copy exists for Tuya's GZL/mini-app runtime:
`com/thingclips/smart/plugin/tunimusicmanager/copyfromrnapi/LightMusicPresenter.java`
+ `IMusicRgbListener.java`, with manifest
`decompiled/js/assets/thing_uni_plugins/TUNIMusicManager.json` exposing
`getRGBAudioManager, startRGBRecord, stopRGBRecord, onAudioRgbChange,
offAudioRgbChange` — i.e. explicitly an **RGB-audio** manager, confirming the
"music manager" is colour-sync, not lullaby playback.

---

## 3. Soothing sounds

Treated by the app as a sibling of lullabies (same cluster string: *"…soothing
sounds, lullabies…"*, `strings.xml:1252` et al.). Statically there is **no separate
soothing-sound module** in the APK: like lullabies, this is a **device-side sound
set selected via a DP** from the cloud panel. The control path is the same generic
`publishDps` of §1.2; the specific DP code(s) (sound id, volume, on/off) are
**UNKNOWN statically** (§5). (confidence: medium — inference from the grouping
string + the absence of any dedicated module; the DP detail is genuinely
unrecoverable from static evidence.)

---

## 4. Voice messages (record → store → playback)

The parent records a message; it is stored (cloud) and played back as a message
clip. Three pieces are statically visible; one link is honestly ambiguous.

### 4.1 Playback primitive — native `playAudioMessage` (confidence: high)
`com/thingclips/smart/camera/nativeapi/ThingCameraNative.java:103`:

```
public static native int playAudioMessage(
    long handle, String path, int i, String key, ThingFinishableCallback cb);
```

with siblings `pauseAudioMessage` (`:85`), `resumeAudioMessage` (`:111`),
`stopAudioMessage` (`:187`). Interface mirror:
`com/thingclips/smart/camera/api/ThingCameraInterface.java:107`
`playAudioMessage(String, int, String, ThingFinishableCallback)`.

Wiring (confidence: high): the middleware implements Tuya's **cloud-message
player** `IThingCloudVideo`:

- `com/thingclips/smart/camera/middleware/bbppbbd.java:2112-2117`
  `playAudio(path, i, key, cb, cb2) { this.f.playAudioMessage(path, i, key, …); }`
  (interface `IThingCloudVideo.playAudio`), with the log tag
  `"ThingCloudVideoPlayer"` (`bbppbbd.java:775`). The `key` (3rd `String`) is the
  decrypt key for the stored encrypted clip (same signature shape as
  `playVideoMessage`, `ThingCameraNative.java:107`).

Interpretation: `playAudioMessage` plays a **stored/cloud audio message clip**
(decrypting with `key`) through the camera-SDK message player. (confidence: high
that this is a message-clip player; see §4.4 for the device-speaker question.)

### 4.2 Playback frame info to the panel (confidence: high)
`com/thingclips/smart/plugin/tunidlipcmanager/TUNIDLIPCManager.java:16`
`onPlayMessageAudioInfo(MessageAudioInfoModel)` emits progress to JS. Model fields
(`MessageAudioInfoModel.java`): `duration, frameRate, height, width, progress,
timestamp`. (Note the `width/height/frameRate` fields — the "audio message" model
is shared with, or is the audio track of, a recorded **video** message; medium
confidence on that nuance.) The manifest `TUNIDLIPCManager.json` lists
`onPlayMessageAudioInfo, onPlayMessageVideoInfo, onPlayMessageVideoFinish`.

### 4.3 In-app audio/TTS player — `TRCTAudioPlayerManager` (confidence: high)
`com/thingclips/smart/rnplugin/trctaudioplayermanager/TRCTAudioPlayerManager.java`,
registered **`TYRCTAudioPlayerManager`** (`TAG`, line 13; `getName` line 807).
`@ReactMethod`s wrap `AudioPlayer` + `TextToSpeechManager` (fields lines 14-20):

- `audioPlay(String url, Callback)` (`:90`) → `audioPlayer.m(url, true, cb)`
- `audioPause()` (`:24`), `audioResume(url,…)` (`:138`), `audioStop()` (`:548`)
- `getCurrentAudioInfo(cb)` (`:617`)
- `textSpeechPlay(String text, float rate, String, cb)` (`:913`) /
  `textSpeechStop()` (`:1173`) → `TextToSpeechManager`

This is an **in-app** player of a URL/file (e.g. preview the recording you just
made, or speak a typed message). It does not itself reach the camera. (confidence:
high for what it is; its exact use in the soothing UI is medium — that wiring lives
in the cloud panel.)

### 4.4 Record + store + "play to the baby" — the honest gaps (confidence: low-medium)
- **Record**: a `RECORD_AUDIO` mic capture done in the cloud panel/native. The
  only in-APK recorder is `LightRecorder` (`LightMusicPresenter.y0`,
  `LightMusicPresenter.java:2430`), which feeds the **RGB** pipeline, *not* a voice
  message — so the voice-message recorder is **not** statically present here.
- **Store/upload**: the generic Tuya cloud-storage signer
  `TUNICloudStorageSignatureManager.generateSignedUrl`
  (`re/js_bundle_map.md`) is the plausible upload path, but no voice-message
  upload call is visible in the static APK. (confidence: low.)
- **Play to the *device speaker* vs in-app**: `playAudioMessage` is an app-side
  **cloud-message player** (`IThingCloudVideo`). Whether the parent's recorded
  message is pushed to the **camera speaker** (to soothe the baby) cannot be
  confirmed statically. The device-speaker direction is more consistent with
  **talk-back** (`startAudioTalk` / `sendAudioTalkData`,
  `ThingCameraNative.java:159,129`) or a **DP-triggered device-side playback of an
  uploaded file** — neither of which is the `playAudioMessage` path. **Flagged
  ambiguous.** (confidence: low.)

---

## 5. Residual unknowns (and what would unblock them)

1. **Nightlight / lullaby / soothing-sound DP codes (ids, value enums, volume)** —
   *not in the static APK*. The SCD921 soothing UI is a **cloud-delivered Philips
   RN panel** (the APK ships only generic Tuya `kit_js` / `mini_app_js` /
   `thing_uni_plugins`; no Philips panel — confirmed by `find decompiled/js/assets`
   and zero `nightlight|lullaby` hits outside `strings.xml`). The DP schema lives
   in the device's per-product cloud schema.
   *Unblock*: pull the device DP schema for the SCD921 productId (mobile-app
   `tuya.m.device.dp.get` / panel bootstrap) from a **live capture of the soothing
   panel**, or decompile the downloaded RN panel bundle. (Available captures
   `emulator_captures/cap0-6` contain *no* DP schema — `grep` for
   `dps|dpCode|schema` returns nothing.)

2. **Lullaby / soothing-sound track names + count** — device-side asset set, not in
   the APK. *Unblock*: same panel/schema capture (the DP enum usually lists them).

3. **`TRCTMusicManager` usage by the SCD921** — strong inference it is the generic
   RGB-bulb feature, **not** this camera's lullaby. *Unblock*: the panel JS (which
   native modules it imports) or a runtime trace.

4. **Voice-message record/upload/trigger chain** — only the *playback* primitive
   (`playAudioMessage`) and an in-app player (`TRCTAudioPlayerManager`) are static.
   *Unblock*: a live capture of the "record + send voice message" action (REST
   upload + the MQTT/DP or message command that triggers playback) and the panel JS.

5. **Whether the recorded message plays on the camera speaker** — ambiguous (§4.4).
   *Unblock*: same live capture; check if playback is `startAudioTalk`-style
   streaming, a DP trigger, or the cloud-message `playAudioMessage` clip player.

---

## Evidence index (primary citations)

- `decompiled/apktool/res/values/strings.xml:1089-1090,1252,1268,1383,1392,1511,8066-8067`
- `…/rnplugin/trctmusicmanager/TRCTMusicManager.java:131-143,231,466,475-506,848,990-1025,1029,1142,1220,1266,1353`
- `…/rnplugin/trctmusicmanager/LightMusicPresenter.java:63-72,476,1639-1646,2007,2155-2161,2216-2222,2225-2245,2267,2350-2351,2430-2437,2503-2509`
- `…/plugin/tunimusicmanager/copyfromrnapi/LightMusicPresenter.java` (+ `IMusicRgbListener.java`); `…/thing_uni_plugins/TUNIMusicManager.json`
- `…/camera/nativeapi/ThingCameraNative.java:85,103,107,111,129,159,187`
- `…/camera/api/ThingCameraInterface.java:107`
- `…/camera/middleware/bbppbbd.java:775,2112-2117`
- `…/plugin/tunidlipcmanager/TUNIDLIPCManager.java:16` (+ `MessageAudioInfoModel.java`); `…/thing_uni_plugins/TUNIDLIPCManager.json`
- `…/rnplugin/trctaudioplayermanager/TRCTAudioPlayerManager.java:13,24,90,138,548,617,807,913,1173`; `…/thing_uni_plugins/TUNIAudioManager.json`
- `…/plugin/tuniipccameramanager/TUNIIPCCameraManager.java:3049`; `…/plugin/tunidevicecontrolmanager/TUNIDeviceControlManager.java` (`publishDps`)
- Cross-refs: `re/js_bundle_map.md`, `re/webrtc_session.md`, `re/streaming_mode.md`
