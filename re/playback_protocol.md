# Recorded-video playback & download protocol (TASK-0100)

**Confidence: HIGH on the Java/native API surface and the encrypted-clip key/cipher
contract (all from decompiled sources, file:line cited). MEDIUM/LOW on the
*native-internal* segment decrypt (the per-segment cipher mode used inside the closed
`.so` is inferred, not byte-verified) and on a few opaque integer/string parameters
that the visible Java passes straight through to JNI.**

This documents the **recorded-video** path (SD-card and cloud time-lapse playback +
download), which is distinct from the already-RE'd **live** stream
(`re/streaming_mode.md`, `re/media_decode_spec.md`, `re/webrtc_session.md`). Live = WebRTC-
over-MQTT + KCP; recorded = a time-slice index API plus segment playback/seek/speed and an
encrypted-clip download/decrypt format described below.

All citations are under `decompiled/jadx/sources` (Java) and `decompiled/apktool`
(resources). No secret/PII values are inlined — only class/method/field/API-topic names.

---

## 1. Two distinct recorded paths (LOCAL-SD vs CLOUD)

The app exposes two parallel recorded-playback stacks behind the same React-Native bridge
(`com/thingclips/smart/rnplugin/trctcameramanager/TRCTCameraManager.java`), which delegates
to `ICameraManager impl`
(`com/thingclips/smart/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java`):

| Aspect | LOCAL-SD playback | CLOUD playback |
|---|---|---|
| RN methods | `playbackStart/Seek/Pause/Resume/Stop`, `requestPlaybackTimeSliceDataByDay`, `getBackDataByMonth` | `cloudPlaybackStart/Pause/Resume/Stop`, `configCloudData`, `configCloudDataV2` |
| Backing SDK obj | `IThingSmartCameraP2P` (`getP2PCamera()`) | `IThingCloudCamera` (`getCloudCamera()`) |
| Index source | **device** over P2P (SD card) | **cloud REST** (`thing.m.ipc.storage.*`) |
| Transport | P2P session to camera | HTTPS segment URLs from cloud |
| Confidence | HIGH | HIGH on API, MEDIUM on wire |

Evidence the RN layer is a thin pass-through: each `@ReactMethod` just forwards to
`this.impl` (e.g. `playbackStart` rnplugin `TRCTCameraManager.java:4103/4155-4157`;
`requestPlaybackTimeSliceDataByDay` rnplugin `:4358/4418-4420`;
`cloudPlaybackStart` rnplugin `:4407/4409-4410`). The `Tz.a()/Tz.b(0)` lines interleaved
everywhere are obfuscation no-ops (`com.ai.ct.Tz`) and carry no logic. **[HIGH]**

---

## 2. The native record-index + playback API (JNI)

All native entrypoints are `static native` in
`com/thingclips/smart/camera/nativeapi/ThingCameraNative.java`; `long j` is the camera
handle. **[HIGH — declarations are explicit]**

| Native decl | `ThingCameraNative.java` | Role |
|---|---|---|
| `getRecordDaysByMonth(long, String, ThingBaseCallback)` | :71 | which days in a month have SD recordings |
| `getRecordFragmentsByDay(long, String, int, ThingBaseCallback, boolean)` | :75 | time-slice fragments for a day |
| `getRecordFragmentsByDayAndPageId(long, String, int, ThingBaseCallback)` | :77 | paged variant |
| `getRecordEventFragmentsByDayAndPageId(long, String, int, ThingBaseCallback)` | :73 | event-only fragments (motion/AI) |
| `startPlayBack(long, int, int, int, int, ThingFinishableCallback)` | :169 | begin SD playback |
| `startPlayBackWithPlayTime(long, int, int, String, ThingFinishableCallback)` | :173 | begin at an explicit play time |
| `startPlayBackDownload(long, int, int, String, String, String, int, int, ThingProgressiveCallback)` | :171 | download an SD time range to a file |
| `pausePlayBack(long)` / `resumePlayBack(long)` / `stopPlayBack(long, cb)` | :91 / :117 / :195 | transport control |
| `setPlayBackSpeed(long, int, ThingBaseCallback)` | :143 | variable-speed (int speed code) |
| `setEncryptionInfo(long, String)` | :139 | install per-uuid decrypt keys (see §5) |
| `getCloudUrls(long, long, long, boolean, String, String) : String` | :63 | cloud segment URLs |
| `playCloudDataWithStartTime(long, long, long, boolean, String, String, ThingFinishableCallback)` | :105 | begin cloud playback at a start time |
| `startCloudDataDownload(long, long, long, String, String, String, String, String, int, ThingProgressiveCallback)` | :161 | download a cloud range to file |
| `setPlayCloudDataSpeed(long, int)` | :145 | cloud variable-speed |

### 2.1 Middleware contract (parameter meanings)

The middleware interface `com/thingclips/smart/camera/middleware/p2p/IThingSmartCameraP2P.java`
(mirror: `com/thingclips/smart/camera/ipccamerasdk/p2p/ICameraP2P.java`) pins the parameter
shapes the app actually uses. **[HIGH]**

- `startPlayBack(int startTime, int stopTime, int playTime, cb, cb)`
  (`IThingSmartCameraP2P.java:239`, `ICameraP2P.java:606`) — three **epoch-second** ints:
  range start, range stop, and the in-range play position.
- `startPlayBackWithEncryption(int, int, int, cb, cb)` (`ICameraP2P.java:614`) — encrypted SD variant.
- `queryRecordDaysByMonth(int year, int month, cb)` (`:130 / :533`).
- `queryRecordTimeSliceByDay(int year, int month, int day, cb)` (`:135 / :537`); plus a
  4-arg paged form (`:132 / :535`) and `queryRecordTimeSliceByDayWithEncryption` /
  `…NoEncryption` (`ICameraP2P.java:539`, `IThingSmartCameraP2P.java:137`).
- `setPlayBackSpeed(int speed, cb)` (`:201 / :580`).
- `startPlayBackDownload(int start, int stop, String folderPath, String fileName, cb, progress, cb)`
  (`:243 / :610`) and `…WithEncryption` (`:612`).
- `getDayKey() : String` (`:91 / :496`) — the cache key used to memoize a day's slices.

> The JNI `startPlayBack` has **four** ints (`ThingCameraNative.java:169`) but the visible
> Java middleware only ever supplies **three** (start/stop/playTime) — e.g.
> `IPCThingP2PCamera.java:13973` calls the 3-int `ThingCamera.startPlayBack(i,i2,i3,cb)`.
> The JNI's 4th int is **not mapped by any visible Java caller**. **[LOW — unresolved, see §6]**

### 2.2 RN → SDK wiring (the actual call bodies)

`com/thingclips/smart/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java`:

- `playbackStart(String start, String stop, String playTime, ok, err)` parses the three
  strings as ints and calls `p2PCamera.startPlayBack(parseInt, parseInt, parseInt, …)`
  (`:12535`, call at `:12540`). On the *second* callback's `onFailure` it emits the RN
  event `"playbackFinished"` (`:12725`) — i.e. end-of-range is reported as a playback-finish.
- **`playbackSeek(start, stop, playTime, ok, err)` simply calls
  `playbackStart(start, stop, playTime, ok, err)`** (`:12423`, delegating at `:12499`).
  **There is no separate native seek — a seek is a fresh `startPlayBack` at the new
  position.** **[HIGH — this is the seek contract]**
- `requestPlaybackTimeSliceDataByDay(int year, int month, int day, cb)` calls
  `p2PCamera.queryRecordTimeSliceByDay(year, month, day, cb)` (`:13144`, call at `:13172`).
  `onSuccess(str)` → `parsePlaybackData` (via `access$3500` → `:2639`); `onFailure` returns
  an empty `JSONArray` (`:13228`).
- `getBackDataByMonth(int, int, ok, err)` calls `p2PCamera.queryRecordDaysByMonth(i, i2, cb)`
  (`:8306`, call at `:8309`); failure → empty `JSONArray` (`:8315`). This is the RN name for
  the native `getRecordDaysByMonth`.
- `isPlaybackStarting(cb)` (`:10571`), `gotoCameraNewPlaybackPanel[WithParams]`
  (rnplugin `:2020/:2116`) are UI/state helpers.

---

## 3. The time-slice index format (the "what's recorded" contract)

`requestPlaybackTimeSliceDataByDay` returns a JSON string from native that
`parsePlaybackData` deserializes (`TRCTCameraManager.java(impl):4840-4858`) as
`RecordInfoBean` → `List<TimePieceBean>`, caches under `p2PCamera.getDayKey()`
(`:4845`), and hands back to RN as a JSON array (`:4848`). **[HIGH]**

`RecordInfoBean` (`com/thingclips/smart/camera/base/bean/RecordInfoBean.java:9-10`):
`{ int count; List<TimePieceBean> items; }`.

`TimePieceBean` (`com/thingclips/smart/camera/middleware/cloud/bean/TimePieceBean.java:11-25`)
— one recorded fragment / segment. Each segment is keyed by `uuid`: **[HIGH]**

| field | type | meaning |
|---|---|---|
| `startTime` | int | fragment start, **epoch seconds** (`getStartTimeInMillisecond = ×1000`, :540/372) |
| `endTime` | int | fragment end, epoch seconds |
| `playTime` | int | current/seek position within the fragment |
| `uuid` | String | per-segment id; the **decrypt-key lookup key** (§5) |
| `encrypt` | String/int | encryption flag — raw native JSON uses int `1` = encrypted (see `filterUsablePlaybackData:5834`) |
| `encryptMD5` | String | integrity tag binding the secret to the segment (§5) |
| `segmentSize` | int | byte size of the segment |
| `prefix` | int | storage prefix id (cloud media prefixes; `thing.m.ipc.storage.prefixs.get`) |
| `type` / `eventType` | long | record type / event classification |
| `event` | boolean | is this an event (motion/AI) clip |
| `videoType` | int | codec/profile hint (`isAOVVideoType`, :689) |
| `authorityJson` | String | per-segment read-authority blob |
| `isAIStorage` | String | AI-storage marker |
| `aiDetectList` | List<AITimePieceBean> | per-segment AI detections |

The cloud index uses the same `TimePieceBean` shape:
`IThingCloudCamera.getTimeLineInfo(String devId, long start, long end, IThingResultCallback<List<TimePieceBean>>)`
(`IThingCloudCamera.java:88`) and `getTimeLineInfoWithPrefix(…)` (`:90`). **[HIGH]**

---

## 4. Cloud playback config + entrypoints

`IThingCloudCamera` (`com/thingclips/smart/camera/ipccamerasdk/cloud/IThingCloudCamera.java`):

- `cloudPlaybackStart(String start, String stop, boolean z, String s3, String s4, ok, err)`
  (impl `TRCTCameraManager.java:5984`) → `cloudCamera.playCloudDataWithStartTime(parseLong(start),
  parseLong(stop), z, s3, s4, …)` (`:6014`). `start/stop` are **epoch (long)**; `s3`/`s4` are
  passed straight to the SDK (the deprecated overload signature is
  `playCloudDataWithStartTime(long,long,boolean,String,String,cb,cb)`, `IThingCloudCamera.java:107`)
  — **inferred** cache-path / key, not confirmed from JS. **[MEDIUM on s3/s4 meaning]**
- `configCloudData(String json)` → `cloudCamera.configCloudDataTagsV1(json, null)`
  (impl `:6718`; iface `:32`, `@Deprecated`).
- `configCloudDataV2(String json, ok, err)` → `cloudCamera.configCloudDataTags(json, cb)`
  (impl `:6727`; iface `:28`). `onSuccess` returns the SDK string verbatim to RN (`:6836`).
  These install the **cloud-data tag set** (which event/storage classes to surface) before
  building the cloud timeline. **[HIGH on call shape; MEDIUM on the JSON schema — not dumped here]**
- Other cloud index/url methods: `getCloudDays(devId, prefix, cb)` (`:63`),
  `getCloudUrls(devId, long, long, boolean, cb)` (`:78`),
  `getCloudFrameDownloadInfo(String, int, int, int, cb)` (`:65`),
  `getCloudStorageUrl(long, String, cb)` (`:74`),
  `setPlayCloudDataSpeed(int, OperationCallBack)` (`:134`),
  `startCloudDataDownload(…)` (`:142/:145`), `stopCloudDataDownload(cb)` (`:151`),
  `registerSlicePlayStartListener(cb)` (`:120`).

### 4.1 Cloud REST endpoints (the index/secret backend)

`com/thingclips/smart/camera/ipccamerasdk/cloud/CloudBusiness.java` (Tuya mobile API
topics, `Business.ResultListener`): **[HIGH]**

| API topic | line | role |
|---|---|---|
| `thing.m.ipc.storage.secret.get` | :38 | per-device cloud-storage secret (`getCloudSecret`, :707) |
| `thing.m.ipc.storage.secret.get.list` | :39 | per-uuid secret list (`getCloudSecretsByUUID`, :773) |
| `thing.m.ipc.storage.prefixs.get` | :34 | media prefixes (`getMediaPrefixs`, :1162) |
| `thing.m.ipc.storage.read.authority.get` | :35 | read-authority for segments |
| `thing.m.ipc.storage.info.day.count` | :40 | day-count index |
| `thing.m.cloud.disk.property.get` | :29 | cloud-disk property (`queryCloudDiskProperty`) |
| `thing.m.storage.timerange.delete` / `thing.m.storage.days.delete` | :27 / :28 | delete clips |

Timeline + url helpers: `getCloudTimeLine(devId, …, cb)` (`:1010`),
`getCloudStorageUrl(cb)` (`:894`), `getCloudStorageUrlConfig(…)` (`:901`). The Tuya
mobile-app sign covers these (see `re/tuya_sign.md` / `re/review_gate_findings.md`).

---

## 5. Encrypted-clip key source + cipher (the decrypt contract)

This is the heart of AC#2. There are **two** decrypt surfaces, sharing one key source.

### 5.1 Key source + integrity binding — `[HIGH]`

A recorded segment is encrypted when its index entry has `encrypt == 1`
(`IPCThingP2PCamera.java:5834`). The AES key for each segment is a **per-uuid `secretKey`**
fetched from the cloud, NOT stored on the clip:

1. App collects the encrypted segments' `uuid`s and calls
   `getCloudSecretsByUUID(List<uuid>, cb)` →
   `mCloudBusiness.getCloudSecretsByUUID(JSON.toJSONString(list), cb)`
   (`IPCThingP2PCamera.java:5864/5899`) → REST `thing.m.ipc.storage.secret.get.list`
   (`CloudBusiness.java:39/773`). The reply array carries `{uuid, secretKey}`.
2. **Integrity check** binds the returned secret to the indexed segment
   (`IPCThingP2PCamera.filterUsablePlaybackData:5826-5862`):
   `sha256 = SHA256Util.sha256(secretKey)` (hex), truncated to 32 chars
   (`:5841-5843`), then **`Base64(sha256_first32.getBytes()) must equal
   TimePieceBean.encryptMD5`** (`:5845`). Only segments that pass are kept playable
   (`:5846`). So `encryptMD5 = Base64( first-32-hex-chars-of-SHA256(secretKey) )`.
   **[HIGH — exact code]**
3. The validated secrets are installed into the decoder via
   `setPlaybackEncryption(jsonArray)` (`IPCThingP2PCamera.java:6429-6538`), which builds
   `{ devId, encryptInfos:[ {uuid, encrypt: secretKey}, … ] }` (`:6520-6532`) and calls
   `thingCamera.setEncryptionInfo(JSON.toJSONString(...))` (`:6534`) → JNI
   `ThingCameraNative.setEncryptionInfo(long, String)` (`:139`). The **native decoder then
   decrypts each segment by uuid** using its `secretKey`. **[HIGH that the key reaches
   native; the in-`.so` cipher is not visible here — see §6]**

> Cloud "frame download" carries the secret inline instead:
> `CloudFrameInfoBean` (`com/thingclips/smart/camera/ipccamerasdk/bean/CloudFrameInfoBean.java:7-10`)
> = `{ cloudUrl, downloadUrl, secret, videoSign }`. The RN encrypted-video download bean
> `VideoDownLoadBean` (`com/thingclips/smart/rnplugin/trctencryptimagedownloadmanager/bean/VideoDownLoadBean.java:22-37`)
> = `{ taskId, videoPath, encryptKey, videoUri, fileId, deviceId }` — i.e. the downloader
> receives `encryptKey` + a `videoUri` to GET. **[HIGH]**

### 5.2 Download-to-file cipher (visible in Java) — `[HIGH]`

The encrypted-clip *file container* and its decrypt are pure Java in
`com/thingclips/smart/camera/uiview/utils/EncryptUtils.java`:

- Cipher: **`AES/CBC/PKCS5Padding`** (`:22`, `:227`), key = `new SecretKeySpec(key.getBytes(),
  "AES")`, IV = `new IvParameterSpec(ivFromFile)` (`initAESCipher:223-228`). The key is the
  raw bytes of the `secretKey`/`encryptKey` string (so a 16-byte key ⇒ 16-char secret).
- **Container header = 64 bytes**: written by `encryptFile` as
  `byte[4] || IV(16) || byte[4] || byte[40]` (`:137-140`); read by `decryptFile` as
  `skip(4); read 16-byte IV; skip(44)` then AES-CBC over the remainder
  (`:47-48, 85-89`). `iv length error` is thrown if the 16-byte IV read is short (`:85-87`).
- The IV is **16 random ASCII alphanumerics** (`getIv:207-220`) stored in-band — so each
  encrypted clip is self-describing for its IV; only the key is external.

`com/thingclips/smart/camera/middleware/utils/ImageEncryptionUtil.java:20` and
`com/thingclips/smart/camera/audiomanager/encryption/FileEncryptionUtil.java:406-408`
use the same `AES/CBC/PKCS5Padding` + `SecretKeySpec(str.getBytes(),"AES")` + IV pattern,
corroborating the scheme app-wide. **[HIGH]**

> Honest caveat: §5.2 is the **download-to-file** path. For **streaming** SD/cloud playback
> the decrypt happens inside the native SDK after `setEncryptionInfo`; the per-segment cipher
> there is *presumed* the same AES family (same key source) but is **not byte-verified**
> statically. See §6.

---

## 6. Variable speed (0.5x–32x)

UI speed labels: `decompiled/apktool/res/values/strings.xml:1679-1686`:
`camera_playback_speed_05X=0.5X, _10X=1X, _15X=1.5X, _20X=2X, _40X=4X, _80X=8X,
_160X=16X, _320X=32X`. **[HIGH]**

> Note: the task brief named these `ipc_playback_speed_*`; the actual resource keys are
> **`camera_playback_speed_*`** (8 entries; `ipc_playback_speed_*` does not exist —
> grep count 0). Honest correction.

Speed is applied as an **int code**, not a float multiplier:
- SD: `setPlayBackSpeed(int, cb)` (`IThingSmartCameraP2P.java:201`; impl
  `IPCThingP2PCamera.java:12555-12558` → `thingCamera.setPlayBackSpeed(i, …)`; default reset to
  `setPlayBackSpeed(1, null)` at `:15061`).
- Cloud: `setPlayCloudDataSpeed(int, OperationCallBack)` (`IThingCloudCamera.java:134`).

The **mapping from the UI label (0.5/1/1.5/2/4/8/16/32) to the int code** is decided in the
React-Native JS bundle (not in this Java layer) and was not dumped here. **[LOW — unmapped;
see §7]**

---

## 7. Residual unknowns (what static analysis cannot pin, and what would unblock it)

1. **In-`.so` segment cipher for streaming playback.** After `setEncryptionInfo`, the actual
   per-segment decryption (mode, IV handling, key transform) is inside the closed native
   camera SDK. §5.2 proves AES/CBC for the *file* path; the streaming path is *inferred*
   same-family. *Unblock:* Ghidra of the camera `.so` `setEncryptionInfo`/playback decrypt
   (cross-ref `re/native_libs.md`), or a live-captured encrypted SD segment + its `secretKey`
   to decrypt and validate against an H.264 keyframe (mirroring the cap4 live-stream proof).
2. **JNI `startPlayBack` 4th int.** `ThingCameraNative.java:169` takes four ints; visible Java
   supplies three (start/stop/playTime). The 4th is unmapped. *Unblock:* Ghidra of the JNI
   `startPlayBack` thunk, or a JS-side trace of the camera-SDK JS wrapper.
3. **Speed int-code table.** The 0.5x–32x → int mapping lives in the RN JS bundle.
   *Unblock:* decode the relevant JS chunk (see `re/js_bundle_map.md`) for the
   `setPlayBackSpeed`/`setPlayCloudDataSpeed` caller.
4. **`cloudPlaybackStart` `s3`/`s4` and `configCloudData*` JSON schema.** The two trailing
   strings of `playCloudDataWithStartTime` and the config-tags JSON are passed through from
   JS; their exact fields are not in this Java layer. *Unblock:* JS bundle dump of the
   cloud-playback caller, or a live capture of `configCloudDataTags`.
5. **Cloud segment container vs HLS.** `getCloudUrls`/`getCloudStorageUrl` yield segment
   URLs; whether the cloud serves an m3u8 playlist or discrete encrypted segments, and
   whether the cloud segment header matches the §5.2 64-byte container, is not confirmed
   statically. *Unblock:* one authenticated GET of a cloud segment URL (owner account) +
   header inspection (store any real URL/secret only under `secrets/`).

---

## 8. Reimplementation contract (summary for the Rust client)

- **Index (LOCAL-SD):** P2P `queryRecordDaysByMonth(year, month)` →
  `queryRecordTimeSliceByDay(year, month, day)` → `RecordInfoBean{count, items:[TimePieceBean]}`.
  Cache per `getDayKey()`.
- **Index (CLOUD):** `configCloudDataTags(json)` then `getCloudTimeLine` / `getTimeLineInfo`
  (`thing.m.ipc.storage.*` REST, Tuya mobile sign) → same `TimePieceBean` shape.
- **Play:** `startPlayBack(startEpoch, stopEpoch, playEpoch)` (SD) /
  `playCloudDataWithStartTime(startEpoch, stopEpoch, mute, …)` (cloud). **Seek = re-issue
  start at the new `playEpoch`** (no dedicated seek). Pause/Resume/Stop are direct.
- **Speed:** int code via `setPlayBackSpeed` / `setPlayCloudDataSpeed` (codes for
  0.5/1/1.5/2/4/8/16/32 — table TBD, §7.3).
- **Decrypt (encrypted segments):** for each `uuid` with `encrypt==1`, fetch `secretKey`
  (`thing.m.ipc.storage.secret.get.list`), verify
  `Base64(SHA256(secretKey)[:32]) == encryptMD5`, then AES-CBC/PKCS5 with
  `key = secretKey.getBytes()` and an in-band 16-byte IV behind a 64-byte container header
  `(4 || IV16 || 4 || 40)` for the download-to-file path; streaming decrypt is in-SDK with the
  same key (cipher mode unverified, §7.1).

Cross-references: `re/streaming_mode.md` (live, NOT this path), `re/tuya_cloud_auth.md` /
`re/tuya_sign.md` (REST signing for the cloud APIs above), `re/native_libs.md` (the camera
`.so` that owns the in-SDK decrypt), `re/js_bundle_map.md` (the RN JS that supplies the
opaque params in §7).
