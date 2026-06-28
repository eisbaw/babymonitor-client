# Message Center — event timeline & encrypted media-clip retrieval (TASK-0101)

How the app lists cloud **events** (motion / sound / cry / AI) for the SCD921, and how the
**event-attached media clips** (short MP4/audio recorded around each event) are fetched and
**decrypted** for playback, download and sharing. This is the cloud *notification + clip*
plane — distinct from the live A/V stream (`re/streaming_mode.md`, `re/webrtc_session.md`) and
from 24/7 cloud/SD timeline storage (`thing.m.ipc.storage.*`).

All evidence is **static** (jadx decompile of `com.philips.ph.babymonitorplus`). The app is a
white-labeled **Tuya/Thing Smart** camera (see `MEMORY.md`); the message center is Tuya's stock
`com.thingclips.smart.ipc.messagecenter` + the React-Native bridge
`rnplugin.trctcameramessagemanager`, driven by an RN/JS panel. The Java methods are padded with
`com.ai.ct.Tz.a()/Tz.b(0)` no-op anti-analysis calls — ignored throughout.

Confidence tags per claim: **[H]** high / **[M]** medium / **[L]** low.

> Secret hygiene: no key material is reproduced here. The per-device storage secret (event-clip
> media key) and any `encryptKey`/`localKey` values live only under `secrets/` — this doc cites
> their *derivation path and call sites*, never a value.

---

## 1. Event timeline — the cloud message-list API

The RN bridge `TRCTCameraMessageManager` exposes four `@ReactMethod`s to JS; each delegates to a
`CameraMessageBusiness` (a Tuya `Business` mobile-gateway client). The gateway "API names" are the
authoritative wire contract. **[H]** — endpoints read literally from
`decompiled/jadx/sources/com/thingclips/smart/ipc/messagecenter/business/CameraMessageBusiness.java`:

| RN method (`TRCTCameraMessageManager.java`) | Business method | Mobile-API name | Ver | Evidence |
|---|---|---|---|---|
| `obtainMessageList` (:2444) | `getAlarmDetectionMessageList` | `thing.m.msg.list.by.json` | 1.0 | `CameraMessageBusiness.java:114` |
| `obtainMessageDaysFor` (:2159) | `queryAlarmDetectionDaysByMonth` | `thing.m.msg.days.by.json` | 2.0 | `CameraMessageBusiness.java:126` |
| `obtainMessageSchemes` (:2687) | `queryAlarmDetectionClassify` | `thing.m.ipc.msg.sort.tag.get` | 1.0 | `CameraMessageBusiness.java:120` |
| `deleteMessage` (:1610) | `deleteAlarmDetectionMessageList` | `thing.m.msg.remove` | 1.0 | `CameraMessageBusiness.java:104` |

Note `CameraMessageBusiness` is annotated `@Deprecated` (`CameraMessageBusiness.java:14`); the
newer, equivalent path lives in `com.thingclips.smart.camera.middleware.dddbppd`
(`IThingCameraMessage`), which calls **`thing.m.msg.list.by.json` v2.0** (`dddbppd.java:74`,
`:565`). The RN panel in this build still wires the deprecated v1.0 business. **[H]**

### 1.1 `obtainMessageList` request (the timeline query)

`TRCTCameraMessageManager.java:2444-2486` builds a fastjson object and POSTs it as the `json` post-
field. Request keys (anonymized; no values) — **[H]**:

```
msgSrcId : <devId>            // device id (from Activity intent extra "devId")  TRCT:2447, :1132
startTime: <int epoch-sec>    // window start                                    TRCT:2448
endTime  : <int epoch-sec>    // window end (key LinkKey.KEY_END_TIME == "endTime") TRCT:2449
msgType  : 4                  // hard-coded == 4 in the RN path                   TRCT:2450
limit    : <int>             // page size                                        TRCT:2451
keepOrig : true              // request original (unaggregated) records          TRCT:2452
offset   : <int>             // page offset                                      TRCT:2453
msgCodes : [<code>,…]        // optional event-type filter (see §2)              TRCT:2454-2460
```

The newer `dddbppd.b(...)` adds a `sourceIds` array filter and parameterizes `msgType`
(`dddbppd.java:546-559`). The response `datas` array is parsed straight into `CameraMessageBean`:
`JSON.parseArray(jSONObject2.getString("datas"), CameraMessageBean.class)` —
`TRCTCameraMessageManager.java:2577`. **[H]**

### 1.2 Event record schema — `CameraMessageBean`

`decompiled/jadx/sources/com/thingclips/smart/ipc/messagecenter/bean/CameraMessageBean.java:10-27`.
Each event in the timeline is one bean. **[H]** for field set (Java members are unobfuscated):

| Field | Type | Meaning (inferred) |
|---|---|---|
| `id` | String | event/message id (used by `deleteMessage`, key-pull) |
| `msgSrcId` | String | source device id |
| `msgCode` | String | event-type code, e.g. `ipc_motion`, `ipc_baby_cry` (§2) |
| `msgType` | int | message class |
| `msgTitle`/`msgContent`/`msgTypeContent` | String | display strings |
| `time` | long | event epoch |
| `dateTime` | String | formatted time |
| `attachPics` | String | attached image(s) reference |
| `attachVideos` | String[] | **attached clip URL(s)** → fed to `playMediaVideoWithPath` (§3) |
| `attachAudios` | String[] | attached audio clip URL(s) → `playMediaAudioWithPath` |
| `actionURL` | String | deep-link |
| `icon` | String | event icon URL |
| `sourceIds` | String[] | sub-source ids |
| `extendParams` | Map<String,Object> | extra per-event params |
| `isDelete` | boolean | tombstone |
| **`isNeedPullEncKey`** | boolean | **flag: this clip needs an encryption key pulled before playback** (§3.3) |

`isNeedPullEncKey` (`CameraMessageBean.java:19`, getter `:882`) is the hinge between the timeline
and the decrypt contract: when set, the client must fetch the device's media secret before it can
decrypt `attachVideos`/`attachAudios`. **[H]** field exists; **[M]** that it gates exactly the
storage-secret pull in §3.3 (wiring is across the deprecated RN path + the newer `dddbppd`).

### 1.3 Calendar + schemes + delete

- `obtainMessageDaysFor(year, month)` → posts `{msgSrcId, ti (TZ), month:"Y-M"}` and returns a
  `JSONArray` of days-with-events for the month picker. `TRCT:2159-2201`, endpoint
  `thing.m.msg.days.by.json` v2.0. **[H]**
- `obtainMessageSchemes()` → `queryAlarmDetectionClassify(devId)` → list of
  `CameraMessageClassifyBean{ describe:String, msgCode:String[], selected:boolean }`
  (`CameraMessageClassifyBean.java:9-11`). These are the **filter chips** ("Motion", "Sound", …),
  each mapping a human label to one-or-more `msgCode`s that feed `obtainMessageList.msgCodes`.
  Endpoint `thing.m.ipc.msg.sort.tag.get`. **[H]**
- `deleteMessage([ids])` → comma-joins the id array (`TRCT:1672-1680`) →
  `deleteAlarmDetectionMessageList` → `thing.m.msg.remove` POST `ids=<csv>`. **[H]**

---

## 2. Event-type taxonomy

### 2.1 `CameraMessageType` — the base `msgCode` namespace

`decompiled/jadx/sources/com/thingclips/smart/ipc/messagecenter/MessageConstant.java:13-23` — **[H]**
(literal string constants):

```
ipc_ai          ipc_motion      ipc_doorbell    ipc_passby      ipc_linger
ipc_leave_msg   ipc_connected   ipc_inspection  ipc_refuse      ipc_unconnected
```

These are the generic Tuya IPC event codes. `ipc_ai` is the umbrella for AI-classified events; the
concrete AI sub-codes are carried by `AIEventBean.aiCode` / `CameraMessageBean.msgCode`.

### 2.2 AI event beans

- `AIEventBean` (`.../camera/middleware/cloud/bean/AIEventBean.java:9-13`): one AI hit —
  `aiCode` (String), `aiCodeDesc`, `aiCodeIcon`, `startTime` (long), `endTime` (long). **[H]**
- `AIDetectConfigBean` (`AIDetectConfigBean.java:10-13`): per-device AI config —
  `aiItemList: List<AIDetectEventBean>`, `hasEventAIItemList: List<AIDetectEventBean>`,
  `isAiDevice: boolean`, `switchState: int`. **[H]**
- `AIDetectEventBean` (`AIDetectEventBean.java:9-15`): one configurable AI category —
  `aiCode`, `aiCodeDesc`, `aiCodeIcon`, `aiCodeSelectedIcon`, `configState: int`,
  `isSelected: boolean`, `orderValue: int`. **[H]**

`aiCode` is the same code space as `msgCode`; `hasEventAIItemList` is the subset of categories that
actually have events in the queried window (drives which filter chips render). **[M]** (semantics
inferred from names + usage, not a spec).

### 2.3 Baby-monitor reskin → `msgCode` mapping

The Philips "nightowl-camera-setting" module defines Kotlin enums mapping each baby-monitor feature
label to the underlying Tuya `msgCode`/`aiCode` string used on the wire. **[H]** for the literal
mappings (`.../ka/ipc/messagecenter/consts/*.java`):

| Enum (label) | wire code | Evidence |
|---|---|---|
| `MotionClassifyKeys.Motion_detected` | `ipc_motion` | `MotionClassifyKeys.java:12` (== `CAMERA_MESSAGE_TYPE_MOTION`) |
| `SoundClassifyKeys.Sound_detected` | `ipc_bang` | `SoundClassifyKeys.java:11` |
| `SoundClassifyKeys.Cry_detected` | `ipc_baby_cry` | `SoundClassifyKeys.java:12` |
| `TempClassifyKeys.Temperature_high` | `ipc_human` | `TempClassifyKeys.java:17` |
| `TempClassifyKeys.Temperature_low` | `ipc_cat` | `TempClassifyKeys.java:18` |
| `SenseIQClassifyKeys.BABY_AWAKE` | `ipc_car` | `SenseIQClassifyKeys.java:12` |
| `CryTranslationClassifyKeys.{no_cry,sleep,hungry,uncomfortable,burp,pain,…}` | `ipc_dev_link, ipc_passby, ipc_linger, ipc_antibreak, ipc_custom, ipc_io_alarm, …` | `CryTranslationClassifyKeys.java:31-40` |

**Honest caveat [L→M]:** the Temp/SenseIQ/CryTranslation rows reuse *generic* Tuya AI-object codes
(`ipc_human`, `ipc_cat`, `ipc_car`) and generic event slots (`ipc_dev_link`, `ipc_io_alarm`) as
**stand-ins** for baby-monitor semantics. Whether the SCD921 firmware actually emits those literal
codes for "high temperature" / "baby awake" / a given cry-reason — versus the UI layer only using
them as local icon/string lookup keys — **cannot be determined statically**. A single captured
`thing.m.msg.list.by.json` response (one real event of each kind) would resolve it; that capture is
the missing evidence. The `Motion_detected→ipc_motion`, `Sound_detected→ipc_bang`,
`Cry_detected→ipc_baby_cry` rows are self-consistent and trustworthy **[H]**.

---

## 3. Encrypted media-clip retrieval contract

Event clips are **encrypted at rest in Tuya cloud**; the app downloads ciphertext and decrypts it
locally with a per-device media key, decoding to raw frames delivered via callback (the RN panel
renders them itself, not a native SurfaceView).

### 3.1 The player object and the three RN entry points

`getCloudVideoCamera()` lazily creates `ThingIPCSdk.getMessage().createVideoMessagePlayer()` → an
`IThingCloudVideo` (`TRCT:1022-1029`), then `createCloudDevice(cacheDir, devId, cb)` initializes it
(`TRCT:1465`, interface `IThingCloudVideo.java:22`). The decrypt/decode pipeline is **inside that
native-backed object** — `IThingCloudVideo` is `@OpenApi` SDK surface, implemented over the Tuya
camera native libs; the concrete bytes-→YUV path is **not** in Java. **[H]** for the API surface;
the actual cipher invocation is native (caveat in §3.4).

| RN method | forwards to `IThingCloudVideo` | Evidence |
|---|---|---|
| `playMediaVideoWithPath(url, encryptKey, i, ok, err)` | `playVideo(url, i, encryptKey, ok, err)` | `TRCT:4070-4103`; iface `IThingCloudVideo.java:40` |
| `playMediaAudioWithPath(url, encryptKey, i, ok, err)` | `playAudio(url, i, encryptKey, ok, err)` | `TRCT:3634-3675`; iface `:37` |
| `startDownloadVideoMessageAttachmentWithUrl(url, encryptKey, savePath, ok, err)` | builds `{url, encryptKey, savePath}` → `…V1` → `startVideoMessageDownload(...)` | `TRCT:4538-4558`; iface `:60/:62` |

So the **clip-retrieval contract is the triple `(url, encryptKey, flag)`** — **[H]**:
- `url` — the clip location from `CameraMessageBean.attachVideos[]` / `attachAudios[]` (an HTTPS
  object URL; a presigned/CDN ref). **[M]** (it is the attach field; exact URL provenance per-event
  not traced further).
- `encryptKey` — the media key string (the per-device storage secret, §3.3). **[H]** it is the key
  argument; **[M]** that it equals the storage-secret value.
- third int arg — a flag. In download it is named `savePath` (path-class selector, `TRCT:4556`); in
  `playVideo/playAudio` its exact meaning (cloud-vs-local / stream index) is **not determinable
  statically [L]**.

The JS panel calls these with the same key names — `mini_app_js` bundles literally reference
`"url","encryptKey","savePath"` / `"secretKey","filePath","url"` object shapes
(`decompiled/js/assets/mini_app_js/*`, grep-confirmed). **[H]** the bridge param names match JS.

### 3.2 Decode callbacks (ciphertext → raw frames → JS)

After decrypt+decode, the native player emits **raw** frames to the registered
`AbsP2pCameraListener` (`TRCT:1197` registers `this.listener`), which the bridge republishes as RN
events. **[H]**:

- **Video:** `onReceiveFrameYUVData(int, ByteBuffer y, ByteBuffer u, ByteBuffer v, w, h, fps,
  isKeyFrame, ts, progress, duration, obj)` (`TRCT:71`) → emits RN event **`playMediaVideoInfo`**
  with `{width,height,frameRate,isKeyFrame,timestamp,progress,duration}` (`TRCT:148-157`). Output is
  **decoded YUV planes**, not H.264 — the clip is fully decrypted *and* decoded natively.
- **Audio:** `onReceiveAudioBufferData(sampleRate, channelNum, bitWidth, ts, progress, duration)`
  (`TRCT:58`) → emits **`playMediaAudioInfo`** `{sampleRate,channelNum,bitWidth,…}` (`TRCT:59-67`).
  Output is **decoded PCM** (raw samples), parameters carried alongside.
- Completion: `playMediaVideoFinished` / `playMediaAudioFinished` events (`TRCT:4209`, `:3874`).
- Transport controls: `pause/resume/stopVideo`, `pause/resume/stopAudio`, `enableMute`
  (`TRCT:3194-4869`) → matching `IThingCloudVideo` ops.

### 3.3 `encryptKey` provenance — the storage-secret pull

The media key is **not** delivered inline in each event; it is a **per-device secret pulled once and
cached**. In the newer `dddbppd` flow, before issuing `thing.m.msg.list.by.json` the client checks a
cached secret `this.b`; if empty it calls **`thing.m.ipc.storage.secret.get` v1.0** with
`devId`, caches the result, then proceeds with the list request — `dddbppd.java:560-570`:

```
if (TextUtils.isEmpty(this.b)) {                       // no cached media secret
    ApiParams p = new ApiParams("thing.m.ipc.storage.secret.get", "1.0");  // dddbppd.java:565
    p.putPostData("devId", str);                       // per-device
    a.asyncRequest(p, JSONObject.class, <cb that caches into this.b>);
} else { cb.onSuccess(this.b); }                        // reuse cached secret
```

A list variant `thing.m.ipc.storage.secret.get.list` also exists (grep-confirmed across the camera
tree). **[H]** that `thing.m.ipc.storage.secret.get` is the media-secret source and that it is keyed
by `devId` and cached; **[M]** that this exact secret string is what is passed as `encryptKey` into
`playVideo`/`startVideoMessageDownload` (the RN path obtains the key on the JS side, which then calls
`playMediaVideoWithPath(url, encryptKey, …)` — the JS join is in the bundle, not re-traced here).
`CameraMessageBean.isNeedPullEncKey` is the per-event signal that this pull is required. **[H]** flag
exists / **[M]** exact gating.

> The pulled secret is per-device key material → **secrets/ only**. Not reproduced here.

### 3.4 Cipher: AES-128-CBC

The Tuya camera Java AES helper `com.thingclips.smart.camera.utils.AES` shows the family in use
**[H]** (literal):
- transform constant = `com.thingclips.sdk.bluetooth.bppdpdq.bdpdqbp` =
  **`"AES/CBC/PKCS5Padding"`** (`.../sdk/bluetooth/bppdpdq.java:15`, used at `AES.java:240`,
  `bppdpdq.java:189`).
- key = first **16 bytes** of `Hmac.a(keyBytes, salt)` → `SecretKeySpec(…, "AES")` ⇒ **AES-128**
  (`AES.java:236-239`).
- IV = the key/seed **string bytes** via `IvParameterSpec(str.getBytes())` (`AES.java:323`); 16-char
  seeds are generated by `AES.c()` (`AES.java:162-179`).

So **AES-128-CBC (PKCS5/PKCS7 padding)** is the cipher family the Tuya camera stack uses for media/
file encryption, with a 16-byte key and a 16-byte IV. **[H] for "AES-128-CBC is the family";
[M] that the *event-clip* (`playVideo` `encryptKey`) decryption is byte-for-byte this exact Java
routine** — `AES.java` is the generic helper (also used for image/file/share encryption:
`ImageEncryptionUtil`, `FileEncryptionUtil`, `EncryptUtils` all reference `"AES/CBC/PKCS5Padding"`),
whereas the *clip* decrypt happens inside the native `IThingCloudVideo` implementation and is not
visible in Java. The exact clip mode (CBC vs CTR), padding, IV derivation, and whether the clip is a
whole-file vs per-chunk encryption are **native-only and not statically confirmed**.

**What would unblock §3.4:** (a) one captured ciphertext clip + its pulled secret + the produced
plaintext (a decrypt oracle), or (b) Ghidra on the camera native lib’s `playVideo`/cloud-download
path to read the actual `mbedtls`/`EVP` cipher init (mode + IV). Cross-reference the proven live-
stream media cipher in `re/media_decode_spec.md` — note the *live* path is AES-128-CBC inline-IV +
HMAC-SHA1 over KCP, which is a **different** plane from these cloud clips; do not assume they share
key derivation.

---

## 4. Share / delete / download

- **shareMedia(map)** (`TRCT:4476-4533`): ensures a cloud device exists, then
  `ShareMessageUtil.a.a(ctx, map.toHashMap(), mCloudVideoCamera)`
  (`.../ipc/messagecenter/utils/ShareMessageUtil.java:47`). That util decrypts/exports the clip to a
  shareable file and hands it to the system share sheet via `ShareUtil.g(...)`
  (`ShareMessageUtil.java:97`, continuation `ShareMessageUtil$shareMediaWithParams$3`). The JS side
  passes `{url, encryptKey/secretKey, fileType, filePath, …}` (bundle-confirmed). **[H]** call graph;
  **[M]** that share performs a full local decrypt-then-export (native step).
- **startDownloadVideoMessageAttachmentWithUrl(url, encryptKey, savePath)** (`TRCT:4538`): the
  decrypt-and-save-to-disk path → `startVideoMessageDownload(...)` (iface `:60/:62`), progress via a
  `ProgressCallBack`, with `downloadMediaVideoProgress`/`downloadMediaVideoFinished` RN events
  (`TRCT:1984`, `:1866`); cancel via `cancelDownloadVideoMessageAttachment` →
  `cancelCloudDataDownload` (`TRCT:1367-1369`). **[H]**
- **deleteMessage([ids])**: §1.3, `thing.m.msg.remove`. **[H]**

---

## 5. Rust reimplementation contract (summary)

For a parity client, the event/clip plane is **mobile-gateway REST + a native-equivalent
decrypt/decode** — no P2P needed:

1. List events: POST `thing.m.msg.list.by.json` (v2.0) with
   `{msgSrcId, startTime, endTime, msgType, limit, keepOrig, offset, msgCodes?, sourceIds?}` →
   parse `datas[]` as `CameraMessageBean`. **[H]**
2. Calendar/filters: `thing.m.msg.days.by.json` (v2.0), `thing.m.ipc.msg.sort.tag.get`. **[H]**
3. Per-device media key: `thing.m.ipc.storage.secret.get` (v1.0, `devId`), cache it. **[H]**
4. For each event with a clip: download `attachVideos[]`/`attachAudios[]` URL, **AES-128-CBC
   decrypt** with the media key, decode (H.264→YUV / audio→PCM). **[H] steps 1-3; [M] step-4 cipher
   detail** (mode/IV/padding/chunking native-unconfirmed — see §3.4).
5. Delete: `thing.m.msg.remove` (`ids` csv). **[H]**

All REST calls go through the Tuya mobile-app gateway with the app sign (see `re/tuya_sign.md`,
`re/live_login.md`); these `thing.m.*` names plug into that signer unchanged.

---

## Residual unknowns (what static analysis cannot settle)

1. **Exact clip cipher params [open].** Mode/IV-derivation/padding/whole-file-vs-chunked for the
   event-clip decrypt are inside native `IThingCloudVideo` (§3.4). AES-128-CBC is the *family*;
   byte-exactness needs a decrypt oracle (ciphertext+secret+plaintext) or Ghidra on the camera lib.
2. **`encryptKey` ↔ storage-secret identity [likely].** The cache-then-pull is proven in
   `dddbppd`; the final hop (cached secret → the `encryptKey` arg of `playVideo`) crosses into the
   RN/JS bundle and was not re-traced to the literal assignment. A JS-bundle trace or one live call
   would confirm.
3. **`msgCode` reality for reskin features [open].** Whether the SCD921 emits `ipc_human`/`ipc_cat`/
   `ipc_car`/`ipc_baby_cry` etc. for temp/sense/cry events, or those are UI-only lookup keys (§2.3).
   One captured `thing.m.msg.list.by.json` response settles it.
4. **Clip URL provenance [partial].** `attachVideos[]` is the clip URL source, but whether it is a
   long-lived object key needing a separate presign vs a ready CDN URL was not traced.
5. **`playVideo` third int arg [open].** Named `savePath` only in the download path; its meaning for
   play (cloud/local/index) is unresolved (§3.1).
6. **Version skew [noted].** The shipped RN bridge uses the `@Deprecated` `CameraMessageBusiness`
   v1.0 list API while `dddbppd` uses v2.0 — a parity client should target v2.0.
