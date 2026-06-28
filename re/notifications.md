# Notifications & Background Monitoring — FCM push, message-push DPs, keep-alive audio service (TASK-0106)

Static RE of how **alerts reach the phone** and how **background monitoring stays
alive** in `com.philips.ph.babymonitorplus` (Tuya-reskin SCD921). Three planes are
mapped here:

1. **Inbound push** — the FCM listener service, the FCM payload schema, and how a
   received message is parsed and routed to the Tuya push center.
2. **Per-event message-push settings** — the in-panel "Notification" screen and the
   Tuya camera DPs that toggle which detected events generate a push.
3. **Background monitoring keep-alive** — the Philips "Night Owl" watchdog
   foreground service (`mediaPlayback`) + its 20-second heartbeat loop that keeps the
   live audio stream playing when the app is backgrounded or the phone is locked.

> **Method / citation note.** All evidence is grep of the jadx Java tree under
> `decompiled/jadx/sources/` and the apktool tree under `decompiled/apktool/`
> (both regenerable via `just decompile`, gitignored). Cites name a **symbol**
> (class / method / DP-code string / resource name) plus a `File.java:NN` hint —
> jadx line numbers drift across re-decompiles, so grep the symbol/string, not the
> bare line. The `Tz.a()/Tz.b(0)` no-ops interleaved in every method are the app's
> control-flow-flattening obfuscation (`com.ai.ct.Tz`); ignore them — the real body
> is the non-`Tz` statements. Every DP-code string (`"ipc_doorbell_push"` etc.) is a
> Tuya **schema identifier**, not a device secret.
>
> **Secret hygiene.** The FCM **sender id** ships as the string resource
> `gcm_sender_id` (referenced from `AndroidManifest.xml:149`,
> `<meta-data android:name="SENDER_ID" android:value="@string/gcm_sender_id"/>`).
> Its **value is deliberately NOT reproduced here** — see
> `decompiled/apktool/res/values/strings.xml` (`gcm_sender_id`, plus the sibling
> `google_app_id` / `google_api_key` / `default_web_client_id` Firebase config). The
> FCM registration token, the 32-hex analytics/stat event id in
> `ThingFcmListenerService`, and any `devId` are likewise referenced by description
> only, never inlined.
>
> **Static-only honesty caveat.** This documents the **client-side** push receive /
> settings / keep-alive control plane. The **server side** (which cloud condition
> emits which FCM message, and the exact `type` enum values) is **not statically
> recoverable** — there is **no captured FCM event payload** in `emulator_captures/`
> for this task, so the payload→event-category mapping below is reconstructed from
> the **parser keys the client reads**, not from a captured push. See Residual
> unknowns.

---

## TL;DR map

### Inbound push pipeline
| Stage | Symbol | File hint | Role |
|---|---|---|---|
| FCM entrypoint | `ThingFcmListenerService.q(RemoteMessage)` | `com/thingclips/smart/fcmpush/service/ThingFcmListenerService.java:22` | Receives FCM, copies `getData()` into a Bundle, hands off to `MainProcessService` |
| Token registration | `ThingFcmListenerService.s(String)` | same:39 | `onNewToken` → `getPushInstance().registerDevice(token,"fcm",…)` |
| Cross-process hop | `MainProcessService.b(Intent)` | `com/thingclips/smart/fcmpush/service/MainProcessService.java:19` | Rebuilds the data map, `FcmManager.b().d(new PushModel(from, map))` |
| Parse + route | `FcmManager.d(PushModel)` | `com/thingclips/smart/fcmpush/fcm/FcmManager.java:382` | data→JSON, reads `link`, `PushUtil.parseMessage`, `PushCenterService.onPostData(bean,"fcm")` |
| Payload model | `PushBean` | `com/thingclips/smart/api/bean/PushBean.java` | Fields `type/devId/link/msgId/ct/c/cc/a/ts/p` |

### Per-event message-push DPs (in-panel "Notification" screen)
| DP code | Func class | File hint | Role |
|---|---|---|---|
| `ipc_doorbell_message` | `FuncMsgNotificationSwitch` | `…/panelmore/func/FuncMsgNotificationSwitch.java:270` | **Master** message/notification switch (gates the rest) |
| `ipc_doorbell_push` | `FuncMsgPushSwitch` | `…/panelmore/func/FuncMsgPushSwitch.java:168,289,319` | App push (ring/doorbell) on/off |
| `doorbell_pir_switch` | `FuncMsgPirSwitch` | `…/panelmore/func/FuncMsgPirSwitch.java:28,237` | PIR/motion alarm push on/off |
| `doorbell_sensitivity` | `FuncMsgMotionDetectionCheck` | `…/panelmore/func/FuncMsgMotionDetectionCheck.java:41,445` | Motion-detection sensitivity (shown only when PIR push on) |
| `ipc_message_set` | `FuncBaseMessagePush` | `…/panelmore/func/FuncBaseMessagePush.java:361` | Device-settings "Notification" entry → opens `CameraMsgPushActivity` |
| `ipc_power_push` / `camerasetting_electric_power_push` | (camera DP) | `…/camera/**` | Low-battery push (electric power) |
| Screen container | `CameraMsgPushActivity` / `CameraMsgPushModel.l7()` | `…/panelmore/activity/CameraMsgPushActivity.java`, `…/panelmore/model/CameraMsgPushModel.java:82` | Builds the switch list from the Funcs above |

### Background keep-alive
| Symbol | File hint | Role |
|---|---|---|
| `com.thingclips.nightowl.watchdog.BackgroundGroundService` | `AndroidManifest.xml:431` (`foregroundServiceType="mediaPlayback"`) | Foreground service that keeps the process alive for background audio |
| `BackgroundGroundService.Companion.e(intent,title,content,devId)` | `…/watchdog/BackgroundGroundService.java:181` | Start entrypoint → `startForegroundService` |
| `BackgroundGroundService.onStartCommand` | same:625 | `startForeground(1, e())` (notification id 1) |
| `PanelWatchDogManager.startRxjava()` | `…/watchdog/PanelWatchDogManager.java:209` | **The monitoring loop**: `Observable.interval(0,20,SECONDS)` heartbeat → `SessionStatus(true)` |
| `LocalNotificationManager` | `…/watchdog/LocalNotificationManager.java` | Lifecycle observer: starts service on background, stops on foreground; renders interrupt notifications |
| RN bridge | `TRCTIpcMonitorManager.showWatchDogLocalNotification` / `removeWatchDogLocalNotification` | `…/rnplugin/trctipcmonitormanager/TRCTIpcMonitorManager.java:1780,1668` | JS panel arms/disarms the watchdog |

---

## 1. FCM push entrypoint (confidence: high)

`AndroidManifest.xml:153` declares the listener in its own `:fcmpush` process:

```
<service android:exported="true"
         android:name="com.thingclips.smart.fcmpush.service.ThingFcmListenerService"
         android:process=":fcmpush">
    <intent-filter><action android:name="com.google.firebase.MESSAGING_EVENT"/></intent-filter>
</service>
```

Plus the Firebase plumbing: `FirebaseInstanceIdReceiver` (`:160`), stock
`FirebaseMessagingService` (`:163`), `MainProcessService` (`:168`),
`FirebaseInitProvider` (`:175`), default channel `tuya_common` (`:151`), and the
`SENDER_ID` meta pointing at `@string/gcm_sender_id` (`:149`).

**Receive path** — `ThingFcmListenerService.java:22`:

```java
public void q(RemoteMessage remoteMessage) {                       // onMessageReceived
    L.i("Push-ThingFcmListenerService", "FCM message received" + remoteMessage.getData());
    Bundle bundle = new Bundle();
    for (Map.Entry<String,String> e : remoteMessage.getData().entrySet())
        bundle.putString(e.getKey(), e.getValue());
    Intent intent = new Intent(this, MainProcessService.class);
    intent.putExtra("push-from", remoteMessage.getFrom());
    intent.putExtra("fcm-data", bundle);
    startService(intent);                                          // hop to main process
}
```

The FCM **data** map (not the notification block) is the carrier; the service does
no parsing itself — it only forwards `push-from` + `fcm-data` to `MainProcessService`
(different process). (confidence: high — full body visible.)

**Token path** — `ThingFcmListenerService.java:39` `s(String)` (`onNewToken`): if
non-empty it (a) reports the token to `StatService` under a hardcoded 32-hex stat
event id *(value intentionally omitted; see source line 48)*, then (b)
`IThingPersonalCenterPlugin.getPushInstance().registerDevice(token,"fcm",cb)` to bind
the token to the account, and on success `PushTrackStatHelper.trackRegister(token,"fcm")`.
(confidence: high.)

---

## 2. FCM payload schema + parse/route (confidence: high for client keys read)

`MainProcessService.b(Intent)` (`MainProcessService.java:19`) rebuilds the string
map from `fcm-data` and calls `FcmManager.b().d(new PushModel(push-from, map))`
(`PushModel` = `{ String from; Map data }`,
`com/thingclips/smart/fcmpush/fcm/PushModel.java:7`).

`FcmManager.d(PushModel)` (`FcmManager.java:382`) is the dispatcher:

```java
JSONObject c = c(pushModel.a());                    // data map -> JSON
String str = c.getString(ConstantStrings.CONSTANT_LINK);   // reads "link"
PushBean parseMessage = PushUtil.parseMessage(str);        // link -> PushBean
parseMessage.setPic(PushUtil.parseImageInfo(c));
if (data.containsKey("tracking")) … setPushMarketingTrackBean(...);
if (isEmpty(bean.getDevId()) && data.containsKey("devId")) bean.setDevId(data.get("devId"));
PushCenterService pushCenterService = MicroServiceManager…a(PushCenterService.class…);
pushCenterService.onPostData(parseMessage, "fcm");  // hands to push center (notify + route)
```

**Payload field dictionary** — `com/thingclips/smart/pushcenter/ConstantStrings.java`
defines the recognised data keys, and `PushBean`
(`com/thingclips/smart/api/bean/PushBean.java`) holds them:

| Key | `ConstantStrings` / `PushBean` | Meaning (client use) |
|---|---|---|
| `type` | `CONSTANT_TYPE` / `PushBean.type` | **Message/event category** (the event discriminator) |
| `devId` | `CONSTANT_DEVID` / `PushBean.devId` | Which device the event is for |
| `link` | `CONSTANT_LINK` / `PushBean.link` | Deep-link route the notification opens |
| `msgId` | `CONSTANT_MSGID` / `PushBean.msgId` | Unique message id |
| `ct` / `c` / `cc` | `CONSTANT_CT/C/CC` | Content text / title / extra |
| `ts` | `CONSTANT_TS` / `PushBean.ts` | Timestamp |
| `p` | `CONSTANT_P` / `PushBean.p` | Extra params map |
| `route` `url` `media` `doorbell` `ac_doorbell` | `CONSTANT_ROUTE/URL/MEDIA/DOORBELL/AC_DOORBELL` | Routing / doorbell-call variants |
| `tracking` | (literal, read in `FcmManager.d`) | Marketing-track blob |

`PushBean.toString()` (`PushBean.java:1380`) confirms the model:
`PushBean{c, a, ct, cc, link, devId, ts, msgId, type, p}`.

**Payload → event mapping (sketch, confidence: medium — keys confirmed, value enum
not).** A detected device event flows: *camera firmware detects condition → Tuya
cloud message center → FCM data message* carrying `{ type, devId, link, ct/c,
msgId, ts, p }`. The client keys on **`type`** for the category and **`link`** for
where to navigate (the deep link is parsed by `PushUtil.parseMessage`). The concrete
`type` values for the SCD921 alert categories (sound / motion / temperature / cry /
SenseIQ) are **server-assigned and not visible in this APK** — the client treats
`type` as an opaque discriminator forwarded to `PushCenterService.onPostData`.
What is recoverable statically is the **per-category enable** that decides whether
the cloud emits a push at all (§3), and the per-feature detection DPs documented in
the sibling docs (`re/motion_detection.md`, `re/sound_detection.md`,
`re/cry_detection.md`, `re/environment_sensors.md`, `re/senseiq.md`).

---

## 3. Per-event message-push settings (confidence: high)

Two entrypoints in the camera "settings → more" UI:

**(a) `FuncBaseMessagePush`** (`FuncBaseMessagePush.java`) — the device-level
"Notification" row. `isSupport()` gates on `querySupportByDPCode("ipc_message_set")`
(`:361`); `dynamicTypeName()` returns `DynamicSettingItemName.NOTIFICARION` and the
row label is `R.string.v4` (= `ipc_message_push_setting`). Tapping it opens
`CameraMsgPushActivity` (`getActivityTitle()` = `R.string.ipc_message_push_setting`,
`CameraMsgPushActivity.java:61`).

**(b) `CameraMsgPushActivity` + `CameraMsgPushModel.l7()`** — builds the switch list.
`CameraMsgPushModel.l7()` (`CameraMsgPushModel.java:82`) is explicit:

```java
mFuncList.add(new FuncMsgNotificationSwitch(mMQTTCamera));        // master
if (master.b() == TRUE) {
    mFuncList.add(new FuncMsgPushSwitch(mMQTTCamera));            // app push
    FuncMsgPirSwitch pir = new FuncMsgPirSwitch(mMQTTCamera);
    mFuncList.add(pir);                                           // PIR alarm push
    if (pir.b() == TRUE)
        mFuncList.add(new FuncMsgMotionDetectionCheck(mMQTTCamera)); // motion sensitivity
}
```

The Func→DP bindings (grep the literal DP string in each file):

- `FuncMsgNotificationSwitch` → **`ipc_doorbell_message`** (read via `x3`, written
  via `L3`, `:270/274/283`). Master toggle; when off, the children are hidden.
- `FuncMsgPushSwitch` → **`ipc_doorbell_push`** (`L3("ipc_doorbell_push", status, cb)`,
  `FuncMsgPushSwitch.java:319`; support via `querySupportByDPCode("ipc_doorbell_push")`
  `:289`). The decompiled `getDisplayableItemClassType` reads it via `x3` and shows a
  `SwitchItem` (`:168`).
- `FuncMsgPirSwitch` → **`doorbell_pir_switch`** (`:28/237`).
- `FuncMsgMotionDetectionCheck` → **`doorbell_sensitivity`** (`:41/445`; note the
  obfuscated `getId()` returns the unrelated literal `"FuncCollisionSensitiveCheck"`,
  but every DP op uses `doorbell_sensitivity`).

All four DP codes are Tuya camera schema codes registered in
`com/thingclips/smart/camera/devicecontrol/operate/DpCamera.java`. Writes go through
`IThingMqttCameraDeviceManager.L3(dpCode, value, IPublishDpsCallback)` (MQTT DP
publish — same control plane documented in `re/ptz_control.md` / `re/motion_detection.md`).

**Important scope note (confidence: medium).** This "Notification" screen is
**doorbell/ring-centric** (the `doorbell_*` DP family). It is the per-event push
control that ships as a *camera DP* in this build. The baby-monitor alert categories
named in the task — **sound / motion / temperature / cry / SenseIQ** — are surfaced in
the **React Native "Night Owl" panel** (runtime-downloaded bundle, not in this APK)
and the **cloud message-center** push settings, each gated by its own detection
feature DP (e.g. `motion_switch`, `decibel_sensitivity`, the temperature alarm DPs,
`cry_detection_switch`, the SenseIQ DPs — see the sibling feature docs). Statically
this APK only proves the doorbell-family DPs above plus the low-battery push
(`ipc_power_push` / `camerasetting_electric_power_push`); the per-category baby-event
push toggles live behind the RN bridge and cloud API and are not DP-bound in this
package.

---

## 4. Background-audio keep-alive service (confidence: high)

The Philips-customised module is `com.thingclips.nightowl.watchdog` ("Night Owl" =
Philips panel skin). Manifest (`AndroidManifest.xml:431`):

```
<service android:exported="false"
         android:foregroundServiceType="mediaPlayback"
         android:name="com.thingclips.nightowl.watchdog.BackgroundGroundService"/>
```

`mediaPlayback` is the correct FGS type to keep an **audio stream alive while
backgrounded/locked** — the persistent notification stops Android from killing the
process so the panel's decoded audio keeps playing. (Note: the audio **decode +
playback** itself happens in the panel/native AV path documented in
`re/media_decode_spec.md` / `re/webrtc_session.md`; this service does **not** contain
a decode loop — it is a process-liveness keeper, not the audio renderer.)

**Start/stop chain:**

- `BackgroundGroundService.Companion.e(intent, title, content, devId)`
  (`BackgroundGroundService.java:181`) sets statics `e=title`, `f=content`, `i=devId`
  then `ThingSdk.getApplication().startForegroundService(intent)`.
- `onStartCommand` (`:625`) → `isStart=true; startForeground(1, e()); d=this; return START_STICKY(1)`.
- `e()` (`:381`) builds a `NotificationCompat.Builder(this, "thing_camera")` with
  `setOngoing(false)`, `setOnlyAlertOnce(true)`, priority `3`, then sets
  `notification.flags = 32` (`FLAG_NO_CLEAR`). Channel created in `f("thing_camera")`
  (`:479`) at **importance 4 (HIGH)**, `setBypassDnd(true)`,
  `setLockscreenVisibility(-1)` (PUBLIC), lights+vibration enabled.
- Tap action `g()` (`:499`) deep-links back into the live view:
  `"<app_scheme>://panel?devId=<devId>&category=0&background=1"` via the
  `com.thingclips.smart.action.router` intent.
- `onDestroy` (`:613`) `stopForeground` + `isStart=false`; `h()` (`:511`) stops the
  service when foregrounded again; `onTimeout(int)` (`:655`) honours the Android-14
  FGS timeout by `stopSelf()`.

**Notification strings (resolved via `res/values/public.xml`, confidence: high).**
The watchdog module's obfuscated `R.string` aliases
(`com/thingclips/nightowl/watchdog/R.java:609`) map to real resource names:

| Alias | id | Resource name | Value / role |
|---|---|---|---|
| `R.string.a` | `0x7f13022a` | `app_name` | Notification **title** (`e`) — "Baby Monitor+" |
| `R.string.b` | `0x7f130238` | `app_scheme` | Deep-link **scheme** in `g()` |
| `R.string.c` | `0x7f130597` | `bmp_background_audio_notification_content` | Notification **content** (`f`) — "Background Audio is active." |
| `R.string.d` | `0x7f130599` | `bmp_background_monitoring_stopped_content_android` | "Background monitoring interrupted by another app." (interrupt notice) |
| `R.string.e` | `0x7f131a23` | `push_channel_common` | Notification **channel** display name |
| `R.string.f` | `0x7f132076` | `thing_device_disonnect_detail` | Device-disconnect body |
| `R.string.g` | `0x7f132077` | `thing_device_disonnect_title` | Device-disconnect title |

So when the app is backgrounded the user sees a HIGH-importance, DnD-bypassing,
ongoing notification titled *Baby Monitor+* / *"Background Audio is active."* whose
tap reopens the live panel in `background=1` mode. The longer educational copy
(`bmp_background_audio_content`, `bm_background_monitoring_content`) is the
in-panel explainer, not the notification body.

---

## 5. The monitoring loop + lifecycle wiring (confidence: high)

`PanelWatchDogManager` (`PanelWatchDogManager.java`, `@Keep`, singleton `instance`):

- `init(Application)` (`:199`) — builds `LocalNotificationManager` (called once from
  `com/smart/app/SmartApplication.java:404`).
- **`startRxjava()` (`:209`) — the heartbeat / monitoring loop:**
  ```java
  subscribe = Observable.interval(0L, 20L, TimeUnit.SECONDS)
                .subscribeOn(Schedulers.io())
                .subscribe(l -> ThingSdk.getEventBus().post(new SessionStatus(true)));
  ```
  i.e. **every 20 s** it posts a `SessionStatus(true)` keep-alive event on the Thing
  event bus (`lambda$startRxjava$0`, `:173`). Idempotent (won't double-subscribe).
- `stopRxjava()` (`:279`) posts `SessionStatus(false)` and disposes the interval.
- `startWatchDogManager(Activity)` (`:275`) → `LocalNotificationManager.w(activity)`.

`LocalNotificationManager` (`LocalNotificationManager.java`) registers on the event
bus (`ThingSdk.getEventBus().register(this)`, ctor `:51`) and installs an
`ActivityLifecycleCallbacks`:

- **`onActivityStopped` (`:1448`)** — app backgrounded: after a guard it calls
  `BackgroundGroundService.INSTANCE.e(new Intent(activity, BackgroundGroundService.class),
  title=app_name, content=bmp_background_audio_notification_content, devId)`
  (`:1594`), i.e. **start the keep-alive FGS**; fallback path posts a plain local
  notification via `v(...)` (`:1603/1607`).
- **`onActivityStarted` / `onActivityResumed` (`:1309/:1149`)** — app foregrounded:
  if `BackgroundGroundService.INSTANCE.a() != null` it tears the service down
  (`:1384`, API ≥ 34 path).
- **`onActivityDestroyed` (`:1045`)** — same teardown guard (`:1090`).
- **`onEventMainThread(SessionStatus)` (`:1827`)** — reacts to the heartbeat /
  session-lost event; on loss renders a device-disconnect notification
  (`thing_device_disonnect_title` + `thing_device_disonnect_detail`, importance 2,
  `:1842/1848`) and tears down the FGS (`:1832`).
- **`onEventMainThread(CallStatus)` (`:1815`)** — on a phone-call interruption renders
  the "Background monitoring interrupted" notice
  (`thing_device_disonnect_title` + `bmp_background_monitoring_stopped_content_android`,
  importance 3, `:1818/1823`).
- `v(ctx, nm, title, body, id)` (`:1946`) is the shared notification builder; it
  (re)creates channel `"thing_camera"` at importance 4 (`:2027`) and deep-links to the
  same `…://panel?devId=…&category=0&background=1` URL (`q()`, `:966`).

`SessionStatus` (`SessionStatus.java`) = `{ boolean a; int b }` with
ctors `SessionStatus(boolean)` and `SessionStatus(int)`; `CallStatus`
(`CallStatus.java`) = `{ boolean a }`.

**RN bridge (who arms it) — `TRCTIpcMonitorManager`** (the IPC-monitor React Native
module the panel talks to):

- `showWatchDogLocalNotification(Callback)` (`:1780`) → `PanelWatchDogManager.getInstance().startRxjava()` (`:1801`) — JS panel **arms** background monitoring.
- `removeWatchDogLocalNotification(Callback)` (`:1668`) → `stopRxjava()` — **disarms**.
- another `@ReactMethod` (`:1741`) → `startWatchDogManager(getCurrentActivity())`.

So the end-to-end arm flow is: **JS "Your baby" screen → RN bridge
`showWatchDogLocalNotification` → `startRxjava` (20 s heartbeat) +
`startWatchDogManager` (lifecycle observer) → on background, observer starts
`BackgroundGroundService` (FGS, `mediaPlayback`) → process stays alive → panel audio
keeps playing**; foregrounding or session-loss tears the service down.

---

## 6. Two distinct keep-alive services — do not conflate (confidence: high)

There are **two** `mediaPlayback` foreground services in the manifest; only the
second is the baby-monitor background-audio keeper:

1. `com.thingclips.smart.push.keeplive.service.KeepAliverService` (`:129`) +
   `KeepAliveJobSchedulerService` (`:130`) — the **generic Tuya push keep-alive**
   (channel `default_channel`, notification id `10001`,
   `KeepAliverService.java:152/262`, `KeepAliveNotificationHelper`). This keeps the
   **push pipeline / MQTT** process resident; it is *not* tied to live audio. Strings
   come from the Tuya SDK, not the Philips `bmp_*` set.
2. `com.thingclips.nightowl.watchdog.BackgroundGroundService` (`:431`) — the
   **Philips background-audio** keeper analysed in §4–§5 (notification id `1`, channel
   `thing_camera`, Philips `bmp_background_audio_*` strings).

The `microphone`/`location`/`mediaProjection` FGS in the manifest
(`SportService`/`MediaCaptureService`) are unrelated SDK features, not baby-audio.

---

## Residual unknowns / what would unblock

1. **`type` enum values for SCD921 alert categories.** The client treats the FCM
   `type` field as opaque (§2). Which integer/string `type` maps to sound vs motion vs
   temperature vs cry vs SenseIQ is **server-assigned and absent from the APK**.
   Unblock: a **captured FCM data payload** for each event class (Frida hook on
   `FcmManager.d` / `RemoteMessage.getData`, or a cloud message-center dump), then
   diff against `PushBean`. There is no such capture in `emulator_captures/` today.
2. **Per-category baby-event push toggles.** Only the doorbell-family DPs
   (`ipc_doorbell_message/push`, `doorbell_pir_switch`, `doorbell_sensitivity`) and
   `ipc_power_push` are DP-bound in this build (§3). The sound/cry/temperature/SenseIQ
   push enables live in the **runtime RN panel + cloud API**. Unblock: capture the
   downloaded Hermes/JS bundle for the Night Owl panel, or trace the RN bridge
   (`TRCTIpcMonitorManager`/message-center plugin) to see which cloud setting each
   category toggle writes.
3. **Whether the 20 s `SessionStatus` heartbeat reaches the cloud or is purely
   local.** Statically it only `post`s to the in-process Thing event bus
   (`PanelWatchDogManager.lambda$startRxjava$0`); whether a downstream subscriber
   forwards it to MQTT/cloud as a "still watching" ping is not proven here. Unblock:
   live MQTT capture during a background-audio session, or enumerate all
   `getEventBus().register` subscribers of `SessionStatus`.
4. **`PushUtil.parseMessage` link grammar.** The exact deep-link path format inside
   the `link` field (beyond the `…://panel?devId=…&category=…&background=…` shape seen
   in the watchdog) is parsed in `PushUtil`/`PushCenterService` and was not fully
   expanded for this task. Unblock: a captured `link` value + reading `PushUtil`.
5. **FCM sender id / Firebase project ownership.** Whether the Firebase project is
   Philips-owned or a shared Tuya project is not determined; the value is referenced
   only (`gcm_sender_id` in `strings.xml`), never inlined here. Unblock: out of scope
   — it is a config value, not a protocol unknown.
