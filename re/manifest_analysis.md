# Manifest & Component Analysis (TASK-0002)

App `com.philips.ph.babymonitorplus` "Baby Monitor+" (white-labeled Tuya/Thing
Smart camera app). Source: base APK `extracted/xapk/com.philips.ph.babymonitorplus.apk`
decoded with apktool 2.12.1 into the gitignored `decompiled/apktool/`. All line
citations below refer to `decompiled/apktool/AndroidManifest.xml` (884 lines total).

Method: `apktool d -f -o decompiled/apktool <base.apk>` (exit 0; full resource +
manifest decode). Component tallies via `grep -cE` over the decoded manifest.

> Note: the `decompiled/apktool/...:line` citations (and any `decompiled/jadx/`
> Java `:line` reference) resolve only after a local `just decompile` — those
> trees are gitignored and not committed.
>
> Citation note (symbol-anchored — TASK-0024): the authoritative anchor is the
> **symbol** — here the manifest `android:name` (permission/activity/service) or a
> resource `name` (e.g. `thing_jump_scheme`). The `:NN` line is an **approximate
> hint**: apktool XML line numbers are more stable than jadx Java, but still
> re-decode-dependent. When a hint drifts, grep the name in
> `decompiled/apktool/AndroidManifest.xml` / `res/values/strings.xml`.

## Component tallies (confidence: confirmed)

| Component | Count | Evidence |
|---|---|---|
| `<activity>` | 574 | `grep -cE '<activity '` on `decompiled/apktool/AndroidManifest.xml:1` |
| `<activity-alias>` | 4 | same manifest |
| `<service>` | 34 | same manifest |
| `<receiver>` | 19 | same manifest |
| `<provider>` | 8 | same manifest |

The huge activity count is the full Tuya/Thing SDK + React Native panel surface,
not Philips code. The Philips-authored surface is thin (theming, splash, a couple
of deep links); the substantive components are all `com.thingclips.*`.

## Permissions relevant to a streaming/pairing client (confidence: confirmed)

Camera/mic/location/network/foreground permissions, each cited to its manifest line:

| Permission | Line | Why it matters |
|---|---|---|
| `android.permission.CAMERA` | `AndroidManifest.xml:20` | local camera (QR pairing scan, two-way video), not the baby-cam itself |
| `android.permission.RECORD_AUDIO` | `AndroidManifest.xml:11` | two-way talk (push-to-talk mic) |
| `android.permission.MODIFY_AUDIO_SETTINGS` | `AndroidManifest.xml:21` | audio routing for playback |
| `android.permission.ACCESS_FINE_LOCATION` | `AndroidManifest.xml:13` | Wi-Fi SSID read during EZ/AP pairing (Android ties SSID to location) |
| `android.permission.ACCESS_COARSE_LOCATION` | `AndroidManifest.xml:10` | same pairing need |
| `android.permission.CHANGE_WIFI_STATE` | `AndroidManifest.xml:5` | switch to device AP during AP-mode provisioning |
| `android.permission.ACCESS_WIFI_STATE` | `AndroidManifest.xml:7` | read Wi-Fi for SmartLink/EZ pairing |
| `android.permission.CHANGE_WIFI_MULTICAST_STATE` | `AndroidManifest.xml:15` | multicast for LAN device discovery (UDP broadcast, see `GwBroadcastMonitorService`) |
| `android.permission.CHANGE_NETWORK_STATE` / `ACCESS_NETWORK_STATE` | `AndroidManifest.xml:6`,`:8` | network transition handling |
| `android.permission.INTERNET` | `AndroidManifest.xml:22` | cloud (Tuya MQTT/HTTPS) |
| `android.permission.FOREGROUND_SERVICE` | `AndroidManifest.xml:16` | keep-alive while streaming/listening |
| `android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK` | `AndroidManifest.xml:84` | the streaming/keep-alive FGS type (see below) |
| `android.permission.POST_NOTIFICATIONS` | `AndroidManifest.xml:18` | cry/motion/doorbell push alerts |
| `android.permission.BLUETOOTH` / `BLUETOOTH_ADMIN` | `AndroidManifest.xml:78`,`:81` | BLE-assisted pairing (`libBleLib.so`, `BluetoothService`) |
| `android.permission.WAKE_LOCK` | `AndroidManifest.xml:3` | hold CPU while monitoring |

NOTE: there is NO dedicated "local network" permission on this Android target;
LAN access is implicit via `INTERNET` + `CHANGE_WIFI_MULTICAST_STATE`. The
`HIGH_SAMPLING_RATE_SENSORS` permission appears twice (`:4` malformed/dup with a
trailing space at `:88`) — a packaging artifact, not load-bearing.

App element: `android:name="com.smart.app.SmartApplication"`
(`AndroidManifest.xml:89`) — the Tuya/Thing `SmartApplication`, confirming the
process is bootstrapped by the Thing SDK, not a Philips Application subclass.
`networkSecurityConfig="@xml/b926312"` (`:89`) — worth a later look for cleartext/
pinning config (filed forward, not chased here).

## Deep links / custom URI schemes (confidence: confirmed)

Three non-standard `<data>` scheme entries — these are the externally reachable
entry points (login redirect / push-tap routing / diagnostics):

| Scheme / host / path | Line | Target |
|---|---|---|
| `philipsclnightowl://com.philips.ph.babymonitorplus/zoundream` | `AndroidManifest.xml:125` | on `com.smart.ThingSplashActivity` (`AndroidManifest.xml` ~:94); `thing_jump_scheme` resolves to the app scheme per the `<string name="thing_jump_scheme">` resource in `decompiled/apktool/res/values/strings.xml` (~:9199) |
| `philipsclnightowl://com.philips.ph.babymonitorplus/path/lineNotify` | `AndroidManifest.xml:743` | `com.thingclips.smart.message.base.activity.line.LineNotifyActivity` — push/notification tap routing |
| `module.entrance://netdiagnosis` | `AndroidManifest.xml:511` | `com.thingclips.smart.netdiagnosis.NetDiagnosisModuleEntrance` — net-diagnostics entry |

`philipsclnightowl` is the app's custom scheme (the SCD9xx line is internally
"Night Owl"/"nightowl", see `com.thingclips.nightowl.*` services). The splash
activity also registers a generic `VIEW`+`BROWSABLE` filter (`:99-103`) used for
router/OAuth-style hand-off.

Exported, deep-link-capable activities (confidence: confirmed):
`com.smart.ThingSplashActivity` (`:94`, LAUNCHER + VIEW),
`com.thingclips.smart.jsbridge.base.webview.LoadingActivity` (`:120`),
`com.thingclips.smart.netdiagnosis.NetDiagnosisModuleEntrance` (`:511`),
`com.thingclips.smart.message.base.activity.line.LineNotifyActivity` (`:743`).

## Service entry points by class (confidence: confirmed)

### Cloud control plane — MQTT
- `com.thingclips.smart.mqtt.MqttService` — `AndroidManifest.xml:252`.
  This is Tuya's MQTT client service: the cloud control/event channel (device
  online/offline, DP updates, and — per the review-gate F2 hypothesis — the
  likely WebRTC signaling transport). **Highest-interest entry point for the
  streaming-mode triage (forward to task 10).**

### Push / notifications (cry, motion, doorbell alerts)
- `com.thingclips.smart.fcmpush.service.ThingFcmListenerService` — `:153`
  (exported, `:fcmpush` process); bound to FCM.
- `com.google.firebase.messaging.FirebaseMessagingService` — `:163` (`:fcmpush`).
- `com.thingclips.smart.fcmpush.service.MainProcessService` — push→main IPC.
- `com.thingclips.smart.camera.push.DoorBellCallService` — `:657` — camera-push
  service for doorbell/call events (paired receiver
  `com.thingclips.smart.camera.push.DoorbellCallBroadcastReceiver`, receiver list #15).
- `com.thingclips.smart.messagepush.service.notify.SystemNotifyService`,
  `com.thingclips.smart.messagepush.sport.SportService` (`:781`, FGS type `location`).

### Foreground / keep-alive (holds the monitoring session alive)
- `com.thingclips.smart.push.keeplive.service.KeepAliverService` — `:129`
  (`foregroundServiceType="mediaPlayback"`, priority 1000).
- `com.thingclips.smart.push.keeplive.service.KeepAliveJobSchedulerService` — `:130`.
- `com.thingclips.nightowl.watchdog.BackgroundGroundService` — `:431`
  (`foregroundServiceType="mediaPlayback"`) — the **"nightowl" (= SCD9xx product
  line) watchdog**; this is the FGS that keeps the audio/video monitor running in
  background. Philips-product-specific naming inside the Tuya namespace.

### LAN device discovery (local pairing / fast-path)
- `com.thingclips.smart.android.hardware.service.GwBroadcastMonitorService` —
  `:872`, label `UDPService`, process `:monitor`, intent-filter action
  `thing.intent.action.udp` (`:874`). This is Tuya's **LAN UDP gateway/device
  broadcast monitor** — local device discovery on the Wi-Fi network. Paired with
  `com.thingclips.smart.android.hardware.service.DevTransferService` (`:871`,
  `:monitor` process) for the local hardware transfer channel.

### Camera media capture (RN panel)
- `com.thingclips.smart.rnplugin.trcthealthwatchmanager.MediaCaptureService` —
  `:861` (`foregroundServiceType="mediaProjection"`, exported) — RN-plugin media
  capture (screen-record/snapshot of the camera panel).

### BLE pairing assist
- `com.thingclips.sdk.blelib.BluetoothService` — BLE scan/connect for
  BLE-assisted device provisioning (`libBleLib.so`).

### Camera RN panel activities (where the live view UI lives)
- `com.thingclips.smart.ipc.camera.rnpanel.activity.ThingRCTSmartCameraPanelActivity`
  — `AndroidManifest.xml:117` — the **IPC camera React-Native panel** host. The
  actual video view + P2P glue is driven from the RN `thing_uni_plugins`/`kit_js`
  bundle inside this activity (see TASK-0003).
- `com.thingclips.smart.panel.base.activity.ThingRCTSmartPanelActivity` — `:116`
  (generic device panel host).

## Providers (confidence: confirmed)
- `com.thingclips.android.universal.apimanager.TUNIModuleProvider` — `:279`
  (`TUNIModuleProvider` authority) — bootstraps the Thing Universal ("TUNI")
  mini-app/RN API module registry (the JS↔native bridge registrar).
- `com.thingclips.smart.optimus.sdk.ThingOptimusProvider` — `:808` — Tuya
  "Optimus" plugin/SDK service-discovery init.
- `com.thingclips.smart.dynamic.resource.configuration.WebViewPackageProvider`
  — `:131` (dynamic-resource authority).
- `com.thingclips.commonFileProvider.ThingUniFileProvider` — `:286`
  (FileProvider for uni-plugin file sharing).
- Plus standard Firebase / MLKit / androidx-startup init providers.

## Receivers of interest (confidence: confirmed)
- `com.thingclips.smart.camera.push.DoorbellCallBroadcastReceiver` (#15) — camera
  call/doorbell broadcast.
- `com.thingclips.smart.rnplugin.trctlocalalarmmanager.alarm.receiver.{LocalAlarm,OpenPanel,NotifyPanel}Receiver`
  (#17-19) — RN local-alarm/lullaby scheduling receivers.
- `com.thingclips.smart.ble.bs.beacon.BeaconScanFilterReceiver` (#11) — BLE beacon
  scan filtering (pairing).
- Firebase / WorkManager / datatransport standard receivers.

## What this gives the Rust reimplementation (confidence: likely)

These are interpretations of the manifest evidence above (each underlying
component citation is `confirmed`; the streaming-role inferences are `likely`).

1. The cloud control plane is **Tuya MQTT** (`MqttService`, `:252`) — model this
   as the event/control channel and the prime WebRTC-signaling candidate.
2. LAN discovery exists (`GwBroadcastMonitorService` UDP, `:872`) — a local
   fast-path / local-key control path is plausible (review-gate F4).
3. The live camera UI is a React-Native IPC panel
   (`ThingRCTSmartCameraPanelActivity`, `:117`) driven from the JS bundle —
   confirms TASK-0003 (JS) is where the streaming/pairing orchestration is
   readable.
4. Pairing uses Wi-Fi (EZ/AP/SmartLink) + BLE + QR (CAMERA perm + MLKit) —
   matches `libThingSmartLink.so` / `libBleLib.so` / `libbarhopper_v3.so`.

## Limitations
- apktool does not give per-claim semantic confidence beyond the manifest text;
  service *behavior* (e.g. whether `MqttService` carries WebRTC signaling) is a
  hypothesis to be confirmed in the JS/native layers, flagged accordingly above.
- Activity count includes many SDK internal activities never user-reachable;
  only the exported/deep-link ones are externally relevant.
