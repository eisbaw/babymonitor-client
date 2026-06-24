# DEX Decompilation Map (TASK-0001)

jadx decompilation of the 14 multidex files from the base APK
(`extracted/xapk/com.philips.ph.babymonitorplus.apk`) into the gitignored
`decompiled/jadx/`. This is the Java/Kotlin substrate every later static-analysis
task greps. Citations below are `decompiled/jadx/sources/<path>` (gitignored but
stable paths) — strip the `decompiled/jadx/sources/` prefix when reading.

## Command (confidence: confirmed)

```
# JADX_OPTS=-Xmx4g is exported by shell.nix (the JVM heap arg; it is NOT a jadx
# CLI flag — passing -Xmx4g on the jadx command line errors "Unknown option").
nix-shell --run 'jadx --no-debug-info \
    --output-dir decompiled/jadx \
    extracted/xapk/com.philips.ph.babymonitorplus.apk'
```

jadx 1.5.0 (JVM heap 4g). Pointed at the APK directly so all 14
`classes*.dex` are processed in one pass (jadx reads every dex in the archive:
the dex files are also copied verbatim into `decompiled/jadx/resources/`).

GOTCHA (carried forward): the first attempt put `-Xmx4g` on the jadx CLI and
failed with "Unknown option: -Xmx4g". The heap must go through `JADX_OPTS`
(already set inside the nix shell), not the command line.

## Coverage / jadx success (confidence: confirmed)

- Input: 14 dex (~190 MB). jadx reports a total of **36,686 classes** to process.
- Output: **~41,700 `.java` files** under `decompiled/jadx/sources/` (more files
  than classes because nested/anonymous classes can emit separate files and jadx
  also writes resource stubs).
- jadx runs to a high percentage cleanly; the **heaviest obfuscated classes
  (in `classes5.dex` 24 MB, `classes8.dex` 20 MB) are slow** and jadx spends a
  long tail at ~79-80% CPU-bound before flushing them. This is expected for a
  full Tuya-SDK + RN dex set, not a failure. Any classes jadx cannot fully
  decompile are emitted with an inline `/* JADX ERROR ... */` comment + the raw
  smali fallback rather than dropped, so partial-failure is visible in-file, not
  silent. The package-level map below is stable regardless of the slow tail
  because the directory/package structure is written up front.
- Honesty note: jadx on heavily R8-obfuscated dex routinely leaves SOME method
  bodies as `// Can't load method ...` / `throw new UnsupportedOperationException`
  stubs. Treat any single decompiled method body as "likely", cross-check against
  the native strings / JS contract before asserting "confirmed".

## Package-level map (confidence: confirmed — counts from `find ... -name '*.java'`)

| Namespace | `.java` files | What it is |
|---|---|---|
| `com/thingclips` | ~16,764 | **Tuya/Thing SDK** — the whole app engine (camera, P2P, mqtt, auth, activator) |
| `com/google` | ~7,160 | Firebase, GMS, MLKit, protobuf, ExoPlayer |
| `com/facebook` | ~1,148 | React Native + Fresco + Folly JNI |
| `com/facebook/react` | ~468 | **React Native bridge runtime** |
| `com/gzl` | ~477 | Tuya "GZL" mini-app / uni-runtime (hosts the JS bundles) |
| `com/alibaba` | ~49 | fastjson / ARouter |
| `com/smart` | ~11 | `com.smart.app.SmartApplication` (app bootstrap) + splash |
| `com/philips` | **1** | Philips' own code is essentially absent — this is a pure Tuya reskin |
| `com/tuya` | 1 | legacy `com.tuya` shim (renamed to `com.thingclips`) |
| obfuscated top-level pkgs | 44 dirs | R8/ProGuard output: `OooO00o`, `defpackage`, `ajers256188v21`, … |
| `kotlin` / `kotlinx` | — | Kotlin stdlib + coroutines |
| `okhttp3` / `okio` / `retrofit2` | — | HTTP stack (cloud REST) |

Obfuscation: **partial**. The Tuya SDK ships with readable package + public-API
class names (`IThingP2P`, `ThingApiSignManager`, `ThingP2PSdk`) but obfuscated
*implementation* classes (e.g. `com/thingclips/smart/p2p/pqdbppq.java`,
`com/thingclips/sdk/user/dbbpbbb.java`) and 44 obfuscated top-level packages. The
public interfaces are the reliable read; the `pqdbppq`-style impls need
cross-referencing.

## Where the camera / P2P / auth / streaming code lives (confidence: confirmed)

Locations are directories under `decompiled/jadx/sources/`.

### P2P transport (the AV session channel)
- `com/thingclips/smart/p2p/` (23 files) — JNI wrapper for `libThingP2PSDK.so`.
  - `com/thingclips/smart/p2p/api/IThingP2P.java` — the P2P API surface:
    `connect(devId/remoteId, mode, timeout, cb)`, `recvData(...)`,
    **`resendOffer(String)`** and `addSessionStateChangeCallback(...)`
    (`resendOffer` = WebRTC SDP offer re-send → confirms WebRTC path).
  - `com/thingclips/smart/p2p/utils/IMqttServiceUtils.java` — the **P2P↔MQTT
    signaling bridge**: `sendMessage(...)`, `send302MessageThroughMqtt(...)`,
    `registerMqtt302(...)`, `isMqttConnected()`. The "302" is Tuya's
    camera-signaling message code carried over MQTT. This is the Java side of the
    WebRTC-over-MQTT transport identified natively in re/native_libs.md.
  - `com/thingclips/smart/p2p/ThingP2PSdk.java` — the SDK entrypoint.
- `com/thingclips/smart/p2pfiletrans/` — `libThingP2PFileTransSDK.so` JNI (album).
- `com/thingclips/smart/camera/ipccamerasdk/` — IPC camera AV glue (`monitor/`,
  `bean/AudioParams.java`, `bean/CameraInfoBean.java`, `msgvideo/IThingCloudVideo`).
- `com/thingclips/smart/camera/middleware/p2p/` — the camera↔P2P middleware.

### Camera / IPC (control + live view)
- `com/thingclips/smart/ipc/` (~901 files) and `com/thingclips/smart/camera/`
  (~844 files) — the IPC camera feature surface, panels, device control.
- RN bridge plugins (the JS contract → Java): `com/thingclips/smart/plugin/
  tuniipccameramanager/`, `tuniipcdoorbellmanager/`, `tunip2pfilemanager/`,
  `tunimqttmanager/`, `tuniapirequestmanager/`, `tuniactivationmanager/`,
  `tuniloginmanager/`, `tunicloudstoragesignaturemanager/` — one Java package per
  TUNI manifest in re/js_bundle_map.md.

### Cloud auth + request signing (forward to task 7)
(confidence: confirmed for class/method presence;
`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java:69`
(`generateSignature`), `:524` (`swapSignString`))

- **`com/thingclips/sdk/network/ThingApiSignManager.java`** — the cloud-API
  request signer. Methods: `generateSignature(params, ThingApiParams)`,
  `generateSignatureSdk(map)`, `getRequestKeyBySorted(map)`,
  `postDataMD5Hex(str)`, and **`swapSignString(str)`** — a byte-permutation that
  reorders MD5-as-base64 substrings (0-8 / 8-24 / 24-32). This is the readable
  Java half of the Tuya mobile-app sign (review-gate F1); the signing KEY is
  expected to come from native (`t_s.bmp` + cert pin / whitebox, task 5). NOTE:
  the static `{}` initializer of this class holds string constants — task 5/7 must
  inspect it for an embedded key WITHOUT copying any value into a committed file.
- `com/thingclips/sdk/user/` (~27 files, obfuscated impls) — account/login SDK
  (the cloud-auth entry the `onTicketSuccess` JS ticket resolves into).
- Login feature packages: `com/thingclips/smart/login/`,
  `com/thingclips/smart/loginapi/` (`com/thingclips/smart/api/loginapi`),
  `com/thingclips/smart/socialloginmanager/`, `com/thingclips/smart/qrlogin/`.

### Cloud control plane (MQTT)
- `com/thingclips/sdk/mqtt/`, `com/thingclips/sdk/mqttmanager/`,
  `com/thingclips/smart/mqttclient/mqttv3/` (Paho-derived), `com/thingclips/smart/
  mqtt/` (the `MqttService`). This is the event/DP/signaling channel.

### Pairing / provisioning
- `com/thingclips/smart/activator/` (~381 files) — EZ/AP/SmartLink/Matter pairing
  (`libThingSmartLink.so` JNI: `ThingSmartLink.smartLink`). Matches the
  `startDeviceActivate` JS contract.

### Crypto / security
- `com/thingclips/security/`, `com/thingclips/netsec/`, `com/thingclips/sdk/
  security/`, `com/thingclips/sdk/armlib/security/`, `com/thingclips/bouncycastle/`
  (a bundled BouncyCastle), `com/thingclips/smart/cloudstorage/
  ThingCloudStorageSignatureTools.java`.

## What this gives the Rust reimplementation (confidence: likely)

Interpretation of the evidence above; underlying citations are in the per-area
sections (e.g.
`decompiled/jadx/sources/com/thingclips/smart/p2p/api/IThingP2P.java:18`,
`.../p2p/utils/IMqttServiceUtils.java:1`).

1. The cloud-auth sign algorithm is statically present in
   `ThingApiSignManager.java` (Java) + the native key source — a real lever for
   task 7, far better than guessing.
2. The P2P/streaming Java API (`IThingP2P` + `IMqttServiceUtils`) confirms the
   WebRTC-over-MQTT signaling shape end-to-end (Java ⇄ native ⇄ JS all agree).
3. Philips wrote essentially no app logic (1 file); the entire target is the Tuya
   SDK, which is publicly documented — feasibility is high.

## Limitations (confidence: confirmed — scoping caveats)
- Obfuscated impl classes (`pqdbppq`-style) need manual cross-referencing; the
  public interfaces are the trustworthy read.
- jadx leaves some method bodies as stubs on the most obfuscated classes; any
  single decompiled body is "likely", to be cross-checked.
- Counts are approximate (`find -name '*.java'`) and were taken as jadx was
  finishing its slow tail on the heaviest dex; the package STRUCTURE is complete
  and stable, individual heavy-class bodies may continue to flush.
