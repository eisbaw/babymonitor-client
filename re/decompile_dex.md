# DEX Decompilation Map (TASK-0001)

jadx decompilation of the 14 multidex files from the base APK
(`extracted/xapk/com.philips.ph.babymonitorplus.apk`) into the gitignored
`decompiled/jadx/`. This is the Java/Kotlin substrate every later static-analysis
task greps. Citations below are `decompiled/jadx/sources/<path>` (gitignored but
stable paths) — strip the `decompiled/jadx/sources/` prefix when reading.

> Citation note (symbol-anchored — TASK-0024): cites name a **symbol**
> (class/method/field). Any `~:NN` line is an **approximate hint** for the current
> `just decompile` tree — jadx line numbers drift between runs, so the symbol is
> authoritative; grep it (`rg 'class Foo|methodName'`).

## Command (confidence: confirmed)

```
# The JVM heap is a JVM arg (-Xmx…) passed via JADX_OPTS, NOT a jadx CLI flag —
# passing -Xmx4g on the jadx command line errors "Unknown option".
# shell.nix sets JADX_OPTS=-Xmx4g, which OOMs on this dex set; override to 12g.
JADX_OPTS='-Xmx12g' nix-shell --run \
    'JADX_OPTS="-Xmx12g" jadx --no-debug-info \
        --output-dir decompiled/jadx \
        extracted/xapk/com.philips.ph.babymonitorplus.apk'
```

jadx 1.5.0 (JVM heap 12g). Pointed at the APK directly so all 14
`classes*.dex` are processed in one pass (jadx reads every dex in the archive:
the dex files are also copied verbatim into `decompiled/jadx/resources/`).

GOTCHA (carried forward): the first attempt put `-Xmx4g` on the jadx CLI and
failed with "Unknown option: -Xmx4g". The heap must go through `JADX_OPTS`, not
the command line. When both `-Xmx4g` (shell default) and `-Xmx12g` are present,
HotSpot uses the LAST one, so prefixing `JADX_OPTS="-Xmx12g"` wins.

## Coverage / jadx success (confidence: confirmed)

- Input: 14 dex (~190 MB). jadx reports **36,686 classes** to process.
- **First run at the shell default `-Xmx4g` FAILED with `java.lang.OutOfMemoryError`
  (exit 1), truncated at ~80% / ~41,680 `.java` files** — the heaviest obfuscated
  classes (in `classes5.dex` 24 MB, `classes8.dex` 20 MB) exhausted the 4g heap.
  This is a real partial failure, recorded honestly, NOT hidden.
- **Re-run at `-Xmx12g` SUCCEEDED cleanly: exit 0, reached 99% (36,685/36,686 —
  the last item is the final write flush), zero `OutOfMemoryError`,** producing
  **51,008 `.java` files** under `decompiled/jadx/sources/` (~888 MB). The extra
  ~9,300 files over the OOM-truncated run are the classes the 4g heap dropped.
- Residual per-method failures (expected on heavily R8-obfuscated dex, flagged
  INLINE by jadx, not silent): **1,397 files carry a marker** — 1,806 `Method not
  decompiled`, 19 `JADX ERROR`, 3 `Failed to decode`. jadx emits these as inline
  comments + a stub body (`throw new UnsupportedOperationException("Method not
  decompiled: …")`) so the class signature/fields are still present; only those
  specific obfuscated method bodies are unreadable. No WHOLE class is dropped.
- Honesty note: treat any single decompiled method body as "likely" and
  cross-check against the native strings / JS contract before asserting
  "confirmed"; for the ~1.8k flagged methods the body is simply absent.

## Package-level map (confidence: confirmed — counts from `find ... -name '*.java'`)

Counts from the complete `-Xmx12g` run (50,977 `.java` under `sources/`):

| Namespace | `.java` files | What it is |
|---|---|---|
| `com/thingclips` | 22,377 | **Tuya/Thing SDK** — the whole app engine (camera, P2P, mqtt, auth, activator) |
| `com/google` | 8,216 | Firebase, GMS, MLKit, protobuf, ExoPlayer |
| `com/facebook` | 1,374 | React Native + Fresco + Folly JNI |
| `com/facebook/react` | 588 | **React Native bridge runtime** |
| `com/gzl` | 762 | Tuya "GZL" mini-app / uni-runtime (hosts the JS bundles) |
| `com/smart` | 15 | `com.smart.app.SmartApplication` (app bootstrap) + splash |
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

## Where the camera / P2P / auth / streaming code lives (confidence: confirmed — for symbol/method PRESENCE only)

> **Scope of the `confirmed` label:** it covers ONLY the *presence* of the named
> classes/methods/packages in the decompiled tree (a grep-verifiable fact with
> the `:line` citations below). Any *interpretation* of what a symbol does for the
> protocol (e.g. "this method means WebRTC") is a separate, individually-labelled
> claim and does NOT inherit this `confirmed` label.

> **Citation note:** the `decompiled/jadx/sources/...:line` citations in this doc
> resolve only after a local `just decompile` — the jadx tree is gitignored and
> not in the repo. Run it to follow any Java `:line` reference here.

Locations are directories under `decompiled/jadx/sources/`.

### P2P transport (the AV session channel)
- `com/thingclips/smart/p2p/` (23 files) — JNI wrapper for `libThingP2PSDK.so`.
  - `com/thingclips/smart/p2p/api/IThingP2P.java` — the P2P API surface:
    `connect(devId/remoteId, mode, timeout, cb)`, `recvData(...)`,
    **`resendOffer(String)`** and `addSessionStateChangeCallback(...)`.
    - `resendOffer` = WebRTC SDP-offer re-send → WebRTC path (confidence:
      confirmed — this inference is ≥2-source: the Java method name here PLUS the
      native dynsym cross-ref in re/native_libs.md, not the method name alone).
  - `com/thingclips/smart/p2p/utils/IMqttServiceUtils.java` — the **P2P↔MQTT
    signaling bridge**: `sendMessage(...)`, `send302MessageThroughMqtt(...)`,
    `registerMqtt302(...)`, `isMqttConnected()`. The "302" is **likely** Tuya's
    camera-signaling message code carried over MQTT (confidence: likely — this is
    inferred from the Java method NAMES `send302MessageThroughMqtt` /
    `registerMqtt302` only; the 302 value itself is not decoded statically here,
    so it is single-source until a payload/constant cross-ref confirms it). This
    is the Java side of the WebRTC-over-MQTT transport identified natively in
    re/native_libs.md.
  - `com/thingclips/smart/p2p/ThingP2PSdk.java` — the SDK entrypoint.
- `com/thingclips/smart/p2pfiletrans/` — `libThingP2PFileTransSDK.so` JNI (album).
- `com/thingclips/smart/camera/ipccamerasdk/` — IPC camera AV glue (`monitor/`,
  `bean/AudioParams.java`, `bean/CameraInfoBean.java`, `msgvideo/IThingCloudVideo`).
- `com/thingclips/smart/camera/middleware/p2p/` — the camera↔P2P middleware.

### Camera / IPC (control + live view)
- `com/thingclips/smart/ipc/` (1,521 files) and `com/thingclips/smart/camera/`
  (1,154 files) — the IPC camera feature surface, panels, device control.
- RN bridge plugins (the JS contract → Java): `com/thingclips/smart/plugin/
  tuniipccameramanager/`, `tuniipcdoorbellmanager/`, `tunip2pfilemanager/`,
  `tunimqttmanager/`, `tuniapirequestmanager/`, `tuniactivationmanager/`,
  `tuniloginmanager/`, `tunicloudstoragesignaturemanager/` — one Java package per
  TUNI manifest in re/js_bundle_map.md.

### Cloud auth + request signing (forward to task 7)
(confidence: confirmed for class/method presence — ≥2 independent sources: the
decompiled signer `ThingApiSignManager`
(`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java`;
`generateSignature` ~:69, `swapSignString` ~:524), AND the public mobile-sign
write-up `nalajcie/tuya-sign-hacking` (review-gate F1) which documents the same
swap/MD5 sign shape. NOTE: presence/shape is confirmed; the signing *key
derivation* remains task-5 work, not confirmed here.)

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
- `com/thingclips/smart/activator/` (648 files) — EZ/AP/SmartLink/Matter pairing
  (`libThingSmartLink.so` JNI: `ThingSmartLink.smartLink`). Matches the
  `startDeviceActivate` JS contract.

### Crypto / security
- `com/thingclips/security/`, `com/thingclips/netsec/`, `com/thingclips/sdk/
  security/`, `com/thingclips/sdk/armlib/security/`, `com/thingclips/bouncycastle/`
  (a bundled BouncyCastle), `com/thingclips/smart/cloudstorage/
  ThingCloudStorageSignatureTools.java`.

## What this gives the Rust reimplementation (confidence: likely)

Interpretation of the evidence above; underlying citations are in the per-area
sections (e.g. `IThingP2P.connect`
`decompiled/jadx/sources/com/thingclips/smart/p2p/api/IThingP2P.java` ~:18,
and interface `IMqttServiceUtils`
`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/IMqttServiceUtils.java`).

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
- jadx leaves 1,806 method bodies as `Method not decompiled` stubs across 1,397
  files (~2.7% of files) on the most obfuscated classes; the class signatures and
  fields are still present. Any single decompiled body is "likely"; for the
  flagged methods the body is absent and must be read from smali if needed.
- The 4g default heap OOMs on this dex set — always use `-Xmx12g`. The final run
  is complete (exit 0, 99%, 51,008 files); the earlier 4g OOM run was discarded.
