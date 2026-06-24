# Milestone 2 Findings — Extraction & Architecture Identification

**App:** `com.philips.ph.babymonitorplus` "Baby Monitor+" v1.9.0 (build 41),
minSdk 23, targetSdk 35. Hardware: Philips Avent SCD921/SCD923.

## Headline: this is a re-skinned Tuya Smart camera app

The decisive evidence is the native library set in `config.arm64_v8a.apk`. The `Thing*` /
`thing*` prefix is **Tuya Smart's SDK** (Tuya rebranded its platform to "Thing" / ThingClips).
Philips white-labeled Tuya's Smart Camera (IPC) platform rather than building a bespoke stack.

### Streaming / device stack (Tuya IPC)
| Library | Role |
|---|---|
| `libThingP2PSDK.so` | Tuya P2P transport — **the audio/video session channel** |
| `libThingP2PFileTransSDK.so` | P2P file transfer (e.g. cloud-clip / album) |
| `libThingCameraSDK.so` (4.8 MB) | IPC camera control SDK |
| `libThingVideoCodecSDK.so` | Video codec (H.264/H.265) |
| `libThingAudioEngineSDK.so`, `libThingMP3CodecSDK.so`, `libThingAudioFileRecorderSDK.so` | Audio engine / codecs |
| `libIPCStitch.so` | IPC frame stitching |
| `libThingSmartLink.so` | Device provisioning (AP / EZ SmartLink WiFi pairing) |
| `libThingCloudStorageSignatureTools.so` | Cloud storage signing |
| `libthingsmart.so`, `libthing-outpoint.so`, `libthingmmkv.so` | Tuya core / KV store |
| `libthing_security.so`, `libthing_security_algorithm.so`, `libthingnetsec.so` | Tuya crypto / secure transport |
| `libsqlcipher.so`, `libcrypto.1.1.so`, `libssl.1.1.so` | Encrypted local DB + OpenSSL 1.1 |

### App framework
- **React Native on V8**: `libreactnativejni.so`, `libv8android.so` (14 MB), `libv8executor.so`,
  `libjsinspector.so`, `libfolly_json.so`, `libyoga.so`, `libfb.so`. Much UI/business logic is in
  a **JS bundle** (see `assets/kit_js`, `assets/mini_app_js`, `assets/thing_uni_plugins` — 101
  Tuya "uni" mini-program plugins). JS is far easier to read than decompiled native/Java.
- **Pairing helpers**: `libbarhopper_v3.so` + `assets/mlkit_barcode_models` → Google ML Kit QR
  scanning (device QR pairing).
- **Two-way audio codecs**: `libopus.so`/`libopusJni.so` (Opus), `libsbcutilJni.so` (SBC).
- **APM/crash** (Kuaishou): `libkoom-*`, `libxcrash*`, `libbytehook`, `libshadowhook`, `libxhook`.

### Bytecode
- **14 multidex files**, ~190 MB total (`classes.dex` … `classes14.dex`; largest `classes5.dex`
  24 MB, `classes8.dex` 20 MB). Consistent with the full Tuya SDK + React Native footprint.

### Cloud config
- `assets/thing_domains_v1` present → Tuya cloud endpoint/region configuration is bundled.

## What this means for the reimplementation

1. **Auth is Tuya account auth + device binding via Tuya cloud** — NOT a Philips-proprietary or
   purely-local scheme. The earlier "local-only device" hypothesis is **refuted**. There is a
   cloud control plane (Tuya's), and P2P streaming is most likely brokered through Tuya servers
   for NAT traversal (with a possible LAN fast-path).
2. **Tuya is a known quantity.** Its pairing token flow, cloud API signing, and P2P transport are
   extensively documented by the public RE community (e.g. tinytuya, tuya-iot SDKs, Tuya-camera
   P2P efforts). This raises feasibility substantially versus a bespoke protocol.
3. **Highest-value artifact to recover next:** the embedded **Tuya AppKey / AppSecret** (Philips'
   Tuya developer app credentials). Tuya cloud signs every API request (HMAC) with these; they are
   required to reimplement cloud auth. They live somewhere in the APK (native string table,
   `assets/*config*.json`, or DEX). → backlog task.
4. The hard core remains **`libThingP2PSDK`**: Tuya's P2P session establishment + the AV framing
   over it. Static-only, this is the riskiest piece; public Tuya-P2P work is the main lever.

## Confidence
- Tuya platform identification: **very high** (native lib names + assets are unambiguous).
- Cloud-brokered P2P streaming: **high** (standard Tuya IPC architecture), to be confirmed by JS +
  native analysis.
- Exact P2P wire format decodability from static analysis alone: **uncertain** — flagged honestly.
