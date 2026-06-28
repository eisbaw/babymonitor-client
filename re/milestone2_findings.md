# Milestone 2 Findings — Extraction & Architecture Identification

**App:** `com.philips.ph.babymonitorplus` "Baby Monitor+" v1.9.0 (build 41),
minSdk 23, targetSdk 35. Hardware: Philips Avent SCD921/SCD923.

> Confidence vocabulary: canonical {confirmed|likely|speculative}, co-located per
> claim section (see TESTING.md Part 1). `confirmed` is used only where ≥2
> independent sources agree; otherwise `likely`/`speculative`.
>
> Citation note: `decompiled/...` paths below are gitignored — run `just decompile`
> (and `just extract`-equivalent unzip) locally to resolve them; the committed
> `re/symbols/` dumps back the native-lib claims.

## Headline: this is a re-skinned Tuya Smart camera app (confidence: confirmed)

**Confidence: confirmed** — two independent sources agree: the native library set
in `config.arm64_v8a.apk` (`lib/arm64-v8a/libThing*.so`, dumped in `re/symbols/`
and inventoried in re/native_libs.md) AND the decompiled package tree
(`decompiled/jadx/sources/com/thingclips` — 22,377 `.java` files; see
re/decompile_dex.md:57). The `Thing*` / `thing*` prefix is **Tuya Smart's SDK**
(Tuya rebranded its platform to "Thing" / ThingClips). Philips white-labeled
Tuya's Smart Camera (IPC) platform rather than building a bespoke stack.

### Streaming / device stack (Tuya IPC) (confidence: confirmed)

**Confidence: confirmed** — the SONAME list below is from `readelf -d` on
`lib/arm64-v8a/*.so` (committed dumps under `re/symbols/`, source
`config.arm64_v8a.apk`), cross-checked against the matching JNI wrapper packages
in the decompiled tree (`decompiled/jadx/sources/com/thingclips/smart/p2p/` etc.,
re/decompile_dex.md:81). Library presence is a grep-verifiable fact; the *role*
column is the Tuya-SDK-documented purpose of each named lib (confidence: likely
where it rests on the lib name alone).
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

### Cloud config (confidence: confirmed)
**Confidence: confirmed** — the asset is present in two independent listings: the
`unzip -l` asset inventory of the base APK (`assets/thing_domains_v1`) AND the
cross-reference in re/js_bundle_map.md:185 (datacenter from
`assets/thing_domains_v1` + login response, review-gate F5).
- `assets/thing_domains_v1` present → Tuya cloud endpoint/region configuration is bundled.

## What this means for the reimplementation (confidence: likely)

**Confidence: likely** — this section is *interpretation* of the confirmed
architecture facts above; each numbered point carries its own label below. The
underlying evidence is re/native_libs.md (committed `re/symbols/`),
re/decompile_dex.md (`decompiled/jadx/sources/...`), and the public Tuya RE
references (tinytuya, tuya-iot SDKs).

1. **Auth is Tuya account auth + device binding via Tuya cloud** — NOT a Philips-proprietary or
   purely-local scheme. The earlier "local-only device" hypothesis is **refuted**. There is a
   cloud control plane (Tuya's), and P2P streaming is most likely brokered through Tuya servers
   for NAT traversal (with a possible LAN fast-path).
2. **Tuya is a known quantity.** Its pairing token flow, cloud API signing, and P2P transport are
   extensively documented by the public RE community (e.g. tinytuya, tuya-iot SDKs, Tuya-camera
   P2P efforts). This raises feasibility substantially versus a bespoke protocol.
3. **Highest-value artifact to recover next:** the embedded **Tuya AppKey / AppSecret** (Philips'
   Tuya developer app credentials). They live somewhere in the APK (native string table,
   `assets/*config*.json`, or DEX) and are needed to reimplement cloud auth. → backlog task.
   *CORRECTION/forward-pointer (TASK-0027, updated TASK-0023):* an earlier draft framed
   appKey/appSecret as **sufficient** to sign ("Tuya cloud signs every API request (HMAC) with
   these"). The later TASK-0005 spike **refutes** that — appKey/appSecret **ALONE are
   insufficient**. The mobile sign KEY also folds in the APK's app-signing-certificate SHA-256
   **and** a token decoded from the embedded `t_s.bmp` asset, and the keyed-hash routine runs in
   native (`libthing_security.so`, command 1). The fully-static dive (TASK-0023,
   `re/tuya_sign_static.md`, **verdict `partially-recoverable`**, SUPERSEDING the earlier
   `needs-runtime-hook`) then showed the cert-SHA-256 is **offline-computable** from the APK
   signing cert and the keyed hash is **plain MD5** (not HMAC-SHA256) — so a **device is NOT
   required**; only the deterministic `t_s.bmp` token decode (TASK-0029) remains un-ported. Net:
   appKey/appSecret are necessary but not sufficient (also need cert-SHA-256 + BMP token), yet all
   three are statically/offline obtainable — see `re/tuya_sign_static.md` (and `re/tuya_sign.md`).
4. The hard core remains **`libThingP2PSDK`**: Tuya's P2P session establishment + the AV framing
   over it. Static-only, this is the riskiest piece; public Tuya-P2P work is the main lever.
   *Forward-pointer (TASK-0026):* the later streaming-mode triage refines this "cloud-brokered
   P2P" framing in points 1 + 4 — see `re/streaming_mode.md`, which finds **WebRTC-over-MQTT
   (signaling code 302) is the PREFERRED per-device transport with legacy PPCS as fallback,
   chosen at runtime from the cloud-provided `p2pType`** — so the AV path is not necessarily the
   proprietary PPCS framing assumed here. (Substance/labels of points 1+4 unchanged; this is a
   navigation pointer only.)

## Confidence summary (canonical labels)

Faithful re-spelling of the earlier very-high/high/uncertain judgments into the
pinned {confirmed|likely|speculative} set (no meaning change):

- Tuya platform identification: **confidence: confirmed** — ≥2 independent
  sources: native lib names (`re/symbols/`, source `config.arm64_v8a.apk`) AND the
  decompiled `com/thingclips` tree (re/decompile_dex.md:57). (was "very high".)
- Cloud-brokered P2P streaming: **confidence: likely** — single architectural
  source (standard Tuya IPC pattern; `libThingP2PSDK.so` + MQTT signaling, see
  re/native_libs.md); to be cross-confirmed by JS + native analysis. (was "high".)
  *Forward-pointer (v0.1.0-live-stream / TASK-0083):* the "to be cross-confirmed by
  JS + native analysis" step has since been satisfied — a working self-contained live
  client cross-confirms the cloud-brokered MQTT-302 signaling + ICE media path by
  connecting to the real SCD921 and streaming. (Historical "likely (was high)" label
  preserved; sustained continuous A/V is still unverified — see next bullet.)
- Exact P2P wire format decodability from static analysis alone: **confidence:
  speculative** — not yet evidenced statically; the P2P feasibility verdict is
  deferred to the dedicated task (see re/review_gate_findings.md F3). (was
  "uncertain".)
  *Forward-pointer (v0.1.0-live-stream / TASK-0083):* this "speculative / deferred"
  verdict is now RESOLVED — the live Rust client decodes a real SCD921 1080p H.264
  keyframe end-to-end (MQTT-302 -> ICE -> KCP + AES-128-CBC + HMAC-SHA1 -> H.264,
  displayed in VLC). Keyframe path proven; sustained continuous A/V still unverified
  (TASK-0085..0089).
