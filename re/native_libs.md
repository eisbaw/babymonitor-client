# Native Library Inventory (TASK-0004)

Source: `extracted/xapk/config.arm64_v8a.apk` (the arm64-v8a split — the base APK
holds NO native libs). Extracted `lib/arm64-v8a/*.so` (58 libs) into the
gitignored `decompiled/nativelibs/`. Tools: `readelf -d` (SONAME/NEEDED),
`nm -D --defined-only` (exports), `strings` (version/role evidence), all run via
the nix shell. Exported-symbol + dynamic-section dumps for the P2P / camera /
codec / audio / smartlink libs are committed under `re/symbols/`.

Citation convention: `lib*.so` (+ a representative string) identifies the
evidence; offsets are not used here because identity comes from symbol names and
embedded strings, not code addresses.

> Note: any `decompiled/...` or `decompiled/jadx/.../*.java:line` citation in this
> doc resolves only after a local `just decompile` — those trees are gitignored
> and not committed. The `re/symbols/` dumps referenced here, by contrast, ARE
> committed.

## Headline (confidence: confirmed)
This is **Tuya's "ipc-tymedia-sdk"** IPC camera media stack. Two independent
proofs: (1) the `Java_com_thingclips_smart_*` JNI symbol prefixes across every
`Thing*` lib (`re/symbols/libThingP2PSDK.dynsym.txt`), and (2) a leaked build
path `/Users/xucs/Desktop/sdk-develop/ipc-tymedia-sdk/third_party/webrtc/...` in
`libThingAudioEngineSDK.so`. The streaming transport is **WebRTC signaled over
Tuya MQTT**, with a legacy **PPCS (TUTK/IOTC-lineage) P2P** path also present —
both inside `libThingP2PSDK.so`. Cross-checked against Tuya's public
`github.com/tuya/tuya-rtc-camera-sdk-android` (WebRTC + MQTT signaling, <300ms),
which matches the recovered strings.

## Full lib table (confidence: confirmed for size/SONAME; role per cited string)

| Library | Size (B) | SONAME | Role / evidence |
|---|---|---|---|
| libThingP2PSDK.so | 1,445,536 | libThingP2PSDK.so | **AV transport.** WebRTC-over-MQTT + legacy PPCS. JNI `com.thingclips.smart.p2p.p2psdk.ThingP2PSDK` (`re/symbols/libThingP2PSDK.dynsym.txt`) |
| libThingP2PFileTransSDK.so | 192,448 | libThingP2PFileTransSDK.so | P2P file transfer (album/cloud-clip). JNI `com.thingclips.smart.p2pfiletrans.jni.ThingP2pFileTransSDKJni` |
| libThingCameraSDK.so | 4,828,656 | libThingCameraSDK.so | IPC camera control + RTP de/framing (H264/HEVC). `ERROR_PPCS_*`, `invalid RTP packet`, `curl` linked |
| libThingVideoCodecSDK.so | 1,280,720 | libThingVideoCodecSDK.so | Video codec = **OpenH264** (Cisco) encoder/decoder + Android MediaCodec bridge. `CWelsDecoder::init_decoder(), openh264 codec version = %s` |
| libThingAudioEngineSDK.so | 1,710,344 | libThingAudioEngineSDK.so | Audio engine = **WebRTC audio_processing** (AEC/AECM, AGC, NS, VAD). Build path leak (see headline) |
| libThingMP3CodecSDK.so | 366,576 | libThingMP3CodecSDK.so | MP3 encode = **LAME**. `LAME %s version %s` (lullaby/recording) |
| libThingAudioFileRecorderSDK.so | 51,104 | libThingAudioFileRecorderSDK.so | Audio file recording |
| libThingAvLogSDK.so | 67,608 | libThingAvLogSDK.so | AV logging; `NEEDED` of libThingP2PSDK |
| libThingSmartLink.so | 223,608 | libThingSmartLink.so | Wi-Fi provisioning (EZ/AP SmartLink). JNI `com.thingclips.smart.android.device.ThingSmartLink.smartLink` |
| libThingCloudStorageSignatureTools.so | 2,121,064 | libThingCloudStorageSignatureTools.so | Cloud-storage request signing; bundles its own OpenSSL/curl (`RSA_get_version`, `SCT_get_version`) |
| libIPCStitch.so | 1,313,144 | libIPCStitch.so | IPC multi-lens frame stitching |
| libthing_security.so | 202,616 | libthing_security.so | Tuya crypto core; full algorithm table (AES-128/192/256 in CBC/GCM/CTR/CCM/ECB/XTS, see below) |
| libthing_security_algorithm.so | 76,816 | libthing_security_algorithm.so | Tuya crypto algorithm helpers (likely the sign/whitebox routines) |
| libthingnetsec.so | 264,384 | libthingnetsec.so | Tuya secure-transport / network security |
| libthingsmart.so | 215,120 | libthingsmart.so | Tuya core SDK glue |
| libthing-outpoint.so | 292,664 | libthing-outpoint.so | Tuya "outpoint" (cloud entry/endpoint resolver) |
| libthingmmkv.so | 523,792 | libthingmmkv.so | MMKV key-value store (Tuya fork) |
| libthing_j2v8.so | 1,137,544 | libthing_j2v8.so | J2V8 (Java↔V8) bridge for mini-app JS |
| libsqlcipher.so | 5,186,904 | libsqlcipher.so | SQLCipher — encrypted local DB |
| libcrypto.1.1.so | 2,170,400 | libcrypto.1.1.so | **OpenSSL 1.1.1w (11 Sep 2023)** |
| libssl.1.1.so | 511,504 | libssl.1.1.so | **OpenSSL 1.1.1w** TLS |
| libBleLib.so | 16,320 | libBleLib.so | BLE pairing helper |
| libbarhopper_v3.so | 4,946,720 | libbarhopper_v3.so | Google MLKit barcode/QR (device QR pairing) |
| libopus.so / libopusJni.so | 406,512 / 347,200 | (self) | Opus two-way-talk codec |
| libsbcutilJni.so | 28,896 | libsbcutilJni.so | SBC codec |
| libreactnativejni.so | 1,641,592 | libreactnativejni.so | React Native core (JNI) |
| libv8android.so | 14,663,120 | libv8android.so | V8 JS engine (RN runs on V8, not Hermes) |
| libv8executor.so / libv8wrapper.so | 1,100,528 / 6,608 | (self) | RN V8 executor bridge |
| libjsinspector.so | 359,984 | libjsinspector.so | RN JS debugger inspector |
| libfolly_json.so / libfb.so / libyoga.so / libglog*.so | — | (self) | RN/Folly/Yoga/glog support |
| libnetwork-android.so | 1,858,336 | libnetwork-android.so | Tuya network stack |
| libyuv.so | 445,016 | libyuv.so | YUV pixel conversion (video render) |
| libgifimage / libstatic-webp / libnative-imagetranscoder / libimagepipeline / libnative-filters | — | (self) | Fresco image pipeline |
| libkoom-*, libxcrash*, libbytehook, libshadowhook*, libxhook_lib, libxdl, libnativethreadstackwalker, libkwai-android-base, libdiagnosis | — | (self) | Kuaishou KOOM APM / crash / native-hook |
| libimage_processing_util_jni / libsurface_util_jni | — | (self) | CameraX helpers (local device camera) |
| libc++_shared.so | 1,253,544 | libc++_shared.so | C++ runtime |

(`libxcrash_dumper.so` has no SONAME — a dlopen-only helper.)

## Pinned versions (confidence: likely — runtime-formatted, see limitation)

| Component | Version evidence | Notes |
|---|---|---|
| OpenSSL | **1.1.1w, 11 Sep 2023** | `strings libcrypto.1.1.so` → `OpenSSL 1.1.1w  11 Sep 2023` — `confirmed` (literal banner) |
| ThingP2PSDK (IMM-P2P/RTC) | `3.10.0` literal in `libThingP2PSDK.so` | the RTC/IMM-P2P version token; SDK exposes `ThingGetApiVersion()` / `imm_p2p_rtc_get_version` |
| ThingCameraSDK | `1.2.0.4` / `1.2.7` literals; runtime `sdk_version:%s` | exact wire version is `%s`-substituted at runtime |
| VideoCodec | OpenH264 (Cisco) — version is `%s`-substituted (`openh264 codec version = %s`) | `1.5.0` token present nearby |
| AudioEngine | Tuya `ipc-tymedia-sdk` third_party/webrtc (Google WebRTC fork) | no single semver literal |
| MP3 | LAME (version is `%s`-substituted) | |
| toolchain | Android clang 9.0.9 (LLVM 9.0.9svn) | build toolchain, not an SDK version |

## Crypto inventory (confidence: confirmed)
- **OpenSSL 1.1.1w** — `libcrypto.1.1.so` / `libssl.1.1.so` (app TLS, cloud HTTPS).
  `libThingCloudStorageSignatureTools.so` statically bundles its own OpenSSL+curl
  for cloud-storage signing (RSA/SCT/EC symbols present).
- **mbedTLS (bundled, static)** inside `libThingP2PSDK.so` — used for the
  **DTLS-SRTP** WebRTC media path (`mbedtls_ssl_conf_dtls_srtp_protection_profiles`,
  `mbedtls_ctr_drbg_seed`; build path `/Users/Pan/GitHub/mbedtls/library/ssl_tls.c`).
  The P2P SDK's `NEEDED` list does NOT include libssl/libcrypto → its TLS is
  self-contained mbedTLS, separate from the app's OpenSSL.
- **Tuya crypto** — `libthing_security.so` carries the full symmetric table:
  AES-128/192/256 in CBC/GCM/CTR/CCM/CCM*-NO-TAG/CFB128/ECB/OFB/XTS/KW/KWP, plus
  SHA/HMAC/RSA. `libthing_security_algorithm.so` + `libthingnetsec.so` are the
  likely home of the **mobile-app request sign / whitebox key derivation** (the
  `t_s.bmp` token + cert-pin scheme from review-gate F1) — to be confirmed in
  task 5, flagged not chased here.
- **SQLCipher** (`libsqlcipher.so`) — AES-encrypted local DB (device list, keys).

## Cross-check vs public Tuya SDK (AC #3) (confidence: confirmed)
The recovered transport strings in `libThingP2PSDK.so` — `connect_v2` command
(`{"cmd":"connect_v2","args":{"remote_id":..,"dev_id":..,"skill":..,"token":..,"lan_mode":..}}`),
SDP/ICE (`a=ice-ufrag`, `a=ice-options:trickle`, `a=rtcp-mux`), STUN/TURN session
creation, DTLS-SRTP, and **MQTT signaling** (`create signaling mqtt worker
thread`, `SendMessageThroughMqtt`) — match Tuya's public
`github.com/tuya/tuya-rtc-camera-sdk-android` (WebRTC audio/video signaled over
MQTT). The legacy `ERROR_PPCS_*` family in `libThingCameraSDK.so` matches the
TUTK/IOTC PPCS P2P lineage (see `wyzecam` `tutk` public reimplementation). No
version *mismatch* recorded; the SDK identity is unambiguous, but Tuya does not
publish per-build semver for the prebuilt `.so`, so the `3.10.0`/`1.2.x` tokens
are the internal build versions, not a Maven-pinnable release tag.

## Streaming-transport implication (forward to task 10) (confidence: likely)
The decisive evidence — WebRTC SDP/ICE/DTLS-SRTP + MQTT signaling **inside**
`libThingP2PSDK.so`, plus Tuya's public WebRTC camera SDK — strongly supports the
review-gate **F2** hypothesis: the SCD921 stream is **WebRTC, signaled over Tuya
MQTT**, NOT (primarily) the proprietary PPCS AV framing. A Rust client over
`webrtc-rs` + an MQTT signaling client is therefore the likely cheaper path than
reconstructing PPCS AV framing. PPCS remains as a fallback/legacy path. The
task-10 triage should confirm which the SCD921 firmware negotiates (the `skill`
field in `connect_v2` likely encodes capability).

## Limitations (confidence: confirmed — these are scoping caveats, not claims)
These caveats are grounded in two independent committed artifacts: the dynamic
section dump `re/symbols/libThingP2PSDK.dynamic.txt:1` AND the exported-symbol dump
`re/symbols/libThingP2PSDK.dynsym.txt:1` (plus the sibling per-lib dumps), both
derived from `lib/arm64-v8a/libThingP2PSDK.so` in `config.arm64_v8a.apk`.
- Most SDK version literals are `printf("%s")`-substituted from a data string the
  loader fills at runtime; the `3.10.0`/`1.2.0.4`/`1.2.7` tokens are the best
  static read but are labelled `likely`, not `confirmed`.
- Role assignments from strings/symbols are high-confidence for the `Thing*` libs
  (named JNI symbols) but the exact sign/key-derivation routine inside
  `libthing_security_algorithm.so` is NOT yet located — that is task 5's job and
  is only pointed at here.
- No code-offset analysis (Ghidra/radare2 disassembly) was done; this task is the
  inventory + identity layer. Wire-format recovery is downstream.
