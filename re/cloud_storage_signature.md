# Cloud-storage subscription & access-signature protocol (TASK-0102)

Static RE of the Tuya cloud-storage service layer used by the Philips Avent Baby
Monitor+ (SCD921, Tuya reskin): how the app authorizes access to a cloud video
clip. Covers the subscription DP operator (`DpCloudStorage`), the request/config
plumbing (`getCloudRequestInfo`, `configCloudDataV2`), and — the core of this task
— the **presigned-URL signature generator** (`TUNICloudStorageSignatureManager` →
native `libThingCloudStorageSignatureTools.so`).

> **Method.** Static analysis only. Java/Kotlin from jadx
> (`decompiled/jadx/sources/...`), the RN/JS bridge from
> `decompiled/js/assets/...`, and the native lib via `strings` + `readelf` on
> `decompiled/nativelibs/libThingCloudStorageSignatureTools.so` (ARM aarch64,
> stripped, BoringSSL statically linked). The native lib was **not** decompiled to
> byte level (Ghidra) for this pass — the algorithm is reconstructed from the
> embedded `printf`-style format templates and the named (un-stripped) exported
> symbols, both of which are unambiguous. Where byte-exact layout matters this is
> called out as a residual unknown.

> **No secret values appear in this file.** This doc records *parameter roles,
> call surface, and algorithm shape* only. The actual access-key / secret-key /
> STS-token / bucket are short-lived STS credentials minted per request by Tuya
> cloud; if/when captured they belong only under `secrets/` (gitignored), never
> here. `secret-scan:allow` markers are not used — the doc carries no value-shaped
> strings.

> **Citation note.** `file:line` cites the jadx tree at
> `decompiled/jadx/sources/`. Native cites use `lib.so@0xADDR`; addresses are
> symbol offsets read from `readelf -sW` on **this** build of
> `libThingCloudStorageSignatureTools.so` (no GNU build-id note present — the lib
> is stripped of notes; verify with `readelf -sW` + a disassembler). `%...`
> literals are the exact C format strings recovered with `strings`.

---

## 1. Verdict (confidence: high)

The cloud-clip access signature is a **standard object-store presigned-URL
generator** implemented entirely in native code. It supports **two** signing
schemes selected at runtime by the `provider` argument:

1. **AWS S3 Signature Version 4** (`AWS4-HMAC-SHA256`) — the SigV4 query-string
   ("presigned URL") variant with `X-Amz-*` query params and `UNSIGNED-PAYLOAD`.
2. **Aliyun OSS** legacy presigned URL — `OSSAccessKeyId` + `Expires` +
   `Signature` (HMAC-SHA1, base64), with an STS `security-token`.

Both consume **short-lived STS credentials** (access key / secret key / session
token) plus bucket/region/endpoint that the app obtains from Tuya cloud *before*
calling the signer. The signer is purely local string-building + a keyed hash; it
holds no long-lived secret. This is **not** the Tuya mobile-app request signer
(`t_s.bmp` / `libthing_security*`, see `re/tuya_sign_static.md`) — it is a
separate, self-contained S3/OSS signer.

This means a Rust reimplementation of the *signing step* is straightforward
(well-documented public algorithms); the unknown is the upstream Tuya API that
mints the STS creds (see §6).

---

## 2. Signature entrypoint and the native lib (AC #1 — confidence: high)

Java/Kotlin entrypoint (the RN "uni-plugin" the JS panel calls):

- `TUNICloudStorageSignatureManager.generateSignedUrl(params, success, fail)` —
  `decompiled/jadx/sources/com/thingclips/smart/plugin/tunicloudstoragesignaturemanager/TUNICloudStorageSignatureManager.java:154`.
  After validating all 9 fields it calls the native bridge at **line 158**:
  `ThingCloudStorageSignatureTools.generateSignedUrl(params.path, params.expiration, params.region, params.token, params.sk, params.provider, params.endpoint, params.ak, params.bucket)`,
  prepends `https://` if the result lacks an `http` scheme (lines 160-162), and
  returns `{ signedUrl }` (`CloudStorageSignatureResponse`, line 164-167).

Native bridge declaration + lib load:

- `com/thingclips/smart/cloudstorage/ThingCloudStorageSignatureTools.java:10` —
  `System.loadLibrary("ThingCloudStorageSignatureTools")` → loads
  `decompiled/nativelibs/libThingCloudStorageSignatureTools.so`.
- `ThingCloudStorageSignatureTools.java:62` —
  `public static native String generateSignedUrl(String, String, String, String, String, String, String, String, String)`
  (9 string args; same order as the call site above).

Native lib (the JNI export and the internal sign chain):

- JNI export `Java_com_thingclips_smart_cloudstorage_ThingCloudStorageSignatureTools_generateSignedUrl`
  @ `libThingCloudStorageSignatureTools.so@0x927dc`.
- Internal driver `ThingCloudSignatureGenerateSignedUrl` @ `…@0x9179c`.
- Core signature builder
  `ThingCloudSignatureCalculateSignatureDataV2(tagCLOUD_CONFIG_S*, const char*, const char*, char*, int)`
  @ `…@0x90b88` (demangled from
  `_Z43ThingCloudSignatureCalculateSignatureDataV2P17tagCLOUD_CONFIG_SPKcS2_Pci`)
  — note the inputs are packed into a `tagCLOUD_CONFIG_S` struct.
- Keyed-hash primitive `ThingCloudHmacEncode(const char*, unsigned char*, unsigned int, unsigned char*, unsigned int, unsigned char*, unsigned int)`
  @ `…@0x9259c` (from `_Z20ThingCloudHmacEncodePKcPhjS1_jS1_j`) — first arg is the
  digest name, so SHA-1 vs SHA-256 is selectable; backed by BoringSSL `HMAC`
  @ `…@0x93694`.
- Time helper `ThingCloudSignatureGetGMTLocalTimeString(char*)` @ `…@0x90a78`.
- Encoding helpers (exported, demangled): `ThingCloudSignatureBase16Encode/Decode`
  (hex), `ThingCloudSignatureBase64encode/decode`, `ThingCloudSignatureUrlEncode/Decode`.

The RN/JS bridge stub and the param-name contract corroborate the Java surface:

- `decompiled/js/assets/kit_js/miniapp_IPCKit.js.pretty:641` —
  `generateSignedUrl: function(e){ return t("TUNICloudStorageSignatureManager","generateSignedUrl",e,{…}) }`.
- `decompiled/js/assets/thing_uni_plugins/TUNICloudStorageSignatureManager.json` —
  `{"generateSignedUrl":{"object":{"path","expiration","region","token","sk","provider","endpoint","ak","bucket"},"success":{"signedUrl"}}}`.

---

## 3. Signature inputs (AC #2, part 1 — confidence: high)

Nine string fields, from `CloudStorageSignatureParams`
(`…/tunicloudstoragesignaturemanager/bean/CloudStorageSignatureParams.java`, all
`@NonNull`) and the TUNI plugin manifest. Roles inferred from the SigV4/OSS
templates in §4 (confidence high for ak/sk/token/bucket/region/endpoint/provider/
expiration; path is the object key):

| field        | role                                                                 |
|--------------|----------------------------------------------------------------------|
| `provider`   | scheme selector — chooses AWS-S3-SigV4 vs Aliyun-OSS code path        |
| `ak`         | STS **access key id** (short-lived; → `Credential` / `OSSAccessKeyId`)|
| `sk`         | STS **secret key** (HMAC key material; never sent on the wire)        |
| `token`      | STS **session/security token** (→ `X-Amz-Security-Token` / `security-token`) |
| `bucket`     | object-store bucket name                                             |
| `region`     | region for the SigV4 credential scope                                |
| `endpoint`   | host (e.g. the S3/OSS endpoint) the URL is built against            |
| `path`       | object key / clip path inside the bucket                            |
| `expiration` | URL validity window (seconds → `X-Amz-Expires` / absolute `Expires`)|

The native lib logs each of these at debug
(`generateSignedUrl ak:%s`, `… sk:%s`, `… token:%s`, … — recovered via `strings`),
which is itself a leak surface on a rooted/log-capturing device; the *values* are
STS creds and must never be committed.

**`ak`/`sk`/`token` are minted by Tuya cloud, not embedded.** The signer is given
them as arguments; it stores no key. Confidence high (no key-shaped constant
strings in the lib; the only crypto constants are BoringSSL's).

---

## 4. Signature algorithm (AC #2, part 2 — confidence: high on scheme, medium on byte-exact layout)

Recovered verbatim format templates (`strings -n 4` on the lib):

**AWS S3 SigV4 (provider = AWS / S3):**

```
AWS4-HMAC-SHA256
%s/%s/s3/aws4_request                         (credential scope, fixed service "s3")
%s/%s/%s/%s/aws4_request                       (generic scope: date/region/service/aws4_request)
X-Amz-Algorithm=%s&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-Expires=%d&X-Amz-Security-Token=%s&X-Amz-SignedHeaders=host
%s&X-Amz-Signature=%s                          (final query suffix; signature is hex)
UNSIGNED-PAYLOAD                               (payload hash placeholder)
%04d%02d%02dT%02d%02d%02dZ                     (X-Amz-Date, ISO8601 basic "YYYYMMDDTHHMMSSZ")
%04d%02d%02d                                   (datestamp "YYYYMMDD" for the scope)
AWS4                                           (signing-key prefix)
```

This is textbook SigV4 query-string signing:
`SignedHeaders=host`, `payload=UNSIGNED-PAYLOAD`, signing key =
`HMAC( HMAC( HMAC( HMAC("AWS4"+sk, datestamp), region), "s3"), "aws4_request")`,
final `X-Amz-Signature = hex( HMAC(signingKey, stringToSign) )` with SHA-256
(`sha-256`/`SHA256` digest-name strings present; HMAC primitive from BoringSSL).
The hex output explains the `ThingCloudSignatureBase16Encode` helper.

**Aliyun OSS (provider = OSS):**

```
%s.%s%s?Expires=%s&OSSAccessKeyId=%s&Signature=%s&security-token=%s
%s%s?security-token=%s
%s.%s%s?%s
```

This is the classic OSS presigned URL: `Signature = base64( HMAC-SHA1(sk,
StringToSign) )`, `OSSAccessKeyId = ak`, absolute `Expires` epoch, STS
`security-token = token`. The `bucket.endpoint/path` virtual-host form
(`%s.%s%s`) matches `bucket.oss-region.aliyuncs.com/key`. The base64 helper
(`ThingCloudSignatureBase64encode`) is the OSS-path signature encoder. Confidence
high (template is unmistakable); OSS StringToSign byte layout (which headers /
canonicalized resource it includes) is the medium-confidence part — see §6.

**Confidence split:** *which* two algorithms are implemented = high (named
constants + exact templates). The *byte-exact canonical request / string-to-sign*
(header ordering, URI-encoding of `path`, trailing-slash handling) = medium —
inferred from the public SigV4/OSS specs + the templates, not from a decompiled
`ThingCloudSignatureCalculateSignatureDataV2`. A Rust port should be validated
against a real signed URL (or a Ghidra decompile) before trusting edge cases.

---

## 5. Surrounding service layer (confidence: high on call shape, medium on semantics)

These feed/anchor the signer but are not themselves the signature:

- **`getCloudRequestInfo(Callback)`** —
  `decompiled/jadx/sources/com/thingclips/smart/ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java:8404`.
  Returns `{ userId: <uid>, uuid: <device uuid> }` to JS (lines 8408-8413). It is
  the **identity context** the JS cloud-storage panel uses to call the Tuya cloud
  API that lists clips and mints STS creds. It does **not** return ak/sk/token
  itself. (The thin RN-bridge wrapper is `…/rnplugin/trctcameramanager/TRCTCameraManager.java:1236`.)
  *Both `userId` (uid) and `uuid` are PII/device-id — never commit their values.*

- **`configCloudDataV2(String, Callback, Callback)`** —
  `…/cameramanager/TRCTCameraManager.java:6727` → `cloudCamera.configCloudDataTags(str, cb)`
  (`IThingCloudCamera`). This pushes the **cloud-clip decryption tags/config**
  (the per-clip AES key material + cipher tags the player needs to decrypt a
  downloaded clip) into the native cloud-camera SDK — a *separate* concern from
  URL signing (the signed URL authorizes the *download*; `configCloudDataTags`
  configures the *decrypt*). Bridge wrapper at
  `…/rnplugin/trctcameramanager/TRCTCameraManager.java:499`; legacy
  `configCloudData(String)` at line 491. Semantics (exact tag schema) =
  medium; the JSON `str` payload was not captured statically.

- **`DpCloudStorage`** —
  `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpCloudStorage.java`.
  A `BaseDpOperator` whose `b()` returns `this.a.getCurDpValue()` (line 14-16) and
  whose `g()` returns `CameraNotifyModel.ACTION.CLOUD_STORAGE` (the notify action,
  recovered at lines 115/~171). This is the **subscription enable/state DP** — the
  device-control wrapper that reads/writes the camera's cloud-storage subscription
  status and emits `CLOUD_STORAGE` change events. The numeric/string **DP id** is
  **not** resolvable from this obfuscated class (its `f()` getter is buried under
  `Tz` control-flow noise and only the operator tag string `"DpCloudStorage"` is
  literal at line 110) — see §6.

---

## 6. Residual unknowns / what would close the gaps

- **Which Tuya cloud API mints the STS creds (ak/sk/token) + bucket/region/
  endpoint/provider.** Not present in the IPCKit JS bundle scanned
  (`miniapp_IPCKit.js.pretty` only has the bridge stub). It lives in the React
  cloud-storage panel bundle (not in this APK's primary asset) or is a server
  round-trip. **Closes with:** a live capture of the cloud-storage panel opening
  (an mitmproxy flow showing the request→`{ak,sk,token,bucket,region,endpoint}`
  response), or locating the panel JS. Confidence that such an API exists: high
  (the 9 fields must come from somewhere); its exact name/shape: unknown.

- **Byte-exact SigV4/OSS canonical string.** §4 gives the scheme from the
  templates; the precise canonical-request assembly (URI-encoding of `path`,
  header set, `\n` joins) is inferred from the public specs. **Closes with:** a
  Ghidra decompile of `ThingCloudSignatureCalculateSignatureDataV2` @ `0x90b88`,
  or diffing the lib's output against a reference SigV4 implementation on one
  sample `(ak,sk,token,path,…)` tuple.

- **`tagCLOUD_CONFIG_S` struct layout.** The signer marshals its 9 args into this
  struct before `CalculateSignatureDataV2`. Layout unknown without decompilation;
  needed only for a native-FFI reimplementation, not for a pure-Rust reimplement.

- **`DpCloudStorage` numeric DP id and value enum** (subscription on/off / state
  codes). Obfuscated out of the class. **Closes with:** the device DP schema
  (cloud `…/devices/{devId}/specifications` or the camera DPS map), or a live DP
  report. The notify action `CLOUD_STORAGE` is confirmed; the wire DP id is not.

- **`configCloudDataTags` payload schema** (the clip-decryption tag JSON). Not
  captured statically. **Closes with:** one live `configCloudDataV2` call payload.

- **Other providers.** Only AWS-S3 and Aliyun-OSS templates were found; Tencent
  COS / Huawei OBS are **not** evidenced in this lib (absence-of-evidence, not
  proof they're unsupported). Confidence medium that AWS+OSS are the only two.

---

## 7. Reimplementation note (Rust)

The signing step is reimplementable from public algorithms once the STS creds are
obtained: SigV4 query presign (HMAC-SHA256 key-derivation chain + hex signature,
`X-Amz-*` query) or OSS presign (HMAC-SHA1 + base64). The hard dependency is the
upstream STS-mint API (§6, first bullet), which is the real blocker — not the
signer. No part of this requires the Tuya mobile-app `t_s.bmp` signer.
