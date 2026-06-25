# Tuya mobile-app request signing — algorithm + key derivation (TASK-0005 SPIKE)

Static recovery of the Tuya **mobile-app SDK** request-signing scheme for
`com.philips.ph.babymonitorplus`, and a verdict on whether the FULL sign-key
derivation (cert pin + BMP token + appSecret + native routine) can be reproduced from
static analysis alone.

**No secret values appear in this file.** The recovered appKey/appSecret/TTID and their
source lines live ONLY in `secrets/tuya_appkey.json` (gitignored). This doc records
*location + method*, never values.

> Citation note: `decompiled/jadx/sources/...:line` paths resolve only after a local
> `just decompile` (the jadx/native trees are gitignored). `lib*.so` citations refer to
> `lib/arm64-v8a/*.so` unzipped from `extracted/xapk/config.arm64_v8a.apk` into the
> gitignored `decompiled/nativelibs/`.

---

## Verdict (confidence: confirmed)

Verdict: needs-runtime-hook

(Token set for THIS spike per task: {recoverable-statically | needs-runtime-hook |
needs-live-capture}. The labelled-verdict lint gate keys on `re/p2p_protocol.md`, not
this file; the label form is used here for consistency as instructed.)

Two independent sources ground this verdict: the decompiled signer chain
`decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java:200`
(keyed step delegates to native cmd=1) AND the native key-material evidence in
`libthing_security.so` (`generateCertificate`/`X509Certificate`/`SHA256`/`t_s.bmp`
strings) — together they prove the key derivation is native + runtime-cert-dependent,
i.e. not byte-reproducible from static analysis alone.

**One-line justification:** appKey/appSecret/TTID are fully static (DEX `BuildConfig`),
and the Java string-to-sign is fully recovered, but the sign **KEY derivation runs in
native, mixes in the runtime app-signing certificate SHA-256 and a matrix-deobfuscated
token from `t_s.bmp`, and the routine is stripped** — so reproducing a correct signature
end-to-end from static analysis alone is not currently possible. A Frida hook on
`JNICLibrary.doCommandNative(..., cmd=1, ...)` (or `pbddddb.bdpdqbp(String)`) extracts
the derived key / a known sign vector in one run and unblocks the rest. See
"What a runtime hook unblocks" below.

---

## End-to-end signing flow (confidence: confirmed)

Two independent sources for the overall shape: the decompiled signer chain (cited
inline below) AND the public mobile-sign write-up `nalajcie/tuya-sign-hacking`
(review-gate F1, `re/review_gate_findings.md:10`), which documents the same
sorted-params → MD5 → swap → native-keyed-sign pipeline.

1. **Canonicalize params** — `ThingApiSignManager.generateSignatureSdk(map)`
   (`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java:99`):
   - take `map.keySet()`, `Collections.sort` (lexicographic ascending);
   - keep only keys in the fixed whitelist `bdpdqbp`
     (`ThingApiSignManager.java:66`: `a, v, lat, lon, lang, deviceId, appVersion, ttid,
     h5, h5Token, os, appId, postData, t, requestId, et, n4h5, sid, chKey, sp`) whose
     value is non-empty;
   - for the `postData` key, replace its value with `postDataMD5Hex(value)` first
     (`ThingApiSignManager.java:146`);
   - join as `key=value` segments separated by the literal **`||`** (NOT `&`):
     separators are `pbpdpdp = "="` and `pbpdbqp = "||"`
     (`decompiled/jadx/sources/com/thingclips/sdk/mqtt/pbbppqb.java:26-27`), used at
     `ThingApiSignManager.java:153-155`.
   This produces the **string-to-sign** `str2`.

2. **postData digest** — `postDataMD5Hex(str)` (`ThingApiSignManager.java:423`):
   `swapSignString( MD5Util.md5AsBase64(str) )`. So the POST body is folded into the
   string-to-sign as a swapped MD5-base64, not raw.

3. **swapSignString(s)** — byte permutation of a 32-char MD5-base64
   (`ThingApiSignManager.java:524`, exact slices at `:567-571`):
   given `s`, let `A=s[0:8]`, `B=s[8:24]`, `B1=B[0:8]`, `B2=B[8:16]`, `C=s[24:32]`;
   output = `B1 + A + C + B2`. (Deterministic, fully reproducible in Rust.)

4. **Keyed sign (native)** — the string-to-sign `str2` is passed to
   `pbddddb.bdpdqbp().bdpdqbp(str2)` (`ThingApiSignManager.java:158`), whose body
   (`decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java:200`) calls:
   `ThingNetworkSecurity.doCommandNative(context, 1, str2.getBytes(), null, ThingSmartNetWork.mD)`.
   **Command code `1` = "produce request signature".** The returned String is the `sign`
   query parameter. This is the step whose KEY is not static (see next sections).

   (Note: `getRequestKeyBySorted` at `:235` is a *sibling* helper that does a plain
   `MD5Util.md5AsBase64` of the sorted string with NO native key — it is used for
   cache/request keys, not the wire `sign`. The wire signature is the cmd=1 native path.)

## The signing KEY is derived in native and depends on runtime inputs (confidence: confirmed)

Two independent sources: the Java init wiring AND the native string/symbol evidence.

- **Java side / init (cmd 0):** the native module is initialized by
  `ThingNetworkSecurity.initJNI(...)`
  (`decompiled/jadx/sources/com/thingclips/sdk/network/ThingNetworkSecurity.java:360`):
  `JNICLibrary.doCommandNative(context, 0, ThingSmartNetWork.mAppSecret.getBytes(),
  ThingSmartNetWork.mAppId.getBytes(), mD)` — i.e. **appSecret + appId are pushed into
  native at init**, and the per-request sign is later produced by cmd 1
  (`pbddddb.java:200`). The native libs loaded are `thing_security_algorithm` then
  `thing_security` (`JNICLibrary.java:724-725`).
- **Native side / key material:** `strings`/symbols of
  `lib/arm64-v8a/libthing_security.so` (`libthing_security.so`) show the exact F1 key
  ingredients clustered together: `t_s.bmp` + `t_s_daily.bmp` (the embedded BMP token),
  `security_infra::SignFileDecoder` (the BMP-decode class), `generateCertificate` /
  `java/security/cert/X509Certificate` / `[Landroid/content/pm/Signature;` /
  `signatures` (reads the **app's own signing certificate** at runtime), and `SHA256`
  (hashes that cert). This is exactly review-gate **F1**'s
  `key = [app_cert_SHA256]_[bmp_token]_[appSecret]` (`re/review_gate_findings.md:16`).
- Therefore the sign KEY is a function of: (a) `appSecret` — **static**; (b) the
  `t_s.bmp` token — embedded but **obfuscated**; and (c) the **SHA-256 of the running
  APK's signing certificate** — a *runtime* input not present as a value in the files.

## The t_s.bmp token decode = imath bignum / matrix deobfuscation (confidence: confirmed)

Two independent sources: the asset itself AND the math library in the algorithm lib.

- `assets/t_s.bmp` is a real `PC bitmap, Windows 3.x, 100 x 75 x 24` (22554 bytes)
  (`decompiled/apktool/assets/t_s.bmp`); the obfuscated token lives in its pixel data —
  the same embedded-BMP mechanism the nalajcie write-up reverses.
- `lib/arm64-v8a/libthing_security_algorithm.so` (`libthing_security_algorithm.so`)
  exports the **imath** multiple-precision library (`mp_int_*`, `mp_rat_*`:
  `mp_int_mul`, `mp_int_div`, `mp_int_read_unsigned`, `mp_int_sqr`, …) and carries the
  string `inited matrix:`. That is precisely the polynomial / linear-algebra (bignum +
  matrix) deobfuscation the F1 reference (`re/review_gate_findings.md:18`,
  `nalajcie/tuya-sign-hacking`) describes for turning the BMP pixels into the token.
- The BMP-decode entry on the native side is `security_infra::SignFileDecoder`
  (symbol `..._ZN...security_infra15SignFileDecoder...` in `libthing_security.so`),
  invoked behind `testSign`/`doCommandNative`.

## appKey / appSecret / TTID — statically recoverable (confidence: confirmed)

Two independent sources: the literal constants AND the wiring that consumes them.

- **Literals:** `decompiled/jadx/sources/com/thingclips/sample/BuildConfig.java:14`
  (`THING_SMART_APPKEY`, 20-char Tuya appKey format), `:16` (`THING_SMART_SECRET`,
  32-char appSecret format), `:18` (`THING_SMART_TTID`). Values copied ONLY to
  `secrets/tuya_appkey.json`.
- **Wiring:** `com/smart/app/SmartApplication.java:117-118` reads
  `BuildConfig.THING_SMART_APPKEY/SECRET` → `ThingSmartSdk.setAppkey/ setAppSecret`
  (`com/thingclips/smart/android/base/ThingSmartSdk.java:779,726`) →
  `ThingSmartNetWork.initialize` sets `mAppId`/`mAppSecret`
  (`com/thingclips/smart/android/network/ThingSmartNetWork.java:3872-3873`).
  A fallback path also reads them from `ApplicationInfo.metaData`
  (`ThingSmartSdk.java:49,69`) if the BuildConfig route is empty.
- So appKey/appSecret are NOT white-box-protected at rest — only the *sign key
  derivation that combines appSecret with the cert hash and BMP token* is native.

## Hash primitive of the keyed sign (confidence: likely)

- The Java half uses MD5 (`MD5Util.md5AsBase64`, `swapSignString`); the native cmd=1
  keyed step is the unknown. F1 (`re/review_gate_findings.md:16`) characterizes the
  mobile sign as `HMAC-SHA256(data, key)`, and `libthing_security.so` exposes `SHA256`
  and the full AES table (`AES-128-GCM/CBC/CTR/...`), consistent with HMAC-SHA256 over
  the derived key. Labelled `likely` (not `confirmed`) because the exact native opcode
  sequence for cmd=1 was not disassembled to byte level — the routine is stripped
  (static `nm` yields no `Sign`/`doCommand` symbol; only `JNI_OnLoad` is exported,
  so natives are registered via `RegisterNatives` and the body is offset-only).

## What is and isn't statically reproducible (confidence: confirmed — scoping summary)

| Ingredient | Static? | Evidence |
|---|---|---|
| String-to-sign construction (sort/whitelist/`||`/postData-MD5/swap) | **YES** | `ThingApiSignManager.java:99,146,153,423,524` |
| appKey / appSecret / TTID | **YES** | `BuildConfig.java:14,16,18` + wiring `SmartApplication.java:117` |
| `t_s.bmp` present | **YES** | `decompiled/apktool/assets/t_s.bmp` |
| BMP token *decoded value* | **NO (not done statically)** | needs running `SignFileDecoder` + imath matrix (`libthing_security_algorithm.so`) |
| App-cert SHA-256 (key half) | **NO (runtime input)** | `generateCertificate`/`X509Certificate`/`SHA256` strings in `libthing_security.so` |
| Final keyed-sign opcode (HMAC?) | **NO (stripped/offset-only)** | only `JNI_OnLoad` exported in `libthing_security.so` |

Because two of the three key ingredients (cert SHA-256, decoded BMP token) plus the
keyed-hash routine are NOT reproduced from static analysis, a byte-exact signature
cannot be produced statically today → `needs-runtime-hook`.

## What a runtime hook (Frida) unblocks (confidence: likely)

A single Frida session on the user's own device/account unblocks the rest cheaply:
- Hook `com.thingclips.smart.security.jni.JNICLibrary.doCommandNative` (or the Java
  wrapper `pbddddb.bdpdqbp(String)` / `SecureNativeApi.testSign`) and log
  `(inputBytes, returnedSign)` pairs → yields a **known-answer differential test vector**
  (string-to-sign → signature) for the Rust signer (TESTING.md Part-2 signal #2). This
  alone lets the Rust client either (a) call the gateway with vectors validated against
  the hook, or (b) reproduce the algorithm if HMAC-SHA256 is confirmed.
- To go *fully* static instead would require disassembling the cmd=1/`SignFileDecoder`
  routines in `libthing_security.so`/`_algorithm.so` to recover the cert-hash + BMP-token
  + appSecret combination order and the exact hash — feasible but heavy Ghidra work;
  the hook is the pragmatic unblock. The app-cert SHA-256 can also be computed offline
  from the APK's signing cert, removing that unknown if the combination order is learned.

## Contingency / what unblocks the spike's remainder (confidence: confirmed — decision record)

- **Primary unblock (filed as follow-up):** Frida hook to capture the
  string-to-sign→signature vector and/or the derived key, on the user's authorized device.
  This produces the differential vector TASK-0012 needs and validates TASK-0007's
  cloud-auth map. Cited: this doc's flow sections + `re/review_gate_findings.md:78` (the
  spike's planned live-capture contingency).
- **Secondary (heavier):** Ghidra disassembly of `libthing_security.so` cmd-dispatch and
  `SignFileDecoder` to make it fully static. Filed as a separate, lower-priority task.
