# chKey — the per-app channel-auth token (native getChKey@0x16000) (TASK-0044)

Static recovery of `chKey`, the per-app channel-auth token the Tuya atop login
envelope carries as the wire param `chKey` and that is a SIGNED whitelist param.
This doc records the algorithm + the static-vs-runtime
verdict; **no secret value appears here** (the computed chKey lives ONLY in
`secrets/chkey.txt`, gitignored).

> Citation note (symbol-anchored): native cites give a `lib.so@0xADDR` **file
> offset** (zero-based, as catalogued in `re/tuya_sign_static.md`); Ghidra loads
> `libthing_security.so` at image base `0x100000`, so a file offset `0xNNNNN`
> appears in Ghidra as `0x1NNNNN`. Both forms are given. `lib*.so` =
> `lib/arm64-v8a/*.so` unzipped into gitignored `decompiled/nativelibs/`. A
> cross-`.md` reference is a navigation pointer, NOT an independent source.

---

## Verdict (confidence: confirmed)

**chKey is STATIC-DERIVABLE — no runtime/device/cloud input.**

```text
chKey = lowercase_hex( HMAC-SHA256( key = appId_bytes,
                                    msg = packageName + "_" + certColonUpper ) )[8..16]
```

> Corrected 2026-06-28 (v0.1.0-live-stream): the output slice is `[8..16]` (8 chars),
> NOT the earlier `[8..24]` (16 chars), and the cert component is `certColonUpper`
> (colon-separated UPPERCASE hex), NOT lowercase plain hex. Both are capture-verified
> against the genuine wire chKey (`re/live_login.md:21` SOLVED section,
> `re/scripts/validate_sign_against_capture.py:154-162`).

where every input is a static, offline-recoverable value:
- `appId` = `ThingSmartNetWork.mAppId.getBytes()` = the Tuya **appKey** (the same
  value carried on the wire as `clientId`; in `secrets/tuya_appkey.json`);
- `packageName` = `getPackageName()` = `com.philips.ph.babymonitorplus` (static,
  from `AndroidManifest.xml` `package=`);
- `certColonUpper` = the app signing-cert SHA-256 as **colon-separated UPPERCASE
  hex** (the same `colon_upper` cert form the request `sign` folds, NOT lowercase
  plain hex) — offline-computable from the APK signing block (already done for the
  request `sign`, `re/tuya_sign_static.md` §4). Capture-verified as the form that
  reproduces the genuine wire chKey (`re/scripts/validate_sign_against_capture.py:154`,
  `re/live_login.md:33`).

The keyed digest is **HMAC-SHA256** (NOT plain MD5 like the request `sign`), but
the native return value is the 8-character slice `hex_hmac[8..16]`, not the full
64-character hex digest. (Corrected 2026-06-28, v0.1.0-live-stream: an earlier
`[8..24]`/16-char reading was the literal root cause of `ILLEGAL_CLIENT_ID` —
see §3a NB and §5 — now fixed and capture-verified, `re/live_login.md:21` SOLVED,
`re/scripts/validate_sign_against_capture.py:162`.)

Two independent sources ground the verdict: (1) the Ghidra 11.4.2 headless
decompilation of `getChKey` + its callees (cited inline), and (2) a radare2
cross-check of the same bytes (the `_`-join, the HMAC `0x36`/`0x5c` pads, the
`SHA256` algo descriptor). Ported to Rust in
`babymonitor/babymonitor-core/src/sign.rs::ch_key` (+ `hmac_sha256`), unit-tested
against RFC 4231 HMAC-SHA256 vectors (an INDEPENDENT differential for the
primitive).

---

## 1. getChKey@0x16000 (Ghidra `FUN_00116000`) (confidence: confirmed)

Two independent sources: the native decompilation of `libthing_security.so@0x16000`
AND the decompiled Java bridge
`decompiled/jadx/sources/com/thingclips/sdk/network/ThingNetworkSecurity.java`.

`JNICLibrary.getChKey(Context, byte[] appId)` — JNI-registered at file offset
`libthing_security.so@0x16000` (`re/tuya_sign_static.md` §1 RegisterNatives table;
signature `(Landroid/content/Context;[B)Ljava/lang/String;`). The Java bridge is
`ThingNetworkSecurity.getChKey(ctx, mAppId.getBytes())`
(`decompiled/jadx/sources/com/thingclips/sdk/network/ThingNetworkSecurity.java`
~:216-258) called from
`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java`
`initUrlParams` ~:1828.

Decompiled body (`libthing_security.so@0x16000`, Ghidra base 0x100000 →
`0x116000`):
1. `GetArrayLength(appId)` → len (`*param_1+0x558`); `GetByteArrayElements(appId)`
   → ptr (`*param_1+0x5c0`). These are the HMAC **key** bytes (the appId).
2. Builds a std::string from two runtime-populated `.bss` globals joined by a
   `'_'` (0x5f) byte: `DAT_001390a0 + "_" + DAT_00139058` (the `0x5f` write is at
   `getChKey@0x116108`; the `append` at `@0x11612c`). This is the HMAC **message**.
3. `FUN_0011775c(6)` selects the algo-6 descriptor (`PTR_DAT_00134390 → 0x132fe0`).
4. `FUN_001179f8(algoCtx, appIdPtr, appIdLen, keyStr, keyLen, out32)` — the keyed
   digest (§3). Output is 32 bytes in `auStack_88`.
5. Hex-encodes the 32 bytes to 64 lowercase chars via `__vsprintf_chk` with the
   format string `DAT_001090ea = "%02x"` (`FUN_00116ae4`, loop to `0x40`).
6. Copies 8 chars from byte offset 8 of the hex string into a second
   std::string and returns that 8-char slice to Java via `NewStringUTF`
   (`*param_1+0x538`). (Corrected 2026-06-28, v0.1.0-live-stream: an earlier
   "up to 16 chars" reading of this copy loop was wrong; the capture-verified wire
   chKey is 8 chars, `[8..16]` — `re/live_login.md:32-36`,
   `re/scripts/validate_sign_against_capture.py:162` — which is authoritative over
   the decompiled-loop length inference.)

So: `chKey = hex( keyed_digest( key=appId, msg=DAT_001390a0_"_"_DAT_00139058 ) )[8..16]`.

## 2. The two `.bss` key-string globals are STATIC values (confidence: confirmed)

Two independent sources: the native `.bss` writer disassembly in
`libthing_security.so@0x16528` (`FUN_00116528`, the reflection callback) AND the
APK manifest `decompiled/apktool/AndroidManifest.xml:2` whose `package=` attribute
is exactly the package-name value the native `getPackageName()` callback yields
into `DAT_001390a0` (so the static manifest independently fixes one of the two key
parts).

`DAT_001390a0` and `DAT_00139058` are in **.bss** (`.bss` starts at file offset
`libthing_security.so@0x38de0`; `readelf -S`), so zero-initialized at load. The
C++ static initializer `_INIT_2` (`libthing_security.so@0x176b4`) only
EMPTY-constructs them (+ registers `__cxa_atexit` destructors) — it does NOT set a
value. They are populated at runtime by `FUN_00116528`
(`libthing_security.so@0x16528`, the cert-hash routine), the only non-init writer
(xref scan: writers are `_INIT_2` + the PARAM into `FUN_00113ed8`/`FUN_00116528`).

`FUN_00116528` is the **app-cert SHA-256** routine — a JNI reflection callback:
- `getPackageManager()` → `getPackageName()` — its result is stored into
  `DAT_001390a0`. So **`DAT_001390a0` = the package name**
  (`com.philips.ph.babymonitorplus`).
- `getPackageInfo(pkgName, 0x40=GET_SIGNATURES)` → `signatures[0]` → `toByteArray`
  → `CertificateFactory.getInstance("X509").generateCertificate(...)` →
  `getEncoded()` → `MessageDigest.getInstance("SHA256").digest(...)`, hex-encoded
  (the `0x40`-iteration `push_back` loop), stored into `DAT_00139058`. So
  **`DAT_00139058` = the app-cert SHA-256 hex**. (NB 2026-06-28, v0.1.0-live-stream:
  the decompiled `push_back` loop reads as plain 64-char hex, but the gold-vector
  reproducer — which reproduces the genuine wire chKey byte-for-byte — uses the
  **colon-separated UPPERCASE** form `certColonUpper`
  (`re/scripts/validate_sign_against_capture.py:154`, `re/live_login.md:33`). The
  capture-validated reproducer is authoritative over this decompiled-loop format
  inference.)

Both are STATIC: the package name is a manifest constant; the cert-SHA-256 is
offline-computable from the APK's own v1 signing cert (the SAME value the request
`sign` already uses, `re/tuya_sign_static.md` §4). The reflection strings
(`getPackageManager`/`getPackageInfo`/`signatures`/`SHA256`/`digest`) are at
`.data 0x138a08`…`0x138c58` — corroborating the §4 cert-hash JNI callback.

Hence the HMAC message = `packageName + "_" + certColonUpper` (the cert SHA-256 in
colon-separated UPPERCASE form, capture-verified) — fully static.

## 3. The keyed digest is HMAC-SHA256 (confidence: confirmed)

Two independent sources: the disassembled algo descriptor + HMAC pad construction
in `libthing_security.so@0x132fe0` AND the published HMAC-SHA256 reference (RFC
4231), against whose Test Case 2 + Case 6 vectors the Rust port is differentially
asserted (`babymonitor/babymonitor-core/src/sign.rs:1` — the
`hmac_sha256_rfc4231_test_case_2` / `_case_6_long_key` tests). The RFC vector is
an independent oracle for the primitive, distinct from the binary.

- **Algo descriptor** at `libthing_security.so@0x132fe0` (selected by
  `FUN_0011775c(6)`): `{ id=6, name="SHA256" (@0x1090fe), digestSize=0x20 (32),
  blockSize=0x40 (64), init=FUN_00117c50, update@+0x20, final@+0x28, … }`. digest
  32 / block 64 ⇒ SHA-256.
- **HMAC construction** in the key-setup `FUN_00117780`
  (`libthing_security.so@0x17780`): if the key is longer than the block size it
  first hashes the key (init/update/final at the descriptor slots), then
  `memset(K0, 0x36, 64)` / `memset(K0+64, 0x5c, 64)` and XORs the key in — the
  canonical HMAC **ipad (0x36) / opad (0x5c)** pads (r2 confirms the `mov w1, 0x36`
  / `mov w1, 0x5c` before `memset` at `libthing_security.so@0x17834` /
  `libthing_security.so@0x1784c`).
- **The double pass** in `FUN_001179f8` (`libthing_security.so@0x179f8`): HMAC
  key-setup with `param_2` (the appId key), then inner `update(message=keyStr)` →
  `final(innerDigest)`, then re-init, `update(opad)` + `update(innerDigest)` →
  `final(out)`. Textbook `H((K^opad) || H((K^ipad) || msg))`.

This CONTRASTS with the request `sign`, which is plain MD5 (`re/tuya_sign_static.md`
§3). chKey is a SEPARATE primitive: HMAC-SHA256.

### 3a. Key vs message ordering (confidence: confirmed)

`confirmed` (promoted 2026-06-28, v0.1.0-live-stream) — a genuine captured wire
chKey now exists and the `[8..16]` derivation reproduces it byte-for-byte via the
1800-combo gold-vector match (`re/scripts/validate_sign_against_capture.py:154-162`,
`re/live_login.md:21` SOLVED). Reproducing the real chKey VALUE validates the FULL
composition end-to-end — including this key/message ordering AND the `[8..16]`
slice — which is the independent second source the prior caveat ("only a live
server-accepted request or a captured device chKey would promote it to confirmed")
was waiting on. The static evidence already agreed: the decompiler arg-order AND an
independent arm64 register re-trace of the SAME binary
(`x24`/`x23` carry the appId into the HMAC ipad/opad key-setup, `x21`/`x20` carry
the `packageName_"_"_certColonUpper` string into the message `update`); the live
capture is now the second, independent source that promotes it. Source: the native
call-site argument order in `libthing_security.so@0x16000` (getChKey) into
`FUN_001179f8` (`libthing_security.so@0x179f8`), corroborated by the captured wire
chKey.

In `getChKey`, `FUN_001179f8(ctx, appIdPtr, appIdLen, keyStr, keyLen, out)` passes
the **appId** as `param_2/param_3` → consumed FIRST by the HMAC key-setup
(`FUN_00117780(&ctx, param_2, param_3)`, regs `x24`/`x23`) → so **appId is the
HMAC KEY**. The built `packageName_"_"_certColonUpper` string is `param_4/param_5` (regs
`x21`/`x20`) → consumed by the inner `update` → so it is the HMAC **MESSAGE**. The
Rust port + a dedicated unit test (`ch_key_key_message_order_is_load_bearing`) pin
this ordering.

> NB (Superseded 2026-06-28, v0.1.0-live-stream) — `ILLEGAL_CLIENT_ID` was SOLVED
> 2026-06-26 (`re/live_login.md:21`): the decisive bug was the wrong chKey **LENGTH**
> (`[8..24]`/16 chars → `[8..16]`/8 chars), NOT the key/message ordering. The atop
> gateway validates this standalone client-binding param and rejected the 16-char
> value *before* sign-verification; the corrected 8-char chKey CLEARS the gate and
> `token.get` returns the success envelope. The earlier claim that "a correctly-ordered
> chKey did not clear the gate" was an artifact of the WRONG 16-char length being held
> constant in both A/B arms (`re/live_login.md:38-40`). `re/live_login.md`'s own
> pre-solve sections (e.g. lines 137, 210-238) are historical and superseded by its
> 2026-06-26 SOLVED section at line 21.

## 4. Rust port + wiring (confidence: likely)

`likely` (single class of source — the committed code is not an independent RE
artifact, it is the implementation of §1-§3). Source: the committed port + tests
in `babymonitor/babymonitor-core/src/sign.rs:600` and the wiring in
`babymonitor/babymonitor-cli/src/live.rs:1` (both carry the asserting unit tests
named below); the package-name const is grounded by the manifest
`decompiled/apktool/AndroidManifest.xml:2` (`package=`).

- Port: `babymonitor/babymonitor-core/src/sign.rs::ch_key(app_key, package_name,
  cert_sha256_hex)` + `hmac_sha256` (over the `sha2` crate; no new dep). The
  `APP_PACKAGE_NAME` const = the manifest package.
- Validation: `hmac_sha256` is differentially tested against RFC 4231 Test Case 2
  and Case 6 (the >block-size pre-hash branch) — INDEPENDENT vectors, not our own
  decompilation. `ch_key_composes_hmac_over_packagename_cert` pins the composition
  and the native `[8..16]` return slice (corrected 2026-06-28, v0.1.0-live-stream;
  capture-verified, `re/live_login.md:21`).
- Computed value: the real chKey is computed in
  `babymonitor/babymonitor-cli/src/live.rs::load_config` from the appKey +
  `APP_PACKAGE_NAME` + the offline cert hash, and persisted to
  `secrets/chkey.txt` (gitignored, 0600). **The value is withheld from every
  tracked file and log** (CLAUDE.md). An operator-pinned `secrets/chkey.txt` (e.g.
  a captured value) is preferred over re-derivation if present.
- Envelope: `chKey` is added to the atop envelope BEFORE signing (it is in
  `SIGN_WHITELIST`), so it rides the wire query AND enters the canonical sign
  string. Tests `envelope_carries_chkey_in_wire_and_canonical_sign` +
  `chkey_changes_the_canonical_sign` assert both surfaces.

## 5. Honest limitations (confidence: likely — scoping)

Scoping record (not a new native claim); each row's basis is cited in §1-§4
above (`libthing_security.so@0x16000`, `re/tuya_sign_static.md` §4 for the
cert-hash ingredient).

- The HMAC primitive, the `_` separator, and the package-name + cert-hash message
  parts are `confirmed` (byte-level Ghidra + the RFC 4231 differential). The
  key/message ORDERING (§3a) is now `confirmed` too (promoted 2026-06-28,
  v0.1.0-live-stream): the genuine captured wire chKey is reproduced byte-for-byte
  by the `[8..16]` derivation (`re/live_login.md:21`,
  `re/scripts/validate_sign_against_capture.py:154-162`), which validates the full
  composition — the prior "only a captured device chKey would reach confirmed"
  caveat is now satisfied. The cert-SHA-256 ingredient — whether our offline
  extractor lifts the byte-for-byte value the device's `signatures[0]` yields, and
  in the correct `colon_upper` form — is likewise capture-validated (the gold
  vector matched only with `cert_formats["colon_upper"]`); it is the SAME ingredient
  the request `sign` depends on, also cross-checked against `openssl` in `sign.rs`
  (the `real_app_cert_matches_openssl_reference` ignored test).
- (Superseded 2026-06-28, v0.1.0-live-stream) chKey IS proven to be THE
  `ILLEGAL_CLIENT_ID` fix: it was SOLVED 2026-06-26 and the decisive bug was the
  wrong chKey **LENGTH** (`[8..24]`/16 chars → `[8..16]`/8 chars). The atop gateway
  validates chKey as a standalone client-binding param *before* sign-verification
  and rejected the 16-char value; the corrected 8-char chKey clears the gate and
  `token.get` returns the success envelope (`re/live_login.md:21`). The earlier
  "server-opaque, only resolvable by the next live token.get" framing is historical
  — the next live run DID resolve it, in favour of the chKey-length fix. (chKey is
  also a SIGNED identity param, so the corrected value rides both the wire request
  and the canonical sign.)
- Addresses are hints for THIS build; re-anchor on the symbol landmarks
  (`getChKey` JNI name, the `SHA256` descriptor `@0x132fe0`, the `0x36`/`0x5c`
  HMAC pads, `getPackageName`/`MessageDigest` reflection strings) if the APK
  version shifts.
