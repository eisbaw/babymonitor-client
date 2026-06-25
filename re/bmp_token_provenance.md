# bmp_token `config` byte[] provenance + exact login sign (TASK-0041)

Resolves the ONE open question gating the Tuya signer: **where does the runtime JNI
`byte[]` `config` (passed to `read_keys_from_content`, the `t_s.bmp` matrix decode)
come from in the Java/JNI flow?** And documents the EXACT login-sign construction.

Ghidra-primary (`re/ghidra/doCommandNative.c`), jadx-confirmed (the Java callers),
r2 cross-checked via the prior `re/bmp_token_whitebox.md`. **No secret VALUES appear
in this file** — recovered material lives only in `secrets/` (gitignored).

> Citation note: native cites name a symbol or `lib.so@0xADDR` (hints for BuildID
> `444ecb4f…` libthing_security.so / `904862d9…` libthing_security_algorithm.so).
> jadx paths are `decompiled/jadx/sources/...`; line hints drift between runs — grep
> the symbol. The `Tz.a()`/`Tz.b(0)` calls littering every Java method are no-op
> control-flow telemetry (ai/ct), NOT data flow.

---

## VERDICT (confidence: confirmed for provenance; the token VALUE is `needs-oracle`)

**The `config` byte[] is STATIC: it is `ThingSmartNetWork.mAppId.getBytes()` — the
app's appKey (appId) as UTF-8 bytes — already recovered offline to
`secrets/tuya_appkey.json:appKey`.** It is NOT cloud-fetched, NOT an AES-decrypted
asset, NOT computed at SDK-init from anything device-specific. So the long-standing
"the decode needs a runtime SDK-config blob, so it is not static-only" residual
(`re/bmp_token_whitebox.md` §9, `re/tuya_sign_static.md` §5/§6) is now **RESOLVED in
favour of static**: the runtime arg's VALUE is a static, already-extracted constant.

Therefore every static INPUT to the `t_s.bmp` matrix decode is now known:
`t_s.bmp` (committed asset) + `config = appKey` (in `secrets/`) + the embedded matrix
constants (ported, `re/scripts/bmp_token_ghidra.py`).

**HONEST RESIDUAL (do NOT overclaim):** running the ported decode end-to-end with the
REAL appKey config reaches the matrix solve (header validates, selector byte = 1 → op1,
`num_keys=1`, `num_coeffs=4` — all sane, NOT the rejection arbitrary configs produce),
but the Vandermonde solve fails the integral gate (`mp_int_compare_value(denom,1)`,
native error `0xb`). The (a,b) coefficient pairs come out with implausible pixel-byte
lengths (200+), i.e. the **offset-walk in the port is not yet byte-exact**, and there is
**NO static oracle** in the `.so` (no embedded test vector) to tune it against. So a
**concrete bmp_token value was NOT written to `secrets/`** — writing a non-integral /
guessed value would be fabrication (CLAUDE.md: never claim success when it doesn't work).

Net: **the signer is static-buildable in PRINCIPLE (all inputs known), but a trustworthy
bmp_token still needs an oracle** — either (a) finishing the byte-exact op1 offset-walk
port and validating it via (b) ONE accepted live sign. This is `needs-live-login` for
*validation*, NOT for *inputs*. See feed-forward.

---

## 1. AC#1 — `config` byte[] provenance (confidence: confirmed)

### 1.1 The JNI signature and the param that is `config` (confidence: confirmed)

Two sources: `re/ghidra/doCommandNative.c` (the param→read_keys_from_content wiring)
AND the `RegisterNatives` JNI table in `re/tuya_sign_static.md` §1 (the signature).

`JNI_OnLoad` registers `doCommandNative` with signature
`(Landroid/content/Context;I[B[BZ)Ljava/lang/Object;`
(`com/thingclips/smart/security/jni/JNICLibrary`, native `@0x13ed8`;
`re/tuya_sign_static.md` §1). Mapping the native params (`re/ghidra/doCommandNative.c`):

| native param | JNI arg | role |
|---|---|---|
| `param_1` | JNIEnv* | — |
| `param_3` | `Context` | asset manager source for `t_s.bmp` (`FUN_00113b5c`) |
| `param_4` | `int` cmd | dispatch: 0=init/decode, 1=sign, 2=ecode |
| `param_5` | `byte[]` #1 | first byte[] |
| `param_6` | `byte[]` #2 | **the `config` blob fed to `read_keys_from_content`** |
| `param_7` | `boolean` | selects `t_s.bmp` (false) vs `t_s_daily.bmp` (true) |

In the **cmd=0** branch (`doCommandNative.c` line 498 `param_4==0`):
- line 519: `pvVar16 = GetByteArrayElements(param_6)`; line 522-524:
  `__dest = calloc(len+1); memcpy(__dest, param_6_bytes, len)` → a NUL-terminated copy.
- line 526: `FUN_00113b5c(...)` reads the raw `t_s.bmp` bytes.
- line 540: **`read_keys_from_content(__dest, &keys, &count, raw_bmp)`** — so
  **`config == __dest == param_6`** (the SECOND byte[]). Confirmed unambiguously.

The cmd=0 path then `_`-joins the decoded key list (line 670: the `0x5f` byte written
between parts) into the cached global key `DAT_00139070`; cmd=1/cmd=2 later MD5 that
CACHED key (this is the Ghidra cmd-attribution correction already recorded in
`re/bmp_token_whitebox.md` §9 — decode is cmd=0 setup, not cmd=1).

### 1.2 The Java caller — what `param_6` actually is (the load-bearing find) (confidence: confirmed)

Two independent sources: the Java caller
`decompiled/jadx/sources/com/thingclips/sdk/network/ThingNetworkSecurity.java`
(`initJNI`, the cmd=0 call with its byte[] args, proving `param_6 = mAppId.getBytes()`)
AND `decompiled/jadx/sources/com/thingclips/smart/android/network/ThingSmartNetWork.java`
(`mAppId`/`mAppSecret`/`mD` declarations + `initialize(...)`, proving `mAppId = appKey`).
The native side `re/ghidra/doCommandNative.c` independently proves `config == param_6`
(cmd=0 branch). They agree end-to-end.

Whole-tree, there are exactly **three** `doCommandNative` call sites (grep
`doCommandNative\(` over `decompiled/jadx/sources`, excluding declarations):

| cmd | caller (symbol) | byte[]#1 (`param_5`) | byte[]#2 = `config` (`param_6`) | `Z` |
|---|---|---|---|---|
| **0** | `ThingNetworkSecurity.initJNI(Context)` | `ThingSmartNetWork.mAppSecret.getBytes()` | **`ThingSmartNetWork.mAppId.getBytes()`** | `mD` |
| 1 | `pbddddb.bdpdqbp(String str)` | `str.getBytes()` (canonical sign string) | `null` | `mD` |
| 2 | `qpqbppd` (mqtt) | `getEcode().getBytes()` | `null` | `mD` |

The cmd=0 call (`com/thingclips/sdk/network/ThingNetworkSecurity.java`,
`initJNI(...)`):
```java
JNICLibrary.doCommandNative(context, 0,
    ThingSmartNetWork.mAppSecret.getBytes(),   // param_5  (appSecret)
    ThingSmartNetWork.mAppId.getBytes(),       // param_6 == config  (appId / appKey)
    ThingSmartNetWork.mD);                      // Z  (debug flag, default false)
```
So **`config = mAppId.getBytes()` = the appKey UTF-8 bytes.** Confirmed both ends:
Ghidra says `config = param_6`; jadx says `param_6 = mAppId.getBytes()`.

### 1.3 Where `mAppId` / `mAppSecret` / `mD` come from (all static)

`com/thingclips/smart/android/network/ThingSmartNetWork.java`:
- `mAppId` and `mAppSecret` are `public static String`, assigned in
  `initialize(ctx, str=appId, str2=appSecret, …)` (lines 3872-3873). The sole caller
  is `com/thingclips/smart/sdk/ThingSdk.java`, wiring them from the app's
  `BuildConfig` appKey/appSecret — the values already recovered to
  `secrets/tuya_appkey.json` (`appKey`, `appSecret`) by TASK-0023.
- `mD` derives from `mAppDebug` (default `false`, `setDebugMode(mAppDebug)` line 3898).
  `mD=false` ⇒ `doCommandNative`'s `Z=false` ⇒ `FUN_00113b5c` selects **`t_s.bmp`**
  (NOT `t_s_daily.bmp`, which is not shipped) — matching prior findings.

**Provenance category: `sdk-init-from-static-appKey`** — read from `BuildConfig` at SDK
init, no network, no device entropy. The `config` for the decode is the appKey string.

### 1.4 strhash over the appKey (confidence: confirmed)

`strhash(config)` (`re/ghidra/strhash.c`) is `acc = acc*31 + byte` over `strlen(config)`
(stops at first NUL). The appKey is a 20-char printable string with no embedded NUL, so
the whole appKey is hashed. With the real appKey: `strhash = 477406661`,
`selector_idx = 830`, `selector_byte = 1` (→ op1 dispatch). This is the load-bearing
contrast with the prior REFUTED claim: arbitrary/probe configs almost always land on
`pixels[base+1] > 5` and get rejected by the header validator
(`test_arbitrary_static_config_does_not_yield_valid_header`); the REAL appKey config
lands on a **valid op1 header** (`num_keys=1`, `num_coeffs=4`). That strongly
corroborates "config = appKey" being the intended input.

---

## 2. AC#2 — exact login sign construction (confidence: confirmed)

The login requests (`thing.m.user.username.token.get`,
`thing.m.user.email.password.login`; `re/tuya_cloud_auth.md` §2) are signed by the SAME
generic signer as every atop request — there is nothing login-special about the
algorithm; the only login specifics are the envelope params present (e.g. `sid` empty,
`setSessionRequire(false)` on token.get).

### 2.1 Canonical string-to-sign (`str2`) (confidence: confirmed)

Two sources: `ThingApiSignManager.generateSignatureSdk`
(`com/thingclips/sdk/network/ThingApiSignManager.java`, the sort+whitelist+join body)
AND the delimiter constants in `com/thingclips/sdk/mqtt/pbbppqb.java` (`pbpdbqp="||"`,
`pbpdpdp="="`). Exact body:

1. `linkedList = new LinkedList(map.keySet()); Collections.sort(linkedList);` — keys
   sorted ascending (lexicographic).
2. Iterate sorted keys; keep a key iff it is in the **whitelist** `bdpdqbp` AND its
   value is non-empty. Whitelist (`ThingApiSignManager.java:66`):
   `a, v, lat, lon, lang, deviceId, appVersion, ttid, h5, h5Token, os, clientId,
   postData, time, requestId, et, n4h5, sid, chKey, sp`.
3. For the `postData` key only: replace its value with `postDataMD5Hex(rawPostData)`
   **before** appending (line 146-150).
4. Build `str2` by joining the kept `key=value` items with `||`:
   - between items: `str2 += "||"`  (`mqtt.pbbppqb.pbpdbqp = "||"`, line 26)
   - each item: `str2 += key + "=" + map.get(key)`  (`pbpdpdp = "="`, line 27)
   i.e. `str2 = k1=v1||k2=v2||…||kn=vn` over the sorted, whitelisted, non-empty keys.
5. `sign = pbddddb.bdpdqbp().bdpdqbp(str2)` (line 159) → the native cmd=1 call
   `doCommandNative(ctx, 1, str2.getBytes(), null, mD)` (§1.2 row cmd=1).

### 2.2 postData fold — `postDataMD5Hex` + `swapSignString` (confidence: confirmed)

Two sources: `ThingApiSignManager.postDataMD5Hex` AND `ThingApiSignManager.swapSignString`
(both `com/thingclips/sdk/network/ThingApiSignManager.java`).

`postDataMD5Hex(str)` (`ThingApiSignManager.java:423`):
- empty → `""`.
- else: `swapSignString( MD5Util.md5AsBase64(str) )`.
  - `md5AsBase64` = base64(MD5_raw16(postDataJson)) → a 24-char base64 string; but the
    code substrings up to index 32, so treat it as the standard Tuya 32-hex MD5 path
    used by `swapSignString` (see caveat below).
- `swapSignString(s)` (line 524-571) block-swaps a 32-char string:
  `out = s[8:16] + s[0:8] + s[24:32] + s[16:24]`
  (substring(0,8)=A, substring(8,24)=BC where B=substring(8,16), C=substring(16,24),
   substring(24,32)=D ⇒ `out = B + A + D + C`).

So in `str2` the `postData` entry is `postData=<swapSignString(md5AsBase64(body))>`.

### 2.3 The key (proves bmp_token IS needed for login) (confidence: confirmed)

Two sources: `re/ghidra/doCommandNative.c` (the `0x5f` `_`-joins building the cached key)
AND `re/tuya_sign_static.md` §3-4 (the MD5 primitive + `_`-join key model, F1-corroborated).

The native cmd=1 sign hashes the **cached key** built at cmd=0 (§1.1) — it is the SAME
key for login and every other request. From `re/tuya_sign_static.md` §3-4 +
`re/ghidra/doCommandNative.c` (the `0x5f` `_` joins) + `md5_key_builder.c`:

```
key = cert_sha256_hex  "_"  <t_s.bmp matrix-decoded key(s), '_'-joined>  "_"  appSecret
sign = MD5_hex_lower( key  [folded with str2 per the cmd=1 md5_key_builder] )
```
- `cert_sha256_hex`: offline-computable from the APK signing cert
  (`secrets/tuya_appkey.json:app_cert_sha256`).
- the middle `_`-part: the `t_s.bmp` matrix decode keyed by `config = appKey` (§1) —
  **this is the bmp_token, and login REQUIRES it** (the cached key is built once at
  cmd=0 and reused for the login cmd=1 sign).
- `appSecret`: `secrets/tuya_appkey.json:appSecret`.
- primitive = plain MD5 → 32-char lowercase hex (`re/tuya_sign_static.md` §3, NOT
  HMAC-SHA256). The cmd=1 builder calls MD5 twice (`md5_key_builder.c`), consistent
  with `MD5(key)` then `MD5(key||str2)`; the exact fold is `likely` until one live
  vector pins it.

**Login-specific notes:** `token.get` sets `setSessionRequire(false)` so `sid` is empty
→ excluded from `str2` (empty-value filter, step 2). `password.login` includes the
RSA-encrypted `passwd` + `token` inside `postData` (so they enter the sign only via the
folded `postDataMD5Hex`, not as top-level signed params). The `a` value on the wire is
the `thing.*→smartlife.*`-rewritten name (`re/tuya_cloud_auth.md` §1a) — the rewrite
happens before signing, so sign over the rewritten `a`.

---

## 3. The decode attempt + why no value was written (confidence: confirmed)

Two sources: the input asset `decompiled/apktool/assets/t_s.bmp` (the BMP whose pixels
the decode walks, validated by the header check) AND the recovered config
`secrets/tuya_appkey.json` (`appKey`, the real `config` value fed in). The ported
decoder `re/scripts/bmp_token_ghidra.py` (run with that real config) reaches the matrix
solve but returns non-integral; the divergence is diagnosed against the Ghidra C
`re/ghidra/decode_op1.c` / `re/ghidra/build_mpint_op1.c`.

Ran `re/scripts/bmp_token_ghidra.py:read_keys_from_content(appKey_bytes, t_s.bmp)`:
- header validates; `dispatch_decode` selects **op1** (`selector_byte=1`);
  `num_keys=1`, `num_coeffs=4` — a well-formed op1 header (NOT the arbitrary-config
  rejection). This is positive evidence that `config = appKey` is the right input.
- BUT the op1 coefficient reads walk to offsets yielding `alen`/`blen` of 200+ pixel
  bytes per coefficient, and the Vandermonde solve returns non-integral (native `0xb`).

> **SUPERSEDED / RESOLVED by TASK-0032 (→ commit b5f9151):** the op1 offset-walk was
> corrected — two bugs found via r2 of `FUN_00105138` (start offset `base+3` not `base+1`;
> per-pair XOR against the pair-START offset, not after-b). With the real appKey config +
> `t_s.bmp` it now **solves INTEGRAL** (`denom==1`, 4×`{alen=4,blen=32}` → a 64-hex key);
> the `bmp_token` **candidate** (integral-solve-consistent; live-login-validated next) is in
> gitignored `secrets/bmp_token.txt`. The pre-fix root-cause text below is retained as history.

Root cause (HISTORICAL, pre-fix — corrected by TASK-0032): the op1 chained-offset arithmetic in the port (`_decode`, the
`xorstep_583c`-driven walk) was **not byte-exact**. Re-deriving from
`re/ghidra/decode_op1.c` + `build_mpint_op1.c` + `xorstep_583c.c`:
- the per-pair offset XOR-step XORs the result with the **pair START offset** `local_68`
  (decode_op1.c lines 99-104), and the op1 start uses
  `local_68 = (xorstep_583c(px, L, <iVar7==r>) ^ r) % L` (lines 57-62, Ghidra elided
  the 3rd xorstep arg; the live register there is `iVar7 == r`).
- I prototyped this byte-exact walk; it still did not yield an integral solve and it
  broke the existing self-consistency test (`test_synthetic_bmp_full_decode_runs`),
  which was crafted against the prior walk. With NO independent oracle I cannot tell a
  correct fix from a wrong one, so I **reverted** the speculative change rather than
  ship an unvalidated/regressing port. The committed port is unchanged and its 16 tests
  pass.

Per CLAUDE.md (no fabrication, no fake-wiring), **`secrets/bmp_token.txt` was NOT
written** — a non-integral / guessed token would be worse than none. The matrix machinery
(Vandermonde build, exact-rational RREF, integral gate, `transform` no-op) is confirmed
correct against `re/ghidra/matrix_fcn5eb0.c` + `matrix_init.c`; the residual is the op1
offset-walk only.

---

## 4. Feed-forward (confidence: confirmed — scoping summary)

Basis cited in §1-§3 above (`re/ghidra/doCommandNative.c`,
`com/thingclips/sdk/network/ThingApiSignManager.java`, `secrets/tuya_appkey.json`).

- **TASK-0042 (live login):** the live login must capture ONE accepted `sign` together
  with its exact `str2` (the canonical string `ThingApiSignManager` built) for a known
  request — that single (`str2` → `sign`) pair is the ORACLE that (a) validates/finishes
  the op1 offset-walk port and (b) disambiguates the cmd=1 MD5 fold (`MD5(key)` vs
  `MD5(key||str2)`). Capture at `pbddddb.bdpdqbp(str2)` / `doCommandNative(ctx,1,...)`.
  Inputs are NOT the blocker (appKey, appSecret, cert_sha256, t_s.bmp all known) — only
  validation is.
- **TASK-0012 (Rust signer):** the config provenance is RESOLVED — wire the bmp_token
  decode with `config = appKey bytes` (from `secrets/tuya_appkey.json`), `t_s.bmp` from
  assets. The signer's only un-validated step is the op1 offset-walk → bmp_token; keep
  the `BmpTokenProvider` as `PendingBmpToken` until the live oracle (TASK-0042) confirms
  it, then flip to the static decode. The cert-hash + appSecret + MD5 + `_`-join +
  canonical-string (§2) are all ready to implement now.
