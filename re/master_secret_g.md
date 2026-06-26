# Master secret G — native `doCommandNative` cmd0 assembly (TASK-0061)

Ground truth for the Tuya mobile-app request **sign** and the ET=3 **postData AES**
key. Recovered statically from the native security lib; no live capture. All secret
VALUES live only under `secrets/` (gitignored) — this file records the recipe, never
a value.

## 1. What G is

`G` is the native **master secret** that `JNICLibrary.doCommandNative(ctx, cmd, …)`
builds once at init (`cmd == 0`) and caches in `.bss` (`DAT_00139070`, vaddr
`0x139070`). Every later crypto op keys off it: cmd1 sign, cmd2 MQTT key,
`getEncryptoKey` (postData AES), `encryptPostData`.

- **confirmed** — G is assembled by the cmd0 branch and stored once, then read by
  cmd1/cmd2: `re/ghidra/doCommandNative.c:497` (cmd0 assembly ~:497-783; cmd1 consume
  ~:449-489) and `re/ghidra/getEncryptoKey.c:40` (reads the same cached buffer).

## 2. Byte layout (the load-bearing part)

`G` is a **raw byte string** (NOT a UTF-8 `String` — one part is binary), joined by a
single `0x5f` (`_`) byte with no length prefix:

```
G = packageName  ++ 0x5f
 ++ certColonUpper ++ 0x5f
 ++ matrixKey0     ++ 0x5f
 ++ appSecret
```

| part            | value (recipe, not the value)                                   | confidence |
|-----------------|------------------------------------------------------------------|------------|
| `packageName`   | `com.philips.ph.babymonitorplus` (UTF-8); manifest `package=`    | **confirmed** |
| `certColonUpper`| app-cert SHA-256 as **colon-grouped UPPERCASE hex, 95 chars** (`A1:B2:…:FF`) | **likely** |
| `matrixKey0`    | `hex_decode(bmp_token)` → **32 RAW bytes** (binary, NOT ascii hex) | **confirmed** (form) |
| `appSecret`     | raw UTF-8 appSecret (`secrets/tuya_appkey.json` `.appSecret`)    | **confirmed** |

Evidence:
- Byte order + `0x5f` joins + the cert/appSecret parts: **confirmed** —
  `re/ghidra/doCommandNative.c:497` (cmd0 ~:497-783) cross-referenced with the jadx
  caller `ThingApiSignManager.generateSignatureSdk`
  (`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java:99`).
- `certColonUpper` form (colon-grouped UPPERCASE, not lowercase 64-hex): same cert
  formatter the native `getChKey` uses — `re/chkey_static.md:1` +
  `re/ghidra/doCommandNative.c:540`. Marked **likely** because the exact
  `String.format`/separator emission is read from control-flow shape, not executed.
- `matrixKey0` = the 32 raw bytes the `bmp_token` (64-hex) decodes to, sourced from
  `assets/t_s.bmp` via `read_keys_from_content` keyed by appId/appKey:
  `re/ghidra/read_keys_from_content.c:1` + `re/ghidra/matrix_fcn5eb0.c:1`. The decode
  itself is un-ported (TASK-0032), so the token VALUE is supplied from
  `secrets/bmp_token.txt` (still **needs-live** to confirm the recovered token value).
- **RESOLVED (Finding 1, TASK-0060/0061): the raw-bytes FORM is `confirmed`, two-source.**
  An earlier review worried `matrixKey0 = hex_decode(bmp_token)` was backwards because
  the native reads each key via `strlen` (`re/ghidra/doCommandNative.c:546`) — which
  would suggest the key is used as ASCII text. It is NOT: after the `strlen`, the
  native copies the key string and passes it through the **hex-DECODER** `FUN_00113150`
  (`doCommandNative.c:572`). `FUN_00113150` resizes its output to `input_len/2` and
  decodes pairs of `[0-9a-fA-F]` nibbles to bytes
  (`decompiled/ghidra_security/funcs/00113150_FUN_00113150.c:32,46-76`). So the key is
  STORED as hex TEXT (strlen reads its 64-char length) and DECODED to 32 RAW bytes
  before folding into G — exactly what our `hex::decode(bmp_token)` produces. Two
  independent sources (the G-assembly order + the hex-decoder output length) agree, so
  the raw-bytes form is `confirmed`; do not re-litigate it. Only the token VALUE
  remains un-ported.

> **Silent-failure trap.** `certColonUpper` is the 95-char colon-UPPER form, and
> `matrixKey0` is the RAW 32-byte decode of `bmp_token` — NOT the lowercase 64-hex
> cert string and NOT the ascii hex of the token. Feeding either ascii form produces
> a wrong-but-plausible G and a server-rejected sign with no local error. This is the
> exact regression TASK-0060/0061 fixes.

## 3. How G is consumed

### 3a. Request `sign` (cmd1)
`sign = lowercase_hex( HMAC-SHA256( key = G, msg = str2 ) )` → **64 hex chars**.
`str2` is the sorted-whitelist canonical string (`re/tuya_sign.md` §1, literal `||`
join), with the `postData` value pre-replaced by `swapSignString(md5_hex(postData))`.

- **confirmed** — `re/ghidra/doCommandNative.c:449` (cmd1 ~:449-489, HMAC-SHA256 over
  the cached G) and jadx `ThingApiSignManager.generateSignatureSdk` →
  `pbddddb.bdpdqbp(str2)` → `doCommandNative(ctx, 1, …)`
  (`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java:159`).

> NOTE: the earlier port used `computeDigest` (MD5 → 32-hex,
> `re/ghidra/computeDigest.c:1`) — that is the inbound **response-verify** path, NOT
> the login signer. Confirmed wrong target; corrected here.

### 3b. ET=3 postData AES-128 key
`key16 = first 16 ASCII hex chars of lowercase_hex( HMAC-SHA256( key = requestId,
msg = G [++ 0x5f ++ ecode] ) )`. Login (`token.get`) sets `setSessionRequire(false)`
so `ecode` is omitted and the message is G alone.

- **confirmed** — `re/ghidra/getEncryptoKey.c:40` (HMAC-SHA256, key=requestId,
  msg=cached G, byte[16] from first 16 hex chars) and `re/ghidra/encryptPostData.c:1`
  (AES over that key).

## 4. Rust port + honest limits

- **confirmed** — implemented in `babymonitor/babymonitor-core/src/sign.rs:283`
  (`assemble_master_key_g`, `cert_sha256_colon_upper`, `et3_encrypto_key`,
  `Signer::sign`) and wired in `babymonitor/babymonitor-cli/src/live.rs:634`
  (`master_key_g`).

What is **offline-validated** (published KATs, not our decompilation): HMAC-SHA256 vs
RFC 4231 (cases 2+6), SHA-256 vs FIPS-180, MD5 vs RFC 1321, and the colon-upper cert
formatter against an exact hand-written gold string.

What is **NOT** offline-validatable: the RECIPE itself (key=G, msg=str2, the 4-part
byte order, `matrixKey0`-as-raw-bytes) is **single-source** native ground truth. There
is no HMAC known-answer vector in the lib and the real `bmp_token` decode is un-ported
(TASK-0032). End-to-end parity therefore needs the recovered token + one server-accepted
`token.get` (the sign oracle, `re/live_login.md`). Until a `BmpTokenProvider` supplies
the token, `Signer::sign` returns `BmpTokenPending` and never fabricates a value.
