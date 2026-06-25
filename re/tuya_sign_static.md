# Tuya mobile-app signer — fully-STATIC recovery dive (TASK-0023)

Heavy static (Ghidra/radare2) disassembly of the native Tuya request-signer, to
decide whether the FULL signer — string-to-sign + `t_s.bmp` token decode + key
combine + keyed hash — can be reproduced in Rust **from static analysis alone, with
no device**. This supersedes the `needs-runtime-hook` verdict of TASK-0005
(`re/tuya_sign.md`) now that the native cmd=1 path and the hash primitive have been
disassembled to byte level.

**No secret values appear in this file.** The recovered appKey/appSecret/TTID and the
(offline-computable) app-cert SHA-256 live ONLY in `secrets/tuya_appkey.json`
(gitignored). This doc records *location + method + algorithm*, never values.

> Citation note (symbol-anchored, line hints approximate): native cites name a
> resolved symbol or a `lib.so@0xADDR` (addresses are **hints** for THIS build,
> BuildID `444ecb4f…` for `libthing_security.so` / `904862d9…` for
> `libthing_security_algorithm.so`; verify with
> `readelf --dyn-syms` + r2 `pdf`). `lib*.so` = `lib/arm64-v8a/*.so` unzipped from
> `extracted/xapk/config.arm64_v8a.apk` into gitignored `decompiled/nativelibs/`.
> A cross-`.md` reference is a navigation pointer, NOT an independent source.

---

## Verdict (confidence: confirmed)

Verdict: partially-recoverable

(Task token set: {recoverable-statically | partially-recoverable |
not-statically-recoverable}. The machine-checked `check-evidence` verdict gate keys on
`re/p2p_protocol.md`, not this file; the label form is used here as instructed.)

**One-line justification:** Every step EXCEPT the `t_s.bmp` token decode is now fully
recovered and Rust-portable from static analysis — the keyed hash is **plain MD5**
(not HMAC-SHA256), the key-combine is underscore-joined, and the app-cert SHA-256 is
**computable offline from the APK signing cert** (no device). The single residual
blocker is the white-box **imath-bignum + matrix** deobfuscation of `assets/t_s.bmp`
into its token: it is deterministic and therefore *reproducible in principle*, but
requires porting the embedded matrix algorithm (imath `mp_int_*` + `mp_int_exptmod`)
— heavy work, filed as a follow-up. So "partially-recoverable": three of four
ingredients are done; the fourth is characterized to the wall.

Two independent sources ground this verdict: (1) the disassembled native cmd-dispatch
and digest routines in `libthing_security.so` (cited inline), and (2) the public
mobile-sign write-up `nalajcie/tuya-sign-hacking` (review-gate F1,
`re/review_gate_findings.md:16`), whose `key=[cert_sha256]_[bmp_token]_[appSecret]` /
embedded-BMP / matrix-decode shape matches what the binary does.

---

## 1. JNI native table — the cmd=1 sign entry (confidence: confirmed)

Two independent sources: the `RegisterNatives` table read from the binary AND the
matching Java declarations in the decompiled SDK.

- `JNI_OnLoad` (`libthing_security.so@0x13d50`) calls `RegisterNatives` with **9
  methods** (`w3=9`) against class `com/thingclips/smart/security/jni/JNICLibrary`,
  table at `.data.rel.ro 0x38c68` (filled by `R_AARCH64_RELATIVE` relocs; resolved
  via `readelf -r`). The 9 `{name, signature, fnptr}` triples are:

  | JNI name | signature | native fn |
  |---|---|---|
  | `doCommandNative` | `(Landroid/content/Context;I[B[BZ)Ljava/lang/Object;` | `@0x13ed8` |
  | `encryptPostData` | `(Ljava/lang/String;[B)[B` | `@0x151f8` |
  | `getEncryptoKey` | `(Ljava/lang/String;Ljava/lang/String;)[B` | `@0x15368` |
  | `genKey` | `(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;` | `@0x15720` |
  | `computeDigest` | `(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;` | `@0x15ad0` |
  | `decryptResponseData` | … | `@0x15e28` |
  | `getChKey` | `(Landroid/content/Context;[B)Ljava/lang/String;` | `@0x16000` |
  | `getConfig` | `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;` | `@0x136e0` |
  | `testSign` | `(Landroid/content/Context;)Ljava/lang/String;` | `@0x16408` |

- This matches the Java wrapper `JNICLibrary.doCommandNative(Context, int, byte[],
  byte[], boolean)` (`com.thingclips.smart.security.jni.JNICLibrary`) which
  `ThingNetworkSecurity`/`pbddddb.bdpdqbp(String)` call with `cmd=1` for the wire
  `sign` (`re/tuya_sign.md` flow §4; decompiled
  `com/thingclips/sdk/network/pbddddb.java`).

## 2. cmd dispatch inside doCommandNative (confidence: confirmed)

Two independent sources: the disassembly AND the Java init/sign cmd codes
(`ThingNetworkSecurity` cmd-0 init vs `pbddddb` cmd-1 sign, `re/tuya_sign.md` §"key…").

- `doCommandNative` (`libthing_security.so@0x13ed8`, 4896 bytes) saves the `int` cmd
  arg (`arg4`) into `w24` (`@0x13f18 mov w24, w3`) and dispatches on it
  (`@0x14428 cmp w24, 2` ; `@0x14434 cmp w24, 1` ; `@0x1443c cbnz w24, …` → 0 falls
  through):
  - **cmd 0** (init) and **cmd 1** (sign) and **cmd 2** all first convert the input
    `byte[]` to a native `std::string` via JNIEnv vtable slots (`[x8,0x5c0]`
    GetByteArrayElements-class, `[x8,0x558]` GetArrayLength) — `@0x14440…0x14610`.
  - All three then call **`read_keys_from_content`** (`@0x146b0`, an **imported**
    symbol resolved in `libthing_security_algorithm.so` — see §5) to split the
    decrypted SDK config blob into a labelled key list; the loop `@0x146d8…0x147e8`
    iterates the parsed keys (`securityOpen`, `data`, … — interned strings at
    `.rodata`, e.g. `@0x8dc2 "securityOpen"`, `@0x8f3e "data"`).
- The **cmd=1 sign tail** (`@0x14840…0x14894`): it builds the key-string, calls the
  MD5 key-builder `@0x13474` (`@0x14858 bl 0x13474`, see §3), and returns the result
  to Java as a `String` via JNIEnv `NewStringUTF` (`[x9,0x538]`, `@0x14890 blr`). The
  returned String is the wire `sign` parameter.

## 3. The keyed hash is plain MD5, NOT HMAC-SHA256 (confidence: confirmed)

This corrects TASK-0005's `likely HMAC-SHA256`. Two independent sources: the MD5
initial-state constants AND the 16-byte digest output width.

- The core digest is `fcn@0x13318` (called from the cmd=1 key-builder `@0x13474`
  twice, and from `computeDigest` `@0x15ad0`; xrefs confirmed by r2 `axt`). It:
  - inits state via `@0x18928` which loads a **24-byte** seed: 16 bytes from
    `@0x76c0` = `00·00·00·00 00·00·00·00 01·23·45·67 89·ab·cd·ef` and 8 bytes from
    `@0x9410` = `fe·dc·ba·98 76·54·32·10` + `80 00 00 …` padding marker. As 32-bit
    little-endian words those are **`0x67452301, 0xefcdab89, 0x98badcfe,
    0x10325476`** — the canonical **MD5 A/B/C/D initialization vector**.
  - updates via `@0x18944` (block feeder → 64-round compression `@0x18a0c`) and
    finalizes via `@0x194b0`, which writes **exactly 16 output bytes**
    (`strb` to `[x19+0]…[x19+15]`, `@0x19518…0x195a0`). 16 bytes ⇒ MD5 (not SHA-256's
    32, not SHA-1's 20).
  - `fcn@0x13318` then hex-encodes those 16 bytes to a 32-char lowercase string using
    the table `@0x7810 "0123456789abcdef"` (high nibble then low nibble per byte,
    loop `cmp x21, 0x10`).
- There is **no HMAC construction** (no ipad/opad 0x36/0x5c key-XOR), and no
  `mbedtls_md_hmac*`/`mbedtls_sha256*` is exported or called on the sign path — the
  only crypto exported by `libthing_security.so` is the mbedtls **cipher/AEAD** suite
  (`mbedtls_aes_*`, `mbedtls_gcm_*`, `mbedtls_base64_*`; `readelf --dyn-syms`, 153
  exported FUNCs, no `_md`/`_sha`/`_hmac`), used to decrypt the SDK config blob, not
  to sign. The "keying" is purely **MD5 over a concatenation that includes the
  derived key material** — Tuya's classic `MD5(key_parts || data)` mobile sign, the
  same family `nalajcie/tuya-sign-hacking` documents (F1).

> Cross-source note: TASK-0005 labelled the primitive `likely HMAC-SHA256` from the
> presence of the `SHA256` string + the F1 prose. The disassembly **refutes
> HMAC-SHA256 for the keyed sign**: the `SHA256` string is used for the *cert hash*
> (§4, a Java callback), while the keyed sign itself is MD5. This contradiction is
> resolved in favour of the disassembly (the stronger, byte-level source).

## 4. Key combine = underscore-joined; cert-SHA256 is offline-computable (confidence: confirmed)

Two independent sources: the underscore-separator concatenation in the disassembly
AND F1's `[cert_sha256]_[bmp_token]_[appSecret]`.

- The key-string is assembled by **underscore concatenation** in native: the literal
  `"_"` is `@0x88c4` (used in `computeDigest@0x15ad0` `@0x15b60-0x15b6c` and the
  key-builder), and `doCommandNative` writes a `'_'` byte (`@0x14c30 mov w12, 0x5f`,
  `@0x14c34 strh` then `basic_string::append`) between parts pulled from runtime
  std::string globals `@0x39058/0x39070/0x39088/0x390a0` (populated from the parsed
  config + the cert hash + appSecret). This is exactly F1's `_`-separated key
  (`re/review_gate_findings.md:16`).
- The **app-cert SHA-256** key part is produced by a **JNI callback into Java**, not
  in native crypto: `libthing_security.so` `.data` carries the reflection strings
  `getPackageManager`/`getPackageInfo` (`@0x38a64`) / `[Landroid/content/pm/Signature;`
  / `generateCertificate` (`@0x38b7b`) / `java/security/cert/X509Certificate` /
  `java/security/MessageDigest` (`@0x38bfc`) / `(Ljava/lang/String;)Ljava/security/MessageDigest;`
  / `SHA256` + `digest([B)[B` (`@0x38c4a`). i.e. native does
  `getPackageInfo(GET_SIGNATURES).signatures[0]` →
  `CertificateFactory.generateCertificate` →
  `MessageDigest.getInstance("SHA256").digest(certBytes)` → hex.
- **This removes the "runtime cert" blocker:** the same SHA-256 is computable OFFLINE
  from the APK's own v1 signing cert. The base APK ships
  `META-INF/BNDLTOOL.RSA` (PKCS#7); SHA-256 over the DER-encoded X509 leaf yields the
  64-hex value. Verified in TASK-0023 to produce a 64-char digest (value withheld;
  method + location recorded in `secrets/tuya_appkey.json:app_cert_sha256`). NB: Tuya
  uses the **hex string** of the cert hash as the key part, not raw bytes (the native
  path hex-encodes before concatenation).

## 5. t_s.bmp token decode = imath bignum + matrix (THE residual blocker) (confidence: confirmed)

> **NOTE (TASK-0030, REINSTATES the imath-matrix model below).** An intermediate
> TASK-0029 "correction" claimed the imath/matrix path decodes only the SDK-config
> blob and that `t_s.bmp` is decoded by a separate white-box cipher. **Both halves of
> that were wrong** and are retracted:
> (1) `fcn.11658` is **standard AES-128-CBC** (not a white-box); its output is the
>     **TLS cert-pinning config**, keyed by MD5(`t_s.bmp`) — `re/bmp_token_whitebox.md`.
> (2) `t_s.bmp` has **TWO** code xrefs; the second (`fcn.13b5c` @ `0x13bf0`, on the
>     cmd=1 sign path) reads the raw `t_s.bmp` bytes and feeds them as the key material
>     to `read_keys_from_content` → the imath matrix (`fcn.5eb0`). So the matrix below
>     **IS** the `t_s.bmp` token decode — the original model in this section is
>     CORRECT. See `re/bmp_token_whitebox.md` §6/§8 for the JOB-1 trace. The paragraphs
>     below stand, with addresses now corroborated; the residual remains the un-ported
>     bignum + matrix.

Two independent sources: the SignFileDecoder asset-read in `libthing_security.so` AND
the imath/matrix exports of `libthing_security_algorithm.so`.

- `security_infra::SignFileDecoder` (mangled
  `..._ZN…security_infra15SignFileDecoder…`, vtable/ctor `@0x199ac`) reads the asset:
  `fcn@0x199d8` calls `AAssetManager_open(…, "t_s.bmp")` (`@0x86c0`),
  `AAsset_read`, then post-processes the pixels via `fcn@0x195cc` (which itself
  MD5-hex's a buffer through the same `@0x18928/0x18944/0x194b0` MD5 routine). The
  decode math `fcn@0x19cf0` uses `pow` (`@0x19dac`) — polynomial evaluation.
- The heavy lifting is in **`libthing_security_algorithm.so`**, which exports the
  **imath** multiple-precision library (`mp_int_init`, `mp_int_mul`, `mp_int_div`,
  `mp_int_exptmod` (modular exponentiation), `mp_int_invmod`, `mp_int_read_string`,
  … ; `readelf --dyn-syms`) plus three high-level functions: `read_keys_from_content`
  (`@0x4974`, the cmd-dispatch callee from §2), `parse` (`@0x4eec`, delimiter-splits
  via `strchr` then transforms), and `transform` (`@0x6c58`). The matrix init/deobf
  is `fcn@0x5eb0` (1864 bytes; prints `"inited matrix:"` `@0x2b30`; dense `mp_int_*`
  calls) — a **linear-algebra / modular-exponentiation deobfuscation** of the BMP
  pixel data into the token. This is the embedded-BMP + matrix mechanism F1 /
  `nalajcie/tuya-sign-hacking` (`re/review_gate_findings.md:18`) reverses.
- **Reproducibility:** the decode is fully **deterministic** — it depends ONLY on the
  static `assets/t_s.bmp` and the embedded matrix constants, with **no runtime
  input**. So it *can* be ported to Rust/python in principle (re-implement imath
  bignum + the matrix `transform`, or emulate these ~6 functions). It is NOT defeated
  by anti-debug or device binding. But it is non-trivial (full bignum + matrix port,
  exact constant extraction) and was not completed within this spike → the single
  residual that keeps the verdict at `partially-recoverable`. Filed as a follow-up
  task.

## 6. What is / isn't statically reproducible (confidence: confirmed — scoping summary)

| Ingredient | Static? | Evidence |
|---|---|---|
| String-to-sign (sort/whitelist/`\|\|`/postData-MD5/swap) | **YES** | `ThingApiSignManager` (`re/tuya_sign.md` §1-3; TASK-0005) |
| appKey / appSecret / TTID | **YES** | `BuildConfig` + `SmartApplication` wiring (TASK-0005) |
| Keyed-hash primitive | **YES — plain MD5 (hex)** | MD5 IV `libthing_security.so@0x76c0`; 16-byte out `@0x194b0`; hex `@0x7810`; §3 |
| Key-combine order/separator | **YES — `_`-joined** | `"_"` `@0x88c4`; `'_'` write `@0x14c30`; §4 |
| App-cert SHA-256 (key part) | **YES — offline from APK cert** | `META-INF/BNDLTOOL.RSA` + openssl/`MessageDigest("SHA256")` strings `@0x38bfc/0x38c4a`; §4 |
| `t_s.bmp` token decoded value | **NO (not ported)** but deterministic & reproducible-in-principle | imath `mp_int_*` + matrix `@0x5eb0`, `SignFileDecoder@0x199d8`; §5 |

Because 5 of 6 ingredients are statically recovered/portable and only the BMP-token
decode remains (deterministic, device-independent, but un-ported), the verdict is
**partially-recoverable**, not `not-statically-recoverable` and not yet
`recoverable-statically`.

## 7. Precise algorithm for the Rust port (TASK-0012) (confidence: likely)

`likely` because the exact ordering of the underscore-joined parts and whether the
hash input also folds the canonical string (vs only the key) was read from the
control-flow shape, not executed; a single differential vector (below) pins it.

```
sign = MD5_hex_lower(  cert_sha256_hex                    # §4, offline from APK cert
                     + "_" + bmp_token                    # §5, from t_s.bmp matrix decode
                     + "_" + appSecret                    # secrets/tuya_appkey.json
                     [ + canonical_string ] )             # the sorted-whitelist "||"-joined str2
```
- `MD5_hex_lower` = standard MD5 → 32-char lowercase hex (§3).
- `canonical_string` (`str2`) construction is already fully specified in
  `re/tuya_sign.md` §1-3 (sorted whitelist, `||` join, postData→`swapSignString(md5
  base64)`); reuse it verbatim.
- The native code computes MD5 **twice** in the cmd=1 key-builder (`@0x13474` calls
  `@0x13318` at `@0x134e0` and `@0x13534`) — consistent with `MD5(key) then
  MD5(key + str2)` or a two-field digest; the differential vector disambiguates.

**Differential vector (TESTING.md Part-2 signal #2):** an INDEPENDENT reference is
available WITHOUT a device — re-implement Tuya's documented mobile sign from
`nalajcie/tuya-sign-hacking` and compare byte-for-byte against our Rust signer on
fixed inputs once the bmp_token is ported. Until the bmp_token port lands, a partial
differential is still possible against the cert-hash+appSecret+MD5 sub-steps (feed a
known bmp_token placeholder and assert the MD5/hex/`_`-join steps match the reference
implementation). This is static and needs no network.

## 8. Limitations / honest gotchas (confidence: likely — caveats on the above)

- The `[+ canonical_string]` fold and the exact part order in §7 are inferred from
  control flow, labelled `likely`; only running the algorithm (or one captured
  request) makes them `confirmed`. The MD5 primitive, the `_` separator, and the
  offline cert-hash are `confirmed` (byte-level).
- The `t_s.bmp` matrix decode is reproducible *in principle* but UN-PORTED; a wrong
  bignum/matrix port silently yields a wrong token and thus a wrong signature with no
  local oracle until the differential reference (§7) is built. This is the real risk.
- Addresses are hints for this exact build (BuildIDs in the header note); a re-pull of
  a different APK version will shift them — re-anchor via the symbol/string landmarks
  (`t_s.bmp`, `inited matrix:`, the MD5 IV bytes, `read_keys_from_content`).
