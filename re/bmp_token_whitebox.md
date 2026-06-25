# `fcn.11658` reconstructed — it is **AES-128-CBC**, not a white-box (TASK-0030)

This supersedes the core claim of `re/bmp_token_decode.md` §3 ("white-box table
cipher, the wall"). Full instruction-level re-disassembly of
`libthing_security.so` fcn.11658 and its callers proves the transform is **standard
AES-128 in CBC mode**, written out in NEON intrinsics (no `aese`/`aesd`), with the
canonical AES tables sitting in `.rodata`. The cipher is therefore **fully ported and
validated**. A separate, honest residual remains about *which* decoded artifact the
request-signer consumes — see §6.

**No secret values appear here.** Any decoded value goes ONLY to `secrets/`.

> Symbol-anchored; addresses are hints for BuildID `444ecb4f…` (libthing_security.so).
> `.rodata` is mapped 1:1 (addr == file offset) for this build, so the table dumps in
> `re/aes_tables.txt` are reproducible with `objdump -s -j .rodata` / r2 `px @ADDR`.

---

## Status (confidence: confirmed)

Two independent sources: the instruction-level disassembly of
`libthing_security.so@0x11658` (the inverse cipher + key schedule @0x119e4), AND the
FIPS-197 known-answer cross-check (`github.com/usnistgov/ACVP`) reproduced in
`re/scripts/test_bmp_token_aes.py` — an external oracle for the AES core.

**Decode: fully-ported-validated** (the cipher) — `re/scripts/bmp_token_aes.py`.

- The AES-128-CBC decryptor is byte-exact: its S-boxes are the literal `.rodata`
  bytes (`re/aes_tables.txt`, cross-checked against the `.so` in a unit test), it
  passes the **FIPS-197 known-answer vector** (an independent oracle), and decrypting
  the real `tecrkcehc_ext` with key = MD5(`t_s.bmp`), IV = the embedded constant
  yields **well-formed JSON** (a near-impossible-by-chance structural oracle — a
  wrong key/IV/mode produces garbage).
- **Caveat (the honest part):** the decrypted blob is the **TLS cert-pinning config**
  `{"securityOpen": bool, "data": [sha256_pin_1, sha256_pin_2]}`, NOT the
  request-signer's `bmp_token`. This AES path is **one of TWO** `t_s.bmp` consumers
  (see the ERRATUM below); the OTHER consumer (`fcn.13b5c`, on the cmd=1 sign path)
  is the one that produces the signer's middle `_`-part, via the imath-bignum + matrix
  decode in `libthing_security_algorithm.so` (JOB-1, TASK-0030, §6). So the
  AES/cert-pinning finding stands, AND the signer's `bmp_token` lives on a separate,
  still-unported path. The signer (TASK-0012) is therefore **not yet offline-unblocked
  by a *confirmed value*** — but the path IS statically characterized end-to-end
  (deterministic, device-independent); see §6 + the feed-forward.

> **ERRATUM (TASK-0030, this revision).** An earlier version of this doc (and the
> commit-`5967f77` message) claimed `t_s.bmp` has **exactly ONE** code xref (the AES
> path) and concluded the "separate t_s.bmp → sign token" model was unsupported. That
> was **WRONG**, caused by an un-analysed `axt`. `r2 axt @ str.t_s.bmp` (relocs
> applied) returns **TWO** code xrefs: (1) `0x19a64` in `fcn.199d8` — the AES
> cert-pinning path (correct), and (2) `0x13bf0` in `fcn.13b5c` — a raw-bytes reader
> called from `doCommandNative` (`fcn.13ef4`) at `0x1466c`, ON the cmd=1 sign path.
> There is also a `t_s_daily.bmp` sibling string (`0x912b`, ref `0x13bfc` in the same
> `fcn.13b5c`), runtime-selected by a boolean flag. So `t_s.bmp` **does** feed the
> sign path — corroborating, not undermining, the F1 model. The single-xref claim is
> retracted.

---

## 1. The call chain and the I/O (confidence: confirmed)

Two independent sources: the driver disassembly `libthing_security.so@0x1a030` (the
call sequence + arg setup) AND the on-disk assets `assets/t_s.bmp` / `assets/tecrkcehc_ext`
whose sizes/shape match the parse (256-byte ciphertext, `226\n` header).

`security_infra::SignFileDecoder` driver `libthing_security.so@0x1a030`:

| step | addr | action |
|---|---|---|
| read BMP | `fcn.199d8` | `AAssetManager_open("t_s.bmp"@0x86c0)` → `AAsset_read`; **MD5** the raw bytes via `fcn.195cc` → 16 RAW digest bytes stored as the std::string at **ctx+0x60** (SSO len byte `0x20`→len 16; bytes copied verbatim, **NOT hex**) |
| read ext | `fcn.19bf4` | `AAssetManager_open("tecrkcehc_ext"@0x8bb2)` → raw bytes at ctx+0x78, len at ctx+0x80 |
| parse+b64 | `fcn.19cf0` | parse leading decimal (`226`, stored ctx+0x14, via `pow(10,·)`); base64-DECODE the body (`fcn.196bc`→`fcn.2e7b0`, alphabet @0x9dc7) into the **256-byte ciphertext** at **ctx+0x30** |
| const | — | load `"7178265647164836"` @`.rodata 0x85f5` (16 ASCII bytes) onto the stack |
| decrypt | `fcn.19810`→`fcn.11570`→`fcn.11658` | AES-128-CBC-decrypt(ciphertext = ctx+0x30, key = ctx+0x60, iv = constant) → plaintext into ctx+0x48 |
| truncate | `fcn.1a030` | copy the first `226` (ctx+0x14) bytes out — the decoded blob |

Arg mapping into the worker (verified at the call sites): `fcn.19810(arg1=ciphertext,
arg2=key, arg3=iv, arg4=out)` → `fcn.11570(out, len, key, iv, …)` →
`fcn.11658(out, in=ciphertext, count=len, key=arg4, iv/prev=arg5)`.

## 2. fcn.11658 = AES-128 inverse cipher (confidence: confirmed)

Two independent sources: the NEON disassembly `libthing_security.so@0x11658` (the
round body + InvMixColumns at @0x11abc), AND the FIPS-197 known-answer vector
(`github.com/usnistgov/ACVP` AES-128 KAT) that the ported round function reproduces in
`re/scripts/test_bmp_token_aes.py` — an external oracle independent of this `.so`.

- **InvSubBytes:** `ldrb w9, [x20, x9]` with `x20 = adr 0x7a5f` — the **inverse
  S-box** (`52 09 6a d5 …`, `re/aes_tables.txt`), applied to each state byte.
- **InvShiftRows:** the cross-index byte permute at `0x11b14…0x11bd0` (e.g. byte 0xd
  ← processed into slot 1, etc.) is the inverse row rotation.
- **InvMixColumns:** `fcn.11abc` loads 4 columns, doubles via `add v.4h, v.4h, v.4h`
  (xtime) with the `movi v8.4h, 0x1b` GF(2⁸) reduction polynomial and `cmlt`/`and`
  conditional reduce, then eor-mixes — the `{0e,0b,0d,09}` matrix.
- **Rounds:** counter `w19 = 9` (`0x11aec`), looped down at `0x11b0c` → 9 main rounds +
  a final round = **AES-128's 10 rounds**.
- **AddRoundKey:** `eor v0.16b, v1.16b, v0.16b` against the expanded round key.
- **CBC:** after the inverse cipher, each 16-byte block is XORed with the previous
  ciphertext block (`x22`, seeded with the IV) — textbook CBC decryption.

## 3. fcn.119e4 = AES-128 key expansion (confidence: confirmed)

Two independent sources: the disassembly `libthing_security.so@0x119e4` (the 40-word
loop + SubWord/Rcon) AND the key material it ingests, `assets/t_s.bmp` (its raw MD5 is
the 16-byte key), whose 16-byte digest length matches the single `ldr q0` the schedule
reads.

Reads the 16-byte key from ctx (stored at `.data 0x38f68`), runs `0x28` (40) word
iterations (→ 44 total words = AES-128), SubWord via the **forward S-box @0x795f**
(`63 7c 77 7b …`), Rcon from the power table @`0x7860`
(`8d | 01 02 04 08 10 20 40 80 1b 36 …`), writes the 176-byte expanded key to
`.data 0x38f70`. This is standard `KeyExpansion` for AES-128.

## 4. fcn.11570 = lock wrapper (confidence: likely)

Source: the disassembly `libthing_security.so@0x11570` (lock/malloc/fallthrough → the
worker §2). Labelled `likely` (single source, not load-bearing for the cipher).

`pthread_mutex_lock` (`0x38f2c`), `malloc`, an optional hook fn-ptr at `.data 0x38f58`
(null in this build → fallthrough), then `fcn.11658`, then unlock. No crypto of its own.

## 5. The extracted tables (confidence: confirmed)

Two independent sources: the live `.so` bytes `libthing_security.so@0x795f` /
`@0x7a5f` AND the FIPS-197 canonical AES S-box (`github.com/usnistgov/ACVP`) — the
committed dump in `re/aes_tables.txt` is asserted equal to BOTH in
`re/scripts/test_bmp_token_aes.py`.

`re/aes_tables.txt` holds the two 256-byte S-boxes verbatim from `.rodata` @0x795f
(forward) and @0x7a5f (inverse). They are the canonical, mutually-inverse AES S-boxes
(asserted in `re/scripts/test_bmp_token_aes.py`). The Rcon power table @0x7860 and the
GF reduction constant `0x1b` are encoded directly in the port. The port loads the
S-boxes from this committed dump, NOT from the gitignored `.so` at runtime.

## 6. What the decrypted blob actually is, and the residual (confidence: confirmed)

Two independent sources: the decrypted output of the real `assets/tecrkcehc_ext` (valid
JSON, asserted in `re/scripts/test_bmp_token_aes.py`) AND the lib's own interned JSON
keys `libthing_security.so@0x8dc2` ("securityOpen"). (`t_s.bmp` has TWO xrefs, not one —
see the ERRATUM in Status; this AES path is the `0x19a64` one.)

Decrypting the real `tecrkcehc_ext` yields valid JSON:
`{"securityOpen": <bool>, "data": ["<sha256-fingerprint>", "<sha256-fingerprint>"]}`
where each `data` entry is a 95-char colon-separated SHA-256 fingerprint (32 hex bytes,
31 colons). This is a **TLS certificate-pinning config**.

Consequences for the request signer (TASK-0012):

- `t_s.bmp` has **TWO** consumers (ERRATUM): the AES cert-pinning path (`0x19a64`,
  this doc) AND the sign path (`fcn.13b5c` @ `0x13bf0`, called from `doCommandNative`
  @ `0x1466c`). The cert-pinning blob this AES path produces is **NOT** the signer's
  `bmp_token`. The F1 model (`cert_sha256 _ bmp_token _ appSecret`) is therefore
  **CORROBORATED**, not undermined.
- The signer's middle `_`-part is produced on the sign path: `fcn.13b5c` reads the
  **raw `t_s.bmp` bytes** (a verbatim `std::string` of the BMP file — no MD5/base64),
  which `doCommandNative` then passes as the key-material argument (`x3`) to
  `read_keys_from_content` (`libthing_security_algorithm.so@0x4974`).
  `read_keys_from_content` validates the BMP header (`fcn.4a34`), takes the **pixel
  array from offset 54** (`bmp+0x36`), and uses it to drive the **imath-bignum +
  matrix** deobfuscation (`fcn.4b28` → `fcn.5138`/`fcn.54f4` → matrix `fcn.5eb0`,
  "inited matrix:") that decodes the SDK-config blob into the labelled key list, which
  then feeds the cmd=1 MD5 key-builder (`fcn.13474`). Full JOB-1 trace below in §8.
- **BmpToken: partially (statically-recoverable-in-principle, not yet ported).** The
  decode is fully **deterministic and device-independent** — it depends only on the
  static `t_s.bmp` pixels + the static config blob + the embedded matrix constants,
  with no runtime/network input. So it CAN be ported offline, but doing so requires
  porting the imath bignum + the matrix `transform` (the same residual already
  characterized in `re/tuya_sign_static.md` §5). This is the original F1 "imath
  matrix" model — now confirmed to be on the t_s.bmp sign path.

**What WOULD shortcut the port:** one captured/accepted live sign (the TASK-0012 AC#3
contingency) pins the middle `_`-part in one place
(`sign::tests::full_signature_byte_parity_pending_task_0030`) and resolves the
`SignBody`/postData ambiguities simultaneously — cheaper than the bignum/matrix port,
but the port is the fully-static route.

## 7. Port + validation summary (confidence: confirmed)

Two independent sources: the per-claim disassembly anchors in the table below
(`libthing_security.so@0x11658`, `@0x195cc`, `@0x85f5`, …) AND the FIPS-197 KAT
(`github.com/usnistgov/ACVP`) + clean-JSON structural oracle in
`re/scripts/test_bmp_token_aes.py`.

| Claim | Evidence | Confidence |
|---|---|---|
| fcn.11658 = AES-128 InvCipher | inv S-box @0x7a5f, InvMixColumns 0x1b NEON, 10 rounds; §2 | confirmed |
| CBC mode | per-block XOR with prev ciphertext (`x22`), IV-seeded; §2 | confirmed |
| key = raw MD5(t_s.bmp) (16B) | fcn.195cc stores 16 raw digest bytes at ctx+0x60; §1 | confirmed |
| IV = "7178265647164836" | `.rodata 0x85f5`, 16 ASCII bytes; §1 | confirmed |
| ciphertext = b64-decode(ext body) | fcn.19cf0 → fcn.196bc → fcn.2e7b0; 256 bytes; §1 | confirmed |
| AES core correct | FIPS-197 KAT passes; `.so` S-box byte-match; clean-JSON oracle | confirmed |
| decrypted blob = cert-pin JSON | `{"securityOpen",…,"data":[2×sha256]}`; §6 | confirmed |
| blob == signer's bmp_token | NO — they are on different `t_s.bmp` consumers (ERRATUM, §6, §8) | confirmed |
| signer bmp_token = raw-`t_s.bmp` → imath matrix decode | `fcn.13b5c`→`read_keys_from_content`→matrix `fcn.5eb0`; §8 | confirmed |
| signer bmp_token ported offline | imath bignum + matrix un-ported (deterministic, device-independent) | **partially** |

Decode (cert-pinning AES path): fully-ported-validated. BmpToken (signer middle
`_`-part): partially (statically-recoverable-in-principle; imath-bignum + matrix
un-ported) — see §8.

## 8. JOB-1: the SECOND `t_s.bmp` consumer — the sign path (confidence: confirmed)

Two independent sources: the instruction-level disassembly of `fcn.13b5c`,
`doCommandNative` (`fcn.13ef4`), and `read_keys_from_content`
(`libthing_security_algorithm.so@0x4974`) cited inline, AND the on-disk `t_s.bmp`
(22554 bytes, `BM` magic, `bfOffBits`=54, 24bpp) whose header exactly satisfies the
validator `fcn.4a34`'s checks.

**`fcn.13b5c` returns the RAW `t_s.bmp` bytes (no transform):**
- `Context.getAssets()` (JNI, `@0x13bb0` "getAssets") → `AAssetManager_fromJava`
  (`@0x13be8`).
- Asset name select (`@0x13bf4`): `tst w20, 1` ; `csel x1, x9, x8, ne` with
  `x8="t_s.bmp"`(`0x86c0`), `x9="t_s_daily.bmp"`(`0x912b`). So **(flag & 1)!=0 →
  `t_s_daily.bmp`, else `t_s.bmp`**. `w20` = `arg3`, set by `doCommandNative` at
  `0x1465c` as `cset w2, ne` from the JNI **boolean `Z`** parameter
  (`(Context,int,[B,[B,Z)` — `arg7`). `t_s_daily.bmp` is **NOT shipped** in this APK
  ⇒ production uses `t_s.bmp` (flag = false).
- `AAssetManager_open` → `AAsset_getLength` → `malloc(len)` → `AAsset_read`
  (`@0x13c08…0x13c30`), then builds a `std::string` of the bytes via SSO (`@0x13c48`,
  len<23) or heap (`@0x13c60`) + `memcpy` (`@0x13c88`). **No MD5, no base64, no slice
  — the verbatim file bytes are returned** (NRVO into `x8`/`x19`).

**`doCommandNative` (`fcn.13ef4`, cmd=1 sign) uses those raw bytes as MATRIX KEY
MATERIAL:**
- Dispatch (`@0x14428`): `cmp w24,2 → 0x14500` (cmd2) ; `cmp w24,1 → 0x144a0`
  (**cmd1 sign**) ; `cbnz w24 → 0x14dfc` (cmd0 fallthrough). cmd 0/1/2 converge at the
  `0x14500…0x145f8` block.
- `@0x14600` GetByteArrayElements / `@0x14620` GetArrayLength on the input `byte[]`
  (the SDK-config blob), copied via `calloc`+`memcpy` into `x28` (`@0x14640`).
- `@0x1466c`: **`bl fcn.13b5c`** with `x2 = (Z flag)` → raw `t_s.bmp` string at
  `x29-0xc8`.
- `@0x146b0`: **`bl read_keys_from_content`** with `x0=x28` (config blob),
  `x2`=out-count, `x1`=out-keylist, **`x3` = the raw `t_s.bmp` bytes** (the matrix key
  material).
- The parsed key list (`@0x146d8…0x147e8` loop over `securityOpen`/`data`/… entries)
  then feeds the cmd=1 MD5 key-builder (`@0x14858 bl fcn.13474`, §3 of
  `re/tuya_sign_static.md`), result returned via `NewStringUTF` (`@0x14890`).

**`read_keys_from_content` (`@0x4974`) consumes the BMP pixels:**
- `arg4` (the raw `t_s.bmp` bytes) → validate header `fcn.4a34` (checks `BM`,
  filesize bounds, `bfOffBits == filesize-0xe-0x28`, 24/32 bpp, compression 0).
- Computes `pixel_len = [bmp+2] - [bmp+0xa]` (filesize − pixel offset) and passes
  `bmp + 0x36` (pixel array, offset **54**) + `pixel_len` to `fcn.4b28`.
- `fcn.4b28`: string-hashes the config blob (`fcn.509c`, `h=h*31+byte`), indexes a
  **selector byte from the pixel data** at `((h % pixel_len)/2) % pixel_len`, and
  dispatches on it: `1 → fcn.5138`, `2 → fcn.54f4` (else error). **Both** call the
  matrix init/deobf `fcn.5eb0` ("inited matrix:" `@0x2b30`, dense `mp_int_*`) — the
  imath-bignum + matrix decode of the config using the BMP pixels.

**Verdict (§8, as of TASK-0030, radare2) — `BmpToken: partially`
(statically-recoverable-in-principle, un-ported).** Superseded in part by §9 below
(the §8 claim of "no runtime input / static config blob" is **CORRECTED** by the
Ghidra port: the config blob is a RUNTIME JNI `byte[]`, not a static asset).

## 9. The Ghidra-C BYTE-EXACT port + the runtime-config finding (TASK-0033, confidence: confirmed)

Two independent sources: **Ghidra 11.4.2 headless** C decompilation of all nine
functions in the decode chain (committed under `re/ghidra/*.c`) AND the radare2
disassembly of `libthing_security_algorithm.so@0x5138` (used to resolve two
offset-walk arguments Ghidra elided). The port is `re/scripts/bmp_token_ghidra.py`
(+ `test_bmp_token_ghidra.py`, 16 tests). Ghidra invocation that worked:

```
ghidra-analyzeHeadless analysis/ghidra bmptok \
  -import decompiled/nativelibs/libthing_security_algorithm.so \
  -scriptPath analysis/ghidra -postScript DumpDecomp.py re/ghidra <name|name@0xADDR ...>
# (Ghidra applies image base 0x100000; pass file-offset+0x100000 for raw addresses.
#  Re-import the SECOND lib into the SAME project with a separate -import run.)
```

**The algorithm, now fully resolved from Ghidra C:**
- `read_keys_from_content(config, &keys, &count, bmp)` → `header_check` (`'BM'`;
  `0x2800≤filesize<0x200001`; `filesize-0x36 ≥ bfOffBits`; bpp∈{24,32}; comp==0) →
  `dispatch_decode(config, …, pixels=bmp+0x36, pixel_len=filesize-bfOffBits)`.
- selector: `h=strhash(config)` (`acc=acc*31+byte`, signed int32, abs); `r=(h%L)//2`;
  `idx=r%L`; `sel=pixels[idx]`; `1→decode_op1`, `2→decode_op2`, else error 0x15.
- `decode_op1/op2`: `num_keys=pixels[(base+1)%L]` (1..5), `num_coeffs=pixels[(base+2)%L]`,
  then read `num_coeffs` `(a,b)` coefficient pairs from the pixels along a chained
  offset (start `= xorstep_u32(px,base+1) ^ r`, XOR-stepped per pair by `xorstep_583c`
  = 4 pixel bytes packed big-endian). op1 takes value bytes **directly** from pixels;
  op2 reconstructs each byte **bit-by-bit from the LSB of 8 consecutive pixel bytes**
  (steganographic LSB packing). Each value is `%02x`-formatted → a base-16 string.
- `matrix_fcn5eb0` (+ `matrix_init`): builds a **Vandermonde** system over exact
  rationals (imath `mp_rat`): row i `= [a_i^(n-1)…a_i^1, 1 | b_i]`, `a_i,b_i =
  mp_rat_read_string(hex, base 16)`; Gaussian elimination with partial pivoting;
  solved final unknown `c = lastrow[n]/lastrow[n-1]`, **REDUCED and REQUIRED integral**
  (`mp_int_compare_value(denom,1)==0`, else error 0xb); output key `= "%02x"` of
  `mp_int_to_binary(numerator)` (leading 0x00 stripped). `transform@0x6c58` is a
  **no-op stub** (`return 0`) in this build — it does NOT post-process the key.

**Ghidra-vs-radare2 cross-check:**
- **AGREE** on the entire algorithm-lib chain (read_keys_from_content → fcn.4a34 →
  fcn.4b28 → fcn.5138/fcn.54f4 → fcn.5eb0; pixels @ offset 54; selector walk). Ghidra
  **ADDS** the exact math r2 only characterized: the Vandermonde build, the
  exact-rational elimination, the denominator==1 gate, the `transform` no-op, and the
  op1-vs-op2 byte-sourcing difference (direct bytes vs LSB packing).
- **DIVERGENCE (recorded):** §8 (r2) put the `fcn.13b5c` raw-BMP read +
  `read_keys_from_content` calls on the **cmd=1** sign branch of `doCommandNative`.
  Ghidra's `doCommandNative.c` shows they are on the **cmd=0** branch (`param_4==0`):
  **cmd=0 runs the BMP decode**, joins the key list with `'_'` (the `0x5f` write at
  `0x114c30`) into the cached global key (`DAT_00139070`), and **cmd=1/cmd=2 then MD5
  that CACHED key** with the request data. End-to-end model unchanged (raw t_s.bmp →
  read_keys_from_content → key list → `_`-joined → MD5); only the cmd-number that
  triggers the decode is corrected (cmd=0 setup, not cmd=1).

**CORRECTION to §5/§8 — the decode is NOT purely static:** Ghidra shows the `config`
argument to `read_keys_from_content` is `param_6` of `doCommandNative` — a **runtime
JNI `byte[]`** (`GetByteArrayElements`/`GetArrayLength` @ vtable 0x5c0/0x558), NOT a
static asset. `strhash(config)` selects both the pixel offset AND (via `pixels[base+1]`)
whether the header is valid. Empirically, for arbitrary/static config strings
`pixels[base+1]` is almost always >5 → the validator rejects (asserted in
`test_arbitrary_static_config_does_not_yield_valid_header`). So the earlier "depends
only on static t_s.bmp + matrix constants, no runtime input" claim is **REFUTED**:
the production token additionally requires the **runtime SDK-config blob**. The matrix
machinery itself is fully ported and runs end-to-end on a synthetic crafted BMP+config
(`test_synthetic_bmp_full_decode_runs`).

**Verdict — `Decode: fully-ported-unvalidated`.** The imath+matrix decode is now
ported byte-exact (Ghidra C primary source, r2-confirmed), with NO static oracle in
the `.so` (no embedded test vector); the only true oracle is a live sign-accept
(excluded by scope). The residual is no longer "port the matrix" (done) — it is
**obtaining the runtime SDK-config `byte[]`** that `doCommandNative(cmd=0)` is called
with (where the Java/SDK layer constructs it). Until that blob is known, the
`BmpTokenProvider` stays `PendingBmpToken` (NOT wired to a fake). A single accepted
live sign remains the cheaper end-to-end oracle (contingency).
