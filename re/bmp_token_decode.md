# `t_s.bmp` → bmp_token decode — static port attempt (TASK-0029)

Closes the residual left open by `re/tuya_sign_static.md` §5: porting the Tuya
mobile-sign `bmp_token` decode to a verifiable OFFLINE implementation. This doc
records the **actual** decode pipeline of THIS APK (byte-level disassembly), how it
relates to the public reference `nalajcie/tuya-sign-hacking`, and the precise wall.

**No secret values appear here.** Any recovered token goes ONLY to
`secrets/tuya_appkey.json` by location.

> Citation note (symbol-anchored; line hints approximate, jadx/r2-run-dependent,
> **symbols are authoritative**). Native cites name a resolved symbol or a
> `lib*.so@0xADDR` for these exact builds: `libthing_security.so` BuildID
> `444ecb4f…`, `libthing_security_algorithm.so` BuildID `904862d9…`. `lib*.so` =
> `decompiled/nativelibs/*.so` (gitignored). A cross-`.md` reference is a navigation
> pointer, NOT an independent source. Verify with `readelf --dyn-syms` + r2 `pdf`.

---

## Status (confidence: confirmed)

> **SUPERSEDED BY TASK-0030 (`re/bmp_token_whitebox.md`). This whole doc is now
> HISTORICAL — read it as the earlier (TASK-0029) hypothesis, not live claims.** Two
> things below were WRONG:
> 1. §3 called `fcn.11658` an "un-portable white-box table cipher". It is in fact
>    **standard AES-128-CBC** (canonical AES S-boxes @0x795f/0x7a5f, InvMixColumns with
>    the 0x1b GF reduction, 10 rounds, CBC), now **fully ported and validated**
>    (`re/scripts/bmp_token_aes.py`, FIPS-197 KAT + clean-JSON oracle). Its output is
>    the **TLS cert-pinning config** `{"securityOpen",…,"data":[2×sha256]}` — read on
>    a DIFFERENT `t_s.bmp` consumer than the signer's `bmp_token`.
> 2. §1 claimed the imath **matrix** path is "unrelated to `t_s.bmp`". That is also
>    WRONG (TASK-0030 JOB-1): `t_s.bmp` has **TWO** code xrefs, and the SECOND
>    (`fcn.13b5c` @ `0x13bf0`, on the cmd=1 sign path) feeds the raw `t_s.bmp` pixels
>    INTO `read_keys_from_content` → the imath matrix. So the matrix DOES consume
>    `t_s.bmp`, and the §5-of-`tuya_sign_static.md` "imath matrix decodes t_s.bmp"
>    hypothesis was RIGHT after all. Read `re/bmp_token_whitebox.md` §6/§8 for the
>    corrected, unified model; the paragraphs below are retained only as the original
>    spike reasoning.

**Decode (cert-pinning AES path): fully-ported-validated. Signer bmp_token:
matrix ported (TASK-0033); production token needs the runtime SDK-config `byte[]`
— not static-only achievable (see `re/bmp_token_whitebox.md` §9).** The earlier
"partially (un-ported, imath matrix)" label is doubly stale: the matrix IS now
ported, and the residual is the **runtime JNI `byte[]` SDK-config**
(`doCommandNative param_6`), not the port. The AES transform (`fcn.11658`) is byte-exact
and validated, but its OUTPUT is the cert-pinning config — NOT the signer's
`bmp_token`. The signer's `bmp_token` is produced on the OTHER `t_s.bmp` consumer
(`fcn.13b5c` → imath matrix), characterized end-to-end but un-ported
(`re/bmp_token_whitebox.md` §8). (The historical §3 "white-box wall" verdict is
retracted; the §1 "matrix unrelated to t_s.bmp" conclusion is also retracted.)

**One-line justification (corrected):** `t_s.bmp` has two consumers — (a) the AES
cert-pin path (`fcn.199d8`→`fcn.11658`, keyed by MD5(t_s.bmp)) and (b) the sign path
(`fcn.13b5c`→`read_keys_from_content`, the raw pixels driving the imath matrix
`fcn.5eb0`). The body of THIS doc earlier wrongly merged these; read the whitebox
doc for the unified model.

Two independent sources ground this corrected Status: (1) the byte-level disassembly
in `libthing_security.so@0x13bf0` (the second `t_s.bmp` xref in `fcn.13b5c`, with the
AES path at `libthing_security.so@0x11658`), AND (2) the on-disk asset
`assets/t_s.bmp` (22554-byte `BM`, `bfOffBits`=54, 24bpp) whose header satisfies the
validator `fcn.4a34` that gates the imath-matrix decode.

---

## 1. [HISTORICAL — partly WRONG] "the two decode paths are distinct" (confidence: speculative)

> **RETRACTED by TASK-0030 JOB-1.** This section concluded the imath matrix is
> "unrelated to `t_s.bmp`". That conclusion was WRONG: it missed the SECOND `t_s.bmp`
> xref (`fcn.13b5c` @ `0x13bf0`), which reads the raw BMP bytes and passes them as the
> matrix key material into `read_keys_from_content`. The matrix DOES consume
> `t_s.bmp` pixels. See `re/bmp_token_whitebox.md` §8. The original reasoning is kept
> below for the record.

(Original TASK-0029 reasoning, retained:)

- The imath/matrix function `read_keys_from_content` is **imported** into
  `libthing_security.so@0x2e600`; its caller is the cmd-dispatch
  `libthing_security.so@0x13ef4` (= `doCommandNative`, the SDK-config-blob parser,
  `re/tuya_sign_static.md` §2). [The earlier draft inferred "no t_s.bmp edge" — but
  `doCommandNative` itself feeds the raw `t_s.bmp` bytes to `read_keys_from_content`
  via `fcn.13b5c` at `0x1466c`; see §8 of the whitebox doc.]
- The matrix input was read as a **comma-separated** coefficient string: `parse`
  (`libthing_security_algorithm.so@0x4eec`) splits on `','` (`strchr` for `0x2c`)
  into 16-byte (a,b) structs — it consumes the decrypted config blob, keyed by the
  BMP pixels.
- Conclusion (now corrected): the imath **matrix** IS the F1 / `nalajcie` BMP-token
  decode, and it IS driven by `t_s.bmp`. The §5-of-`tuya_sign_static.md` "t_s.bmp uses
  the imath matrix" claim was CORRECT.

## 2. The recovered t_s.bmp pipeline (confidence: confirmed)

Two independent sources: the disassembled driver chain in `libthing_security.so`
AND the on-disk assets it reads (`t_s.bmp`, `tecrkcehc_ext`), whose structure
matches the parse.

`security_infra::SignFileDecoder` decode driver `libthing_security.so@0x1a030` runs:

1. **`fcn@0x199d8`** — `AAssetManager_open(…, "t_s.bmp")` (`@0x86c0`) → `AAsset_read`
   into a heap buffer, then MD5-hexes it via `fcn@0x195cc` (same MD5 routine as the
   signer, `re/tuya_sign_static.md` §3). t_s.bmp = 100×75×24bpp BMP, 22554 bytes,
   pixel array 22500 bytes (bfOffBits 54).
2. **`fcn@0x19bf4`** — `AAssetManager_open(…, "tecrkcehc_ext")` (`@0x8bb2`) →
   `AAsset_read` into `[ctx+0x78]`, length `[ctx+0x80]`. On disk this asset is
   `"226\n"` + a 344-byte base64 body.
3. **`fcn@0x19cf0`** — parses that buffer as **ASCII decimal digits**: base-10
   accumulate `result = digit*pow(10, pos) + result` (uses `double pow`, `@0x19dac`),
   stopping at the first `0x0a` newline; result stored at `[ctx+0x14]`. → integer 226.
4. An **embedded constant** `"7178265647164836"` is loaded from `.rodata`
   (`libthing_security.so@0x85f5`) into a local std::string.
5. **`fcn@0x19810`** calls the transform `fcn@0x11570` with (t_s-derived bytes, the
   ext payload, the constant, an output std::string), then copies the result bytes
   into the caller's output string `[x19]` (the `bmp_token`).

The framing in steps 1–4 (BMP offset access, the decimal parse, the constant) is
re-implemented and unit-tested in `re/scripts/bmp_token_decode.py`.

## 3. [HISTORICAL — WRONG] "the core transform is a white-box table cipher — the wall" (confidence: speculative)

> **RETRACTED by TASK-0030.** `fcn.11658` is **standard AES-128-CBC**, not an
> un-portable white-box; it is fully ported and validated
> (`re/scripts/bmp_token_aes.py`, `re/bmp_token_whitebox.md`). Its OUTPUT is the TLS
> cert-pinning config, not the signer's `bmp_token`. The "wall" framing below is the
> earlier (mistaken) hypothesis, retained for the record.

(Original TASK-0029 reasoning, retained:)

Two independent sources: the NEON table/substitution instructions in
`libthing_security.so@0x11658` AND the public reference
`nalajcie/tuya-sign-hacking`, whose documented BMP decode is a polynomial/matrix
solver — categorically unlike this pure table network, confirming the schemes differ.

- `fcn@0x11570` is a thin lock-wrapper: `pthread_mutex_lock`, `malloc`, an optional
  function pointer `[0x38f58]` (null in this build → fallthrough), then the worker
  `fcn@0x11658` (2220 bytes).
- `fcn@0x11658` is a **substitution-permutation / white-box table cipher**:
  - byte **substitution** via `tbl v0.16b, {v16.16b-v19.16b}, v0.16b`
    (`libthing_security.so@0x11e10`) — a 64-entry vector S-box lookup;
  - a large **T-table** load `ldr q1, [x9, 0x800]` with `x9 = adrp 0x7000`
    (`libthing_security.so@0x11b00`) → `.rodata@0x7800`, a structured 2KB+ table;
    further tables at `.data.rel.ro 0x38000` / `0x39000`;
  - dense **GF(2) linear mixing**: a long run of `eor v*.8b, v*.8b, v*.8b`
    (`libthing_security.so@0x11afc…0x11ddc`) — MixColumns-style diffusion.
- There are **no** hardware `aese`/`aesd` on this path and **no** `pow`/imath/matrix
  calls — it is a *software white-box* table network, not the public matrix solve.
- **Why it is the wall:** a full static port needs every T-table extracted byte-exact
  and the SPN round function (`fcn@0x11658`) reconstructed instruction-faithfully,
  with **no local oracle** to catch a one-byte error (the first correct check is the
  end-to-end Tuya sign differential, which itself needs this token). This is feasible
  in principle but is a large, brittle effort and was not completed.

## 4. Match to nalajcie / the independent cross-check (confidence: confirmed)

Two independent sources: the public reference's documented algorithm
(`re/review_gate_findings.md:24`, https://github.com/nalajcie/tuya-sign-hacking) AND
our faithful re-implementation of it, run against this APK's `t_s.bmp`.

- nalajcie reverses an **older** Tuya SDK whose BMP token is a `hash(clientId)→pixel
  offset` walk yielding `(a_i, b_i)` pairs, solved by **exact-rational polynomial
  interpolation** (Gaussian elimination over the rationals; reduced denominator must
  be 1; the numerator big-int is the token). Their `imath` use is `mp_int_*`/rational
  ops — the same family our `libthing_security_algorithm.so` exports
  (`mp_rat_div/mul/sub/reduce`, `mp_int_compare_value`, `mp_int_to_binary`;
  `readelf --dyn-syms`). **That matrix is real in our lib — but it is the config-key
  path (§1), not the BMP path.**
- `re/scripts/bmp_token_decode.py` re-implements nalajcie's scheme independently
  (`nalajcie_decode`) and its solver is validated on a planted known-vector
  (`test_recovers_planted_token`). Applied to this APK's `t_s.bmp`, it yields **no
  consistent token** (`test_matrix_scheme_does_not_apply`): the header bytes at the
  hashed offset are not a plausible `keys_cnt`/`coeffs_cnt`, confirming this APK does
  not use the matrix scheme. The cross-check is therefore non-circular: the
  reference is correct (known-vector passes) and provably inapplicable here.

## 5. What is / isn't recovered (confidence: confirmed — scoping summary)

| Piece | Recovered? | Evidence |
|---|---|---|
| t_s.bmp asset read | **YES** | `libthing_security.so@0x199d8` (`AAsset` "t_s.bmp" `@0x86c0`); §2 |
| `tecrkcehc_ext` framing (decimal len + base64 body) | **YES — ported+tested** | `libthing_security.so@0x19cf0`; asset on disk; §2 |
| native offset string-hash (acc*31+byte, abs) | **YES — ported+tested** | `libthing_security_algorithm.so@0x509c`; §4; nalajcie |
| embedded transform constant | **YES** | `libthing_security.so@0x85f5` "7178265647164836"; §2 |
| nalajcie matrix reference (cross-check) | **YES — ported+tested, inapplicable** | nalajcie ref; `re/scripts/bmp_token_decode.py`; §4 |
| ~~the white-box table cipher (token producer)~~ | **RETRACTED** — `fcn.11658` is AES-128-CBC (cert-pin config, not token); see whitebox doc | corrected |
| signer bmp_token = raw `t_s.bmp` → imath matrix | **NO — un-ported (deterministic)** | `fcn.13b5c`→`read_keys_from_content`→matrix `fcn.5eb0`; whitebox §8 |

## 6. Impact on TASK-0012 and honest limitations (confidence: confirmed)

Two independent sources: the native signer composition — the `'_'` key-join write
in `libthing_security.so@0x14c30` feeding the MD5 key-builder `@0x13474`
(`re/tuya_sign_static.md` §3-4) — AND the public reference `nalajcie/tuya-sign-hacking`
(`key = [cert_sha256]_[bmp_token]_[appSecret]`), both of which require the
`bmp_token` shown un-recovered in §3.

- The byte-for-byte differential signer (TASK-0012) is **still blocked** offline on
  exactly one input: the `bmp_token`. Everything else (canonical string, MD5, `_`
  key-join, offline cert-SHA256, appKey/appSecret) is recovered
  (`re/tuya_sign_static.md` §3-7). A *partial* differential (cert-hash + appSecret +
  MD5/hex/`_`-join sub-steps with a placeholder token) remains achievable now.
- **Honest gotchas (corrected by TASK-0030):**
  - The §5-of-`tuya_sign_static.md` "imath matrix decodes t_s.bmp" hypothesis was
    **RIGHT**, not wrong (this doc earlier mis-retracted it). `t_s.bmp`'s raw pixels
    ARE fed to the imath matrix via `fcn.13b5c` → `read_keys_from_content`
    (whitebox §8). The "white-box cipher decodes t_s.bmp" claim here was the mistaken
    one.
  - `re/scripts/bmp_token_decode.py` does **not** output a token. It implements the
    recovered framing + the independent nalajcie reference. It must NOT be presented
    as a working token decode.
  - Remaining static path for the signer's `bmp_token` (large, no local oracle): port
    imath bignum (`mp_int_*`) + the matrix `fcn.5eb0`/`transform`, feed the raw
    `t_s.bmp` pixels (offset 54) + the SDK-config blob. Deterministic and
    device-independent, so portable in principle. A single captured/accepted request
    (gold oracle) is still the cheaper end-to-end route — recommended contingency for
    TASK-0012.
