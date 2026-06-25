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

> **SUPERSEDED IN PART BY TASK-0030 (`re/bmp_token_whitebox.md`).** §3 below calls
> `fcn.11658` an "un-portable white-box table cipher". Re-disassembly proves that is
> WRONG: it is **standard AES-128-CBC** (canonical AES S-boxes @0x795f/0x7a5f,
> InvMixColumns with the 0x1b GF reduction, 10 rounds, CBC). It is now **fully ported
> and validated** (`re/scripts/bmp_token_aes.py`, FIPS-197 KAT + clean-JSON oracle).
> The decrypted blob is the **TLS cert-pinning config** `{"securityOpen",…,
> "data":[2×sha256]}`, not obviously the signer's `bmp_token` — see
> `re/bmp_token_whitebox.md` §6 for the residual. Read that doc, not §3, for the
> cipher.

**Decode: fully-ported-validated (cipher); signer-token-mapping-open** — the AES
transform is byte-exact and validated; the framing/IO is recovered; what remains open
is which decrypted artifact the request-signer's middle `_`-part consumes (needs a
live sign-accept). (Original §3 verdict "white-box wall" is retracted.)

This is grounded by two independent sources: (1) the byte-level disassembly of the
BMP decode driver and its callees in `libthing_security.so@0x1a030` (cited inline),
and (2) the public reference `nalajcie/tuya-sign-hacking`
(`re/review_gate_findings.md:24`), which documents a *different* (older) scheme that
provably does not reproduce this APK's token.

**One-line justification:** `re/tuya_sign_static.md` §5 hypothesised the t_s.bmp
token was decoded by the imath-bignum **matrix** in `libthing_security_algorithm.so`.
Disassembly **refutes** that for the BMP path: the imath `read_keys_from_content`
matrix decodes the *SDK-config blob* (asset `tecrkcehc`), while `t_s.bmp` is consumed
by a separate **white-box table-network block cipher** (`libthing_security.so@0x11658`)
keyed by an embedded constant. The framing around it is fully recovered; the cipher
itself is the wall.

---

## 1. The two decode paths are distinct — the §5 conflation is corrected (confidence: confirmed)

Two independent sources: the xref graph of the imported `read_keys_from_content`
AND the named public reference's separate "config keys" vs "BMP token" mechanisms.

- The imath/matrix function `read_keys_from_content` is **imported** into
  `libthing_security.so@0x2e600`; its **only** caller is the cmd-dispatch
  `libthing_security.so@0x13ef4` (= `doCommandNative@0x13ed8`, the SDK-config-blob
  parser, `re/tuya_sign_static.md` §2). There is **no edge** from the BMP decode
  driver `libthing_security.so@0x1a030` to `read_keys_from_content` (r2 `axt`
  confirms a single xref).
- The matrix input is a **comma-separated** coefficient string: `parse`
  (`libthing_security_algorithm.so@0x4eec`) splits on `','` (`strchr` for `0x2c`)
  into 16-byte (a,b) structs — i.e. it consumes the decrypted config blob (asset
  `tecrkcehc`, a JSON `{"data":[...]}` of cert-pin hex pairs), not raw BMP pixels.
- Therefore the imath **matrix** is the public reference's *config-key* decode, and
  is unrelated to `t_s.bmp`. The §5 claim that t_s.bmp uses the imath matrix is a
  **cross-source contradiction**, here resolved in favour of the disassembly.

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

## 3. The core transform is a white-box table cipher — the wall (confidence: confirmed)

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
| **the white-box table cipher** (token producer) | **NO — the wall** | `libthing_security.so@0x11658` (tbl/eor/T-table); §3 |

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
- **Honest gotchas:**
  - The §5-of-`tuya_sign_static.md` "imath matrix decodes t_s.bmp" hypothesis was
    WRONG; that matrix is the config-key path. The actual t_s.bmp decode is a
    white-box cipher — a *harder* residual than first characterised.
  - `re/scripts/bmp_token_decode.py` does **not** output a token (it raises
    `WhiteBoxResidual`). It implements the recovered framing + the independent
    reference and proves the scheme mismatch. It must NOT be presented as a working
    token decode.
  - Remaining static path (large, no oracle): extract the `.rodata@0x7800` /
    `.data.rel.ro@0x38000`/`0x39000` tables, reconstruct `fcn@0x11658` byte-exact,
    feed t_s.bmp + `tecrkcehc_ext` + the constant. Realistically this is the point
    where a single captured request (gold oracle) is far cheaper than completing the
    white-box port — recommend that contingency for TASK-0012.
