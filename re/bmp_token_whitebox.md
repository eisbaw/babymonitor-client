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
  `{"securityOpen": bool, "data": [sha256_pin_1, sha256_pin_2]}`, NOT obviously the
  request-signer's `bmp_token`. `t_s.bmp` has exactly ONE consumer in the lib (this
  AES path), so the prior model of a *separate* "t_s.bmp → sign token" decode is not
  supported by the disassembly. The mapping from this output to the signer's middle
  `_`-part is the residual (§6). The signer (TASK-0012) is therefore **not yet
  offline-unblocked** by a confirmed token — see the feed-forward.

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
keys `libthing_security.so@0x8dc2` ("securityOpen") / the single `t_s.bmp` xref @0x19a64.
(The signer-mapping question in the bullets is the OPEN part — no static oracle, flagged.)

Decrypting the real `tecrkcehc_ext` yields valid JSON:
`{"securityOpen": <bool>, "data": ["<sha256-fingerprint>", "<sha256-fingerprint>"]}`
where each `data` entry is a 95-char colon-separated SHA-256 fingerprint (32 hex bytes,
31 colons). This is a **TLS certificate-pinning config**.

Consequences for the request signer (TASK-0012):

- `t_s.bmp`'s ONLY xref in `libthing_security.so` is `0x19a64` (this AES path). There
  is **no separate "t_s.bmp → sign token" decode**; the prior model (a distinct
  white-box token producer) is **not supported** by the disassembly.
- So the signer's middle `_`-part ("bmp_token", per nalajcie `cert_sha256 _ token _
  appSecret`) is **one of these decrypted artifacts** — most plausibly a `data[]`
  cert-fingerprint or `securityOpen` — OR the original signer decomposition
  (`re/tuya_sign_static.md` §7) over-split the key. This cannot be disambiguated
  statically: the only true oracle is the end-to-end Tuya sign-accept (a single live
  signed request), which is OUT OF SCOPE here.

**What WOULD validate the end-to-end signer offline:** one captured/accepted live
sign (the TASK-0012 AC#3 contingency). With that single vector, the middle `_`-part
is pinned in one place (`sign::tests::full_signature_byte_parity_pending_task_0030`),
and the `SignBody` / postData ambiguities resolve simultaneously.

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
| blob == signer's bmp_token | NO static oracle (needs a live sign) | **open** |

Decode: fully-ported-validated (cipher) / signer-token-mapping-open (needs a live
sign-accept; see §6).
