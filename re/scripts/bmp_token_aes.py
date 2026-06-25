#!/usr/bin/env python3
"""bmp_token_aes.py -- BYTE-EXACT offline port of the Tuya AES-128-CBC routine that
decrypts the TLS **cert-pinning config** (asset `tecrkcehc_ext`) using MD5(`t_s.bmp`)
as the key (TASK-0030).

NAME/SCOPE NOTE (corrected TASK-0030 P1-2): the historical filename says
"bmp_token", but this module does NOT produce the request-signer's `bmp_token`
(the middle `_`-part of the sign key). It produces the **cert-pinning config**. The
signer's `bmp_token` is produced on a SEPARATE path -- `fcn.13b5c` reads the RAW
`t_s.bmp` bytes and feeds them to `read_keys_from_content`
(libthing_security_algorithm.so) whose imath-bignum + matrix (fcn.5eb0) decode is
the still-unported residual (see re/bmp_token_whitebox.md JOB-1 + re/tuya_sign_static.md
Sec.5). This file is kept named `*_aes` for git history; the public API below is named
for what it actually returns (the cert-pinning config).

THE CORRECTION (vs TASK-0029 / re/bmp_token_decode.md):
  TASK-0029 characterised `libthing_security.so` fcn.11658 as an un-portable
  "white-box table cipher". Re-disassembly (this task) proves that is WRONG: it is
  STANDARD **AES-128-CBC DECRYPTION**, only lightly disguised by being written out
  in NEON intrinsics instead of using the `aesd`/`aese` instructions. Evidence
  (libthing_security.so, BuildID 444ecb4f...):
    - fcn.119e4  = AES key expansion: 0x28 (40) word loop, SubWord via the FORWARD
                   S-box @0x795f (bytes `63 7c 77 7b ...`), Rcon power table @0x7860
                   (`8d 01 02 04 08 10 20 40 80 1b 36 6c ...`), writes the 176-byte
                   expanded key to .data 0x38f70.
    - fcn.11658  = the InvCipher: per-round InvSubBytes via the INVERSE S-box @0x7a5f
                   (`52 09 6a d5 30 36 a5 38 ...`), InvShiftRows (the byte-permute at
                   0x11b14..0x11bd0), InvMixColumns (the NEON `add v.4h,v.4h,v.4h`
                   xtime + `movi v8.4h,0x1b` GF(2^8) reduction + eor mixing at
                   0x11c60..), 9 main rounds (w19=9) + final round = AES-128 (10
                   rounds), then CBC-XOR with the previous ciphertext block (arg5).
  So fcn.11658(out, in, len, key=arg4, iv/prevblock=arg5) is AES-128-CBC-decrypt.

I/O MAPPING (driver fcn.1a030 -> fcn.19810 -> fcn.11570 -> fcn.11658):
  - CIPHERTEXT: `tecrkcehc_ext` asset = "<declared_len>\n<base64 body>". fcn.19cf0
    parses declared_len (=226) as decimal, then base64-DECODES the body
    (fcn.196bc -> fcn.2e7b0, alphabet @0x9dc7) into a 256-byte ciphertext stored at
    ctx+0x30.
  - KEY: fcn.199d8 reads `t_s.bmp` and computes MD5 over its raw bytes (fcn.195cc),
    storing the **16 RAW digest bytes** (NOT the 32-char hex string) as the
    std::string at ctx+0x60 (SSO length byte 0x20 => len 16; bytes copied verbatim).
    The AES-128 key = those 16 raw MD5 digest bytes; key expansion fcn.119e4 reads
    exactly one 16-byte `ldr q0`. (This corrects the earlier "first 16 bytes of the
    hex string" docstring -- the code below, the oracle, and the .so all use the RAW
    16-byte digest. See `aes_key_from_bmp`.)
  - IV: the embedded constant "7178265647164836" @.rodata 0x85f5 (16 ASCII bytes),
    passed as arg5 (the first CBC chaining block).
  - OUTPUT: AES-128-CBC-decrypt(ciphertext, key, iv) -> 256 plaintext bytes, then
    TRUNCATED to `declared_len` (226) bytes. That truncated buffer is the
    **TLS cert-pinning config** JSON `{"securityOpen": bool, "data": [pin, pin]}` --
    NOT the request-signer's bmp_token (see the NAME/SCOPE NOTE above).

VALIDATION:
  - The AES-128 core is validated against the FIPS-197 / NIST known-answer vector
    (see test_bmp_token_aes.py) -- an INDEPENDENT static oracle for the cipher.
  - Determinism + stable shape on the real assets is checked.
  - The decrypted blob parses as the expected cert-pinning JSON config -- a strong
    STRUCTURAL oracle (a wrong key/iv/mode yields garbage, not valid JSON).
  - Status: fully-ported-validated (cipher). This does NOT validate the signer's
    bmp_token (a different, unported path).

NO SECRET VALUE IS HARDCODED. The decoded cert-pinning config, if emitted, is written
ONLY to secrets/ -- never a tracked file or test assertion.
"""
from __future__ import annotations

import base64
import hashlib
import os
import sys
from typing import List

ASSETS_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "decompiled",
    "apktool",
    "assets",
)

# The IV constant embedded at libthing_security.so .rodata 0x85f5.
IV_CONSTANT = b"7178265647164836"  # 16 bytes


# ---------------------------------------------------------------------------
# Self-contained AES-128 (decrypt path). The S-boxes are the EXACT bytes
# extracted from libthing_security.so and committed to re/aes_tables.txt, so the
# port does not depend on the gitignored .so at runtime. (They are the canonical
# AES tables; the unit tests cross-check both that they are committed verbatim and
# that they pass the FIPS-197 known-answer vector.)
# ---------------------------------------------------------------------------

_TABLES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aes_tables.txt")


def _load_tables(path: str = _TABLES_PATH):
    """Load the two 256-byte S-box tables from the committed hexdump re/aes_tables.txt.
    Each table is preceded by a `# ...` header line; returns (forward, inverse)."""
    blocks: List[List[int]] = []
    cur: List[int] = []
    for line in open(path, "r", encoding="ascii"):
        line = line.strip()
        if line.startswith("#"):
            if cur:
                blocks.append(cur)
                cur = []
            continue
        if not line:
            continue
        cur.extend(int(tok, 16) for tok in line.split())
    if cur:
        blocks.append(cur)
    if len(blocks) < 2 or any(len(b) != 256 for b in blocks[:2]):
        raise ValueError(f"aes_tables.txt malformed: expected two 256-byte tables, got "
                         f"{[len(b) for b in blocks]}")
    return blocks[0], blocks[1]


SBOX, INV_SBOX = _load_tables()

# Rcon (xtime powers of two in GF(2^8)); index 1.. used by key expansion.
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res & 0xFF


def key_expansion(key: bytes) -> List[List[int]]:
    """AES-128 key expansion -> 11 round keys, each a list of 16 bytes (column-major
    AES state order). Mirrors fcn.119e4."""
    assert len(key) == 16
    words: List[List[int]] = [list(key[i * 4 : i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = []
        for w in range(4):
            rk.extend(words[r * 4 + w])
        round_keys.append(rk)
    return round_keys


def _add_round_key(state: List[int], rk: List[int]) -> None:
    for i in range(16):
        state[i] ^= rk[i]


def _inv_sub_bytes(state: List[int]) -> None:
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _inv_shift_rows(state: List[int]) -> None:
    # state is column-major: byte index = col*4 + row. Row r is shifted right by r.
    for row in range(1, 4):
        vals = [state[col * 4 + row] for col in range(4)]
        vals = vals[-row:] + vals[:-row]
        for col in range(4):
            state[col * 4 + row] = vals[col]


def _inv_mix_columns(state: List[int]) -> None:
    for c in range(4):
        i = c * 4
        s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gmul(s0, 14) ^ _gmul(s1, 11) ^ _gmul(s2, 13) ^ _gmul(s3, 9)
        state[i + 1] = _gmul(s0, 9) ^ _gmul(s1, 14) ^ _gmul(s2, 11) ^ _gmul(s3, 13)
        state[i + 2] = _gmul(s0, 13) ^ _gmul(s1, 9) ^ _gmul(s2, 14) ^ _gmul(s3, 11)
        state[i + 3] = _gmul(s0, 11) ^ _gmul(s1, 13) ^ _gmul(s2, 9) ^ _gmul(s3, 14)


def aes128_decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """Decrypt one 16-byte block (the equivalent inverse cipher of fcn.11658's
    per-block rounds, before the CBC XOR)."""
    state = list(block)
    _add_round_key(state, round_keys[10])
    for r in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def aes128_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC decrypt. Mirrors fcn.11658: InvCipher(block) then XOR previous
    ciphertext block (IV for the first)."""
    assert len(ciphertext) % 16 == 0, "ciphertext must be block-aligned"
    round_keys = key_expansion(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(ciphertext), 16):
        blk = ciphertext[off : off + 16]
        dec = aes128_decrypt_block(blk, round_keys)
        out.extend(dec[i] ^ prev[i] for i in range(16))
        prev = blk
    return bytes(out)


# ---------------------------------------------------------------------------
# The full cert-pinning-config decode (the recovered AES pipeline)
# ---------------------------------------------------------------------------
def parse_ext_asset(raw: bytes):
    """Return (declared_len:int, ciphertext:bytes) from the `tecrkcehc_ext` asset
    `<decimal>\\n<base64 body>`. The body is base64-decoded (native fcn.196bc)."""
    nl = raw.index(b"\n")
    declared_len = int(raw[:nl].decode("ascii"))
    body = raw[nl + 1 :]
    ciphertext = base64.b64decode(body)
    return declared_len, ciphertext


def aes_key_from_bmp(bmp_raw: bytes) -> bytes:
    """AES-128 key = the RAW 16-byte MD5(t_s.bmp) digest.

    Native fcn.195cc computes MD5 into a 16-byte `operator new[]` buffer and stores
    those 16 RAW bytes as the std::string at ctx+0x60 (SSO length byte = 0x20, i.e.
    len=16; the 16 digest bytes are copied verbatim via stp/stur -- NOT hex-encoded).
    The key expansion fcn.119e4 then reads exactly those 16 bytes."""
    return hashlib.md5(bmp_raw).digest()


def decode_cert_pinning_config(assets_dir: str) -> bytes:
    """Full offline decode of the TLS cert-pinning config (length = declared_len).

    Returns the decrypted `{"securityOpen":bool,"data":[pin,pin]}` JSON bytes. This is
    NOT the request-signer's bmp_token (a different, unported path). It is fully-ported
    and validated by the clean-JSON structural oracle; never commit the value."""
    with open(os.path.join(assets_dir, "t_s.bmp"), "rb") as f:
        bmp_raw = f.read()
    with open(os.path.join(assets_dir, "tecrkcehc_ext"), "rb") as f:
        ext_raw = f.read()
    declared_len, ciphertext = parse_ext_asset(ext_raw)
    key = aes_key_from_bmp(bmp_raw)
    plaintext = aes128_cbc_decrypt(ciphertext, key, IV_CONSTANT)
    return plaintext[:declared_len]


def main(argv: List[str]) -> int:
    assets = argv[1] if len(argv) > 1 else ASSETS_DEFAULT
    if not os.path.exists(os.path.join(assets, "t_s.bmp")):
        print(f"ERROR: assets not found under {assets}", file=sys.stderr)
        return 2
    config = decode_cert_pinning_config(assets)
    # Print SHAPE only, never the value (CLAUDE.md / TESTING.md: no secret in stdout
    # of a committed-runnable path; the value goes to secrets/ via --emit-cert-pin).
    printable = all(32 <= b < 127 for b in config)
    print(f"cert-pinning config decoded: {len(config)} bytes, printable_ascii={printable}")
    print("Decode: fully-ported-validated (AES-128-CBC + clean-JSON oracle). "
          "NOTE: this is the cert-pinning config, NOT the signer's bmp_token.")
    if "--emit-cert-pin" in argv:
        # Write the VALUE only to secrets/ (gitignored), never stdout.
        secrets_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "secrets",
        )
        os.makedirs(secrets_dir, exist_ok=True)
        out = os.path.join(secrets_dir, "cert_pinning_config.json")
        with open(out, "wb") as f:
            f.write(config)
        print(f"(cert-pinning config VALUE written to {out} -- gitignored)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
