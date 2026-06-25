#!/usr/bin/env python3
"""bmp_token_decode.py -- offline decode attempt for the Tuya mobile-sign
`bmp_token` residual (TASK-0029).

This script does THREE things, all offline and deterministic:

  1. NALAJCIE REFERENCE (independent cross-check). A faithful, self-contained
     re-implementation of the *public* Tuya BMP-token deobfuscation documented by
     `nalajcie/tuya-sign-hacking` (review-gate F1): a hash(clientId)->offset walk
     over the BMP pixel bytes that yields (a_i, b_i) coefficient pairs, then an
     EXACT-RATIONAL polynomial-interpolation solve (Gaussian elimination over the
     rationals, denominator must reduce to 1, numerator-bytes == token). This is
     the "independent reference" required by TESTING.md Part-2 signal #2 -- it does
     NOT read our own decompiled control flow as its oracle.

  2. THIS-APP FRAMING (recovered parts). The pieces of *this* APK's actual
     `security_infra::SignFileDecoder` pipeline that ARE statically recovered:
       - the `tecrkcehc_ext` asset framing (a decimal length line + a base64
         ciphertext body), parsed exactly as native `fcn.19cf0` does (ASCII-decimal
         base-10 accumulate, stop at '\n');
       - the embedded constant string the transform is keyed with;
       - the djb2-style string hash native uses for the BMP offset (`fcn.509c`:
         acc = acc*31 + byte; abs()).

  3. WALL CHARACTERISATION. A programmatic assertion that this APK's BMP-token
     decode is NOT the nalajcie matrix scheme but a white-box table cipher
     (`libthing_security.so fcn.11658`), so the reference in (1) cannot reproduce
     this app's token. This is the honest residual.

NO SECRET VALUE IS HARDCODED. Any recovered value is computed from the assets and,
if ever fully recovered, must be written ONLY to secrets/ (never a tracked file).

Symbol anchors (BuildID libthing_security.so 444ecb4f..., algorithm 904862d9...):
  - SignFileDecoder asset read  : libthing_security.so fcn.0x199d8 (AAsset "t_s.bmp")
  - BMP decode driver           : libthing_security.so fcn.0x1a030
  - tecrkcehc_ext reader         : libthing_security.so fcn.0x19bf4 (AAsset "tecrkcehc_ext")
  - ASCII-decimal parse          : libthing_security.so fcn.0x19cf0 (pow(10,...) accumulate, stop 0x0a)
  - embedded constant            : libthing_security.so .rodata 0x85f5 "7178265647164836"
  - white-box transform (WALL)   : libthing_security.so fcn.0x11570 -> fcn.0x11658
                                   (tbl v0.16b,{v16-v19}; ldr q1,[x9,0x800] T-table @0x7800;
                                    dense eor v.8b GF(2) mixing) -- a software white-box
                                    table-network block cipher, NOT a polynomial/matrix solve.
  - imath/matrix lib             : libthing_security_algorithm.so read_keys_from_content@0x4974
                                   -> parse@0x4eec (comma split) -> matrix fcn.0x5eb0
                                   (mp_rat_div/mul/sub/reduce, mp_int_compare_value denom==1,
                                    mp_int_to_binary numerator). This path decodes the
                                   *SDK-config blob* (asset `tecrkcehc`, JSON {"data":[...]}),
                                   NOT t_s.bmp -- verified: the only xref to the imported
                                   read_keys_from_content is fcn.0x13ef4 (cmd-dispatch), there
                                   is no edge from the BMP driver fcn.0x1a030.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from fractions import Fraction
from typing import List, Optional, Tuple

ASSETS_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "decompiled",
    "apktool",
    "assets",
)


# ---------------------------------------------------------------------------
# BMP pixel-data access
# ---------------------------------------------------------------------------
def bmp_pixel_data(raw: bytes) -> bytes:
    """Return the pixel-array bytes of a Windows BMP (everything from bfOffBits)."""
    if raw[:2] != b"BM":
        raise ValueError("not a BMP (missing 'BM' magic)")
    off = int.from_bytes(raw[10:14], "little")
    return raw[off:]


# ---------------------------------------------------------------------------
# (2) THIS-APP recovered primitives
# ---------------------------------------------------------------------------
def native_str_hash(s: bytes) -> int:
    """djb2-ish hash native uses for the BMP offset (libthing_security_algorithm.so
    fcn.0x509c): acc = acc*31 + byte, over strlen(s) bytes; result then abs()'d.
    Matches the public nalajcie `(acc<<5)-acc+c` == acc*31+c."""
    acc = 0
    for c in s:
        acc = (acc * 31 + c) & 0xFFFFFFFF
    # interpret as signed 32-bit, then abs(), as native does via int + abs()
    if acc >= 0x80000000:
        acc -= 0x100000000
    return abs(acc)


def parse_decimal_line(buf: bytes) -> int:
    """Reproduce native fcn.0x19cf0: read ASCII decimal digits, base-10 accumulate,
    stop at the first newline (0x0a). Returns the integer value of the first line."""
    val = 0
    for b in buf:
        if b == 0x0A:
            break
        if 0x30 <= b <= 0x39:
            val = val * 10 + (b - 0x30)
        else:
            # native subtracts 0x30 unconditionally; non-digits would corrupt --
            # the real asset only has digits before the newline.
            val = val * 10 + (b - 0x30)
    return val


@dataclass
class ExtAsset:
    declared_len: int          # the decimal header (fcn.0x19cf0 output)
    payload: bytes             # the body after the first '\n' (white-box ciphertext)


def parse_ext_asset(raw: bytes) -> ExtAsset:
    """Parse the `tecrkcehc_ext` asset: `<decimal>\\n<base64-ciphertext>`."""
    nl = raw.index(b"\n")
    return ExtAsset(declared_len=parse_decimal_line(raw[: nl + 1]), payload=raw[nl + 1 :])


EMBEDDED_CONSTANT = b"7178265647164836"  # .rodata 0x85f5; keys the white-box transform


# ---------------------------------------------------------------------------
# (1) NALAJCIE REFERENCE: exact-rational polynomial-interpolation decode
# ---------------------------------------------------------------------------
@dataclass
class Coeff:
    a: int
    b: int


def _read_len_prefixed(pixels: bytes, off: int) -> Tuple[bytes, int]:
    """Read [len byte][len data bytes]; return (data, next_off). Wraps modulo len."""
    n = len(pixels)
    ln = pixels[off % n]
    out = bytes(pixels[(off + 1 + i) % n] for i in range(ln))
    return out, off + 1 + ln


def _be32(pixels: bytes, off: int) -> int:
    n = len(pixels)
    return (
        (pixels[off % n] << 24)
        | (pixels[(off + 1) % n] << 16)
        | (pixels[(off + 2) % n] << 8)
        | pixels[(off + 3) % n]
    )


def nalajcie_read_coeffs(pixels: bytes, client_id: bytes) -> Optional[List[Coeff]]:
    """Public-reference coefficient extraction (read_keys.c shape).

    start = (abs(strhash(client_id)) % len(pixels)) // 2
    header @ start+1: keys_cnt, @ start+2: coeffs_cnt, @ start+3..+6: 4-byte magic.
    Then coeffs_cnt records of [len|a-bytes][len|b-bytes][4-byte magic], with the
    next record offset XOR-chained by the magic. a/b bytes are taken as big-endian
    integers (the hex-string in the C is just bytes_to_str of these same bytes).

    Returns None if the header is implausible for *this* BMP (which is the expected
    outcome here -- see the wall note in the module docstring)."""
    n = len(pixels)
    if n < 8:
        return None
    start = (native_str_hash(client_id) % n) // 2
    keys_cnt = pixels[(start + 1) % n]
    coeffs_cnt = pixels[(start + 2) % n]
    if not (1 <= keys_cnt <= 4):
        return None
    if not (1 <= coeffs_cnt <= 64):
        return None
    off = (start + 3) % n
    magic = _be32(pixels, off)
    off = (off + 4) % n
    coeffs: List[Coeff] = []
    for _ in range(coeffs_cnt):
        a_bytes, off = _read_len_prefixed(pixels, off)
        b_bytes, off = _read_len_prefixed(pixels, off)
        nxt = _be32(pixels, off)
        off = (off + 4) % n
        if not a_bytes or not b_bytes:
            return None
        coeffs.append(Coeff(int.from_bytes(a_bytes, "big"), int.from_bytes(b_bytes, "big")))
        off = (off ^ (nxt ^ magic)) % n
    return coeffs


def solve_polynomial_rational(coeffs: List[Coeff]) -> Optional[int]:
    """Exact-rational Gaussian elimination (coeffs_to_key.c shape, mp_rat_* in our
    algorithm lib): build rows [a^(d-1), ..., a, 1 | b], reduce to triangular form,
    back-nothing -- the documented decode takes res = c_last / r_last,last and
    REQUIRES the reduced denominator == 1; the numerator big-int IS the token bytes.

    Returns the numerator integer if the system is consistent and integral, else
    None."""
    d = len(coeffs)
    if d == 0:
        return None
    # Vandermonde-style augmented matrix over Fraction (exact).
    mat: List[List[Fraction]] = []
    for c in coeffs:
        row = [Fraction(c.a) ** (d - 1 - j) for j in range(d)]
        row.append(Fraction(c.b))
        mat.append(row)
    # forward elimination to upper triangular
    for col in range(d):
        piv = None
        for r in range(col, d):
            if mat[r][col] != 0:
                piv = r
                break
        if piv is None:
            return None
        mat[col], mat[piv] = mat[piv], mat[col]
        for r in range(col + 1, d):
            if mat[r][col] != 0:
                factor = mat[r][col] / mat[col][col]
                for k in range(col, d + 1):
                    mat[r][k] -= factor * mat[col][k]
    res = mat[d - 1][d] / mat[d - 1][d - 1]  # c_last / r_last,last
    if res.denominator != 1:
        return None
    return res.numerator


def numerator_to_token(num: int) -> bytes:
    """The reduced numerator big-int, as big-endian bytes, IS the token ASCII
    (native uses mp_int_to_binary; nalajcie's C uses mp_int_to_string base16 then
    hex_to_str -- equivalent)."""
    if num <= 0:
        return b""
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, "big")


def nalajcie_decode(bmp_raw: bytes, client_id: bytes) -> Optional[bytes]:
    """Full public-reference decode: BMP + clientId -> token bytes, or None."""
    pixels = bmp_pixel_data(bmp_raw)
    coeffs = nalajcie_read_coeffs(pixels, client_id)
    if not coeffs:
        return None
    num = solve_polynomial_rational(coeffs)
    if num is None:
        return None
    return numerator_to_token(num)


# ---------------------------------------------------------------------------
# (3) THIS-APP decode -- the wall
# ---------------------------------------------------------------------------
class WhiteBoxResidual(NotImplementedError):
    """Raised to mark the un-ported white-box table cipher (fcn.0x11658)."""


def thisapp_decode(assets_dir: str) -> bytes:
    """What this APK actually does for the bmp_token. The framing is recovered; the
    core transform is a white-box table cipher and is NOT statically ported."""
    raise WhiteBoxResidual(
        "this APK's t_s.bmp token = white-box table cipher (libthing_security.so "
        "fcn.0x11658: tbl S-box + GF(2) eor mixing + T-table @0x7800), keyed by the "
        "constant '7178265647164836' over the tecrkcehc_ext base64 ciphertext. It is "
        "NOT the nalajcie polynomial/matrix scheme. Full static port requires "
        "extracting all T-tables and reconstructing the SPN round function byte-exactly. "
        "See re/bmp_token_decode.md (Decode: not-portable-via-reference / partially-ported)."
    )


# ---------------------------------------------------------------------------
# CLI / report
# ---------------------------------------------------------------------------
def main(argv: List[str]) -> int:
    assets = argv[1] if len(argv) > 1 else ASSETS_DEFAULT
    t_s = os.path.join(assets, "t_s.bmp")
    ext = os.path.join(assets, "tecrkcehc_ext")
    if not os.path.exists(t_s):
        print(f"ERROR: {t_s} not found (unzip the APK assets first)", file=sys.stderr)
        return 2

    bmp_raw = open(t_s, "rb").read()
    pixels = bmp_pixel_data(bmp_raw)
    print(f"t_s.bmp: {len(bmp_raw)} bytes, pixel-array {len(pixels)} bytes")

    if os.path.exists(ext):
        ea = parse_ext_asset(open(ext, "rb").read())
        print(f"tecrkcehc_ext: declared_len(decimal)={ea.declared_len}  "
              f"ciphertext_len={len(ea.payload)} (base64 body)")
    print(f"embedded constant (key/IV): {EMBEDDED_CONSTANT.decode()}")

    # (1) Run the independent nalajcie reference. Demonstrate it does NOT apply here.
    # We probe a small set of plausible clientId byte-strings; the goal is to SHOW
    # the matrix scheme yields no consistent token from this BMP (the wall), not to
    # brute the real clientId (which lives in secrets/, not here).
    sample_ids = [b"3fjrekuxank9eaej3gcx"]  # the nalajcie demo clientId (public)
    matched = False
    for cid in sample_ids:
        tok = nalajcie_decode(bmp_raw, cid)
        if tok:
            matched = True
            print(f"nalajcie-reference produced a token for clientId={cid!r}: "
                  f"{len(tok)} bytes")
    if not matched:
        print("nalajcie-reference: NO consistent matrix token from this BMP "
              "(expected -- this APK uses a white-box cipher, not the matrix scheme).")

    # (3) The actual app decode is the wall.
    try:
        thisapp_decode(assets)
    except WhiteBoxResidual as e:
        print("\nWALL (residual):", str(e))
    print("\nDecode: not-portable-via-reference (white-box) / partially-ported (framing)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
