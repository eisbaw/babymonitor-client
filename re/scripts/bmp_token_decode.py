#!/usr/bin/env python3
"""bmp_token_decode.py -- offline decode attempt for the Tuya mobile-sign
`bmp_token` residual (TASK-0029).

> ***SUPERSEDED / CORRECTED BY TASK-0030 (`re/bmp_token_whitebox.md` §6/§8).***
> The original (TASK-0029) verdict embedded in this script -- "this APK's bmp_token
> is a white-box table cipher, NOT the nalajcie matrix scheme; the imath matrix does
> NOT consume t_s.bmp; there is no edge from the BMP driver" -- is **WRONG and
> RETRACTED**. The corrected, instruction-level-verified model (see the banner of
> `re/bmp_token_decode.md` and `re/bmp_token_whitebox.md` §6/§8) is:
>
>   - `t_s.bmp` has **TWO** consumers in `libthing_security.so`:
>       (a) `fcn.199d8` @0x19a64 -> `fcn.11658` = **standard AES-128-CBC** (FIPS-197
>           S-boxes), keyed by MD5(t_s.bmp); its OUTPUT is the **TLS cert-pinning
>           config** -- a RED HERRING for the sign token (now fully ported+validated
>           in `re/scripts/bmp_token_aes.py`). It is NOT a white-box cipher.
>       (b) `fcn.13b5c` @0x13bf0 = a **raw-bytes reader** (no transform), called from
>           `doCommandNative` (`fcn.13ef4`) @0x1466c, which passes the **raw t_s.bmp
>           bytes** to `read_keys_from_content` (`libthing_security_algorithm.so`
>           @0x4974) -> imath-bignum + matrix decode (`fcn.5eb0`, "inited matrix:")
>           -> key list -> cmd=1 MD5 key-builder.
>   - So the signer's **bmp_token IS the imath-matrix decode of `t_s.bmp`** on the
>     sign path (corroborates F1 `[cert_sha256]_[bmp_token]_[appSecret]` and
>     `tuya_sign_static.md` §5). The matrix FAMILY is the correct model.
>   - NARROW TRUE FACT preserved below: nalajcie/tuya-sign-hacking's SPECIFIC older
>     byte-layout does NOT reproduce THIS APK's token (TASK-0029: this BMP's header
>     bytes are implausible for that exact reader). That is a *layout* mismatch, NOT
>     evidence against the matrix scheme -- do not conflate the two.

This script does THREE things, all offline and deterministic:

  1. NALAJCIE REFERENCE (older-SDK layout cross-check). A faithful, self-contained
     re-implementation of the *public* Tuya BMP-token deobfuscation documented by
     `nalajcie/tuya-sign-hacking` (review-gate F1): a hash(clientId)->offset walk
     over the BMP pixel bytes that yields (a_i, b_i) coefficient pairs, then an
     EXACT-RATIONAL polynomial-interpolation solve (Gaussian elimination over the
     rationals, denominator must reduce to 1, numerator-bytes == token). The matrix
     FAMILY is the right model for this APK (TASK-0030); however nalajcie's SPECIFIC
     older byte-layout does NOT match this APK's t_s.bmp bytes, so this reader yields
     no token here. It remains a useful independent reference for the matrix family
     (it does NOT read our own decompiled control flow as its oracle).

  2. THIS-APP FRAMING (recovered parts). The pieces of *this* APK's actual
     `security_infra::SignFileDecoder` pipeline that ARE statically recovered:
       - the `tecrkcehc_ext` asset framing (a decimal length line + a base64
         ciphertext body), parsed exactly as native `fcn.19cf0` does (ASCII-decimal
         base-10 accumulate, stop at '\n');
       - the embedded constant string the AES cert-pin transform is keyed with;
       - the djb2-style string hash native uses for the BMP offset (`fcn.509c`:
         acc = acc*31 + byte; abs()).

  3. RESIDUAL CHARACTERISATION. A programmatic assertion that this APK's signer
     bmp_token = the imath+matrix decode of t_s.bmp on the sign path -- deterministic
     and device-independent, but UN-PORTED (no local oracle; nalajcie's older
     byte-layout doesn't match this APK's specific bytes). This is the honest
     residual. (The separate AES consumer of t_s.bmp is the cert-pinning config, a
     red herring -- see `re/scripts/bmp_token_aes.py`.)

NO SECRET VALUE IS HARDCODED. Any recovered value is computed from the assets and,
if ever fully recovered, must be written ONLY to secrets/ (never a tracked file).

Symbol anchors (BuildID libthing_security.so 444ecb4f..., algorithm 904862d9...):
  - SignFileDecoder asset read  : libthing_security.so fcn.0x199d8 (AAsset "t_s.bmp")
  - BMP decode driver           : libthing_security.so fcn.0x1a030
  - tecrkcehc_ext reader         : libthing_security.so fcn.0x19bf4 (AAsset "tecrkcehc_ext")
  - ASCII-decimal parse          : libthing_security.so fcn.0x19cf0 (pow(10,...) accumulate, stop 0x0a)
  - embedded constant            : libthing_security.so .rodata 0x85f5 "7178265647164836"
  - AES cert-pin transform       : libthing_security.so fcn.0x11570 -> fcn.0x11658
                                   (standard AES-128-CBC, FIPS-197 S-boxes @0x795f/0x7a5f,
                                    InvMixColumns 0x1b GF reduction, 10 rounds, CBC).
                                   This is the cert-pinning-config consumer of t_s.bmp
                                   (keyed by MD5(t_s.bmp)) -- a RED HERRING for the sign
                                   token, fully ported in re/scripts/bmp_token_aes.py.
  - raw t_s.bmp reader (sign)    : libthing_security.so fcn.0x13b5c @0x13bf0 -- returns the
                                   VERBATIM t_s.bmp bytes (no transform), called from
                                   doCommandNative fcn.0x13ef4 @0x1466c.
  - imath/matrix lib (SIGN TOKEN): libthing_security_algorithm.so read_keys_from_content@0x4974
                                   -> parse@0x4eec (comma split) -> matrix fcn.0x5eb0
                                   (mp_rat_div/mul/sub/reduce, mp_int_compare_value denom==1,
                                    mp_int_to_binary numerator). This path DOES consume the
                                   raw t_s.bmp bytes (passed as arg4/x3 from doCommandNative
                                   @0x146b0) AND the SDK-config blob -- it is the SIGNER's
                                   bmp_token decoder. (The earlier "no edge from the BMP
                                   driver / single xref to read_keys_from_content" claim was
                                   FALSE: the second t_s.bmp xref fcn.13b5c feeds this matrix.)
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
# (3) THIS-APP decode -- the residual (un-ported imath+matrix on the sign path)
# ---------------------------------------------------------------------------
class MatrixResidual(NotImplementedError):
    """Raised to mark the un-ported imath+matrix sign-token decode
    (read_keys_from_content@0x4974 -> matrix fcn.0x5eb0). The token is
    deterministic + device-independent but has no local oracle; nalajcie's older
    byte-layout does not match this APK's specific bytes."""


# Backwards-compat alias (the historical name; the residual is a matrix decode, not
# a white-box cipher -- the "white-box" verdict was retracted by TASK-0030).
WhiteBoxResidual = MatrixResidual


def thisapp_decode(assets_dir: str) -> bytes:
    """What this APK actually does for the signer's bmp_token. The framing is
    recovered, but the token itself is UN-PORTED: it is the imath+matrix decode of
    the raw t_s.bmp bytes on the sign path -- not produced here."""
    raise MatrixResidual(
        "this APK's signer bmp_token = the imath+matrix decode "
        "(libthing_security_algorithm.so read_keys_from_content@0x4974 / matrix "
        "fcn.0x5eb0) of the RAW t_s.bmp bytes on the sign path (fed via "
        "libthing_security.so fcn.0x13b5c -> doCommandNative fcn.0x13ef4 @0x1466c). "
        "It is deterministic + device-independent but UN-PORTED: no local oracle, and "
        "nalajcie's older byte-layout doesn't match this APK's specific bytes. The "
        "AES path (fcn.0x11658) is the SEPARATE cert-pinning consumer of t_s.bmp, a "
        "red herring (ported in re/scripts/bmp_token_aes.py). "
        "See re/bmp_token_whitebox.md §8."
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
    print(f"embedded constant (AES cert-pin key/IV): {EMBEDDED_CONSTANT.decode()}")

    # (1) Run the nalajcie older-SDK-layout reference. The matrix FAMILY is the right
    # model for this APK (TASK-0030), but nalajcie's SPECIFIC older byte-layout does
    # not match this APK's t_s.bmp bytes -- so this exact reader yields no token here.
    # We probe the public demo clientId only to SHOW the layout mismatch, not to brute
    # the real clientId (which lives in secrets/, not here).
    sample_ids = [b"3fjrekuxank9eaej3gcx"]  # the nalajcie demo clientId (public)
    matched = False
    for cid in sample_ids:
        tok = nalajcie_decode(bmp_raw, cid)
        if tok:
            matched = True
            print(f"nalajcie-reference produced a token for clientId={cid!r}: "
                  f"{len(tok)} bytes")
    if not matched:
        print("nalajcie-reference (older SDK layout): NO token from this BMP "
              "(expected -- the matrix FAMILY is correct, but nalajcie's specific "
              "older byte-layout doesn't match this APK's t_s.bmp bytes).")

    # (3) The actual signer bmp_token is the un-ported imath+matrix residual.
    try:
        thisapp_decode(assets)
    except MatrixResidual as e:
        print("\nRESIDUAL (un-ported):", str(e))
    print("\nDecode: signer bmp_token un-ported (imath+matrix of raw t_s.bmp on the "
          "sign path) / framing partially-ported / AES cert-pin path ported separately "
          "(re/scripts/bmp_token_aes.py)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
