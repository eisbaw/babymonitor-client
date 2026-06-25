#!/usr/bin/env python3
"""bmp_token_ghidra.py -- BYTE-EXACT port of the t_s.bmp imath-bignum + matrix
key-list decode, reconstructed from **Ghidra's C decompilation** (TASK-0033).

This is the deep-static port that the radare2-only trace in
`re/bmp_token_whitebox.md` §8 could only *characterize*. Ghidra's decompiler
(11.4.2, headless; see TASK-0033 notes for the exact invocation) resolved the
control flow far enough to port the decode 1:1. The Ghidra C sources are
committed under `re/ghidra/*.c` as the primary evidence.

PRIMARY SOURCE = Ghidra C. Each function here cites the Ghidra C file it ports.
Cross-checked against the r2 trace; the ONE material divergence found is recorded
in the module docstring below and in `re/bmp_token_whitebox.md`.

------------------------------------------------------------------------------
THE DECODE (libthing_security_algorithm.so), from Ghidra C
------------------------------------------------------------------------------
read_keys_from_content(config, &out_keys, &out_count, bmp_bytes)   # read_keys_from_content.c
  -> header_check(bmp)            # header_check.c: 'BM'; 0x2800<=filesize<0x200001;
                                  #   filesize-0x36 >= bfOffBits; bpp in {24,32}; comp==0
  -> dispatch_decode(config, ..., pixels = bmp+0x36,               # dispatch_decode.c
                     pixel_len = filesize - bfOffBits)
       h   = strhash(config)                       # strhash.c: acc=acc*31+byte; abs(int32)
       r   = (h % pixel_len) // 2
       idx = r % pixel_len
       sel = pixels[idx]
       if   sel == 1: decode_op1(...)              # decode_op1.c
       elif sel == 2: decode_op2(...)              # decode_op2.c
       else:          error 0x15

  decode_op1 / decode_op2:
       num_keys   = pixels[(r+1) % L]              (op1; op2 reads via LSB bit-packing)
       num_coeffs = pixels[(r+2) % L]              (== rows of the linear system)
       # read num_coeffs (a,b) coefficient pairs from the pixels, walking a
       # chained offset that is XOR-stepped by xorstep_583c (4 pixel bytes, BE u32).
       #   op1: each value's bytes are taken DIRECTLY from pixels  (build_mpint_op1.c)
       #   op2: each value's bytes are reconstructed bit-by-bit from the LSB of 8
       #        consecutive pixel bytes                            (read_5b68 / readbytes_op2)
       #   in BOTH cases the bytes are then formatted "%02x" -> a hex string
       # split into num_keys groups of (num_coeffs/num_keys) pairs; each group is
       # solved independently into one output key string.

  matrix_solve (FUN_00105eb0):                     # matrix_fcn5eb0.c + matrix_init.c
       # matrix_init builds a Vandermonde system over the rationals (imath mp_rat):
       #   row i = [ a_i^(n-1), a_i^(n-2), ..., a_i^1, a_i^0 | b_i ]
       #   where a_i,b_i = mp_rat_read_string(hexstring, base 16)  (make_rational_6a38.c)
       # Gaussian elimination with partial pivoting over exact rationals; the solved
       # last variable c = x[n+1]/x[n] is REDUCED and REQUIRED to be an integer
       #   (mp_int_compare_value(denominator,1) == 0).
       # output key = "%02x"-hex of mp_int_to_binary(numerator), leading 0x00 stripped
       #   (out_emit_693c.c). transform() (transform.c) is a NO-OP stub in this build.

  -> out_keys[] = the per-group key strings; out_count = num_keys.

------------------------------------------------------------------------------
GHIDRA-vs-r2 CROSS-CHECK (TASK-0033)
------------------------------------------------------------------------------
AGREE on the whole algorithm-lib chain: read_keys_from_content -> header_check
(fcn.4a34) -> dispatch_decode (fcn.4b28) -> op1/op2 (fcn.5138/fcn.54f4) ->
matrix (fcn.5eb0), pixels @ offset 54, selector = strhash(config) walk. Ghidra
ADDS the precise math r2 could not: the Vandermonde build, the exact-rational
Gaussian elimination, the denominator==1 integrality gate, and that `transform`
is a no-op stub.

DIVERGENCE (recorded): the r2 trace (§8) attributed the
fcn.13b5c (raw t_s.bmp read) + read_keys_from_content calls to the **cmd=1** sign
branch of doCommandNative. Ghidra's doCommandNative.c shows those calls are on the
**cmd=0** branch (param_4==0): cmd=0 runs the BMP decode, joins the key list with
'_' into the cached global key (DAT_00139070), and cmd=1 / cmd=2 then MD5 that
CACHED key with the request data (md5_key_builder.c). The end-to-end model
(raw t_s.bmp -> read_keys_from_content -> key list -> '_'-joined -> MD5) is
UNCHANGED and corroborated; only the cmd-number that triggers the decode differs
(cmd=0 setup, not cmd=1). This refines, not contradicts, F1.

------------------------------------------------------------------------------
VALIDATION STATUS: fully-ported-unvalidated.
There is NO embedded static oracle (no test vector / expected token in the .so).
The matrix machinery is deterministic + device-independent and runs offline.
HOWEVER (see re/bmp_token_whitebox.md §9 -- REFUTED static-only): the production
token is NOT static-only -- read_keys_from_content's `config` arg is a RUNTIME JNI
byte[] (doCommandNative param_6), which selects the pixel offset AND the
header-validity branch. So the matrix runs offline, but emitting the REAL key list
additionally requires the runtime SDK-config blob (or one live sign vector); the
ONLY true oracle is a live sign-accept (EXCLUDED by scope). A wrong constant fails
silently. Any produced value goes to secrets/ ONLY; never a tracked file.
------------------------------------------------------------------------------
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


class DecodeError(Exception):
    """Mirrors the native error returns (0x15 invalid, 0xb singular, etc.)."""


# ---------------------------------------------------------------------------
# header_check.c  (FUN_00104a34) + read_keys_from_content.c (FUN_00104974)
# ---------------------------------------------------------------------------
@dataclass
class BmpView:
    raw: bytes
    filesize: int     # [bmp+2]  (u32 LE)
    bf_off_bits: int  # [bmp+10] (u32 LE)
    pixels_base: int  # bmp+0x36 (constant 54, per dispatch_decode)
    pixel_len: int    # filesize - bf_off_bits  (per dispatch_decode)


def header_check_and_view(raw: bytes) -> BmpView:
    """Port of header_check.c + the offset math in read_keys_from_content.c.

    Native validator (header_check.c, returns 0 on OK / 0x15 on reject):
      - raw[0:2] == 'BM'
      - filesize  = u32le(raw[2:6]);  filesize < 0x200001  AND  filesize >= 0x2800
      - filesize - 0x36 >= bf_off_bits          (bf_off_bits = u32le(raw[10:14]))
      - bpp = u16le(raw[0xe+? ]) in {0x18, 0x20}   (DIB biBitCount)
      - compression (biCompression) == 0
    NOTE: header_check.c reads bpp/compression at param_2 = raw+0xe (it is called
    as FUN_00104a34(bmp, bmp+0xe)); biBitCount is at DIB offset 0x1c overall, i.e.
    param_2+0xe, and biCompression at param_2+0x10. We replicate those exact reads.
    """
    if raw[0:2] != b"BM":
        raise DecodeError("header: missing 'BM' magic (0x15)")
    filesize = int.from_bytes(raw[2:6], "little")
    if filesize >= 0x200001:
        raise DecodeError("header: filesize >= 0x200001 (0x15)")
    if filesize < 0x2800:
        raise DecodeError("header: filesize < 0x2800 (0x15)")
    bf_off_bits = int.from_bytes(raw[10:14], "little")
    if filesize - 0x36 < bf_off_bits:
        raise DecodeError("header: filesize-0x36 < bf_off_bits (0x15)")
    # param_2 = raw + 0xe ; bpp @ param_2+0xe = raw+0x1c ; comp @ param_2+0x10 = raw+0x1e
    bpp = int.from_bytes(raw[0x1C:0x1E], "little")
    if bpp not in (0x18, 0x20):
        raise DecodeError(f"header: bpp {bpp} not in {{24,32}} (0x15)")
    comp = int.from_bytes(raw[0x1E:0x22], "little")
    if comp != 0:
        raise DecodeError("header: compression != 0 (0x15)")
    pixel_len = filesize - bf_off_bits
    return BmpView(
        raw=raw,
        filesize=filesize,
        bf_off_bits=bf_off_bits,
        pixels_base=0x36,
        pixel_len=pixel_len,
    )


def pixels(view: BmpView) -> bytes:
    """The pixel array the native code indexes: raw[0x36 : 0x36 + pixel_len].

    dispatch_decode is called with param_4 = bmp + 0x36 and param_5 = pixel_len
    (= filesize - bf_off_bits). All native indexing is `*(byte*)(param_4 + i)`
    with i already reduced mod pixel_len, so we expose exactly that slice.
    """
    return view.raw[view.pixels_base : view.pixels_base + view.pixel_len]


# ---------------------------------------------------------------------------
# strhash.c  (FUN_0010509c)
# ---------------------------------------------------------------------------
def strhash(s: bytes) -> int:
    """acc = acc*31 + byte over strlen(s) bytes, as signed int32, then abs().
    NB: native strlen stops at the first NUL -- the config blob here is a C string
    (NUL-terminated), so we hash up to the first 0x00 if present."""
    nul = s.find(b"\x00")
    if nul != -1:
        s = s[:nul]
    acc = 0
    for c in s:
        acc = (acc * 31 + c) & 0xFFFFFFFF
    if acc >= 0x80000000:
        acc -= 0x100000000
    return abs(acc)


# ---------------------------------------------------------------------------
# xorstep_583c.c  (FUN_0010583c): read 4 pixel bytes (BE) as a u32 magic
# ---------------------------------------------------------------------------
def xorstep_u32(px: bytes, off: int) -> int:
    """xorstep_583c.c (FUN_0010583c): the four pixel reads use indices
    (off), (off+1), (off+2), (off+3) each reduced mod L (the native code computes
    `idx - (idx//L)*L` per byte = idx % L), packed big-endian:
        (px[off]<<24) | (px[off+1]<<16) | (px[off+2]<<8) | px[off+3]."""
    L = len(px)
    b0 = px[off % L]
    b1 = px[(off + 1) % L]
    b2 = px[(off + 2) % L]
    b3 = px[(off + 3) % L]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


# ---------------------------------------------------------------------------
# build_mpint_op1.c (FUN_00105900): `length` pixel bytes -> hex string
# read_5b68 / readbytes_op2_5c64 (op2): `length` bytes, each reconstructed
#   from the LSB of 8 consecutive pixel bytes -> hex string
# ---------------------------------------------------------------------------
def _hexstr(byte_vals: List[int]) -> str:
    return "".join("%02x" % (b & 0xFF) for b in byte_vals)


def read_value_op1(px: bytes, off: int, length: int) -> Tuple[str, int]:
    """op1: `length` raw pixel bytes from off (mod L), hex-formatted.
    Returns (hexstring, next_off). next_off = off + length (native walks
    param_4 + (off+i)%L, then advances off by the run for the b-value chain)."""
    L = len(px)
    vals = [px[(off + i) % L] for i in range(length)]
    return _hexstr(vals), off + length


def read_byte_op2(px: bytes, off: int) -> Tuple[int, int]:
    """op2 single byte: read_5b68 / readbytes_op2_5c64 reconstruct one byte from
    the LSB of 8 consecutive pixel bytes (LSB-first into bits 0..7), advancing the
    offset by 8 and wrapping mod L *before* each read (if off>=L). Returns
    (byte, next_off)."""
    L = len(px)
    val = 0
    for bit in range(8):
        if off >= L:
            off = off % L
        val = (val + ((px[off] & 1) << bit)) & 0xFF
        off += 1
    return val, off


def read_value_op2(px: bytes, off: int, length: int) -> Tuple[str, int]:
    """op2: `length` LSB-packed bytes -> hex string. Returns (hexstring, next_off)."""
    vals: List[int] = []
    for _ in range(length):
        b, off = read_byte_op2(px, off)
        vals.append(b)
    return _hexstr(vals), off


# ---------------------------------------------------------------------------
# matrix_fcn5eb0.c + matrix_init.c + make_rational_6a38.c
#   Vandermonde over rationals; solve; require integral; numerator -> bytes -> hex
# ---------------------------------------------------------------------------
def _hexstr_to_fraction(hexstr: str) -> Fraction:
    """make_rational_6a38.c: mp_rat_read_string(value, base 16). A base-16 rational
    string with no '/' is just the integer value in hex."""
    if hexstr == "":
        return Fraction(0)
    if "/" in hexstr:
        num, den = hexstr.split("/", 1)
        return Fraction(int(num, 16), int(den, 16))
    return Fraction(int(hexstr, 16))


def matrix_solve(pairs: List[Tuple[str, str]]) -> Optional[bytes]:
    """Port of FUN_00105eb0 (+ matrix_init FUN_001065f8).

    Builds the Vandermonde augmented matrix over exact rationals:
        row i = [ a_i^(n-1), a_i^(n-2), ..., a_i^1, 1 | b_i ]   (n = len(pairs))
    Gaussian elimination with partial pivoting (swap when pivot is zero), then
        c = lastrow[n] / lastrow[n-1]   (the solved final unknown)
    REQUIRE the reduced denominator == 1 (mp_int_compare_value(denom,1)==0);
    output = mp_int_to_binary(numerator) with leading 0x00 stripped.
    Returns the key bytes, or None if singular / non-integral (native -> 0xb)."""
    n = len(pairs)
    if n == 0:
        return None
    a_vals = [_hexstr_to_fraction(a) for a, _ in pairs]
    b_vals = [_hexstr_to_fraction(b) for _, b in pairs]
    # augmented Vandermonde: n rows, n columns + RHS
    mat: List[List[Fraction]] = []
    for i in range(n):
        row = [a_vals[i] ** (n - 1 - j) for j in range(n)]
        row.append(b_vals[i])
        mat.append(row)
    for col in range(n):
        piv = None
        for r in range(col, n):
            if mat[r][col] != 0:
                piv = r
                break
        if piv is None:
            return None  # singular -> native 0xb
        mat[col], mat[piv] = mat[piv], mat[col]
        for r in range(col + 1, n):
            if mat[r][col] != 0:
                factor = mat[r][col] / mat[col][col]
                for k in range(col, n + 1):
                    mat[r][k] -= factor * mat[col][k]
    denom_pivot = mat[n - 1][n - 1]
    if denom_pivot == 0:
        return None
    c = mat[n - 1][n] / denom_pivot
    if c.denominator != 1:
        return None  # non-integral -> native 0xb
    num = c.numerator
    if num < 0:
        return None
    if num == 0:
        return b""
    length = (num.bit_length() + 7) // 8
    out = num.to_bytes(length, "big")
    return out.lstrip(b"\x00")


def key_to_hex(key_bytes: bytes) -> str:
    """out_emit_693c.c: emit the numerator bytes as a "%02x" hex string."""
    return key_bytes.hex()


# ---------------------------------------------------------------------------
# decode_op1.c / decode_op2.c : read the (a,b) pairs and group -> keys
# ---------------------------------------------------------------------------
def _decode(px: bytes, config: bytes, op: int) -> List[str]:
    """Port of decode_op1 (op=1) / decode_op2 (op=2).

    Selector / header reads (decode_op*.c):
      h    = strhash(config)
      r    = (h % L) // 2
      base = r % L
      num_keys   = pixels[(base+1) % L]
      num_coeffs = pixels[(base+2) % L]      (must be 1..5 in BOTH the key count and
                                              the coeff count; native checks <6 && >0)
    Then read `num_coeffs` (a,b) pairs, walking a chained offset that starts at
      off = (xorstep_u32(px, base) ^ r) % L
    and after each pair is XOR-stepped again. The read width of a/b is a length
    byte taken from the pixel stream. Finally split the pairs into `num_keys`
    consecutive groups of (num_coeffs // num_keys) pairs and matrix_solve each.

    HONEST LIMITATION (see module docstring / TASK-0033 notes): the precise
    chained-offset arithmetic for the per-pair (a,b) reads in decode_op1.c uses
    several `FUN_00105900(param_4, param_5, bVar2, iVar7)` calls whose first read
    length `bVar2 = pixels[off]` and second from `pixels[off2]`, with the offset
    advanced by `iVar7 + bVar2` then XOR-stepped. This implementation follows that
    structure 1:1 from decode_op1.c; op2 follows decode_op2.c's FUN_00105b68/5c64.
    """
    L = len(px)
    if L == 0:
        raise DecodeError("empty pixel array")
    h = strhash(config)
    r = (h % L) // 2
    base = r % L
    sel = px[base]
    if sel != op:
        # caller already dispatched; this is a guard
        raise DecodeError(f"selector {sel} != op {op}")

    # num_keys (decode_op*.c: *param_3 = pixels[(base+1)%L]; valid 1..5)
    num_keys = px[(base + 1) % L]
    if not (0 < num_keys < 6):
        raise DecodeError(f"num_keys {num_keys} out of (0,6) (0x15)")
    # num_coeffs (pixels[(base+2)%L])
    num_coeffs = px[(base + 2) % L]
    if num_coeffs == 0:
        raise DecodeError("num_coeffs == 0 (0x15)")

    # Chained offset start. Ghidra rendered this as `FUN_0010583c(param_4,param_5)`
    # (it dropped the 3rd arg); the r2 disassembly of 0x5138 shows the actual call
    # is xorstep(px, L, base+1) and the result is XOR'd with `r` (the (strhash%L)/2
    # value), then reduced mod L:
    #     off = (xorstep_u32(px, base+1) ^ r) % L
    off = (xorstep_u32(px, (base + 1) % L) ^ r) % L

    pairs: List[Tuple[str, str]] = []
    for _ in range(num_coeffs):
        if op == 1:
            # a: length byte at off, then `len` raw bytes; advance off
            alen = px[off % L]
            a_hex, _ = read_value_op1(px, (off + 1) % L, alen)
            off2 = (off + 1 + alen) % L
            blen = px[off2 % L]
            b_hex, _ = read_value_op1(px, (off2 + 1) % L, blen)
            off = (off2 + 1 + blen) % L
        else:
            # op2: read a length byte then `len` LSB-packed bytes
            alen, off = read_byte_op2(px, off)
            a_hex, off = read_value_op2(px, off, alen)
            blen, off = read_byte_op2(px, off)
            b_hex, off = read_value_op2(px, off, blen)
        pairs.append((a_hex, b_hex))
        # per-pair offset XOR-step (decode_op1.c tail; r2 0x53fc: bl 0x583c; eor):
        #     off = (xorstep_u32(px, off) ^ off) % L
        off = (xorstep_u32(px, off) ^ off) % L

    # split into num_keys groups; each group solved independently
    group = num_coeffs // num_keys if num_keys else num_coeffs
    if group == 0:
        group = num_coeffs
    keys: List[str] = []
    for g in range(num_keys):
        chunk = pairs[g * group : (g + 1) * group]
        if not chunk:
            continue
        kb = matrix_solve(chunk)
        if kb is None:
            raise DecodeError("matrix solve singular/non-integral (0xb)")
        keys.append(key_to_hex(kb))
    return keys


def read_keys_from_content(config: bytes, bmp_raw: bytes) -> List[str]:
    """Top-level port of read_keys_from_content.c: validate header, dispatch on the
    selector pixel, return the decoded key list."""
    view = header_check_and_view(bmp_raw)
    px = pixels(view)
    h = strhash(config)
    r = (h % view.pixel_len) // 2
    idx = r % view.pixel_len
    sel = px[idx]
    if sel == 1:
        return _decode(px, config, 1)
    if sel == 2:
        return _decode(px, config, 2)
    raise DecodeError(f"selector byte {sel} not in {{1,2}} (0x15)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: List[str]) -> int:
    assets = argv[1] if len(argv) > 1 else ASSETS_DEFAULT
    t_s = os.path.join(assets, "t_s.bmp")
    if not os.path.exists(t_s):
        print(f"ERROR: {t_s} not found", file=sys.stderr)
        return 2
    bmp_raw = open(t_s, "rb").read()
    view = header_check_and_view(bmp_raw)
    print(f"t_s.bmp: filesize={view.filesize} bf_off_bits={view.bf_off_bits} "
          f"pixel_len={view.pixel_len}")
    px = pixels(view)
    # The config blob (param_1/x0 to read_keys_from_content) is the SDK-config
    # byte[] passed into doCommandNative -- it is NOT a static asset, it is supplied
    # by the caller at runtime. So a fully-resolved token requires that runtime
    # config blob; here we demonstrate the decode machinery against a probe config
    # to show it runs end-to-end and is deterministic.
    probe = argv[2].encode() if len(argv) > 2 else b"securityOpen"
    h = strhash(probe)
    r = (h % view.pixel_len) // 2
    idx = r % view.pixel_len
    sel = px[idx]
    print(f"probe config={probe!r}: strhash={h} selector_idx={idx} selector_byte={sel}")
    try:
        keys = read_keys_from_content(probe, bmp_raw)
        print(f"decoded {len(keys)} key(s); lengths={[len(k) for k in keys]}")
        print("NOTE: values intentionally not printed; write to secrets/ only.")
    except DecodeError as e:
        print(f"decode result for this probe config: {e}")
    print("\nDecode: fully-ported-unvalidated (no static oracle; live sign-accept "
          "is the only true oracle, excluded by scope). Real token needs the "
          "runtime SDK-config blob.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
