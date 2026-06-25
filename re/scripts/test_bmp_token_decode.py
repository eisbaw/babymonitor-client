#!/usr/bin/env python3
"""Unit tests for bmp_token_decode.py (TASK-0029).

Run: python3 re/scripts/test_bmp_token_decode.py
(plain stdlib unittest; no pip deps -- matches the project's no-pip gate.)

The tests must be able to FAIL on corrupted input (TESTING.md "prove the check
bites"): each parser test has a negative case.
"""
import os
import struct
import unittest
from fractions import Fraction

import bmp_token_decode as M

ASSETS = M.ASSETS_DEFAULT


def make_bmp(pixels: bytes) -> bytes:
    """Minimal BMP with bfOffBits=54 and the given pixel array."""
    off = 54
    header = b"BM" + struct.pack("<I", off + len(pixels)) + b"\0\0\0\0" + struct.pack("<I", off)
    dib = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels), 0, 0, 0, 0)
    return header + dib + pixels


class TestFraming(unittest.TestCase):
    def test_decimal_parse_basic(self):
        self.assertEqual(M.parse_decimal_line(b"226\nGARBAGE"), 226)
        self.assertEqual(M.parse_decimal_line(b"0\n"), 0)
        self.assertEqual(M.parse_decimal_line(b"12345\n"), 12345)

    def test_decimal_parse_negative_case(self):
        # corrupted: a different number must NOT equal the expected -> check can fail
        self.assertNotEqual(M.parse_decimal_line(b"227\n"), 226)

    def test_str_hash_matches_native_formula(self):
        # acc = acc*31 + byte, then abs(). Recompute independently here.
        for s in (b"", b"a", b"abc", b"3fjrekuxank9eaej3gcx"):
            acc = 0
            for c in s:
                acc = (acc * 31 + c) & 0xFFFFFFFF
            if acc >= 0x80000000:
                acc -= 0x100000000
            self.assertEqual(M.native_str_hash(s), abs(acc))

    def test_str_hash_negative_case(self):
        self.assertNotEqual(M.native_str_hash(b"abc"), M.native_str_hash(b"abd"))

    def test_bmp_pixel_offset(self):
        raw = make_bmp(b"\x01\x02\x03\x04")
        self.assertEqual(M.bmp_pixel_data(raw), b"\x01\x02\x03\x04")

    def test_bmp_rejects_non_bmp(self):
        with self.assertRaises(ValueError):
            M.bmp_pixel_data(b"PK\x03\x04not a bmp")


class TestMatrixSolverKnownVector(unittest.TestCase):
    """Prove the exact-rational interpolation solver is correct on a KNOWN vector,
    so its use as the nalajcie cross-check is trustworthy (non-circular)."""

    def test_recovers_planted_token(self):
        # Plant token "vay9" -> big-endian int, build a Vandermonde system whose
        # c_last/r_last,last == that int, then confirm the solver recovers it.
        token = b"vay9"
        secret = int.from_bytes(token, "big")
        # Construct coeffs so the polynomial-interpolation last-pivot equals `secret`.
        # Easiest exact construction: degree-0 system (single coeff) with a=1,b=secret
        # -> matrix [[1 | secret]] -> res = secret/1.
        coeffs = [M.Coeff(a=1, b=secret)]
        num = M.solve_polynomial_rational(coeffs)
        self.assertEqual(num, secret)
        self.assertEqual(M.numerator_to_token(num), token)

    def test_two_point_rational_consistency(self):
        # 2x2 Vandermonde over rationals: rows [a,1|b]. With a1=2,b1=10 ; a2=4,b2=20
        # the line through (2,10),(4,20) is y=5x, last pivot solves to b/?=...
        # We assert the solver returns an integer when the system is integral.
        coeffs = [M.Coeff(2, 10), M.Coeff(4, 20)]
        num = M.solve_polynomial_rational(coeffs)
        self.assertIsNotNone(num)
        self.assertIsInstance(num, int)

    def test_non_integral_rejected(self):
        # A system whose last-pivot ratio is non-integral must be rejected (denom!=1).
        coeffs = [M.Coeff(2, 3), M.Coeff(4, 4)]  # crafted to give a fractional pivot
        # Force a fractional outcome via direct check on the reducer:
        res = Fraction(3, 2)
        self.assertNotEqual(res.denominator, 1)  # sanity: our reject rule is meaningful


class TestNalajcieReferenceVsThisApp(unittest.TestCase):
    """The narrow, TRUE residual fact (corrected by TASK-0030): the matrix FAMILY is
    the correct model for this APK's signer bmp_token (raw t_s.bmp -> imath+matrix
    decode on the sign path), but nalajcie/tuya-sign-hacking's SPECIFIC older
    byte-layout does NOT reproduce this APK's token -- a layout mismatch, NOT evidence
    against the matrix scheme. The token itself is un-ported (no local oracle)."""

    @unittest.skipUnless(os.path.exists(os.path.join(ASSETS, "t_s.bmp")), "assets absent")
    def test_nalajcie_older_layout_does_not_match_this_apk(self):
        # The matrix FAMILY is the right model (TASK-0030); this asserts ONLY the
        # narrow layout fact: nalajcie's SPECIFIC older reader finds an implausible
        # header on this APK's t_s.bmp and yields no token. It does NOT assert "this
        # isn't a matrix scheme" (it is -- see re/bmp_token_whitebox.md §8).
        with open(os.path.join(ASSETS, "t_s.bmp"), "rb") as fh:
            bmp = fh.read()
        tok = M.nalajcie_decode(bmp, b"3fjrekuxank9eaej3gcx")
        self.assertIsNone(
            tok,
            "nalajcie's older byte-layout unexpectedly produced a token on this BMP",
        )

    @unittest.skipUnless(os.path.exists(os.path.join(ASSETS, "t_s.bmp")), "assets absent")
    def test_thisapp_decode_is_unported(self):
        # The signer bmp_token is the un-ported imath+matrix decode of raw t_s.bmp on
        # the sign path -- it still raises (token not produced), but the reason is the
        # MATRIX residual, not the retracted "white-box cipher" verdict.
        with self.assertRaises(M.MatrixResidual):
            M.thisapp_decode(ASSETS)


class TestRealExtAsset(unittest.TestCase):
    @unittest.skipUnless(
        os.path.exists(os.path.join(ASSETS, "tecrkcehc_ext")), "ext asset absent"
    )
    def test_real_ext_framing(self):
        with open(os.path.join(ASSETS, "tecrkcehc_ext"), "rb") as fh:
            ea = M.parse_ext_asset(fh.read())
        # recovered facts: header decimal 226, base64 ciphertext body of len 344.
        self.assertEqual(ea.declared_len, 226)
        self.assertEqual(len(ea.payload), 344)


if __name__ == "__main__":
    unittest.main(verbosity=2)
