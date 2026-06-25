#!/usr/bin/env python3
"""Unit tests for bmp_token_aes.py -- the AES-128-CBC port of libthing_security.so
fcn.11658 (TASK-0030).

Validation strategy (static-only; what we CAN prove without a live oracle):
  - The S-box tables in re/aes_tables.txt are the EXACT bytes in the .so (when the
    gitignored .so is present) AND are the canonical mutually-inverse AES S-boxes.
  - The AES-128 decrypt core passes the FIPS-197 / NIST known-answer vector -- an
    INDEPENDENT oracle for the cipher (not derived from our own decompilation).
  - The full pipeline is deterministic and, on the real assets, yields a clean,
    well-formed JSON config -- a strong structural self-consistency oracle (random
    key/iv/mode errors would yield garbage, not valid JSON).

What we CANNOT prove here (honest): that the decrypted blob is byte-identical to what
the app uses, or that it is the signer's sign-key middle part. See re/bmp_token_whitebox.md.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bmp_token_aes as M  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ASSETS = os.path.join(REPO, "decompiled", "apktool", "assets")
SO = os.path.join(REPO, "decompiled", "nativelibs", "libthing_security.so")


class TestTables(unittest.TestCase):
    def test_sboxes_are_mutual_inverses(self):
        for i in range(256):
            self.assertEqual(M.INV_SBOX[M.SBOX[i]], i)

    def test_sboxes_are_canonical_aes(self):
        # Canonical AES S-box / inverse S-box first rows (FIPS-197).
        self.assertEqual(M.SBOX[:8], [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])
        self.assertEqual(M.INV_SBOX[:8], [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38])

    @unittest.skipUnless(os.path.exists(SO), "gitignored .so not present")
    def test_tables_match_the_so_bytes(self):
        with open(SO, "rb") as fh:
            so = fh.read()
        # .rodata is mapped 1:1 (addr == file offset) for this build.
        self.assertEqual(list(so[0x795F:0x795F + 256]), M.SBOX, "fwd S-box drift vs .so")
        self.assertEqual(list(so[0x7A5F:0x7A5F + 256]), M.INV_SBOX, "inv S-box drift vs .so")


class TestAesCore(unittest.TestCase):
    def test_fips197_known_answer_decrypt(self):
        # FIPS-197 Appendix B/C.1 AES-128 vector (independent oracle).
        key = bytes(range(16))
        pt = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        rk = M.key_expansion(key)
        self.assertEqual(M.aes128_decrypt_block(ct, rk), pt)

    def test_cbc_first_block_xors_iv(self):
        # CBC self-consistency: decrypting [C0] with IV == ECB-decrypt(C0) XOR IV.
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        c0 = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        rk = M.key_expansion(key)
        ecb = M.aes128_decrypt_block(c0, rk)
        expect = bytes(ecb[i] ^ iv[i] for i in range(16))
        self.assertEqual(M.aes128_cbc_decrypt(c0, key, iv), expect)

    def test_block_must_be_aligned(self):
        with self.assertRaises(AssertionError):
            M.aes128_cbc_decrypt(b"\x00" * 15, bytes(16), bytes(16))


class TestPipeline(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(os.path.join(ASSETS, "t_s.bmp")),
                         "assets not extracted")
    def test_ext_parse_and_ciphertext_alignment(self):
        with open(os.path.join(ASSETS, "tecrkcehc_ext"), "rb") as fh:
            raw = fh.read()
        declared_len, ct = M.parse_ext_asset(raw)
        self.assertEqual(declared_len, 226)
        self.assertEqual(len(ct) % 16, 0, "ciphertext must be AES-block-aligned")
        self.assertEqual(len(ct), 256)

    @unittest.skipUnless(os.path.exists(os.path.join(ASSETS, "t_s.bmp")),
                         "assets not extracted")
    def test_key_is_raw_md5_digest(self):
        with open(os.path.join(ASSETS, "t_s.bmp"), "rb") as fh:
            bmp = fh.read()
        key = M.aes_key_from_bmp(bmp)
        self.assertEqual(len(key), 16, "AES-128 key is the 16-byte raw MD5 digest")

    @unittest.skipUnless(os.path.exists(os.path.join(ASSETS, "t_s.bmp")),
                         "assets not extracted")
    def test_decode_is_deterministic(self):
        a = M.decode_bmp_token(ASSETS)
        b = M.decode_bmp_token(ASSETS)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 226)

    @unittest.skipUnless(os.path.exists(os.path.join(ASSETS, "t_s.bmp")),
                         "assets not extracted")
    def test_decoded_blob_is_valid_json_config(self):
        # STRUCTURAL oracle: the decrypted plaintext parses as the expected
        # cert-pinning config {"securityOpen": bool, "data": [pin, pin]}. Getting
        # valid JSON out of AES-CBC is essentially impossible with a wrong
        # key/iv/mode -- this jointly validates cipher + key + iv + truncation.
        tok = M.decode_bmp_token(ASSETS)
        self.assertTrue(all(32 <= b < 127 for b in tok), "plaintext must be printable")
        obj = json.loads(tok.decode("ascii"))
        self.assertIn("securityOpen", obj)
        self.assertIn("data", obj)
        self.assertIsInstance(obj["data"], list)
        # Each data entry is a colon-separated SHA-256 fingerprint (32 hex bytes).
        for pin in obj["data"]:
            self.assertEqual(len(pin), 95)
            self.assertTrue(all(c in "0123456789abcdefABCDEF:" for c in pin))
            self.assertEqual(pin.count(":"), 31)


if __name__ == "__main__":
    unittest.main(verbosity=2)
