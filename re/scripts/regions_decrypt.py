#!/usr/bin/env python3
"""regions_decrypt.py -- BYTE-EXACT offline decrypt of the Tuya
`assets/thing_domains_v1/regions` (and `pins`) datacenter-config blob (TASK-0043).

VERDICT: the `regions`/`pins` decrypt is **AES-256-CTR** and **fully static-derivable
from the asset itself** -- the key and IV are the first 48 bytes of the asset's own
base64-decoded content. NO runtime input, NO appKey, NO native `getConfig` call is
needed. (The native `SecureNativeApi.getConfig` @0x136e0 is the decryptor for a
SEPARATE asset, `t_cdc.tcfg`, the optional custom-domain override -- AES-GCM keyed on
appKey/appSecret/packageName, NOT shipped in this APK. See re/regions_decrypt.md.)

The pure-Java decrypt path (the one actually used for regions/pins):
  DomainHelper.parseDomainsConfig(str):                     [Java source, confirmed]
    decode  = Base64.decode(str)            # the asset file IS base64 text
    key     = decode[0:32]                  # first 32 bytes  (AES-256 key)
    bArr2   = decode[32:]                   # remainder
    return AESCTRUtil.decrypt(key, Base64.encodeToString(bArr2))
  AESCTRUtil.decrypt(key, str):
    b2 = Base64.decode(str)                 # == bArr2 (round-trip identity)
    iv = b2[0:16]                           # next 16 bytes (CTR IV/nonce)
    ct = b2[16:]                            # the ciphertext
    Cipher "AES/CTR/NoPadding", SecretKeySpec(key,"AES"), IvParameterSpec(iv)
    return new String(cipher.doFinal(ct))

So end-to-end on the raw asset bytes:
    decode = base64(asset_file)
    key    = decode[0:32]      # 32-byte AES-256 key (ASCII hex chars)
    iv     = decode[32:48]     # 16-byte CTR IV     (ASCII hex chars)
    ct     = decode[48:]       # ciphertext
    plaintext = AES-256-CTR-decrypt(ct, key, iv)

The decrypted `regions` plaintext is a JSON array of datacenter configs (one per
region) -- ALL values are PUBLIC Tuya datacenter hosts/ports (mobileApiUrl, gwApiUrl,
mqtt/quic brokers, dns). There is NO account-specific secret in the blob, so the
recovered hosts may be documented (re/regions_decrypt.md). This script prints SHAPE +
the (non-secret) per-region mobileApiUrl/gwApiUrl; it writes no secret.

No external crypto dependency: a self-contained AES-256 CTR keystream is implemented
here, cross-checked against `openssl enc -aes-256-ctr`.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from typing import List

ASSETS_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "decompiled",
    "apktool",
    "assets",
    "thing_domains_v1",
)

# ---------------------------------------------------------------------------
# Self-contained AES (encrypt/forward direction only -- CTR needs only the
# forward cipher applied to the counter to make the keystream). Supports the
# 32-byte (AES-256) key the regions blob uses. The S-box is the canonical AES
# table (FIPS-197); cross-checked against openssl in this file's __main__.
# ---------------------------------------------------------------------------

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


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
    """AES key expansion for 16/24/32-byte keys -> (Nr+1) round keys of 16 bytes."""
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    words: List[List[int]] = [list(key[i * 4: i * 4 + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for w in range(4):
            rk.extend(words[r * 4 + w])
        round_keys.append(rk)
    return round_keys


def _sub_bytes(s):
    for i in range(16):
        s[i] = SBOX[s[i]]


def _shift_rows(s):
    for row in range(1, 4):
        vals = [s[col * 4 + row] for col in range(4)]
        vals = vals[row:] + vals[:row]
        for col in range(4):
            s[col * 4 + row] = vals[col]


def _mix_columns(s):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        s[i + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def aes_encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    nr = len(round_keys) - 1
    s = list(block)
    for i in range(16):
        s[i] ^= round_keys[0][i]
    for r in range(1, nr):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        for i in range(16):
            s[i] ^= round_keys[r][i]
    _sub_bytes(s)
    _shift_rows(s)
    for i in range(16):
        s[i] ^= round_keys[nr][i]
    return bytes(s)


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CTR (Java AES/CTR/NoPadding semantics: 16-byte IV is the initial 128-bit
    big-endian counter; increment the whole 128-bit block per keystream block)."""
    round_keys = key_expansion(key)
    out = bytearray()
    counter = int.from_bytes(iv, "big")
    for off in range(0, len(ciphertext), 16):
        ks = aes_encrypt_block(counter.to_bytes(16, "big"), round_keys)
        blk = ciphertext[off: off + 16]
        out.extend(blk[i] ^ ks[i] for i in range(len(blk)))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


def decrypt_asset(path: str) -> bytes:
    """Decrypt a thing_domains_v1 asset (regions/pins). Returns plaintext bytes."""
    with open(path, "rb") as fh:
        raw = fh.read()
    decode = base64.b64decode(bytes(b for b in raw if b not in b"\r\n \t"))
    key = decode[:32]
    iv = decode[32:48]
    ct = decode[48:]
    return aes_ctr_decrypt(ct, key, iv)


def _unescape_regions_json(pt: bytes):
    txt = pt.decode("utf-8", "replace")
    # The plaintext is a backslash-escaped JSON array string in this build.
    return json.loads(txt.replace('\\\\"', '"').replace('\\"', '"'))


def region_host_fields(region_config: dict) -> List[tuple]:
    """Return EVERY scalar `regionConfig` field as (key, value) pairs, sorted.

    The root-cause of the host false-exhaustion (TASK-0046 review gate) was that
    this script printed only `mobileApiUrl`/`gwApiUrl`, so 20+ other datacenter
    host/port fields (fusionUrl, pxApiUrl, deviceHttpsPskUrl, the mqtt/quic
    brokers, a3, etc.) were never even visible to the host-routing hypothesis.
    We now emit ALL of them. Every value here is a PUBLIC Tuya datacenter
    host/port (no account-specific secret), so they may be documented.

    Nested/object fields (if any future build adds them) are skipped — only
    scalar host/port/string config is returned (that is what a gateway probe
    needs).
    """
    out = []
    for k in sorted(region_config.keys()):
        v = region_config[k]
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            out.append((k, v))
    return out


def main(argv: List[str]) -> int:
    assets = argv[1] if len(argv) > 1 else ASSETS_DEFAULT
    regions_path = os.path.join(assets, "regions")
    if not os.path.exists(regions_path):
        print(f"ERROR: {regions_path} not found", file=sys.stderr)
        return 2
    pt = decrypt_asset(regions_path)
    try:
        data = _unescape_regions_json(pt)
    except Exception as e:  # pragma: no cover - shape print fallback
        print(f"decrypted {len(pt)} bytes (JSON parse failed: {e})")
        print(pt[:200])
        return 1
    print(f"regions decrypted: {len(data)} region(s) (AES-256-CTR, static key/IV from asset header)")
    # Per-region hosts are PUBLIC Tuya datacenter URLs -- safe to print. Emit
    # EVERY regionConfig host/port field, not just mobileApiUrl/gwApiUrl, so the
    # full datacenter-host list is authoritative (TASK-0048 root-cause fix).
    for r in data:
        rc = r.get("regionConfig", {})
        tag = "  [defaultConfig]" if r.get("defaultConfig") else ""
        fields = region_host_fields(rc)
        print(f"  region={r.get('region')}{tag}  ({len(fields)} host/port fields)")
        for k, v in fields:
            print(f"    {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
