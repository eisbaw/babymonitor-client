#!/usr/bin/env python3
"""Validate our recovered Tuya signer against the GENUINE captured token.get.

Gold-vector test: the emulator capture (emulator_captures/cap1) contains the real
app's token.get request params AND its 64-hex `sign`. Master key G is app-static
(same APK -> same packageName/cert/t_s.bmp/appSecret), so if our recipe is correct,
some combination of {sign-fn, cert-format, matrixKey0-form, postData-fold, part-order}
must reproduce the captured sign EXACTLY.

Prints ONLY non-secret results (MATCH recipe / no-match + diagnostics). Never echoes
secret values. Reads all secrets from files; no literals here.
"""
import base64
import hashlib
import hmac
import itertools
import json
import os
import subprocess
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAP = os.path.join(ROOT, "emulator_captures/cap1/flows.json")
APK = os.path.join(ROOT, "extracted/xapk/com.philips.ph.babymonitorplus.apk")
APPKEY = os.path.join(ROOT, "secrets/tuya_appkey.json")
BMP = os.path.join(ROOT, "secrets/bmp_token.txt")

# ── 1. genuine token.get (earliest login one) ────────────────────────────────
flows = json.load(open(CAP))
tg = [f for f in flows if isinstance(f.get("request_form"), dict)
      and "token.get" in str(f["request_form"].get("a", ""))]
tg.sort(key=lambda f: f["ts"])
form = tg[0]["request_form"]
genuine_sign = form["sign"].lower()
print(f"genuine token.get: host={tg[0]['url'].split('/')[2]} sign_len={len(genuine_sign)}")

# ── 2. raw-embedded leaf cert SHA-256 (Android signatures[0] semantics) ───────
def cert_sha256_bytes():
    z = zipfile.ZipFile(APK)
    rsa = [n for n in z.namelist() if n.upper().endswith((".RSA", ".DSA", ".EC"))][0]
    der = z.read(rsa)
    with tempfile.NamedTemporaryFile(suffix=".p7", delete=False) as t:
        t.write(der); p7 = t.name
    # find first leaf cert SEQUENCE offset (d=4 after cont[0] d=3)
    out = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", p7],
                         capture_output=True, text=True).stdout
    in_certs = False; off = None
    for ln in out.splitlines():
        if "d=3" in ln and "cont [ 0 ]" in ln:
            in_certs = True; continue
        if in_certs and "d=4" in ln and "cons: SEQUENCE" in ln:
            off = int(ln.split(":")[0].strip()); break
    leaf = p7 + ".der"
    subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", p7,
                    "-strparse", str(off), "-noout", "-out", leaf], check=True)
    h = hashlib.sha256(open(leaf, "rb").read()).digest()
    os.unlink(p7); os.unlink(leaf)
    return h

cert32 = cert_sha256_bytes()
print(f"cert sha256 recovered: {len(cert32)} bytes")

ak = json.load(open(APPKEY))
appSecret = ak["appSecret"].encode()
pkg = ak.get("package", "com.philips.ph.babymonitorplus").encode()
bmp = open(BMP).read().strip()

# ── 3. helpers ───────────────────────────────────────────────────────────────
def swap(s):  # B1+A+C+B2
    return s[8:16] + s[0:8] + s[24:32] + s[16:24] if len(s) == 32 else None

def md5hex(b): return hashlib.md5(b).hexdigest()

pd = form["postData"]
pd_raw = None
try:
    pd_raw = base64.b64decode(pd)
except Exception:
    pd_raw = None

postdata_folds = {
    "swap(md5hex(pd_str))": swap(md5hex(pd.encode())),
    "md5hex(pd_str)": md5hex(pd.encode()),
    "swap(md5hex(pd_raw))": swap(md5hex(pd_raw)) if pd_raw else None,
    "md5hex(pd_raw)": md5hex(pd_raw) if pd_raw else None,
    "as_is(pd)": pd,
}
postdata_folds = {k: v for k, v in postdata_folds.items() if v}

SIGNED = ["a", "v", "lang", "deviceId", "appVersion", "ttid", "os",
          "clientId", "postData", "time", "requestId", "et", "chKey",
          "isH5", "h5Token", "n4h5", "sid", "sp", "lat", "lon"]

def str2(pd_fold):
    p = dict(form); p["postData"] = pd_fold
    items = [f"{k}={p[k]}" for k in sorted(SIGNED) if str(p.get(k, "")) != ""]
    return "||".join(items).encode()

cert_formats = {
    "colon_upper": ":".join(f"{b:02X}" for b in cert32).encode(),
    "colon_lower": ":".join(f"{b:02x}" for b in cert32).encode(),
    "plain_upper": cert32.hex().upper().encode(),
    "plain_lower": cert32.hex().encode(),
}
mk_forms = {
    "raw32": bytes.fromhex(bmp),
    "ascii_lower": bmp.lower().encode(),
    "ascii_upper": bmp.upper().encode(),
}
SEP = b"_"
orders = [
    ("pkg_cert_mk_sec", lambda c, m: SEP.join([pkg, c, m, appSecret])),
    ("pkg_cert_sec_mk", lambda c, m: SEP.join([pkg, c, appSecret, m])),
    ("cert_mk_sec",     lambda c, m: SEP.join([c, m, appSecret])),
    ("pkg_mk_cert_sec", lambda c, m: SEP.join([pkg, m, c, appSecret])),
    ("sec_pkg_cert_mk", lambda c, m: SEP.join([appSecret, pkg, c, m])),
    ("pkg_cert_mk",     lambda c, m: SEP.join([pkg, c, m])),
]
sign_fns = {
    "hmac(G,str2)":      lambda G, s: hmac.new(G, s, hashlib.sha256).hexdigest(),
    "hmac(str2,G)":      lambda G, s: hmac.new(s, G, hashlib.sha256).hexdigest(),
    "sha256(str2+G)":    lambda G, s: hashlib.sha256(s + G).hexdigest(),
    "sha256(G+str2)":    lambda G, s: hashlib.sha256(G + s).hexdigest(),
    "sha256(str2+||+G)": lambda G, s: hashlib.sha256(s + b"||" + G).hexdigest(),
}

# ── 4. grid search ───────────────────────────────────────────────────────────
hits = []
tried = 0
for pdn, pdf in postdata_folds.items():
    s2 = str2(pdf)
    for (on, ob), (cfn, cf), (mkn, mk), (sfn, sf) in itertools.product(
            orders, cert_formats.items(), mk_forms.items(), sign_fns.items()):
        tried += 1
        G = ob(cf, mk)
        if sf(G, s2).lower() == genuine_sign:
            hits.append(dict(postdata=pdn, order=on, cert=cfn, mk=mkn, signfn=sfn))

print(f"\ntried {tried} combinations across {len(postdata_folds)} postData folds")
if hits:
    print(f"\n*** {len(hits)} MATCH(es) — recovered the real recipe: ***")
    for h in hits:
        print("   ", h)
else:
    print("\nNO MATCH — our bmp_token candidate and/or str2 reconstruction is wrong "
          "(no {signfn,cert,mk,order,postData} combo reproduces the genuine sign).")
    # also report our CURRENT recipe's output distance (non-secret: just whether equal)
    G = orders[0][1](cert_formats["colon_upper"], mk_forms["raw32"])
    cur = sign_fns["hmac(G,str2)"](G, str2(postdata_folds.get("swap(md5hex(pd_str))", b"")))
    print(f"   (current Rust recipe reproduces genuine sign: {cur.lower()==genuine_sign})")

# ── 5. chKey reproducer (committed offline check) ────────────────────────────
# ch_key() = hex(HMAC-SHA256(appKey, packageName + "_" + certColonUpper))[8:16].
# Verify it reproduces the genuine wire chKey from the capture (8 chars).
gen_chkey = form.get("chKey", "")
appKey = ak["appKey"].encode()
ck = hmac.new(appKey, pkg + b"_" + cert_formats["colon_upper"],
              hashlib.sha256).hexdigest()
print(f"\nchKey: ch_key()[8:16] reproduces genuine wire chKey ({len(gen_chkey)} chars): "
      f"{ck[8:16] == gen_chkey}  (old [8:24] would match: {ck[8:24] == gen_chkey})")
assert ck[8:16] == gen_chkey, "chKey hex[8:16] must equal the captured wire chKey"
