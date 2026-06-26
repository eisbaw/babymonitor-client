#!/usr/bin/env python3
"""Decrypt the captured login-flow postData/result with the recovered master key G.

Validates our ET=3 crypto round-trip against ground truth AND extracts the exact
request/response STRUCTURE for each login step (the implementation spec for TASK-0065).

postData wire = base64(nonce[12] || AES-128-GCM_ct || tag[16]); key = the ET=3 key =
first 16 ASCII hex chars of HMAC-SHA256(key=requestId, msg=G). (token.get/password.login
set setSessionRequire(false) => ecode omitted => msg=G.)

Prints STRUCTURE only — email/password/token values are redacted to <type:len>.
Reads secrets from files; no secret literals here.
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAP = os.path.join(ROOT, "emulator_captures/cap1/flows.json")
APK = os.path.join(ROOT, "extracted/xapk/com.philips.ph.babymonitorplus.apk")

# ── master key G ────────────────────────────────────────────────────────────
ak = json.load(open(os.path.join(ROOT, "secrets/tuya_appkey.json")))
appSecret = ak["appSecret"].encode()
pkg = ak.get("package", "com.philips.ph.babymonitorplus").encode()
bmp = open(os.path.join(ROOT, "secrets/bmp_token.txt")).read().strip()


def cert32():
    z = zipfile.ZipFile(APK)
    rsa = [n for n in z.namelist() if n.upper().endswith((".RSA", ".DSA", ".EC"))][0]
    with tempfile.NamedTemporaryFile(suffix=".p7", delete=False) as t:
        t.write(z.read(rsa)); p7 = t.name
    out = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", p7],
                         capture_output=True, text=True).stdout
    inc = False; off = None
    for ln in out.splitlines():
        if "d=3" in ln and "cont [ 0 ]" in ln:
            inc = True; continue
        if inc and "d=4" in ln and "cons: SEQUENCE" in ln:
            off = int(ln.split(":")[0]); break
    leaf = p7 + ".der"
    subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", p7,
                    "-strparse", str(off), "-noout", "-out", leaf], check=True)
    h = hashlib.sha256(open(leaf, "rb").read()).digest()
    os.unlink(p7); os.unlink(leaf)
    return h


colon_upper = ":".join(f"{b:02X}" for b in cert32()).encode()
G = b"_".join([pkg, colon_upper, bytes.fromhex(bmp), appSecret])


def et3_key(request_id):
    return hmac.new(request_id.encode(), G, hashlib.sha256).hexdigest()[:16].encode()


def decrypt(field, request_id):
    raw = base64.b64decode(field)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(et3_key(request_id)).decrypt(nonce, ct, None)


# Keys that are NOT PII/secret — show their values to read the flow structure.
SHOW = {"options", "errorCode", "errorMsg", "state", "exponent", "ifencrypt",
        "countryCode", "isUid", "componentId", "status", "success", "ticket",
        "type", "verifyType", "mfaType", "way", "extraInfo", "needMfa"}
# PII/secret keys: always redact to <str:len>.
HIDE = {"username", "email", "passwd", "password", "token", "publicKey", "pbKey",
        "uid", "sid", "phone", "mobile"}


def redact(obj, key=None):
    if isinstance(obj, dict):
        return {k: redact(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj][:5]
    if isinstance(obj, str):
        if key in HIDE:
            return f"<str:{len(obj)}>"
        if key in SHOW or len(obj) <= 40:
            return obj
        return f"<str:{len(obj)}>"
    return obj


flows = json.load(open(CAP))
STEPS = ["token.get", "password.login", "verification.code.get", "mfa.code.get"]
t0 = min(f["ts"] for f in flows if f.get("ts"))
for f in sorted([x for x in flows if isinstance(x.get("request_form"), dict)],
                key=lambda f: f["ts"]):
    a = f["request_form"].get("a", "")
    step = next((s for s in STEPS if s in a), None)
    if not step:
        continue
    rid = f["request_form"].get("requestId", "")
    print(f"\n=== t={f['ts']-t0:.1f}  {a} (v{f['request_form'].get('v')}) ===")
    try:
        pt = decrypt(f["request_form"]["postData"], rid)
        print("  REQUEST  postData =", json.dumps(redact(json.loads(pt))))
    except Exception as e:
        print("  REQUEST  decrypt FAILED:", type(e).__name__, str(e)[:60])
    # response result uses the same requestId-derived key in the ET3 scheme
    try:
        rb = json.loads(f["response_body"])
        if "result" in rb:
            pt = decrypt(rb["result"], rid)
            print("  RESPONSE result  =", json.dumps(redact(json.loads(pt)))[:240])
    except Exception as e:
        print("  RESPONSE decrypt FAILED:", type(e).__name__, str(e)[:60])
