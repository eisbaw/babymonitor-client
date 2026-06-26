#!/usr/bin/env python3
"""Decrypt the cap1 POST-LOGIN device-discovery flow (home.space.list -> device list).

Post-login postData/result are ET3 AES-128-GCM with key = et3_key(requestId, G, ECODE)
where ECODE comes from the login. Extracts the exact request shapes (how homeId/gid is
passed) and the device-record fields (category, p2pType, ...). PII/keys redacted.
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
flows = json.load(open(os.path.join(ROOT, "emulator_captures/cap1/flows.json")))
ak = json.load(open(os.path.join(ROOT, "secrets/tuya_appkey.json")))
appSecret = ak["appSecret"].encode()
pkg = ak.get("package", "com.philips.ph.babymonitorplus").encode()
bmp = open(os.path.join(ROOT, "secrets/bmp_token.txt")).read().strip()
APK = os.path.join(ROOT, "extracted/xapk/com.philips.ph.babymonitorplus.apk")


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


def et3_key(rid, ecode=None):
    msg = G if not ecode else G + b"_" + ecode.encode()
    return hmac.new(rid.encode(), msg, hashlib.sha256).hexdigest()[:16].encode()


def dec(field, rid, ecode=None):
    raw = base64.b64decode(field)
    return AESGCM(et3_key(rid, ecode)).decrypt(raw[:12], raw[12:], None)


# Account-identifying values — redact to shape/type even when short or numeric
# (CLAUDE.md: never surface real uid/homeId/device id through any channel, incl. stdout).
HIDE = {"localKey", "p2pKey", "uid", "sid", "token", "passwd", "email", "username",
        "psk", "secKey", "mac", "ip", "latitude", "longitude", "lon", "lat",
        "publicKey", "pbKey", "deviceId", "iotId", "gwId",
        "devId", "gid", "groupId", "homeId", "ownerId", "groupUserId", "id", "uuid"}
# Non-account, RE-relevant values that are safe to print (device model/type, transport).
SHOW = {"category", "categoryCode", "p2pType", "productId", "schema", "name",
        "isOnline", "p2pConfig", "skill", "dpName", "bv", "pv", "deviceType",
        "capability", "switchDp", "errorCode", "status", "success", "admin", "role"}


def redact(o, k=None):
    if isinstance(o, dict):
        return {kk: redact(v, kk) for kk, v in o.items()}
    if isinstance(o, list):
        return [redact(x) for x in o][:2]
    if k in HIDE:
        # type/shape only — never the value (handles numeric ids too).
        return f"<str:{len(o)}>" if isinstance(o, str) else f"<{type(o).__name__}>"
    if isinstance(o, str):
        return o if (k in SHOW or len(o) <= 24) else f"<str:{len(o)}>"
    return o


# 1) get ECODE from the final (success) password.login result (login resp is ecode=None)
ecode = None
for f in sorted(flows, key=lambda x: x.get("ts", 0)):
    rf = f.get("request_form")
    if not isinstance(rf, dict) or "password.login" not in str(rf.get("a", "")):
        continue
    try:
        rb = json.loads(f["response_body"])
        inner = json.loads(dec(rb["result"], rf["requestId"]))
        if inner.get("success") and isinstance(inner.get("result"), dict):
            ecode = inner["result"].get("ecode")
    except Exception:
        pass
print("recovered session ecode:", "<present>" if ecode else "<none>", "\n")

# 2) decrypt the device-discovery flows
ACTIONS = ["home.space.list", "smart.local.device.list", "device.ref.info.list",
           "home.detail", "group.device.list"]
for f in sorted(flows, key=lambda x: x.get("ts", 0)):
    rf = f.get("request_form")
    if not isinstance(rf, dict):
        continue
    a = rf.get("a", "")
    if not any(s in a for s in ACTIONS):
        continue
    rid = rf.get("requestId", "")
    print(f"=== {a} (v{rf.get('v')}) ===")
    if "postData" in rf:
        try:
            print("  REQUEST postData:", json.dumps(redact(json.loads(dec(rf["postData"], rid, ecode)))))
        except Exception as e:
            print("  REQUEST decrypt failed:", type(e).__name__)
    else:
        print("  REQUEST: (no postData)")
    try:
        rb = json.loads(f["response_body"])
        if "result" in rb:
            inner = json.loads(dec(rb["result"], rid, ecode))
            print("  RESPONSE:", json.dumps(redact(inner))[:600])
    except Exception as e:
        print("  RESPONSE decrypt failed:", type(e).__name__)
    print()
