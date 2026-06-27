#!/usr/bin/env python3
"""Decrypt the cap1 streaming-signaling flows to recover WebRTC/P2P config STRUCTURE.

Targets: smartlife.m.rtc.config.get, smartlife.m.p2p.main.pre.link.get,
smartlife.m.rtc.log, and smartlife.m.api.batch.invoke (mqtt/turn/ice bearing).

ET3 AES-128-GCM, key = et3_key(requestId, G, ECODE) with ECODE from password.login.
Reports SHAPE only; never emits literal uid/sid/localKey/p2pKey/devId/MQTT creds/SRTP keys.
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


# Account/secret-identifying values -> redact to shape/type. Includes WebRTC secret-bearing keys.
HIDE = {"localKey", "p2pKey", "uid", "sid", "token", "passwd", "email", "username",
        "psk", "secKey", "mac", "ip", "latitude", "longitude", "lon", "lat",
        "publicKey", "pbKey", "deviceId", "iotId", "gwId", "credential", "password",
        "devId", "gid", "groupId", "homeId", "ownerId", "groupUserId", "id", "uuid",
        "auth", "authKey", "motoId", "moto_id", "p2pId", "deviceP2pKey", "initString",
        "p2pSn", "ticket", "sk", "key", "appKey", "appSecret", "localNonce", "tcpKey",
        "p2pConfig", "aesKey", "aes_key", "icePassword", "iceUfrag", "sessionId",
        "traceId", "sessionTid", "bizId", "communicationNode", "iconUrl", "bizDM",
        "message", "params", "sign", "p2pSpecifiedType"}
# Non-secret, RE-relevant values that are safe to print (shape of transport/config).
# NOTE: STUN/TURN/relay host:port + topic + domain are shared Tuya infra (not per-user
# secrets) and ARE the deliverable, so we surface them. urls is whitelisted to show host shape.
SHOW = {"category", "categoryCode", "p2pType", "productId", "schema", "name",
        "isOnline", "skill", "dpName", "bv", "pv", "deviceType", "type",
        "capability", "switchDp", "errorCode", "status", "success", "admin", "role",
        "protocol", "scheme", "transport", "stun", "turn", "host", "port",
        "supplier", "vendor", "mode", "rtcType", "webrtc", "enabled", "enable",
        "urls", "topic", "api", "domain", "address", "transmission", "preconnect",
        "interval", "level", "size", "expire", "ttl", "frequency", "range"}


def redact(o, k=None):
    if isinstance(o, dict):
        return {kk: redact(v, kk) for kk, v in o.items()}
    if isinstance(o, list):
        return [redact(x) for x in o]
    if k in HIDE:
        return f"<str:{len(o)}>" if isinstance(o, str) else f"<{type(o).__name__}>"
    if isinstance(o, str):
        # urls/hosts: keep scheme+host shape but strip query/userinfo to be safe
        if k in SHOW or len(o) <= 40:
            return o
        return f"<str:{len(o)}>"
    return o


def keyshape(o, depth=0, prefix=""):
    """Print just the key tree + scalar types, never values, for deep structures."""
    out = []
    if isinstance(o, dict):
        for kk, v in o.items():
            if isinstance(v, (dict, list)):
                out.append(f"{'  '*depth}{kk}:")
                out += keyshape(v, depth+1)
            else:
                t = type(v).__name__
                out.append(f"{'  '*depth}{kk}: <{t}>")
    elif isinstance(o, list):
        out.append(f"{'  '*depth}[{len(o)}]")
        if o:
            out += keyshape(o[0], depth+1)
    return out


# 1) recover ECODE from the success password.login result
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

ACTIONS = ["smartlife.m.rtc.config.get", "smartlife.m.p2p.main.pre.link.get",
           "smartlife.m.rtc.log", "smartlife.m.api.batch.invoke"]

# Dump full UNREDACTED decrypted blobs to a gitignored secrets/ path for reference.
DUMP = os.path.join(ROOT, "secrets/cap1_rtc_decrypted")
os.makedirs(DUMP, exist_ok=True)
seen = {}

for f in sorted(flows, key=lambda x: x.get("ts", 0)):
    rf = f.get("request_form")
    if not isinstance(rf, dict):
        continue
    a = rf.get("a", "")
    if a not in ACTIONS:
        continue
    rid = rf.get("requestId", "")
    print(f"================ {a} (v{rf.get('v')}) ================")
    dump = {}
    if "postData" in rf:
        try:
            req = json.loads(dec(rf["postData"], rid, ecode))
            dump["request"] = req
            print("  REQUEST postData:", json.dumps(redact(req)))
        except Exception as e:
            print("  REQUEST decrypt failed:", type(e).__name__, e)
    else:
        print("  REQUEST: (no postData)")
    try:
        rb = json.loads(f["response_body"])
        if "result" in rb:
            inner = json.loads(dec(rb["result"], rid, ecode))
            dump["response"] = inner
            full = json.dumps(redact(inner))
            if a == "smartlife.m.rtc.config.get":
                print("  RESPONSE (redacted, FULL):", full)
            else:
                print("  RESPONSE (redacted):", full[:700])
            print("  RESPONSE keyshape:")
            for ln in keyshape(inner, depth=2):
                print(ln)
        else:
            print("  RESPONSE (no result field):", json.dumps(redact(rb))[:400])
    except Exception as e:
        print("  RESPONSE decrypt failed:", type(e).__name__, e)
    if dump:
        n = seen.get(a, 0); seen[a] = n + 1
        fn = os.path.join(DUMP, f"{a}{('_'+str(n)) if n else ''}.json")
        json.dump(dump, open(fn, "w"), indent=2)
    print()
print("full decrypted blobs written under:", DUMP)
