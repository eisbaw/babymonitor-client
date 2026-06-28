# Tuya MQTT message-2.2 binary frame (the 302 signaling wire format)

**Confidence: HIGH.** Verified byte-for-byte against a real captured publish
(`emulator_captures/cap5/offer_302_frame.bin`, gitignored) AND the decompiled
encode/parse/dedup code. `crc32(frame[7:]) == frame[3:7]` reproduces exactly with
stock zlib crc32.

This is the frame the SCD921 camera actually parses. Our earlier client published
a JSON `{data,gwId,protocol,pv,t}` envelope (the wrong cap3-era hypothesis) — the
camera CRC-checks `frame[3:7]`, the JSON has no such field, so it silently drops the
offer. That was the **camera-silent** root cause.

## Evidence (decompiled, jadx)

- **Encode (build the published bytes):**
  - `com/thingclips/sdk/mqtt/qpbpqpq.java:63` (MqttControl2_2):
    `contact( pv.getBytes(), pbbppqb.bdpdqbp(s,o,ct), intToBytes2(s), intToBytes2(o), ct )`
  - `com/thingclips/sdk/mqtt/pbbppqb.java:493` — the CRC field:
    `intToBytes2( crc32( contact(intToBytes2(s), intToBytes2(o), ct) ) )`
  - ciphertext `ct` = `qpqddqd.bdpdqbp(PublishBean2_2, localKey)` (`qpqddqd.java:628`)
    = AES-128/ECB/PKCS5 of `JSON.toJSONString(bean)`; returns **raw bytes** (not base64).
- **Parse (validate a received frame) — the inverse, confirms offsets:**
  - `com/thingclips/sdk/mqtt/qbpppdb.java:290-294` — CRC check:
    `crc32(frame[7:]) != bytesToInt2(frame[3:7])` → reject `12002 signature is not match`.
  - `qbpppdb.java:187-201` — dedup: `s = frame[7:11]`, `o = frame[11:15]`,
    `isDataUpdated(devId, s, o)` → reject `12003 cloud command repeat`.
  - `qbpppdb.java:377-379` — ciphertext = `frame[15:]`, AES-decrypt with localKey.
- **`intToBytes2` is big-endian** (`ByteUtils.java:610`: `>>24,>>16,>>8,&255`).
- **Dedup is a 5-second time-window** keyed on `devId+s+o`
  (`qdddqdp.java:725-728`): same `(devId,s,o)` within 5000 ms ⇒ duplicate. No
  monotonic requirement, **no cross-session persistence** (in-memory map).

## Wire layout (all multi-byte fields big-endian)

```
offset  size  field
0       3     pv ascii            e.g. "2.2"  (the device's protocol version)
3       4     crc32(frame[7:])    standard zlib crc32 (poly 0xEDB88320, init/xor ~)
7       4     s  = sequence       per-publish counter
11      4     o  = order          per-publish counter
15      ..    ciphertext          AES-128/ECB(localKey) of the envelope, PKCS7
```

`localKey` = the device's 16-char `localKey` (ASCII bytes are the AES key directly).

## AES plaintext = the PublishBean2_2 envelope (NOT the 302 json directly)

```json
{ "data": { ...the 302 signaling json... }, "protocol": 302, "t": <unix_seconds> }
```

`JSON.toJSONString` field order is `data, protocol, t`. **Order/spacing do not
matter for acceptance** — the camera JSON-parses; only the CRC must be
self-consistent with the bytes actually sent.

### The inner 302 json (`data`)

```json
{ "header": { "from":<uid>, "to":<devId>, "sessionid":<sid>, "moto_id":"",
              "type":"offer", "trace_id":<id>, "is_pre":0, "path":"mqtt",
              "security_level":3, "p2p_skill":1635 },
  "msg":    { "sdp":<offer-sdp>, "token":[...STUN/TURN...], "tcp_token":{...},
              "log":{...}, "preconnect":true } }
```

`path` = `"mqtt"` for the MQTT publish, `"lan"` for the parallel LAN publish.
`security_level` selects the media cipher suite (3 = AES-128-CBC + HMAC-SHA1).
`token`/`tcp_token`/`log` come from `rtc.config.get`. (Earlier docs placed
`token`/`tcp_token`/`log` at `data` level — they are inside `msg`.)

## Camera acceptance gates (what a self-contained client must satisfy)

1. `crc32(frame[7:]) == frame[3:7]` — we compute it from our own bytes; trivially met.
2. `(devId, s, o)` not seen in the last 5 s — increment `s` per publish; always safe.
3. AES-ECB(localKey) of `frame[15:]` decrypts (PKCS7) to valid JSON with
   `protocol == 302` and a `data.header`/`data.msg` the WebRTC layer accepts.

⇒ **Byte-matching the app is unnecessary.** Reproducing the captured frame
byte-for-byte is only used as a KAT (feed the captured `s,o,t,localKey,inner-json`
→ deterministic CRC+AES → equals `offer_302_frame.bin`).

> Note on the KAT's byte-exactness: `build_302_frame` re-parses the inner json
> through a `serde_json::Value`, so the published bytes use serde_json's key order
> (alphabetical — `serde_json` is built **without** `preserve_order` here). That
> happens to match Tuya's compact output for this envelope, so the KAT byte-matches.
> **Acceptance does not depend on this** (the CRC is self-consistent with whatever
> bytes we send); only the cosmetic byte-for-byte equality with the app does.

## Confidence

- **Outbound (app → camera) publish frame: HIGH / byte-pinned.** `build_302_frame`
  reproduces the real `cap5/offer_302_frame.bin` byte-for-byte (`tests/mqtt_frame_cap5.rs`).
- **Inbound (camera → app) answer/candidate frame: MEDIUM.** Same format by symmetry
  with the decompiled app parser (`qbpppdb.java:290-379`), and `parse_302_frame`
  round-trips our own output — but it is **not** byte-validated against a captured
  *inbound* frame (cap5 captured only the outbound offer). A captured camera answer
  frame would upgrade this to byte-pinned.

## Topics (confirmed on the wire)

- publish:   `smart/mb/out/<devId>`
- subscribe: `smart/mb/in/<devId>`

The camera answer arrives on `smart/mb/in/<devId>` in the **same** 2.2 frame format
(symmetric) — parse it with the inverse routine.
