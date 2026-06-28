# Media-start handshake — the conv=0 KCP control channel (TASK-0083)

**Confidence: HIGH on structure (decrypted from cap4/media.pcap). The full conv=0
order is now live-validated end-to-end (TASK-0083 DONE, v0.1.0-live-stream):
AUTH(sn=0, 104B) + VERSION(sn=1, 24B) + 3 command PDUs(sn=2,3,4). MEDIUM remains only
on the reqId@4 interpretation (non-monotonic captured values) and the lowercase-hex
inference noted later.**

## Why this exists
After ICE validates (camera answers our plain connectivity check), the camera
still does NOT stream until the **client sends KCP control packets first**. cap4's
working flow proves it: the app sends conv=0 KCP PUSH (frames 253–255) and the
camera begins streaming 37 ms later (frame 256, then video on conv=1 at 259).
Our client did ICE then only *received* → camera-silent media. This is the fix.

## Wire format (suite 3, identical to the proven RX path)
Each media UDP datagram on the connected ICE 5-tuple:
```
[ KCP segment header 24B, little-endian ] [ KCP payload ] [ HMAC-SHA1 20B ]
  conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)
  cmds: 0x51 PUSH, 0x52 ACK, 0x53 WASK, 0x54 WINS
  HMAC = HMAC-SHA1(media_key16, datagram[..−20])   (media_key = SDP a=aes-key, 16B)
```
A PUSH media-start segment payload (`len=48`) = `IV(16) || AES-128-CBC(media_key16,
PKCS7(28-byte control PDU)) = 32B`. (The earlier sub-analysis that called it
AES-ECB was wrong; openssl `aes-128-cbc -d` with inline IV yields clean PKCS7.)

## The 28-byte imm control PDU (decrypted from cap4 with key#0, HMAC-confirmed)
Little-endian; offsets:
```
@0  magic    = 0x12345678   (constant — imm control marker)
@4  u32      = per-message:  f253=0x00010004  f254=0x00010003  f255=0x00010005
@8  u32      = 0
@12 u32      = per-message:  f253=9  f254=6  f255=0x00040006
@16 u32      = 8             (constant across the 3)
@20 u32      = 0
@24 u32      = per-message:  f253=4  f254=0  f255=4
```
Raw plaintexts:
```
f253: 78563412 04000100 00000000 09000000 08000000 00000000 04000000
f254: 78563412 03000100 00000000 06000000 08000000 00000000 00000000
f255: 78563412 05000100 00000000 06000400 08000000 00000000 04000000
```
These are **protocol constants / small codes — NO session tokens, no creds**, so
they are replayable in a fresh session (the AES/HMAC use the new session's
`a=aes-key`; the plaintext is the same). The 104-byte `SendAuthorizationInfo`
(magic@0, code@4, username@8, password@0x28; `decompiled/ghidra_p2p/.../00147608`)
is a *larger* control message — and the live work showed it is the conv=0 **AUTH**
PDU (sn=0) that the camera requires *before* these command PDUs (see §"LIVE A/B
RESULT" and §"conv=0 AUTH password derivation").

**Field semantics** (per `ThingNetProtocolManager::SendCommand` @002c5e54, ground
truth v0.1.0-live-stream): @0 magic `0x12345678`; @4 reqId (MEDIUM — captured values
are non-monotonic and unexplained); @8 direction (0=app cmd / 1=camera resp); @0xc =
`(low_cmd<<16)|high_cmd`; @0x10 payload-len; @0x14 payload. conv ids: **0=control,
1=video, 2=downstream audio** (16 kHz mono S16LE, inferred). The cap4 PDUs above are
commands `(9,0)`, `(6,0)`="open video", `(6,4)` at KCP sn=2,3,4.

## The KCP sequencing — RESOLVED (2026-06-28, v0.1.0-live-stream, TASK-0083 DONE)
conv=0 begins at **sn=0** with the AUTH PDU, then **VERSION at sn=1**, then the three
cap4 command PDUs at **sn=2,3,4**. The client initialises conv=0 `snd_nxt` at 0.

The earlier "send stream starts at sn=3 / two live-testable hypotheses (A start at 3
and send sn=3,4,5; B start at 0 and send sn=0,1,2)" framing is **obsolete**: the 3
command PDUs are **not** the first segments. The first two conv=0 segments — AUTH
(sn=0) and VERSION (sn=1) — simply fell **outside cap4's capture window**; sn=2 onward
(the command PDUs) were inside it. KCP is in-order, so the camera buffers until sn=0
arrives — which is exactly why supplying AUTH(sn=0)+VERSION(sn=1) unblocked streaming
(see §"LIVE A/B RESULT").

## Sequence the client must reproduce (cap4 f217→f256)
The conv=0 control stream is **5 contiguous PDUs, all suite-3 sealed**:
1. (optionally) KCP ACK (cmd=0x52, len=0, 44B) acking the camera's conv=0 segments.
2. **AUTH** (KCP sn=0, 104B): `SendAuthorizationInfo` — magic `0x12345678`, username
   `admin`@8, derived-md5 password@0x28 (see §"conv=0 AUTH password derivation").
3. **VERSION** (KCP sn=1, 24B): `SendCommand(0, 10, 0, {0x00010000})`.
4. **3× command PDUs** (KCP sn=2,3,4): the cap4 f253/254/255 PDUs — commands `(9,0)`,
   `(6,0)`="open video", `(6,4)`.
5. Then receive: camera conv=0 PUSH at +37 ms, then **conv=1 video** PUSH (frame 259)
   → the proven RX pipeline decodes it.

## KAT frames (cap4, local-only)
f217 (ACK shape), **f253 (primary: header + 48B seal + 28B PDU)**, f254/f255 (the
burst + varying fields), f256 (camera's una-advance), f259 (conv=1 video starts only
after the conv=0 handshake).

## LIVE A/B RESULT (resolves the sn unknown — content gap now closed)
Implemented the client TX (KCP sender + AES-CBC seal + HMAC + the 3 PDUs + KCP ACK
of the camera's segments) and live-tested both hypotheses, reading the camera's
conv=0 reply header (`conv cmd sn una`):
- **`MEDIA_START_SN=3, una=2`** (cap4 mirror): camera replies `conv=0 cmd=0x52 sn=3
  **una=0**` (repeated). `una=0` ⇒ the camera's rcv_nxt for OUR stream is 0; our
  sn=3,4,5 are out-of-order, buffered, never delivered → stall. **Wrong.**
- **`MEDIA_START_SN=0, una=0`** (fresh start): camera replies `conv=0 cmd=0x52 sn=2
  **una=3**`. **`una=3` ⇒ the camera received + acked our sn=0,1,2.** Sequencing is
  CORRECT. The TX/KCP mechanism works end-to-end (camera accepts our PUSHes, its
  cumulative `una` advances 0→3, and we ACK its segments).

**RESOLVED (Superseded 2026-06-28, v0.1.0-live-stream, TASK-0083 DONE).** Sequencing
starts at sn=0 — the `MEDIA_START_SN/UNA = 0` baseline is correct. The reason the
camera initially ACKed and stopped was a **content gap, not a sequencing gap**: the
sn=0,1 prefix was missing. That prefix is **AUTH** (KCP sn=0, the derived-md5
password — see §"conv=0 AUTH password derivation") + **VERSION** (KCP sn=1); cap4's
three 28-byte command PDUs follow at sn=2,3,4. With AUTH+VERSION supplied, the camera
streams: the self-contained Rust client now decodes the live **1080p H.264 keyframe
end-to-end** (VLC displayed it). **cap7 is no longer required** for the keyframe path.

**HONEST CAVEAT — sustained A/V NOT yet verified.** Only the keyframe path is PROVEN.
Across live runs the camera's conv=1 video froze at ~12 segments (its initial KCP
send window): the single-threaded media pump does a blocking write into ffmpeg that
starves the KCP ACK loop, so the camera's `snd_una` never advances. Follow-ups:
**TASK-0085** (decouple the ACK loop from the blocking sink — the blocker),
**TASK-0086** (KCP WASK/WINS + flush cadence), **TASK-0087** (A/V sink),
**TASK-0088** (newtype the derived auth password), **TASK-0089** (ACK byte-shape vs
cap4 + sustained-A/V harness).

## conv=0 AUTH password derivation (jadx-confirmed)
**Confidence: HIGH on structure; the lowercase-hex assumption is validated by the
live test.** The conv=0 AUTH PDU (`SendAuthorizationInfo`, KCP sn=0) does **NOT**
carry the raw 8-char camera password. The real app derives it before connecting:

```
auth_password = md5_hex_lower( utf8(password) ++ "||" ++ utf8(localKey) )   // 32 ASCII hex chars
username      = "admin"   (constant)
```

- `password` = `rtc.config result.password` (the 8-char `CameraInfoBean.password`).
- `localKey` = the device `localKey` (`DeviceBean.getLocalKey()`).
- `||`       = the separator constant `com.thingclips.sdk.mqtt.pbbppqb.pbpdbqp`
  (`decompiled/jadx/sources/com/thingclips/sdk/mqtt/pbbppqb.java:26`).
- MD5 → lowercase 32-hex via `com.thingclips.smart.camera.utils.chaos.MD5Utils.b(s)
  = HexUtil.a(MD5(s.getBytes()))` (Tuya `HexUtil` is lowercase across their SDKs).

Citations
(`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/IPCThingP2PCamera.java`):
```
6874: String password = this.mBean.getPassword();   // 8-char rtc.config password
6875: this.mLocalkey = this.mBean.getLocalKey();     // device localKey
6881: this.mPwd = MD5Utils.b(password + pbbppqb.pbpdbqp + this.mLocalkey);  // "||"
6975: this.thingCamera.connect("admin", this.mPwd, ...);   // username "admin"
```

The C++ side `ThingNetProtocolManager::SendAuthorizationInfo` (@002c8028) `strncpy`s
the username@8 (max `0x1f`) and password@0x28 (max `0x3f`) into the 104-byte
magic-`0x12345678` blob, so the 32-char hex password fits without truncation.

This **supersedes** the earlier raw-password attempt (the §"The 28-byte imm control
PDU" note originally treated the 104-byte `SendAuthorizationInfo` as merely a separate
larger control message): the AUTH PDU password is the derived md5, not the raw
`password` field.
Implemented in `babymonitor-core/src/stream/media/control.rs`
(`derive_media_auth_password`) and wired in `babymonitor-cli/src/stream_live.rs`.
