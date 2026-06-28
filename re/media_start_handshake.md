# Media-start handshake — the conv=0 KCP control channel (TASK-0083)

**Confidence: HIGH on structure (decrypted from cap4/media.pcap), MEDIUM on the
full sequence (sn=0,1,2 not in cap4's window).**

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
is a *different, larger* control message and is NOT what triggers streaming here.

## The KCP sequencing — the residual unknown
The app's conv=0 **send** stream starts at **sn=3** — across ALL 132 conv=0 PUSH
packets in cap4 (every session, every candidate), the minimum sn is 3; sn=0,1,2 are
NEVER sent as conv=0 PUSH. The camera's frame 256 `una=6` acks app sn 3,4,5, i.e.
the camera's rcv_nxt for the app stream was 3 before. So either:
- the imm/tuya KCP initialises conv=0 `snd_nxt`/`rcv_nxt` at **3** (likely — both
  sides agree), OR
- sn=0,1,2 were exchanged on an earlier path/connection outside cap4's capture
  window (the app multipaths conv=0 across ICE candidate attempts).

KCP is in-order, so this MUST be right or the camera buffers our PUSH forever. The
two live-testable hypotheses: (A) start our conv=0 `snd_nxt` at 3 and send the 3
PDUs as sn=3,4,5 (mirror the app); (B) start at 0 and send them as sn=0,1,2.

## Sequence the client must reproduce (cap4 f217→f256)
1. (optionally) KCP ACK (cmd=0x52, len=0, 44B) acking the camera's conv=0 segments.
2. 3× KCP PUSH (cmd=0x51, sn=3,4,5, una=2, wnd=512, len=48) carrying the f253/254/255
   PDUs sealed under suite 3. The 3 are sent in a ~12 ms burst.
3. Then receive: camera conv=0 PUSH (sn=2, una=6) at +37 ms, then **conv=1 video**
   PUSH (frame 259) → the proven RX pipeline decodes it.

## KAT frames (cap4, local-only)
f217 (ACK shape), **f253 (primary: header + 48B seal + 28B PDU)**, f254/f255 (the
burst + varying fields), f256 (camera's una-advance), f259 (conv=1 video starts only
after the conv=0 handshake).

## LIVE A/B RESULT (resolves the sn unknown — but exposes a content gap)
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

**But the camera ACKs and stops — no conv=1 video.** So the sn=0,1,2 **content** is
wrong: cap4's three 28-byte PDUs are the sn=3,4,5 *continuation*, not the *initial*
handshake. The true sn=0,1,2 (likely the imm auth — `SendAuthorizationInfo`,
104-byte magic-`0x12345678` with code/username/password, `decompiled/ghidra_p2p/.../00147608`)
is **outside cap4's capture window**. ⇒ Baseline pinned to `MEDIA_START_SN/UNA = 0`
(correct sequencing). Remaining unblock: **cap7** (capture a FRESH live-view from
connection #1, getting conv=0 sn=0,1,2 + the auth) OR RE the imm conv=0 control
sender to synthesize the initial PDUs (and find the auth-cred source).

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

This **supersedes** the earlier raw-password attempt (§"The 28-byte imm control PDU"
note that called the 104-byte `SendAuthorizationInfo` "a different, larger control
message"): the AUTH PDU password is the derived md5, not the raw `password` field.
Implemented in `babymonitor-core/src/stream/media/control.rs`
(`derive_media_auth_password`) and wired in `babymonitor-cli/src/stream_live.rs`.
