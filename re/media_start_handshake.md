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
