# Media decode spec (cap3 AES/KCP, PT 6001) — RE from libThingP2PSDK.so

# Media Receive→Decode Spec — Philips Avent Baby Monitor+ (cap3 `AES/KCP`, PT 6001)

**Scope:** RX-only spec for the Rust client. Source: static decompile of `libThingP2PSDK.so` (arm64). Ghidra image base `0x100000`; `funcs/<addr>_<name>.c` file offset = addr − `0x100000`. Confidence tags inline: **[C]** confirmed (read from decompile / reloc-verified), **[I]** inferred (derived, consistent), **[G]** guess (flagged, needs capture).

**No secret values appear below — only per-session runtime *shapes* (buffer offsets, lengths, encodings).**

---

## 0. The one cross-analysis contradiction, resolved

Three of the four traces (RECV+DECRYPT, AES-KEY, KCP) **agree** that the media AES decrypt happens **inside this library**, per KCP segment, via a process-packet hook. The imm/RTP-FRAMING trace claimed (by absence) that the AES-decrypt + de-framing is "delegated to `libThingCameraSDK`." That claim is **wrong for the decrypt step** and is superseded: it simply did not follow the `ikcp_setprocesspkt` hook. The hook registration and call are explicit:

- `ikcp_setprocesspkt(kcp, ctx_session_chan_process_pkt)` — `funcs/00168f78_FUN_00168f78.c:83-87` **[C]**
- `ikcp_parse_data` invokes `kcp+0x198` per PUSH segment — `funcs/0014cec4_ikcp_parse_data.c` **[C]**
- The hook *is* the AES-CBC/GCM decryptor — `funcs/0015e448_ctx_session_chan_process_pkt.c:16-17` **[C]**

What the FRAMING trace got right and remains the **one genuine gap**: the **video** RTP→H.264 *depacketize/assemble* step for PATH A is not proven to live in this lib (the SRTP worker `FUN_0016b3f0` only de-pays *audio*). The decrypt is in-lib; the post-decrypt media parse for video is the open item (see §5, TASK-0068).

---

## 1. Pipeline — exact order, each transform

Wire framing of one UDP datagram on the imm/`AES/KCP` channel **[C]**:

```
UDP payload = [ KCP header 24B | KCP segment payload ] (×N segments per datagram, KCP-coalesced)
              [ ...other segments... ]
              [ HMAC-SHA1 tag 20B ]           ← present only when suite==3 (CBC)

KCP segment payload (per PUSH segment, after KCP strips its 24B header) =
              [ IV 16B (cleartext) | AES-128-CBC ciphertext (PKCS#7-padded, 16B-aligned) ]
```

**Receive order (do NOT reorder — HMAC is outer/whole-datagram, AES is inner/per-segment):**

1. **Recv UDP datagram.** `FUN_0016e350` ingress demux; imm path taken when `session+0xe54 == 0` (`funcs/0016e350_FUN_0016e350.c:31`). **[C]**
2. **HMAC strip + verify (suite 3 only).** `tag_len` = **20** (SHA-1). Reject if `len < tag_len + 24` (i.e. `len < 20 + 24`). Compute `HMAC-SHA1(key, datagram[0 .. len−20])`, `memcmp` vs trailing 20 bytes; mismatch → drop `"invalid md code"`. `FUN_0016e350.c:34, 66-79`. **[C — live-validated, milestone v0.1.0-live-stream / commit fa930f0]** Key = the 16 raw bytes at `session+0x84b0` (same key as AES). **[C]**  
   *Note (Superseded 2026-06-28, v0.1.0-live-stream):* a prior note claimed the static `mbedtls_md_get_size(md)` read pinned this at **32-byte HMAC-SHA256**. The live SCD921 negotiates a **20-byte HMAC-SHA1** tag — the end-to-end live keyframe decode validates SHA-1/20B per datagram. If the static decompile still literally shows `md_get_size`=32/SHA256, that read does not match the observed wire and is overruled by the live decode; the earlier "truncated / ~20-byte" intuition was closer than the SHA256 overrule. **[C — live]**
3. **Demux to KCP channel by `conv`.** `conv = ikcp_getconv(first 4 bytes)`. Then `ikcp_input(channel.kcp, datagram, len−tag_len, now_ms)` — **the KCP header + IV + ciphertext are fed to KCP intact; only the HMAC tag is stripped here. No decrypt yet.** `FUN_0016e350.c:45-60, 94`. **[C]**
4. **KCP parse + per-segment AES-decrypt.** `ikcp_input → ikcp_parse_data`; for each new PUSH segment, the process-packet hook `ctx_session_chan_process_pkt` runs:
   - `ct_len = seg_len − 0x10`; require `ct_len > 0 && (ct_len & 0xf) == 0` (block-aligned ⇒ block cipher). `0015e448:12-14`. **[C]**
   - `IV = seg_payload[0..16]`, `ct = seg_payload[16..]`; dispatch `decrypt_vtable[suite*4](session, dec_ctx, ct_len, IV, ct, out)`. `0015e448:16-17`. **[C]**
   - **PKCS#7 unpad:** `pad = out[ct_len−1]; if (pad ≤ 0x10 && pad ≤ ct_len) plain_len = ct_len − pad`. `0015e448:24-30`. **[C]**
   - Decrypted plaintext stored at `seg+0x54`, length `seg+0x2c`. **[C]**
5. **KCP reassembly.** Segments ordered by `sn` in `rcv_buf`, in-order `frg`-complete runs moved to `rcv_queue`; app reads complete messages via `ikcp_recv_mbufwithdata` (`FUN_001636c4` → `imm_p2p_rtc_recv_data@16340c`). **[C]** Each delivered KCP *message* = one application media unit.
6. **imm/RTP parse.** The delivered message is a standard **12-byte RTP header + payload** (`imm_p2p_rtp_decode_rtp2@173054:20-49`). **[C]** (Whether media messages carry an extra imm length-prefix wrapper before RTP is unproven — see §3 caveat. **[G]**)
7. **Depacketize.** H.264 RFC-6184 STAP-A/FU-A → Annex-B NAL stream; audio = G.711 µ-law (PCMU). **[C for layout; depacketize derived by inversion — [I]]** *(Audio codec contested: the live milestone v0.1.0-live-stream observed conv=2 downstream audio provisionally as **16 kHz mono S16LE (inferred)**, which conflicts with this static G.711 µ-law/PCMU read. Both remain uncertain; resolve via the conv=2 byte-shape verification — ground-truth TASK-0089.)*

**ASCII summary:**
```
UDP ─▶ HMAC-SHA1 verify+strip (whole datagram, suite3) ─▶ ikcp_input
     ─▶ ikcp_parse_data ─▶ [per segment] strip 16B IV ─▶ AES-128-CBC decrypt ─▶ PKCS#7 unpad
     ─▶ KCP frg reassembly (ikcp_recv) ─▶ RTP(12B) parse ─▶ H.264 STAP-A/FU-A | audio (PCMU vs 16k S16LE — contested, TASK-0089)
```

---

## 2. AES mode + IV — **definitive**

**Mode = AES-128-CBC** for the cap3 path (suite 3). Confirmed three independent ways:

1. `mbedtls_aes_crypt_cbc(dec_ctx, 0 /*MBEDTLS_AES_DECRYPT*/, len, iv, in, out)` — `funcs/00164ffc_FUN_00164ffc.c:19`. Encrypt sibling uses mode `1`: `funcs/00164f94_FUN_00164f94.c:19`. **[C]**
2. Block-alignment guard `(ct_len & 0xf)==0` (`0015e448:14`) — rules out CTR/stream. **[C]**
3. PKCS#7 unpad (`0015e448:24-30`) — CBC/ECB-family, and the explicit IV param rules out ECB. **[C]**

**Key = AES-128** (`mbedtls_aes_setkey_enc/dec(ctx, session+0x84b0, 0x80)` — `0x80` bits = 128; `funcs/00164db4_FUN_00164db4.c:32-36`). Separate enc/dec key schedules. **[C]**

**IV source = per-segment, explicit, transmitted inline** = the **first 16 bytes of each KCP segment payload** (cleartext, before ciphertext). Not zero, not seq/ts-derived. `0015e448:16` passes `iv = seg_payload`, `in = seg_payload+0x10`. **[C]** Send side confirms symmetry: `imm_p2p_misc_rand_hex(&iv, 0x10)` written before ciphertext, PKCS#7 pad `0x10-(len&0xf)`, framed `len + (suite4 ? 0x10 tag : 0) + 0x10 iv` — `funcs/0016304c_FUN_0016304c.c:88-106,116`. **[C]**

**Cipher-suite vtable** (vaddr `0x157df8` / Ghidra `0x257df8`, stride 32B `{setkey,free,encrypt,decrypt}`, index = `security_level` at `session+0x3274` = word `[0xc9d]`), reloc-verified from `readelf -r`: **[C]**

| suite | setkey | decrypt | cipher | datagram tag |
|---|---|---|---|---|
| 0,1 | 0x164a80 | 0x164a98 (no-op) | **plaintext stub** | none |
| 2 | 0x164acc | 0x164d0c | **ChaCha20** (16B key duplicated→32B) | inline (mode-4-style) **[G]** |
| **3** | **0x164db4** | **0x164ffc** | **AES-128-CBC** | **20B HMAC-SHA1 trailer** (live-validated, v0.1.0-live-stream; supersedes the earlier 32B SHA256 static read) |
| 4 | 0x165068 | 0x165284 | **AES-128-GCM** | 16B GCM tag inside segment (`ct_len−0x20`) |

**Which suite is live is cloud-negotiated** (`security_level`, `session+0x3274`) and **not statically pinnable**. The `AES/KCP` SDP codec + cap3 observation gives **suite 3 (CBC) as the default/observed**. RECV+DECRYPT observed `0x3274 == 3`. **[C that suite3=CBC; G that the live session is always 3 vs 4]**

**Is it ambiguous?** Only CBC-vs-GCM (suite 3 vs 4), and only because the value is runtime/auth-gated. Everything else (CBC mechanics, IV, padding, key size) is unambiguous. **One test that resolves CBC-vs-GCM:** capture one offer/answer (302) — read `security_level` from the negotiated params (`session+0x3274`); OR Frida-hook `mbedtls_aes_crypt_cbc` vs `mbedtls_gcm_auth_decrypt` on-device and see which fires. If CBC fires → suite 3; if GCM → suite 4 (then IV is still the inline 16B, but a 16B auth tag trails the ciphertext inside the segment and there is no datagram HMAC).

---

## 3. KCP params + imm frame header

**KCP is stock skywind3000/ikcp** (`IWORDS_BIG_ENDIAN=0`, native LE on aarch64), extended with (a) mbuf zero-copy segments and (b) the per-segment crypto hook. **[C]**

**Segment header — 24 bytes, native little-endian** (`funcs/0014d338_ikcp_input.c:58-73`, encode `funcs/0014decc_ikcp_flush_mbuf.c:52-63`): **[C]**

| Off | Size | Field | Notes |
|----|----|----|----|
| 0  | 4 | `conv` | channel demux key; must equal `kcp->conv` |
| 4  | 1 | `cmd`  | `0x51 PUSH`, `0x52 ACK`, `0x53 WASK`, `0x54 WINS` |
| 5  | 1 | `frg`  | fragment index, counts **down** N…0 (0 = last) |
| 6  | 2 | `wnd`  | receiver window |
| 8  | 4 | `ts`   | timestamp |
| 12 | 4 | `sn`   | sequence number |
| 16 | 4 | `una`  | cumulative ack |
| 20 | 4 | `len`  | length of segment payload that follows (the IV+ciphertext) |
| 24 | `len` | payload | `[16B IV | AES ciphertext]` |

**conv id source:** first 4 bytes of the datagram (`ikcp_getconv`). **[C]**
- `conv == 0x010000f3` → **control/signaling channel** (records, not media; §below). **[C]**
- else `conv = (active_handle << 16) | channel_id`; high half validated vs `session+0x3384`, `channel_id = conv & 0xffff` validated `≤ session+0x121c` (channel count). Channel structs: base `session+0xe08`, stride `0xa0`, KCP handle at `chan+0x20`. `FUN_0016e350.c:45-60`. **[C]**
  - **conv mapping resolved (2026-06-28, v0.1.0-live-stream):** the live SCD921 demuxes by simple conv ids **0=control, 1=video, 2=downstream audio** (no `(handle<<16)|channel_id` packing observed on the wire). **[C — live]** *Tension with the static model:* this lib's `FUN_0016e350` decompile models conv as `0x010000f3` (control) else `(active_handle<<16)|channel_id`, whereas the live device uses bare 0/1/2. The Rust client implements the **bare conv 0/1/2** demux that the live device actually sends; the `(handle<<16)|channel_id` packing is not exercised on the observed path.

**KCP tuning (must match for interop)** — `funcs/00168f78_FUN_00168f78.c`: **[C]**
- `ikcp_setmtu(kcp, 0x578)` → **MTU 1400**; `mss = mtu − 24 = 1376` (`funcs/0014eb64_ikcp_setmtu.c`).
- `ikcp_nodelay(kcp, 0, 10, 0x14, 1)` → nodelay **off**, **interval 10 ms**, **fast-resend 20**, **congestion control off (nc=1)**.
- `ikcp_wndsize(kcp, sndbytes/0x640, rcvbytes/0x640)` (window = byte budget / 1600). **[C]**
- Effective per-segment plaintext budget < 1376 (subtract 16B IV + ≤16B PKCS#7). Relevant for the send path. **[C]**

**imm frame header / "PT 6001":** The `a=rtpmap:6001 AES/KCP` `6001` is the **SDP format number, not the 7-bit RTP PT** (RTP PT is ≤127). `0x1771 = 6001`; codec registered via `imm_p2p_rtc_sdp_add_imm_codec(sdp, "AES/KCP", 0x1771, …)` (`funcs/00167bd0_FUN_00167bd0.c:158`); profile string `"AES/KCP"` at `sdp_ctx+0x6a8` (`funcs/00175fa0_imm_p2p_rtc_sdp_negotiate.c:129,132`). **[C]**

After decrypt + KCP reassembly, the **media unit is a standard 12-byte RTP header** (RFC 3550, big-endian): **[C]**
```
byte0: V(2)=2 | P(1) | X(1) | CC(4)      decoder checks (b0 & 0xc0)==0x80
byte1: M(1) | PT(7)                       PT = b1 & 0x7f
2-3:   sequence (BE u16)
4-7:   timestamp (BE u32)
8-11:  SSRC (BE u32)
12+:   CC×CSRC, then [X]→ext(u16 profile,u16 len_words, words×4), then payload, then [P]→trailing pad-count byte
header_len = 12 + CC*4 (+ ext)
```
Getters byte-swap BE→host (`imm_p2p_rtp_get_seq@17342c`, `imm_p2p_rtp_get_timestamp@1733f4`). **[C]**

**Control/signaling channel record framing** (conv `0x010000f3`, drained inline in `FUN_0016e350.c:96-134`): `[u16 type/flags][u16 BE length][body][pad to 4B align]`; type-field 0 + magic `0x100` → SDP/cmd blob → `FUN_00162020`. **[C]** This is signaling, **not** media.

**Caveat [G]:** RECV+DECRYPT stated "the imm frame header is length-prefixed inside the encrypted KCP payload." For the **control** channel that length-prefix is confirmed. For **media** channels, the most consistent model is that one `ikcp_recv` message == one RTP packet (KCP `frg` provides the boundary, no extra prefix), but this is not directly proven from a media decompile path. A single media-bytes capture (TASK-0068) settles whether media RTP packets are bare or length-prefixed.

---

## 4. Validation — confirm a correct decrypt on one captured frame

Given one captured imm UDP datagram + the session `a=aes-key` (32 hex chars → 16 raw bytes) and security_level:

**Step A — integrity gate (proves key + framing, before any decrypt):** if suite 3, compute `HMAC-SHA1(key16, datagram[0 .. len−20])` and compare to the trailing 20 bytes. **A match alone proves the 16-byte key and the datagram framing are correct.** (Mirrors `FUN_0016e350.c:66-79`.) **[C — live-validated, v0.1.0-live-stream; supersedes earlier 32B SHA256]**

**Step B — KCP parse:** parse the 24B header; confirm `conv` matches and `cmd ∈ {0x51..0x54}`, `len` ≤ remaining. PUSH (`0x51`) carries media. **[C]**

**Step C — decrypt + unpad sanity:** `IV = payload[0..16]`; AES-128-CBC-decrypt `payload[16..]`; read last byte `pad`. **Correct key+mode ⇒ `1 ≤ pad ≤ 16` and all `pad` trailing bytes equal `pad`** (valid PKCS#7). Wrong key/mode ⇒ random last byte, ~15/16 chance of an invalid pad immediately. **[C]**

**Step D — RTP/H.264 structural check (definitive positive):**
- Unpadded plaintext byte0: `(b0 & 0xc0) == 0x80` (RTP V=2). **[C]**
- Payload (after 12B RTP header) first byte `& 0x1f` = NAL type ∈ `{1..23 single, 24 STAP-A, 28 FU-A}`. **[C]**
- For a keyframe datagram: expect NAL types **7 (SPS), 8 (PPS), 5 (IDR)**; emitting `00 00 00 01` + NAL to a file and feeding `ffprobe`/`openh264`/`ffplay` should decode a frame. **[I]**
- Audio: RTP `PT == 0` (PCMU); payload is G.711 µ-law (8 kHz); `pts = rtp_ts >> 3` ms (`imm_p2p_rtc_recv_frame.c:91-99`). G.711 has no sync word — validate by decoding µ-law→PCM and checking sane amplitude envelope. **[C for PT/ts; I for audio plausibility]** *(Contested 2026-06-28: the live milestone v0.1.0-live-stream observed conv=2 downstream audio provisionally as **16 kHz mono S16LE (inferred)**, not 8 kHz µ-law. Static PCMU read kept but flagged pending conv=2 byte-shape verification — TASK-0089.)*

**Best single ground-truth check:** Step A (HMAC) + Step C (PKCS#7 valid) + Step D (RTP V=2 + NAL type in range) all passing on one datagram is conclusive that key, suite, IV placement, and framing are all correct.

---

## 5. Rust plan

**Crates:**

- **KCP:** `kcp` (zonyitoo, skywind3000 port). **Constraint [C/I]:** stock `kcp` exposes only `input()/recv()` — it has **no per-segment process-packet hook**, and you **cannot** decrypt after `recv()` because each segment carries its own IV + PKCS#7 and KCP concatenates segment *plaintexts*, not ciphertexts. ⇒ **You must decrypt per segment.** Two viable approaches: (a) **vendor/fork** the `kcp` crate and add a per-segment decrypt callback at the `parse_data` equivalent (mirrors `ctx_session_chan_process_pkt`); or (b) hand-roll a minimal ikcp RX (header parse + `rcv_buf`/`frg` reassembly is ~200 lines) with the decrypt inline. (a) is lower-risk for ARQ/window correctness. Configure `nodelay(false,10,20,true)`, `mtu 1400`, `wndsize = budget/1600`. **[C params]**
- **HMAC:** `hmac` + `sha1` → `Hmac<Sha1>`, 20-byte tag, key = 16 raw bytes. **[C — live-validated, v0.1.0-live-stream; supersedes earlier `sha2`/`Hmac<Sha256>`/32B]**
- **AES-CBC (suite 3):** `aes` + `cbc` → `cbc::Decryptor<aes::Aes128>`, `block-padding = Pkcs7`, IV = inline 16B. **[C]**
- **AES-GCM (suite 4, if live):** `aes-gcm` (`Aes128Gcm`), 16B inline IV/nonce + 16B trailing tag. **[C mechanics; G whether needed]**
- **ChaCha20 (suite 2, unlikely):** `chacha20`/`chacha20poly1305`; key = 16B duplicated to 32B. **[G]**
- **RTP parse:** `rtp` (webrtc-rs) or hand-roll the 12B header (trivial, BE). **[C]**
- **H.264 depacketize:** `webrtc` / `rtp`'s `codecs::h264::H264Packet` (RFC-6184 STAP-A/FU-A), or hand-roll the inversion below. **[I]**
- **H.264 decode/render:** `openh264` (Cisco) for in-process decode, or write Annex-B to a pipe and use `ffplay`/`ffmpeg-next`. **[I]**
- **Audio:** G.711 µ-law decode is a 256-entry LUT (no crate needed). Opus via `opus` crate **only if** a capture shows Opus RTP — **not confirmed in this lib's RX path [G]**. *(Contested: the live milestone v0.1.0-live-stream saw conv=2 downstream audio as 16 kHz mono S16LE (inferred) — possibly raw PCM rather than µ-law — so the conv=2 byte shape must be verified before committing to a µ-law LUT path. TASK-0089.)*

**H.264 depacketizer (derived by inverting the confirmed send packetizer — `imm_p2p_h264_packetize` STAP-A@`15026c:42-46`, FU-A@`150100:53-56`, threshold `0x4a7`=1191) [I]:**
```
b0 & 0x1F:
  1..23  single NAL → emit 00 00 00 01 + payload
  24     STAP-A      → drop b0; loop { size=BE16; emit 00 00 00 01 + payload[size]; advance }
  28     FU-A        → nal_hdr = (b0 & 0xE0) | (b1 & 0x1F)
                       if b1 & 0x80 (S): emit 00 00 00 01 + nal_hdr, then frag from byte+2
                       else append frag from byte+2;  b1 & 0x40 (E) ends the NAL
Access-unit boundary = RTP M-bit (byte1 bit7). Keyframe = NAL type 5 (IDR), preceded by 7/8.
```

**Confirmed vs needs the media-bytes capture (TASK-0068):**

| Item | Status |
|---|---|
| KCP wire format, header, cmd set, MTU/MSS/nodelay/wnd | **[C]** |
| Datagram HMAC-SHA1 (suite 3), 20B tag, key=16B `session+0x84b0` | **[C — live-validated, v0.1.0-live-stream; supersedes 32B SHA256]** |
| Per-segment AES-128-CBC, inline 16B IV, PKCS#7 | **[C]** |
| Key acquisition: SDP `a=aes-key` = 32 hex chars → hex-decode → 16 raw bytes at `session+0x84b0`; writers `FUN_00167bd0:162-174` (offerer) / `FUN_0016a004:75` (answerer `imm_p2p_rtc_sdp_get_aes_key`) | **[C]** (resolves the KCP-trace "open writer" item) |
| 12B RTP header layout; ts/seq BE | **[C]** |
| Audio codec: static PT0=PCMU (8 kHz µ-law) vs live conv=2 = 16 kHz mono S16LE (inferred) | **contested [C static / I live]** — TASK-0089 |
| H.264 STAP-A/FU-A layout (send side) | **[C]**; RX depacketize **[I]** |
| **Live suite: CBC (3) vs GCM (4)** | **[G]** — one 302 offer/answer or one `mbedtls_aes_crypt_cbc`/`gcm` Frida hook |
| **Numeric conv ids / channel ids per channel** | **resolved [C — live, v0.1.0-live-stream]:** conv 0=control, 1=video, 2=downstream audio (bare conv ids; not the static `(handle<<16)|channel_id` packing) |
| **Media RTP: bare vs imm length-prefixed inside KCP message** | **[G]** — capture |
| **PATH A video depacketize/assemble residence** (this lib vs `libThingCameraSDK`) | **[G]** — capture or `libThingCameraSDK` dive |
| **Opus presence on RX** | **[G]** — capture |

**TASK-0068 unblocks all [G] rows at once:** a single captured imm UDP datagram + the session's `a=aes-key`/`security_level` lets you run §4 Steps A–D end-to-end, pin the suite, confirm conv ids, and decide the bare-vs-prefixed RTP question.

---

## Key file references (all under `/home/mpedersen/topics/philips_babymonitor_re/`)

`decompiled/ghidra_p2p/funcs/`: `0016e350_FUN_0016e350.c` (ingress+HMAC), `0015e448_ctx_session_chan_process_pkt.c` (per-segment decrypt+PKCS7), `00164ffc_FUN_00164ffc.c` / `00164f94_FUN_00164f94.c` (AES-CBC dec/enc), `00164db4_FUN_00164db4.c` (AES-128 setkey), `00165068_FUN_00165068.c` (GCM setkey), `00164acc_FUN_00164acc.c` (ChaCha), `00167bd0_FUN_00167bd0.c` (offerer key + PT6001 codec), `0016a004_FUN_0016a004.c` (answerer key + HMAC ctx), `0016304c_FUN_0016304c.c` (send IV+pad), `00168f78_FUN_00168f78.c` (KCP setup + setprocesspkt), `0016950c_FUN_0016950c.c` (send HMAC append), `0014d338_ikcp_input.c`, `0014cec4_ikcp_parse_data.c`, `0014c3c8_ikcp_recv.c`, `0014c798_ikcp_recv_mbufwithdata.c`, `0014decc_ikcp_flush_mbuf.c`, `0014eb64_ikcp_setmtu.c`, `001636c4_FUN_001636c4.c`, `00173054_imm_p2p_rtp_decode_rtp2.c`, `0015026c_..._nal_stapa.c`, `00150100_..._nal_fua.c`, `00150448_..._find_next_nal_unit.c`, `00175fa0_imm_p2p_rtc_sdp_negotiate.c`, `00174e2c_imm_p2p_rtc_sdp_decode.c`, `0016b3f0_FUN_0016b3f0.c` (PATH B SRTP worker — separate transport).
`re/ghidra/`: `imm_p2p_rtc_sdp_{get,set}_aes_key.c`, `imm_p2p_rtc_recv_frame.c`, `imm_p2p_rtc_recv_data.c`, `imm_p2p_h264_packetize.c`.
Cipher vtable: vaddr `0x157df8` (Ghidra `0x257df8`), reloc-verified via `readelf -r decompiled/nativelibs/libThingP2PSDK.so`.

**Doc correction to apply:** `re/webrtc_session.md` §2a/§3c/§3d/§4/§7 describe cap3 media as DTLS-SRTP — that is **PATH B** (`session+0x395`/`+0xe54 != 0`, return-audio only). **cap3 `AES/KCP` (PT 6001) is PATH A: AES-128-CBC + HMAC-SHA1 over KCP, keyed directly by the SDP `a=aes-key`, no DTLS exporter.** (HMAC corrected 2026-06-28 to SHA-1/20B per the live milestone v0.1.0-live-stream; earlier SHA256/32B static read superseded.) `aes_decrypt_with_raw_key@1f2c7c` (libsrtp) has zero callers on this path — do not model the imm decrypt on it.