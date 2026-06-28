# Media Capture Plan — SCD921 live A/V bytes (decrypted frames + ciphertext)

**Audience:** the OWNER, on their rig (physical SCD921 + rooted AVD).
**Goal:** in ONE live-view session, capture BOTH of the things the Rust media
decoder needs to be validated against:

1. **Decrypted media frames** — the cleartext H.264 NAL / audio payloads the
   native stack produces, plus the AES cipher/mode that produced them.
2. **Media ciphertext + transport** — the raw UDP/KCP datagrams of the media
   socket, to confirm the on-wire framing (DTLS-SRTP vs imm/AES).
   *(RESOLVED 2026-06-28, v0.1.0-live-stream: this framing question is settled — the
   A/V rides the **imm/AES/KCP** channel, AES-128-CBC with an inline 16-byte IV plus a
   per-datagram HMAC trailer; **DTLS-SRTP is ruled out** for the media path. Original
   text kept as historical context.)*

This is the missing half of cap3: cap3 captured the WebRTC **signaling** plaintext
+ the per-session media key (`a=aes-key`); it did NOT capture the **media itself**
(native P2P over UDP, off the HTTP proxy). See `emulator_captures/cap3/TRAFFIC.md`
and `DECRYPT.md` §3.

> **Static-RE basis (so you know the hooks are real, not guessed).** Every native
> symbol named below is an **exported `T` symbol** in
> `re/symbols/libThingP2PSDK.dynsym.txt` (or `…CameraSDK.dynsym.txt`), so Frida can
> hook it **by name** with `Module.getExportByName(lib, name)` — no offset math
> needed. The frame struct + recv path are decompiled in
> `re/ghidra/imm_p2p_rtc_recv_frame.c` and `re/webrtc_session.md` §4.

> **Secrets:** the per-session `a=aes-key` is a live secret and **rotates every
> connect**. This plan never contains a key value — the agent **extracts it at
> runtime** from the SDP (reusing the cap3 B3/B5 signaling hooks) and uses it only
> as an in-process filter. Keep all `cap4/` byte dumps under `secrets/` discipline
> until reviewed; `just secret-scan` must stay green over tracked files.

---

> **RESOLVED — read this first (2026-06-28, milestone `v0.1.0-live-stream`, commit
> `fa930f0`).** The media protocol this plan set out to determine is now **pinned and
> live-validated** against the cap4 bytes by the self-contained Rust client. Ground
> truth: media = **KCP** (conv `0`=control/auth, `1`=video, `2`=downstream audio) +
> **AES-128-CBC** (cleartext **inline 16-byte IV**, PKCS#7) per KCP segment + a
> **per-datagram HMAC trailer** over each media UDP datagram. It is the
> **imm/`a=aes-key`** channel, **NOT DTLS-SRTP** — the DTLS-SRTP path is ruled out for
> the A/V media. This plan is **retained as the capture methodology that produced
> cap4**; its "cipher mode unknown / DTLS-SRTP vs imm/AES" framing below is now
> **historical context**, kept for provenance. For the resolved, current spec see
> `re/media_decode_spec.md` (cipher/HMAC suite) and `re/live_stream_run.md` (live
> end-to-end run). Confidence on the resolution: **live-validated [confirmed]** for
> the keyframe path; sustained/continuous A/V is **not yet verified** (see follow-up
> tasks TASK-0085..0089).

---

## 0. The capture strategy in one paragraph

The media key from the SDP (`a=aes-key:<hex>`) is fed to **one** AES routine on the
recv path. We attack it from **three independent angles in the same session**, so
even if one misses we still get ground truth:

- **C1 — decrypted frames, no key needed (primary, robust).**
  `imm_p2p_rtc_recv_frame(session, frame*)` (lib `0x62ad8`) writes the
  **already-decrypted, RTP-de-paketized** payload into `frame->payload` with
  `frame->length`, and sets `frame->type` (0=audio, 1=video, 2=video-keyframe) and
  `frame->pts`. Hooking it **onLeave** and dumping `payload[0..length]` yields the
  cleartext frames directly — this is the H.264/audio the Rust decoder must match,
  and it does **not** depend on identifying the cipher.
- **C2 — the cipher/mode (validates the Rust *decrypt*).** Hook the AES primitives
  that `libThingP2PSDK.so` bundles, **filtered to calls keyed with the SDP
  `a=aes-key`**. Which function fires tells you the mode (ecb/cbc/ctr/gcm); a
  non-null IV/nonce arg confirms it; its `in`/`out` give a ciphertext↔plaintext
  pair to KAT the Rust impl. This is the artifact that says "AES-128-CTR with this
  IV derivation" vs "ECB", which static RE could not pin (`re/webrtc_session.md`
  §9, residual #1/#5).
  *(SUPERSEDED 2026-06-28, v0.1.0-live-stream: the mode is now pinned —
  **AES-128-CBC** with a **cleartext inline 16-byte IV** (first 16 bytes of each KCP
  segment payload) and **PKCS#7** padding; it is **not CTR and not ECB**. See
  `re/media_decode_spec.md` §AES — live-validated three independent ways **[confirmed]**.)*
- **C3 — ciphertext + transport.** A UDP pcap (tcpdump on the AVD) **and/or** a
  Frida `recvfrom`/`sendto` hook on the media fd, to capture the raw KCP/UDP
  datagrams, confirm DTLS-presence/absence, and tie the flow to the ICE candidate
  IPs from the live SDP.

C1∩C2 in the same session lets you prove: `decrypt(ciphertext_from_C3, sdp_key) ==
plaintext_from_C1`, with C2 telling you exactly which AES recipe `decrypt` is.

---

## 1. Which AES primitive to hook — the static shortlist (why these, by lib)

`libThingP2PSDK.so` **does not link** the app's `libcrypto.1.1.so`/`libssl.1.1.so`
(its `NEEDED` list has neither — `re/symbols/libThingP2PSDK.dynamic.txt`). It carries
its **own static mbedTLS + libsrtp**, and exports them. So the media-path AES is one
of these **exported** routines (addresses are file offsets from the dynsym dump):

| Family | Exported symbol (lib `libThingP2PSDK.so`) | Off | Role / why it matters |
|---|---|---|---|
| **Tuya raw-key wrapper** | `aes_decrypt_with_raw_key` | `0xf2c7c` | **Prime suspect for the imm/`a=aes-key` media.** Takes a *raw key as an argument* → the SDP key is passed straight in, easiest to filter. |
| mbedTLS ECB | `mbedtls_aes_crypt_ecb` | `0x9f378` | mode = ECB (no IV) |
| mbedTLS CBC | `mbedtls_aes_crypt_cbc` | `0x9f41c` | mode = CBC (IV arg present) |
| mbedTLS CTR | `mbedtls_aes_crypt_ctr` | `0x9fd80` | mode = CTR (nonce/counter arg) |
| mbedTLS GCM | `mbedtls_gcm_auth_decrypt` / `mbedtls_gcm_update` | `0xb8110` / `0xb788c` | mode = GCM (tag + AAD) |
| mbedTLS generic | `mbedtls_cipher_update` (+ `mbedtls_cipher_setkey`) | `0xa9eac` | catch-all if it routes via the generic cipher API |
| key-set seams | `mbedtls_aes_setkey_enc` / `mbedtls_aes_setkey_dec` | `0x9e30c` / `0x9e8cc` | mbedTLS crypt fns take a *context*, not a raw key — hook setkey to learn **which ctx holds the SDP key**, then filter the crypt fns by ctx |
| **libsrtp** | `srtp_cipher_decrypt` / `srtp_aes_decrypt` | `0xf327c` / `0xf5600` | the **standard SRTP tracks** — keyed by the **DTLS exporter, NOT the SDP key**. If the real A/V shows up here (and the SDP-key filter never fires on the imm path), that itself is the finding: media is on SRTP, not the imm channel. *(RESOLVED 2026-06-28, v0.1.0-live-stream: the answer is the **imm/AES/KCP** channel, so these SRTP hooks are **expected NOT to fire on the A/V path**. Kept as belt-and-suspenders.)* |

`libThingCameraSDK.so` additionally bundles **full OpenSSL** (`EVP_DecryptInit_ex`,
`EVP_DecryptUpdate`, `EVP_aes_128_{ecb,cbc,ctr,gcm}`, `AES_cbc_encrypt`,
`AES_decrypt` — `re/symbols/libThingCameraSDK.dynsym.txt`). Less likely for the live
imm media (that lib is camera-control + cloud-storage signing), but the agent below
hooks the EVP seam too as a cheap belt-and-suspenders.

**Decision rule the hook encodes:** mbedTLS `*_crypt_*` take a *context* (key set
earlier via `setkey`), OpenSSL EVP takes the key in `Init`, `aes_decrypt_with_raw_key`
takes it inline. So we filter the **key-set seams** (`setkey` / `EVP_DecryptInit_ex`)
and the **raw-key wrapper** by comparing 16 key bytes to the SDP key, remember the
matched **context pointers**, then dump on the matched **crypt/update** calls. The
single function that ends up firing = the mode.

---

## 2. The filter mechanism — how a hook "knows" it's the media call (no hardcoded key)

The agent gets the key the same way cap3 did — by hooking the **signaling** methods
(`P2PMQTTServiceManager.handleMqttAnswer` = B3 inbound, `…send302MessageThroughMqtt`
= B5 outbound). Both carry the SDP text. The agent runs a regex
`/a=aes-key:([0-9a-fA-F]+)/` over that text, hex-decodes it to 16 bytes, and stores
it in an in-process global `MEDIA_KEY`. Every AES hook then compares the candidate
key bytes against `MEDIA_KEY` and only logs/dumps on a match.

Consequences:
- The literal key never appears in this plan or any tracked file — it is learned at
  runtime from the live SDP and lives only in agent memory + the (gitignored) dumps.
- Because the key rotates per connect, the agent re-arms `MEDIA_KEY` on every new
  302 offer/answer, so a reconnect mid-capture is handled automatically.
- A hook firing with a key-match is the **positive signal** that you found the media
  decryptor; the agent prints `[MEDIA-AES] <fn> mode=<…> keymatch=1` to the console
  so you see it live.

---

## 3. The agent — `agent-media.js`

Save as `android_emulator_re/scripts/agent/agent-media.js` (sits next to
`agent.js` / `agent-deep.js`). It **reuses** the cap3 pattern: `import './agent.js'`
(TLS unpin + Tuya anti-tamper), the same `deferInstall` retry installer, and the
same `emit(tag,text)` JSONL channel handled unchanged by `spawn-capture.py`. Binary
frame/ciphertext bytes are written **in-process** to the app's own files dir (the
app can write there; you pull them with `su`), because shipping MB of frames over
the Frida message channel is slow.

```js
/*
 * cap4 media agent — capture decrypted media frames + the AES cipher, in one
 * live-view session. Extends the cap3 deep pattern (agent.js unpin + anti-tamper).
 *
 * Compile:  cd android_emulator_re/scripts/agent
 *           npx frida-compile agent-media.js -o ../media-compiled.js -c
 * Load:     python3 scripts/spawn-capture.py emulator-5554 \
 *               com.philips.ph.babymonitorplus scripts/media-compiled.js \
 *               ../philips_babymonitor_re/emulator_captures/cap4/media_meta.jsonl
 *
 * Binary dumps land on-device at:
 *   /data/data/com.philips.ph.babymonitorplus/files/cap4_frames.bin   (decrypted frames, C1)
 *   /data/data/com.philips.ph.babymonitorplus/files/cap4_aes.bin      (cipher in/out pairs, C2)
 *   /data/data/com.philips.ph.babymonitorplus/files/cap4_udp.bin      (socket datagrams, C3 fallback)
 * Pull them after the session (see plan §5).
 */
import './agent.js';                 // generic unpin + Tuya anti-tamper (lab agent.js)
import Java from 'frida-java-bridge';

const PKG = 'com.philips.ph.babymonitorplus';
const OUTDIR = '/data/data/' + PKG + '/files';
function emit(tag, text) { try { send({ tag: tag, text: text }); } catch (e) {} }

/* ---- in-process binary sink (one File per stream, append mode) ---- */
function Sink(name) {
  this.path = OUTDIR + '/' + name;
  this.f = null; this.off = 0;
  this.write = function (buf) {            // buf: ArrayBuffer
    try {
      if (!this.f) this.f = new File(this.path, 'wb');
      this.f.write(buf); this.f.flush();
      const at = this.off; this.off += buf.byteLength; return at;
    } catch (e) { console.log('[sink] ' + name + ' write failed: ' + e); return -1; }
  };
}
const frameSink = new Sink('cap4_frames.bin');   // C1 decrypted frames
const aesSink   = new Sink('cap4_aes.bin');       // C2 cipher in/out
const udpSink   = new Sink('cap4_udp.bin');       // C3 raw datagrams (fallback)

/* ---- the per-session media key, learned live from the SDP ---- */
let MEDIA_KEY = null;                 // Uint8Array(16) or null
const MATCHED_CTX = {};               // ptr-string -> {mode} for mbedTLS/EVP contexts
function hexToBytes(h) { const n = h.length >> 1, a = new Uint8Array(n);
  for (let i = 0; i < n; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
function captureKeyFromSdp(text) {
  if (!text) return;
  const m = /a=aes-key:([0-9a-fA-F]{32,46})/.exec(text);   // 16..23 bytes hex
  if (m) { MEDIA_KEY = hexToBytes(m[1]); console.log('[MEDIA-KEY] armed (' + (m[1].length / 2) + ' bytes) from SDP'); }
}
function keyMatchesAt(ptr) {           // does the 16 bytes at ptr == MEDIA_KEY?
  if (!MEDIA_KEY || ptr.isNull()) return false;
  try { const b = new Uint8Array(ptr.readByteArray(16));
    for (let i = 0; i < 16; i++) if (b[i] !== MEDIA_KEY[i]) return false; return true;
  } catch (e) { return false; }
}

/* ---- retry installer (Tuya P2P classes load only when live view opens) ---- */
function deferInstall(label, fn) {
  let tries = 0;
  const iv = setInterval(function () { tries++;
    Java.perform(function () {
      try { fn(); clearInterval(iv); console.log('[media] installed ' + label); }
      catch (e) { if (tries > 240) { clearInterval(iv); console.log('[media] gave up ' + label + ': ' + e); } }
    });
  }, 300);                              // 240*300ms = 72s window
}

/* ======================================================================
 * K — signaling hooks: harvest the per-session a=aes-key (B3/B5, cap3 pattern)
 * ==================================================================== */
deferInstall('K sdp-in (handleMqttAnswer)', function () {
  const C = Java.use('com.thingclips.smart.p2p.utils.P2PMQTTServiceManager');
  C.handleMqttAnswer.overload('java.lang.String', 'java.util.Map')
    .implementation = function (s, m) { captureKeyFromSdp(s); emit('SIG-in', s); return this.handleMqttAnswer(s, m); };
});
deferInstall('K sdp-out (send302MessageThroughMqtt)', function () {
  const C = Java.use('com.thingclips.smart.p2p.utils.P2PMQTTServiceManager');
  C.send302MessageThroughMqtt.overload('boolean', 'java.lang.String', 'java.lang.String')
    .implementation = function (z, d, j) { captureKeyFromSdp(j); emit('SIG-out', j); return this.send302MessageThroughMqtt(z, d, j); };
});

/* ======================================================================
 * Native hooks — installed after libThingP2PSDK.so is loaded (live view).
 * ==================================================================== */
function hookNative() {
  const P2P = 'libThingP2PSDK.so', CAM = 'libThingCameraSDK.so';
  const exp = (lib, name) => { try { return Module.getExportByName(lib, name); } catch (e) { return null; } };
  let n = 0;
  function attach(lib, name, cbs) { const a = exp(lib, name); if (a) { Interceptor.attach(a, cbs); n++; console.log('[native] hooked ' + name); } }

  /* ---- C1: decrypted frames (no key needed) ---- */
  // imm_p2p_rtc_recv_frame(int session, imm_p2p_rtc_frame_t* frame)
  //   frame: 0x00 payload*, 0x08 capacity, 0x0c length, 0x10 pts, 0x20 type
  attach(P2P, 'imm_p2p_rtc_recv_frame', {
    onEnter(a) { this.frame = a[1]; this.session = a[0].toInt32(); },
    onLeave(ret) {
      try {
        if (ret.toInt32() < 0 || this.frame.isNull()) return;     // <0 = no frame
        const payload = this.frame.readPointer();
        const length  = this.frame.add(0x0c).readU32();
        const type    = this.frame.add(0x20).readU32();           // 0 audio,1 video,2 keyframe
        const pts     = this.frame.add(0x10).readU64();
        if (payload.isNull() || length === 0 || length > 4 * 1024 * 1024) return;
        const buf = payload.readByteArray(length);
        const at  = frameSink.write(buf);
        emit('FRAME', JSON.stringify({ off: at, len: length, type: type, pts: pts.toString(), session: this.session }));
      } catch (e) {}
    }
  });
  // recv_data (generic byte plane) — boundaries only, helps correlate
  attach(P2P, 'imm_p2p_rtc_recv_data', {
    onEnter(a) { this.lenptr = a[3]; },
    onLeave(ret) { try { if (ret.toInt32() >= 0 && !this.lenptr.isNull())
      emit('DATA', JSON.stringify({ len: this.lenptr.readU32() })); } catch (e) {} }
  });

  /* ---- C2: the cipher — Tuya raw-key wrapper (key is an arg) ---- */
  // aes_decrypt_with_raw_key(...) — exact sig unknown; scan the first 4 ptr args
  // for the one whose 16 bytes == MEDIA_KEY. That arg index reveals the layout.
  attach(P2P, 'aes_decrypt_with_raw_key', {
    onEnter(a) {
      this.hit = -1;
      for (let i = 0; i < 4; i++) { if (keyMatchesAt(a[i])) { this.hit = i; break; } }
      if (this.hit >= 0) { this.a = [a[0], a[1], a[2], a[3], a[4], a[5]];
        console.log('[MEDIA-AES] aes_decrypt_with_raw_key keymatch arg' + this.hit); }
    },
    onLeave() { if (this.hit < 0) return;
      // Heuristic dump: arg after the key is usually (in,inlen) or (in,inlen,out).
      // Record raw arg pointers so you can reconstruct offline; also dump 256B around them.
      try {
        const probe = (p) => { try { return Array.from(new Uint8Array(p.readByteArray(64))).map(x => ('0' + x.toString(16)).slice(-2)).join(''); } catch (e) { return null; } };
        emit('AES-raw', JSON.stringify({ keyArg: this.hit,
          a0: this.a[0].toString(), a1: this.a[1].toString(), a2: this.a[2].toString(),
          a3: this.a[3].toString(), a4: this.a[4].toString(), a5: this.a[5].toString(),
          probe2: probe(this.a[2]), probe4: probe(this.a[4]) }));
      } catch (e) {}
    }
  });

  /* ---- C2: mbedTLS — learn matched contexts at setkey, dump at crypt ---- */
  // int mbedtls_aes_setkey_dec(ctx, key, keybits) / _enc — key = arg1
  ['mbedtls_aes_setkey_dec', 'mbedtls_aes_setkey_enc'].forEach((nm) =>
    attach(P2P, nm, { onEnter(a) { if (keyMatchesAt(a[1])) {
      MATCHED_CTX[a[0].toString()] = { via: nm };
      console.log('[MEDIA-AES] ' + nm + ' -> ctx ' + a[0] + ' holds media key'); } } }));
  // ecb(ctx,mode,in[16],out[16]) | cbc(ctx,mode,len,iv,in,out) | ctr(ctx,len,*off,nonce,sblk,in,out)
  const dumpCrypt = (mode, ctxArg, inArg, outArg, lenArg, ivArg) => ({
    onEnter(a) {
      this.on = !!MATCHED_CTX[a[ctxArg].toString()];
      if (!this.on) return;
      this.len = lenArg < 0 ? 16 : a[lenArg].toInt32();
      this.inp = a[inArg]; this.out = a[outArg];
      this.iv  = ivArg < 0 ? null : a[ivArg];
      try { this.inBytes = this.inp.readByteArray(Math.min(this.len, 65536)); } catch (e) { this.inBytes = null; }
    },
    onLeave() {
      if (!this.on) return;
      let outBytes = null; try { outBytes = this.out.readByteArray(Math.min(this.len, 65536)); } catch (e) {}
      const ai = this.inBytes ? aesSink.write(this.inBytes) : -1;
      const ao = outBytes ? aesSink.write(outBytes) : -1;
      console.log('[MEDIA-AES] FIRED mode=' + mode + ' len=' + this.len + ' iv=' + (this.iv && !this.iv.isNull() ? 'yes' : 'no'));
      emit('AES', JSON.stringify({ mode: mode, len: this.len,
        ivPresent: !!(this.iv && !this.iv.isNull()), inOff: ai, outOff: ao }));
    }
  });
  attach(P2P, 'mbedtls_aes_crypt_ecb', dumpCrypt('ecb', 0, 2, 3, -1, -1));
  attach(P2P, 'mbedtls_aes_crypt_cbc', dumpCrypt('cbc', 0, 4, 5,  2,  3));
  attach(P2P, 'mbedtls_aes_crypt_ctr', dumpCrypt('ctr', 0, 5, 6,  1,  3));
  attach(P2P, 'mbedtls_gcm_update',    dumpCrypt('gcm', 0, 3, 4,  2, -1));   // gcm_update(ctx,len,in,out)/variant — verify arg order in re/ghidra if it fires

  /* ---- C2: libsrtp (standard SRTP tracks; DTLS-keyed, won't match SDP key) ---- */
  // RESOLVED (2026-06-28, v0.1.0-live-stream): the A/V is on the imm/AES/KCP channel,
  // so this hook is EXPECTED NOT to fire on the A/V path. Kept as belt-and-suspenders;
  // a fire here would be a surprise worth investigating, not the media path. Boundaries only.
  attach(P2P, 'srtp_cipher_decrypt', { onEnter() { emit('SRTP', '{"fired":1}'); } });

  /* ---- C2: OpenSSL EVP in libThingCameraSDK (belt-and-suspenders) ---- */
  // EVP_DecryptInit_ex(ctx,type,impl,key,iv): key=arg3, type=arg1 -> mode
  const evpModes = {};
  ['ecb','cbc','ctr','gcm'].forEach((m) => { const a = exp(CAM, 'EVP_aes_128_' + m);
    if (a) { try { evpModes[new NativeFunction(a, 'pointer', [])().toString()] = m; } catch (e) {} } });
  attach(CAM, 'EVP_DecryptInit_ex', { onEnter(a) {
    if (keyMatchesAt(a[3])) { const mode = evpModes[a[1].toString()] || 'evp?';
      MATCHED_CTX[a[0].toString()] = { via: 'EVP', mode: mode };
      console.log('[MEDIA-AES] EVP_DecryptInit_ex ctx ' + a[0] + ' mode=' + mode); } } });
  // EVP_DecryptUpdate(ctx,out,*outl,in,inl) for a matched ctx
  attach(CAM, 'EVP_DecryptUpdate', {
    onEnter(a) { this.ctxKey = a[0].toString(); const c = MATCHED_CTX[this.ctxKey]; this.on = !!c;
      this.mode = c ? (c.mode || 'evp') : 'evp';
      if (this.on) { this.out = a[1]; this.outl = a[2]; this.inp = a[3]; this.inl = a[4].toInt32();
        try { this.inBytes = this.inp.readByteArray(this.inl); } catch (e) { this.inBytes = null; } } },
    onLeave() { if (!this.on) return; let ol = 0; try { ol = this.outl.readU32(); } catch (e) {}
      let outBytes = null; try { outBytes = this.out.readByteArray(ol); } catch (e) {}
      const ai = this.inBytes ? aesSink.write(this.inBytes) : -1;
      const ao = outBytes ? aesSink.write(outBytes) : -1;
      console.log('[MEDIA-AES] FIRED mode=' + this.mode + ' (EVP) len=' + ol);
      emit('AES', JSON.stringify({ mode: this.mode, len: ol, inOff: ai, outOff: ao })); }
  });

  /* ---- C3: media socket ciphertext (fallback to tcpdump) ---- */
  // Hook recvfrom/sendto; dump UDP datagrams. Tie to the flow by peer addr (the
  // ICE candidate IPs from the live SDP; in cap3 these were host 10.0.2.15 (the
  // generic emulator NAT IP) and relay <TURN relay IP> — confirm from THIS session's
  // SIG-in/out SDP candidates. ICE candidate addresses are session-sensitive; do not
  // commit the real relay IP).
  ['recvfrom', 'sendto'].forEach((nm) => attach('libc.so', nm, {
    onEnter(a) { this.buf = a[1]; this.dir = nm; },
    onLeave(ret) { try { const n = ret.toInt32(); if (n <= 0 || n > 2000) return;
      // length-prefixed record: [u8 dir][u32 len][bytes] so you can split offline
      const hdr = new Uint8Array(5); hdr[0] = (this.dir === 'recvfrom') ? 0 : 1;
      hdr[1] = n & 255; hdr[2] = (n >> 8) & 255; hdr[3] = (n >> 16) & 255; hdr[4] = (n >> 24) & 255;
      udpSink.write(hdr.buffer); udpSink.write(this.buf.readByteArray(n));
    } catch (e) {} }
  }));

  console.log('[native] media hooks installed: ' + n);
}

// libThingP2PSDK.so loads only when live view opens — install on dlopen, and once now.
(function armNative() {
  let done = false;
  function tryNow() { if (done) return; try { if (Module.findBaseAddress('libThingP2PSDK.so')) { hookNative(); done = true; } } catch (e) {} }
  tryNow();
  try { Interceptor.attach(Module.getGlobalExportByName('android_dlopen_ext'), { onLeave() { tryNow(); } }); } catch (e) {}
  const iv = setInterval(function () { tryNow(); if (done) clearInterval(iv); }, 500);
})();

console.log('[media] cap4 agent armed: K(sdp-key) + C1(frames) + C2(aes) + C3(udp)');
```

> **Caveats baked in (read them):**
> - `imm_p2p_rtc_frame_t` offsets (0x0c length, 0x10 pts, 0x20 type) are from
>   decompilation (`re/webrtc_session.md` §4a, **confidence: likely**). If `FRAME`
>   lengths look wrong, dump the first 0x28 bytes of `frame` raw and re-derive — the
>   committed `re/ghidra/imm_p2p_rtc_recv_frame.c` is the source of truth.
> - `aes_decrypt_with_raw_key` arg layout is **unknown** — the hook *discovers* the
>   key arg and probes neighbours; once you see which `probeN` is ciphertext vs
>   plaintext you can tighten the dump. It may not be the media path at all.
> - `mbedtls_gcm_update` / EVP arg orders should be re-checked against the
>   `re/ghidra/*.c` if those hooks fire — the dumpCrypt indices are the common
>   mbedTLS/OpenSSL signatures, not verified for this exact build.
> - The EVP path is belt-and-suspenders (the media AES is almost certainly the
>   `libThingP2PSDK.so` mbedTLS/raw-key seam, not `libThingCameraSDK.so` OpenSSL);
>   it is wired correctly (ctx tracked from `Init` to `Update`) but expect it to
>   stay silent unless the camera-control lib is the one decrypting frames.

---

## 4. Run sequence (copy-paste, owner's rig)

All from inside the `android_emulator_re` FHS shell (`nix develop`), serial
`emulator-5554`, package `com.philips.ph.babymonitorplus`. Assumes the rig is
already at the cap1/cap3 state (rooted AVD, frida-server up, app installed & logged
in — `just frida-ps` lists processes).

```bash
# --- 0. workspace for the new capture (host) ---
mkdir -p ../philips_babymonitor_re/emulator_captures/cap4

# --- 1. build the media agent ---
cd android_emulator_re/scripts/agent
npx frida-compile agent-media.js -o ../media-compiled.js -c
cd ../../..

# --- 2. (C3 primary) start a UDP pcap on the AVD, in the background ---
#   Tuya media is UDP (ICE/DTLS-SRTP + KCP). Capture all UDP; filter offline.
#   tcpdump must exist on the image; if not, push a static arm64 tcpdump or rely
#   on the agent's recvfrom/sendto sink (cap4_udp.bin) as the fallback.
adb -s emulator-5554 shell "su -c 'tcpdump -i any -s 0 -U -w /sdcard/cap4_media.pcap udp'" &
TCPDUMP_BG=$!

# --- 3. spawn the app under the media agent (writes meta JSONL on the host) ---
python3 android_emulator_re/scripts/spawn-capture.py emulator-5554 \
  com.philips.ph.babymonitorplus \
  android_emulator_re/scripts/media-compiled.js \
  ../philips_babymonitor_re/emulator_captures/cap4/media_meta.jsonl
#   ^ leave this running. Watch its console for:
#       [MEDIA-KEY] armed (16 bytes) from SDP        <- key harvested
#       [MEDIA-AES] FIRED mode=ctr len=... iv=yes     <- the cipher pinned (C2)
#       [dump] FRAME (... chars)                       <- frames flowing (C1)

# --- 4. IN THE APP: open the camera live view. Let it run ~30-60 s.
#        Talk-back / switch quality once to exercise audio + keyframes.
#        Then close live view and stop spawn-capture.py (Ctrl-C).

# --- 5. stop the pcap, pull all artifacts to cap4/ ---
kill $TCPDUMP_BG 2>/dev/null
adb -s emulator-5554 shell "su -c 'pkill tcpdump'"
DST=../philips_babymonitor_re/emulator_captures/cap4
adb -s emulator-5554 exec-out su -c 'cat /sdcard/cap4_media.pcap'                                   > $DST/media.pcap
adb -s emulator-5554 exec-out su -c 'cat /data/data/com.philips.ph.babymonitorplus/files/cap4_frames.bin' > $DST/decrypted_frames.bin
adb -s emulator-5554 exec-out su -c 'cat /data/data/com.philips.ph.babymonitorplus/files/cap4_aes.bin'    > $DST/aes_pairs.bin
adb -s emulator-5554 exec-out su -c 'cat /data/data/com.philips.ph.babymonitorplus/files/cap4_udp.bin'    > $DST/media_udp.bin
#   media_meta.jsonl is already on the host (spawn-capture.py wrote it).
#   Rename media_meta.jsonl -> decrypted_frames.jsonl for clarity if you like.

# --- 6. clean device-side dumps (they contain live key-adjacent bytes) ---
adb -s emulator-5554 shell "su -c 'rm -f /sdcard/cap4_media.pcap /data/data/com.philips.ph.babymonitorplus/files/cap4_*.bin'"
```

**Exact files to produce in `emulator_captures/cap4/`:**

| File | Source | Content |
|---|---|---|
| `decrypted_frames.bin` | C1, agent `cap4_frames.bin` | concatenated decrypted frame payloads (H.264 NAL / audio) |
| `decrypted_frames.jsonl` (= `media_meta.jsonl`) | agent `send()` | one record per frame/AES/SDP event: `{tag, ...}` — `FRAME` records carry `{off,len,type,pts}` indexing into `decrypted_frames.bin`; `AES` records carry `{mode,len,ivPresent,inOff,outOff}` indexing into `aes_pairs.bin`; `SIG-in/out` carry the SDP (incl. the `a=aes-key`, **gitignored**) |
| `aes_pairs.bin` | C2, agent `cap4_aes.bin` | ciphertext→plaintext byte pairs from the matched AES call (the KAT for the Rust decrypt) |
| `media.pcap` | C3, tcpdump | raw UDP datagrams of the media flow (KCP/DTLS framing) |
| `media_udp.bin` | C3 fallback, agent `cap4_udp.bin` | length-prefixed `[dir u8][len u32][bytes]` socket datagrams (use if tcpdump absent) |

---

## 5. Success checks (how you know the capture is good)

1. **Key armed (K).** spawn-capture console shows `[MEDIA-KEY] armed (16 bytes)`.
   If not, the SDP didn't carry `a=aes-key` (wrong transport — check `SIG-*` JSONL;
   a `p2pType=2`/PPCS session has no SDP, `re/webrtc_session.md` §9 residual #2).
2. **Decrypted frames (C1) are real codec data.** The single most important check —
   H.264 Annex-B start codes in `decrypted_frames.bin`:
   ```bash
   # count NAL start codes (00 00 00 01) — should be many for a video stream
   xxd -p emulator_captures/cap4/decrypted_frames.bin | tr -d '\n' \
     | grep -o '00000001' | wc -l
   # first bytes of a video frame: 00 00 00 01 67 (SPS) / 68 (PPS) / 65 (IDR) / 41 (P)
   xxd -l 64 emulator_captures/cap4/decrypted_frames.bin
   ```
   For audio, `FRAME.type==0`: G.711 µ-law (PCMU) is raw 8-bit, no sync word; if
   the build uses AAC instead, look for ADTS sync `FF F1`/`FF F9`. (Per
   `re/webrtc_session.md` §4d the SDP audio codec is PCMU; Opus on the talk path.)
   A cleaner check is to carve frames by the `FRAME` offsets in the JSONL and feed a
   `type==1/2` (video) run to `ffmpeg -f h264 -i - -f null -` — it should decode.
3. **Cipher pinned (C2).** Exactly one `[MEDIA-AES] FIRED mode=<…>` family should
   recur. That `mode` + `ivPresent` is the recipe the Rust `media_decrypt` must
   implement. Validate offline: take an `AES` record's `(inOff,len)` ciphertext and
   `(outOff,len)` plaintext from `aes_pairs.bin` and confirm
   `openssl enc -d -aes-128-cbc -K <sdp_key_hex> -iv <inline_iv_hex> -nopad` reproduces
   the plaintext, where `<inline_iv_hex>` is the **first 16 bytes of the KCP segment
   payload** (the IV is transmitted inline, not derived). (Run this against the
   gitignored key under `secrets/`, never commit it.)
   *(RESOLVED 2026-06-28, v0.1.0-live-stream — known outcome: the mode is
   **AES-128-CBC over KCP**, inline 16-byte IV + PKCS#7, on the imm/`a=aes-key`
   channel; example shown above as `cbc` accordingly. The "only `SRTP` fires ⇒ media
   on DTLS-SRTP" branch below is the **DISPROVEN** branch, retained for completeness.)*
   **Caveat — this KAT validates only the inner cipher, not the datagram MAC.** Each
   media UDP datagram carries a **per-datagram HMAC trailer** over the whole datagram
   (ground truth: **20-byte HMAC-SHA1(`media_key16`)**, live-validated; note the static
   spec in `re/media_decode_spec.md` describes a **32-byte HMAC-SHA256** trailer for
   suite 3 — this byte-shape mismatch is an **open discrepancy to verify**, kept honest
   here). The `openssl` AES check reproduces the plaintext but says **nothing** about
   the HMAC; verify the trailer separately against the raw datagram bytes.
   The (DISPROVEN) SRTP branch, for the record: if **only `SRTP` fired** and the
   SDP-key AES hooks never matched, the conclusion would have been that the live A/V
   rides the **standard DTLS-SRTP tracks** (DTLS-exporter keyed), not the
   imm/`a=aes-key` channel — that branch did **not** hold (imm/AES confirmed); see
   `re/webrtc_session.md` §9 residual #1.
4. **Ciphertext + transport (C3).** `media.pcap` should show a high-rate UDP flow to
   one of the SDP ICE candidate IPs (host-LAN or the TURN relay). Confirm DTLS
   presence/absence:
   ```bash
   tshark -r emulator_captures/cap4/media.pcap -q -z conv,udp     # find the busy flow
   tshark -r emulator_captures/cap4/media.pcap -Y 'dtls'          # DTLS handshake? -> SRTP path
   ```
   No DTLS on the busy flow + a match in C2 ⇒ imm/AES media. DTLS present ⇒ SRTP.
   *(RESOLVED 2026-06-28, v0.1.0-live-stream — known outcome: there is **no DTLS** on
   the media flow; it is **imm/AES-128-CBC over KCP** (+ per-datagram HMAC trailer).
   The "DTLS present ⇒ SRTP" arm is the **DISPROVEN** branch, retained for completeness.)*
5. **End-to-end cross-validation (the whole point).** Pick one timestamp window:
   the C3 ciphertext datagram, decrypted with the K key under the C2 mode, must equal
   the C1 plaintext frame for the same `pts`. That triple agreement is the
   ground-truth oracle the Rust `babymonitor` media decoder is validated against.

---

## 6. Notes, limits, and honesty

- **C1 is the safety net.** Even if C2 (the cipher) and C3 (the pcap) both fail to
  pin cleanly, `imm_p2p_rtc_recv_frame`'s output is the **decrypted, de-paketized**
  payload by construction — so you still get cleartext frames to validate the
  decoder. C2/C3 are what let you reimplement the *decrypt* rather than just
  observe the *result*.
- **Transport: per-datagram HMAC trailer + inline-IV per-segment AES (RESOLVED
  2026-06-28, v0.1.0-live-stream).** Each media UDP datagram carries a **per-datagram
  HMAC trailer computed over the whole datagram** — ground truth from the live run is
  a **20-byte HMAC-SHA1(`media_key16`)** trailer **[confirmed]**, while the static spec
  in `re/media_decode_spec.md` describes a **32-byte HMAC-SHA256** trailer for suite 3;
  that byte-shape mismatch is an **open discrepancy to verify** (keeping honesty
  discipline — do not assume one over the other). AES is applied **per KCP segment**
  with the **IV transmitted inline** (the first 16 bytes of each segment payload),
  PKCS#7-padded. Consequence for this plan: the C2/C3 hooks and the `openssl` AES KAT
  in success-check #3 capture/verify the **inner cipher only** — they say nothing about
  the **datagram MAC**, so verify the HMAC trailer separately against the raw C3
  datagram bytes or you will miss it entirely.
- **The key rotates per connect.** Capture C1/C2/C3 in **one** continuous session;
  do not reconnect between starting the pcap and opening live view, or the
  `a=aes-key` in `media.pcap`'s session won't match the one the agent armed.
- **Transport is firmware-gated.** If this SCD921 negotiates PPCS (`p2pType=2`)
  instead of WebRTC, there is no SDP/`a=aes-key`; the media is TUTK/IOTC AV framing
  and this plan's K/C2 don't apply — you'd capture C1 (`recv_frame` still works) +
  C3 and pivot to `re/p2p_triage.md` §5 (PPCS). Check `SIG-*` first.
- **tcpdump availability.** The `google_apis_playstore` x86_64 image may not ship
  tcpdump. If `su -c tcpdump` errors, the agent's `recvfrom`/`sendto` sink
  (`media_udp.bin`) is the guaranteed fallback — it captures the same datagrams at
  the syscall boundary (you lose IP/UDP headers but keep payload + direction + len,
  which is enough for the KCP/DTLS-framing check).
- **Secrets discipline.** `SIG-*` records and the device-side dumps contain the live
  `a=aes-key`, ICE creds, session ids, and possibly the device id. Keep `cap4/`
  gitignored (same as cap1-3), redact before any push, and run `just secret-scan`.
  This plan file itself contains **no key value** — only the runtime extraction
  mechanism.
- **All native offsets/structs are static-RE, confidence: likely.** They are
  anchored to committed `re/symbols/*.dynsym.txt` (symbol→export, confirmed) and
  `re/ghidra/imm_p2p_rtc_recv_frame.c` (struct, likely). If a hook misbehaves, the
  committed Ghidra C is the source of truth to re-derive arg/offset indices.
</content>
</invoke>
