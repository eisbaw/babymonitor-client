# Live stream run — getting a real frame off the SCD921

The EXACT owner-only steps to take `babymonitor-cli` from a cold start to a live
video frame. As of **v0.1.0-live-stream (commit fa930f0)** the live **keyframe**
path is **PROVEN end-to-end**: MQTT-302 signaling → ICE → conv=0 media-start auth
→ conv=1 video → an H.264 keyframe rendered in VLC against the REAL SCD921. The
remaining honest gap is **SUSTAINED continuous A/V** (the camera froze at ~12
segments — see §6), NOT the first connection. Everything here touches the account
owner's OWN device on their OWN network; the live run has now happened on the
owner's kit.

> Scope reminder (CLAUDE.md): this is static-analysis-only here. The commands
> below are the procedure for the *account owner* to run on their own kit. No
> secret value is committed; every secret lives under gitignored `secrets/`.

---

## 0. What you need (secrets)

All under gitignored `secrets/`:

| file | what | source |
|---|---|---|
| `secrets/tuya_login.json` | `{ "email", "password", "twofa_code_file": "secrets/2fa.txt" }` | your Philips/Avent account |
| `secrets/tuya_appkey.json` | `{ "appKey", "appSecret", "ttid", "version_name" }` | the app (`re/tuya_cloud_config.md`) |
| `secrets/bmp_token.txt` | the `t_s.bmp` token (one line) | `re/bmp_token_provenance.md` |
| `secrets/stream_runtime.json` | OPTIONAL override — auto-built in-process when absent (§3, TASK-0078) | your live device session |
| device `localKey` | the 16-byte AES key for the 302 MQTT payload | the device-list response |

The cert hash is computed offline from the extracted APK — no extra file.

---

## 1. Log in (the MFA two-run flow)

The login path is **gated behind `--features live`** and is READ-ONLY (it sends at
most one `password.login`, stops at 2FA). The earlier `ILLEGAL_CLIENT_ID` identity
gate is **RESOLVED** (Superseded 2026-06-28, v0.1.0-live-stream): it was three
client-side bugs — the `chKey` was sliced `hex[8..16]`, the request signer is
HMAC-SHA256, and the password field is RSA-of-`md5_hex` (see MEMORY /
`re/tuya_cloud_auth.md`). Full MFA login → session → device discovery now works
(the end-to-end live milestone could not exist otherwise). The working flow is:

```sh
# Run 1 — triggers the emailed MFA code, then STOPS with "NEED 2FA CODE".
nix-shell --run 'cd babymonitor && cargo run --features live --bin babymonitor-cli -- \
    auth live-login --host a1.tuyaeu.com'
```

It prints `NEED 2FA CODE` and writes the challenge state to
`secrets/tuya_2fa_state.json`. Open the email, then:

```sh
# Paste the 6-digit code into the file tuya_login.json's twofa_code_file points at:
printf '123456' > secrets/2fa.txt

# Run 2 — submits the SAME login carrying the pasted code (never a re-guess).
nix-shell --run 'cd babymonitor && cargo run --features live --bin babymonitor-cli -- \
    auth live-login --host a1.tuyaeu.com'
```

On success it persists the structured session (sid/uid/**ecode**, region base) to
the XDG `SessionStore` (redacted in `Debug`) and captures the device list to
`secrets/`. `a1.tuyaeu.com` is the EU mobile atop gateway (you are in DK →
EU datacenter, `re/tuya_cloud_config.md`); the login response's
`User.domain.mobileApiUrl` pins the live host for any later call.

If you instead have a **captured session** (Frida / a sniffed login), inject it
into the `SessionStore` (README §6) and skip the login — `auth status` should then
show a stored session.

---

## 2. Confirm the camera (device discovery)

```sh
nix-shell --run 'cd babymonitor && cargo run --features live --bin babymonitor-cli -- \
    devices list --live'
```

This drives the post-login `m.life.home.space.list` → `m.life.my.group.device.list`
read with your injected `sid` and reports `camera_found` + `p2pType`. For the
SCD921 you want **`p2pType == 4`** (THING / WebRTC-over-MQTT — the path this client
implements; `re/streaming_mode.md`, `device.rs`). A `p2pType == 2` device is the
legacy PPCS transport and is out of scope.

From that device record, note the camera's `devId`, `localKey`, and `pv`.

---

## 3. (Optional) the runtime bundle — now AUTO-BUILT in-process (TASK-0078)

**You no longer need to hand-assemble `secrets/stream_runtime.json`.** When it is
absent, `stream --live` AUTO-BUILDS the runtime in-process from the session
(`babymonitor-cli/src/stream_live.rs::build_runtime_from_session`):

- **device** ← `secrets/tuya_device_list.json` (devId, localKey, pv, skills.p2pType);
- **camera** ← ONE live `rtc.config.get` for that devId (ices, session, the per-session
  `auth` signaling token); the media `a=aes-key` is **MINTED** per session by the
  client (cap3: offer==answer aes-key, both != that session's
  `rtc.config session.aesKey`), NOT taken from `rtc.config`;
- **broker** ← the captured login `User.domain.mobileMqttsUrl` (:8883) + the DERIVED
  302 topics `smart/mb/out|in/<devId>` + `User.partnerIdentity`;
- **mqtt**   ← `User.sid` (= `MqttConnectConfig.token`) + the offline-derived
  appId/chKey/master-key-G.

A hand-written `secrets/stream_runtime.json` is still HONORED (override / back-compat).
Its shape (still the inputs the core `StreamCredentials`/`BrokerConfig`/`MqttAuthInputs`
types require) is:

```json
{
  "broker": {
    "host": "m1.tuyaeu.com",          // ssl://<getMobileMqttsUrl()>:8883, from login baseConfig
    "port": 8883,
    "tls": true,
    "publish_topic": "<device 302 publish topic>",
    "subscribe_topic": "<device 302 subscribe topic>",
    "partner_identity": "<MqttConnectConfig.getPartnerIdentity()>"
  },
  "device":  { "dev_id": "<devId>", "local_key": "<localKey>", "pv": "2.2", "p2p_type": 4 },
  "camera":  { "p2p_id": "<CameraInfoBean.p2pId>", "p2p_key": "<P2pConfig.p2pKey>",
               "ices": "<P2pConfig.ices JSON string>", "session": "<P2pConfig.session>",
               "token": "<per-session signaling token>", "skill": "<CameraInfoBean.skill JSON>" },
  "mqtt":    { "token": "<MqttConnectConfig.getToken()>", "app_id": "<appKey>",
               "ch_key": "<getChKey(app, appKey)>", "master_key_g_hex": "<hex(master key G)>" }
}
```

Field provenance (which live API yields each):

- `device` ← `m.life.my.group.device.list` (devId, localKey, pv, `skills.p2pType`).
- `camera` ← `CameraInfoBean` / `rtc.config.get` (p2pId, p2pKey, ices, session, token).
- `mqtt`   ← `SdkMqttCertificationInfo` (`qpqbppd.java`) + the master key **G**
  (`re/master_secret_g.md`; `partnerIdentity`, `token`, `appId`, `chKey`, `G`).
- `broker` ← the login `baseConfig` (MQTT endpoint + the device 302 topics).

`uid` and `ecode` are read from the `SessionStore` (the login of §1) — not in this
file. NO value here is ever logged by the CLI.

---

## 4. Stream it

```sh
nix-shell --run 'cd babymonitor && cargo run --features live --bin babymonitor-cli -- \
    stream --output http --port 8554'
```

> Note: the default `--output http --port 8554` can collide with a local QEMU
> emulator on the same port; pick a free port if so (a free-port check is tracked
> in TASK-0087).

The driver runs the assembled pipeline (`babymonitor-cli/src/stream_live.rs`):

```
1 auth  (SessionStore) → 2 discovery (runtime bundle) → 3 derive MQTT creds
→ 4 broker TLS connect (8883) → 5 302 offer/answer
→ 6 ICE host-direct (binds the media UDP socket early, trickles its OWN host
    candidate, NO USE-CANDIDATE, tolerates ICMP ECONNREFUSED) + consent
→ 7 conv=0 media-start: AUTH (username "admin", password =
    md5_hex_lower(<camera password> ++ "||" ++ <localKey>) — lowercase-hex
    INFERRED, live-validated not byte-verified) + VERSION + the 3 command PDUs,
    all CONTIGUOUS / suite-3 sealed
→ 8 MediaEngine pump (suite-3 AES-128-CBC + 20B HMAC-SHA1 / KCP / fixed-12B RTP)
   → H.264 (conv 1) + 16 kHz S16LE audio (conv 2) → 9 ffmpeg → MPEG-TS over HTTP
```

When it prints `pumping; connect a player`, open the feed:

```sh
vlc    http://127.0.0.1:8554/stream.ts
mpv    http://127.0.0.1:8554/stream.ts
ffplay http://127.0.0.1:8554/stream.ts
```

Video is H.264 copied through; the **downstream camera audio is 16 kHz mono S16LE**
(NOT G.711 — see §6) and is encoded to AAC in the TS. **Caveat (live audio is
UNVERIFIED):** live runs received **0 conv=2 audio bytes** (TS-file mode wrote 0
audio bytes; the sink yields nothing when no conv=2 audio arrives). The 16 kHz
S16LE decode path is proven ONLY by the offline cap4 replay (§5), not on the wire.

If any stage is missing, the driver stops with an honest `StreamPending` /
`Transport` error naming exactly what is absent — it never fabricates a stream.

---

## 5. Offline sanity check (no camera)

You can prove the **back half** (decrypt → depacketize → A/V mux → serve) with no
network, using a captured/synthetic Annex-B + S16LE:

```sh
nix-shell --run 'just stream-validate'   # part of `just e2e`
# or by hand, muxing real downstream audio alongside video:
babymonitor-cli stream --replay-annexb video.264 --replay-audio audio.s16le \
    --output ts --ts-out av.ts
ffprobe av.ts        # -> a h264 video stream AND an audio (aac) stream
```

The cap4 capture validates this byte-exact: `cargo test -p babymonitor-core --test
cap4_replay -- --ignored` reconstructs the 4 090 176-byte H.264 and the
**1 532 800-byte S16LE audio** identically to the independent ground truth.

---

## 6. Honest risks — what is NOT yet verified live

These are real gaps; do not assume they "just work":

1. **SUSTAINED conv=1 video is NOT yet verified — this is the live blocker now.**
   Across live runs the camera's conv=1 video **froze at ~12 segments** (its initial
   KCP send window). Root cause (architecture + codex review): the single-threaded
   media pump (`stream_live.rs` `pump_to_output`) does a **BLOCKING** write into the
   ffmpeg sink (`stream.rs` `write_annexb` / `OutputSink`), which starves the KCP ACK
   loop (`mod.rs` `drain_media_acks`) so the camera's `snd_una` never advances. Also:
   `kcp.rs` `IKCP_CMD_WASK`/`WINS` is a **no-op** and there is **no standalone ACK
   flush cadence**. So "live keyframe decodes + displays" is PROVEN, but "smooth
   continuous A/V" is NOT. Follow-ups: **TASK-0085** (decouple the ACK loop from the
   blocking sink — *the blocker*), **TASK-0086** (KCP WASK/WINS + flush cadence),
   **TASK-0089** (verify conv1/conv2 ACK byte-shape vs cap4 + a sustained-A/V harness).

2. **MQTT CONNECT now SUCCEEDS live** (Superseded 2026-06-28, v0.1.0-live-stream).
   The self-contained v0.1.0 client established MQTT-302 signaling against the REAL
   broker (CONNECT succeeded, the camera answered the 302). The clientId/username are
   string-assembled and the password is the ported `doCommandNative(2, ecode)`
   (`md5_hex_lower(md5_hex_lower(G) ++ ecode)`, middle-16 — `stream::mqtt_auth`,
   algorithm cross-checked vs Python MD5). **Residual:** the credentials are not yet
   **byte-diffed** against a real TLS:8883 CONNECT capture (cap3's mitmproxy was
   HTTP-only; `re/mqtt_signaling.md` §4). **Close the byte-level gap with Frida:** hook
   `SdkMqttCertificationInfo` (`com/thingclips/sdk/mqtt/qpqbppd.java`) — its
   `bdpdqbp()` (clientId), `qddqppb()` (username) and `bppdpdq()` (password) — dump the
   three values and diff them against `derive_credentials(...)` for the same session.

3. **The DERIVED 302 topics are now LIVE-CONFIRMED** (Superseded 2026-06-28,
   v0.1.0-live-stream). `smart/mb/out/<devId>` (publish) + `smart/mb/in/<devId>`
   (subscribe) demonstrably reach the camera on the live run — it received the
   published offer and answered the 302. **Residual:** no TLS:8883 pcap of the literal
   topic string exists (the broker is off the cap0–cap3 HTTP proxy). Derivation pinned
   two-source from the Java publish path (`re/mqtt_signaling.md` §1a; `stream::topics`).

4. **TURN relay is a documented stub.** cap4 reached the camera via a LAN **host**
   candidate with no relay, so host-direct works on the same Wi-Fi as the camera.
   Remote / NAT-traversed access needs a real TURN client
   (`stream::media::transport::allocate_turn_relay` returns a loud error today).

5. **srflx is loopback-validated only.** The STUN Binding / XOR-MAPPED-ADDRESS
   round-trip is proven over a localhost responder, not against the SDP `stun:`
   server (TASK-0075). Host-direct does not need it.

6. **Inbound-trickle handling — partially reconciled** (Superseded 2026-06-28,
   v0.1.0-live-stream). The client now **self-trickles its OWN host candidate and
   binds the media socket early** (§4 step 6), which is what got the live path
   connected against the SCD921 — so the earlier "the driver only selects the host
   candidate from the answer SDP" framing no longer fully holds. Still open: surfacing
   the camera's **inbound** trickle candidates (`poll_inbound`) is not exercised; the
   live SCD921 supplied a usable host candidate in/with the answer, so this did not
   block, but a camera that only trickles its host candidate later would need it.

**Follow-up tasks:** TASK-0083 (live media transport) is **DONE**. Open:
TASK-0085 (decouple the ACK loop from the blocking sink — the blocker), TASK-0086
(KCP WASK/WINS + flush cadence), TASK-0087 (A/V sink: drop ffmpeg `-shortest` /
free-port check / clean disconnect), TASK-0088 (newtype the derived conv=0 auth
password), TASK-0089 (conv1/conv2 ACK byte-shape vs cap4 + sustained-A/V harness).

---

## 7. Where the code is

- driver: `babymonitor/babymonitor-cli/src/stream_live.rs` (the ONE assembled driver)
- conv=0 media auth: `control::derive_media_auth_password()` + the `media_auth_args()`
  seam in `stream_live.rs` (the §4 step-7 AUTH/VERSION/command PDUs)
- media engine: `babymonitor/babymonitor-core/src/stream/media/` (`mod.rs` pump,
  `crypto.rs`, `kcp.rs`, `frame.rs`, `h264.rs`, `audio.rs`, `stun.rs`, `transport.rs`)
- signaling: `…/stream/{signaling.rs, session.rs, mqtt_crypto.rs, sdp.rs}`
- MQTT auth + broker: `…/stream/{mqtt_auth.rs, transport.rs}`
- spec: `re/media_decode_spec.md`, `re/mqtt_signaling.md`, `re/webrtc_session.md`
