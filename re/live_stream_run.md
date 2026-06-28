# Live stream run — getting a real frame off the SCD921

The EXACT owner-only steps to take `babymonitor-cli` from a cold start to a live
video+audio frame, plus the honest list of what is **proven offline** vs what is
**still un-verified and needs your live run** (with a Frida recipe to close the
last gap). Everything here touches the account owner's OWN device on their OWN
network — static analysis cannot reach a broker or a camera, so the live front
half is yours to run.

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
most one `password.login`, stops at 2FA). It is the project's known hard block: a
from-scratch login currently hits the server-side identity gate
(`ILLEGAL_CLIENT_ID`, see MEMORY / `re/tuya_cloud_auth.md`). If you have a fresh
gateway/appKey that clears it, the flow is:

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

The driver runs the assembled pipeline (`babymonitor-cli/src/stream_live.rs`):

```
1 auth  (SessionStore) → 2 discovery (runtime bundle) → 3 derive MQTT creds
→ 4 broker TLS connect (8883) → 5 302 offer/answer → 6 ICE host-direct + consent
→ 7 MediaEngine pump (suite-3 AES-128-CBC + 20B HMAC-SHA1 / KCP / fixed-12B RTP)
   → H.264 (conv 1) + 16 kHz S16LE audio (conv 2) → 8 ffmpeg → MPEG-TS over HTTP
```

When it prints `pumping; connect a player`, open the feed:

```sh
vlc    http://127.0.0.1:8554/stream.ts
mpv    http://127.0.0.1:8554/stream.ts
ffplay http://127.0.0.1:8554/stream.ts
```

Video is H.264 copied through; the **downstream camera audio is 16 kHz mono S16LE**
(NOT G.711 — see §6) and is encoded to AAC in the TS, so you hear the room.

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

1. **MQTT CONNECT auth is UN-verified on the wire.** The clientId/username are
   string-assembled and the password is the ported `doCommandNative(2, ecode)`
   (`md5_hex_lower(md5_hex_lower(G) ++ ecode)`, middle-16 — `stream::mqtt_auth`,
   algorithm cross-checked vs Python MD5). But there is **no packet capture of the
   real CONNECT** (the broker is TLS:8883; cap3's mitmproxy was HTTP-only). So the
   *derived credentials have no wire vector to diff against* (`re/mqtt_signaling.md`
   §4). **Close the gap with Frida:** hook `SdkMqttCertificationInfo`
   (`com/thingclips/sdk/mqtt/qpqbppd.java`) — its `bdpdqbp()` (clientId),
   `qddqppb()` (username) and `bppdpdq()` (password) — dump the three values and
   diff them against `derive_credentials(...)` for the same session. If they match,
   stage 4 is confirmed; if not, the discrepancy is in the username field order or
   the `ecode`/`G` feed.

2. **The 302 publish/subscribe topics are now DERIVED** (TASK-0078), no longer
   injected: `smart/mb/out/<devId>` (publish) + `smart/mb/in/<devId>` (subscribe),
   pinned two-source from the Java publish path (`re/mqtt_signaling.md` §1a;
   `stream::topics`). **Residual:** the literal topic string is not capture-confirmed
   (the broker is TLS:8883, off the cap0–cap3 HTTP proxy; cap4 is the media UDP pcap)
   — only its input `devId` is validated against the cap3 302 `header.to`. Confirm the
   exact wire topic on the live run by hooking the publish (`pbbppqb.java`) or the
   broker subscribe (`bqbppdq.java:3661`).

3. **TURN relay is a documented stub.** cap4 reached the camera via a LAN **host**
   candidate with no relay, so host-direct works on the same Wi-Fi as the camera.
   Remote / NAT-traversed access needs a real TURN client
   (`stream::media::transport::allocate_turn_relay` returns a loud error today).

4. **srflx is loopback-validated only.** The STUN Binding / XOR-MAPPED-ADDRESS
   round-trip is proven over a localhost responder, not against the SDP `stun:`
   server (TASK-0075). Host-direct does not need it.

5. **Trickle candidates are not surfaced** by `connect_and_negotiate` — the driver
   selects the host candidate from the answer SDP. If your camera only trickles its
   host candidate (not in the answer SDP), wire `poll_inbound` candidates in.

---

## 7. Where the code is

- driver: `babymonitor/babymonitor-cli/src/stream_live.rs` (the ONE assembled driver)
- media engine: `babymonitor/babymonitor-core/src/stream/media/` (`mod.rs` pump,
  `crypto.rs`, `kcp.rs`, `frame.rs`, `h264.rs`, `audio.rs`, `stun.rs`, `transport.rs`)
- signaling: `…/stream/{signaling.rs, session.rs, mqtt_crypto.rs, sdp.rs}`
- MQTT auth + broker: `…/stream/{mqtt_auth.rs, transport.rs}`
- spec: `re/media_decode_spec.md`, `re/mqtt_signaling.md`, `re/webrtc_session.md`
