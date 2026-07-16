# Philips Avent Baby Monitor+ — reverse-engineered Rust client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A from-scratch **Rust** client for the Philips Avent "Baby Monitor+" (hardware
**SCD921 / SCD923**) — reverse-engineered from the Android app
`com.philips.ph.babymonitorplus` so the camera can be watched without the official app.

It can log in to the real cloud (password + email-MFA), but an already provisioned
camera can now **stream entirely over its LAN**: key-proven Tuya frame-32
signaling on TCP 6668 → local ICE → KCP / AES media → H.264 video + audio. Cloud
MQTT remains available as an explicitly selected remote-signaling mode.

The proof used fresh client processes against an already-running paired camera.
A camera cold-power restart and long-session reconnect behavior are not yet
validated; factory reset/re-pair recovery may still require the vendor flow.

## Quick start

Everything runs inside the project's nix shell (`shell.nix` provides every tool — jadx,
Ghidra, radare2, cargo, ffmpeg):

```sh
nix-shell --run 'just e2e'              # build + the full offline test suite (no device needed)
nix-shell --run 'just stream-validate'  # offline demo: a synthetic H.264 sample → a playable MPEG-TS
```

Watching a **real** camera — `just gui-stream` (in-app window) or `just live-stream`
(HTTP → VLC) — needs the **owner's own device** and the gated `--features live`
build. Cloud mode needs an authenticated session; LAN mode uses a private,
owner-provisioned local config. See [`babymonitor/README.md`](babymonitor/README.md)
for the `stream` command and its options.

## Scope / authorized use

A **benign, authorized personal project**: it targets **only the owner's own Tuya account
and their own SCD921/SCD923 device**. Do not point it at any account or device you do not
own. No Philips/Tuya credentials are redistributed — recovered keys live in a gitignored
`secrets/` store, referenced by location only, never committed. See [`re/prd.md`](re/prd.md).

## How it works

The Baby Monitor+ is a **re-skinned Tuya Smart (ThingClips) IPC camera** app, so auth is
Tuya account auth and the streaming stack is Tuya's — a known quantity also documented by
the public RE community. Two parts carry the project:

- **Video — Tuya P2P with selectable signaling.** The same message-code **302**
  envelope is proven over either cloud MQTT or key-proven Tuya
  `IPC_LAN_302` frame type 32 on TCP 6668. LAN mode supplies a private, local
  RFC 5389 STUN responder so the camera creates and advertises its UDP host
  candidate without public STUN/TURN. Signaling is
  standard WebRTC shape (SDP + trickle-ICE); the **media is not DTLS-SRTP** but Tuya's own
  KCP / AES-128-CBC + HMAC-SHA1 framing, with the media key carried in the SDP. See
  [`re/streaming_mode.md`](re/streaming_mode.md) and [`re/webrtc_session.md`](re/webrtc_session.md).
- **Auth — Tuya mobile-app sign.** Cloud requests use Tuya's mobile-app SDK signature
  (plain MD5 over underscore-joined parts), recovered to byte level from the native libs;
  login is the APK-faithful `token.get → password.login → email-MFA` flow. See
  [`re/tuya_cloud_auth.md`](re/tuya_cloud_auth.md) and [`re/tuya_sign_static.md`](re/tuya_sign_static.md).
- **Firmware WIP — read-only OTA metadata + unconfirmed candidate downloader.** An authorized live query
  reached the same primary and legacy metadata APIs used by the app; both returned a
  no-offer response with server-reported channel versions and no package URL. No newer live
  query was made after hardening because the session available during that validation had
  expired; that earlier result remains the live evidence. The separate downloader is
  implemented without an OTA-confirm call. It rejects expired/near-expiry sessions and non-app-evidenced
  gateways, caps metadata responses, requires production HTTPS with redirects disabled,
  and preserves each successful or package-stage failure as a private, provenance-bearing
  acquisition. Secret/session transactions remain relative to validated, pinned directory
  descriptors; Linux publication uses durable atomic no-clobber semantics and fails closed
  where that primitive is unavailable. The transfer path is loopback-tested, but a real
  offered package/CDN transfer has not yet been observed. This neither provides the camera's
  installed flash bytes nor rules out an undiscovered archive surface. See
  [`re/firmware_ota.md`](re/firmware_ota.md).

The recovered transport matches independent public Tuya WebRTC projects
field-for-field. Both carriers are live-proven against the owner's camera. In the
LAN test, a kernel egress allowlist denied every destination except loopback and
the camera, yet a fresh run produced decodable 1920×1080 H.264 plus audio. TCP
6668 carries only signaling; A/V remains direct ICE/KCP UDP. Initial pairing—and
recovery if a reset rotates `localKey`—is not yet cloud-free.

## The Rust client

[`babymonitor/`](babymonitor/README.md) is a faithful, tested client:

- **`babymonitor-core`** — the cloud request signer, the session store, the device/camera
  models, and the WebRTC-over-MQTT protocol layer.
- **`babymonitor-cli`** — a CLI viewer (`auth`, `devices`, `stream`, `firmwareWIP`), human + `--json`
  output, secret/PII fields redacted by default.

The offline surface (`auth`/`devices` against fixtures, `stream --replay-annexb`) runs
with no device; the live path is gated behind `--features live`. A captured session can be
injected to drive the read/stream path without logging in again — see
[`babymonitor/README.md`](babymonitor/README.md).

## Repo layout

| Path | What |
|---|---|
| `babymonitor/` | the Rust workspace (`babymonitor-core` + `babymonitor-cli`) |
| `re/` | the reverse-engineering analysis docs + `re/scripts/` grounding gates |
| `Justfile` | build / test / lint / run + grounding recipes (run inside `nix-shell`) |
| `TESTING.md` | the grounding stance — what "good vs bad" means for docs and client |
| `secrets/` | gitignored store for recovered creds, fixtures, PII (never tracked) |

## Methodology

The protocol was recovered primarily by **static analysis** of the decompiled Java/Kotlin
and native libraries (jadx + Ghidra/radare2), then validated against emulator network
captures and **confirmed on authorized live runs** against the owner's own device. Every
protocol claim in `re/*.md` carries a confidence label and a symbol-anchored citation,
linted by `just check-evidence`; `just secret-scan` blocks any leaked credential or PII.
Follow the `re/*.md` links for per-claim evidence and honest limitations.

## Thanks to

Thanks to [`rust-async-tuyapi`](https://github.com/FruitieX/rust-async-tuyapi),
and especially [uplg's Tuya protocol 3.5 pull request
#21](https://github.com/FruitieX/rust-async-tuyapi/pull/21), for making this LAN
protocol work available as a public reference. See [`NOTICES.txt`](NOTICES.txt).

## License

**MIT** — see [`LICENSE`](LICENSE) (the Rust workspace also declares `license = "MIT"`).
