# Philips Avent Baby Monitor+ — reverse-engineered Rust client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A from-scratch **Rust** client for the Philips Avent "Baby Monitor+" (hardware
**SCD921 / SCD923**) — reverse-engineered from the Android app
`com.philips.ph.babymonitorplus` so the camera can be watched without the official app.

It logs in to the real cloud (password + email-MFA) and **streams the camera's live A/V
end-to-end** — WebRTC-over-MQTT signaling → ICE → KCP / AES media → H.264 video + audio —
played in a standard player or an in-app window.

## Quick start

Everything runs inside the project's nix shell (`shell.nix` provides every tool — jadx,
Ghidra, radare2, cargo, ffmpeg):

```sh
nix-shell --run 'just e2e'              # build + the full offline test suite (no device needed)
nix-shell --run 'just stream-validate'  # offline demo: a synthetic H.264 sample → a playable MPEG-TS
```

Watching a **real** camera — `just gui-stream` (in-app window) or `just live-stream`
(HTTP → VLC) — needs the **owner's own device + an authenticated session** (the gated
`--features live` build). See [`babymonitor/README.md`](babymonitor/README.md) for the
`stream` command and its options.

## Scope / authorized use

A **benign, authorized personal project**: it targets **only the owner's own Tuya account
and their own SCD921/SCD923 device**. Do not point it at any account or device you do not
own. No Philips/Tuya credentials are redistributed — recovered keys live in a gitignored
`secrets/` store, referenced by location only, never committed. See [`re/prd.md`](re/prd.md).

## How it works

The Baby Monitor+ is a **re-skinned Tuya Smart (ThingClips) IPC camera** app, so auth is
Tuya account auth and the streaming stack is Tuya's — a known quantity also documented by
the public RE community. Two parts carry the project:

- **Video — WebRTC-over-MQTT.** The camera streams over Tuya's own WebRTC, signaled via
  MQTT (message code **302**) and chosen at runtime by the cloud `p2pType`. Signaling is
  standard WebRTC shape (SDP + trickle-ICE); the **media is not DTLS-SRTP** but Tuya's own
  KCP / AES-128-CBC + HMAC-SHA1 framing, with the media key carried in the SDP. See
  [`re/streaming_mode.md`](re/streaming_mode.md) and [`re/webrtc_session.md`](re/webrtc_session.md).
- **Auth — Tuya mobile-app sign.** Cloud requests use Tuya's mobile-app SDK signature
  (plain MD5 over underscore-joined parts), recovered to byte level from the native libs;
  login is the APK-faithful `token.get → password.login → email-MFA` flow. See
  [`re/tuya_cloud_auth.md`](re/tuya_cloud_auth.md) and [`re/tuya_sign_static.md`](re/tuya_sign_static.md).

The recovered transport matches independent public Tuya WebRTC projects field-for-field,
and the whole chain — login → device discovery → signaling → ICE → media decrypt — is
implemented and confirmed on a live run against the owner's camera. (The LAN protocol on
TCP 6668 is datapoint-only and is not an A/V source.)

## The Rust client

[`babymonitor/`](babymonitor/README.md) is a faithful, tested client:

- **`babymonitor-core`** — the cloud request signer, the session store, the device/camera
  models, and the WebRTC-over-MQTT protocol layer.
- **`babymonitor-cli`** — a CLI viewer (`auth`, `devices`, `stream`), human + `--json`
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

## License

**MIT** — see [`LICENSE`](LICENSE) (the Rust workspace also declares `license = "MIT"`).
