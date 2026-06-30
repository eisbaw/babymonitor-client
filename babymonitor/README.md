# babymonitor — Rust client for the Philips Avent Baby Monitor+

A from-scratch Rust client for the **Philips Avent Baby Monitor+** (hardware
SCD921 / SCD923), a white-labeled **Tuya IPC camera**. Protocol recovered by **static
analysis**, then validated on emulator captures + authorized live runs; see `../re/` for the
analysis artifacts.

Workspace:

- `babymonitor-core` — the library: the Tuya mobile-app ("atop") request
  **signer**, the **session** token store, and the **device-list / camera**
  models + accessors.
- `babymonitor-cli` — the command-line viewer over that library.

## Authorized scope

This is a **benign, authorized personal project**. It targets **only the user's
own Tuya account and their own SCD921/SCD923 device**. Do not point it at any
account or device you do not own.

## Build

From the repo root, inside the nix shell:

```sh
nix-shell --run 'just build'      # compile the workspace
nix-shell --run 'just e2e'        # build + test + clippy -D + fmt-check + stub-grep + offline
nix-shell --run 'just showcase'   # run every read-only CLI command (regression tripwire)
```

Run the CLI:

```sh
nix-shell --run 'just run -- devices list'
nix-shell --run 'just run -- --json auth status'
```

## Status: live login + full A/V stream working

The client **logs in against the real Tuya cloud** (`auth live-login`: password +
email-MFA → an authenticated `sid`/`uid` session), drives **signed cloud calls** with
that session (`device.list`, `rtc.config.get`), and **streams the SCD921's live A/V
end-to-end** — WebRTC-over-MQTT **302** signaling → host-direct ICE → KCP /
AES-128-CBC + HMAC-SHA1 media → **H.264 video + S16LE audio**. The media back-half is
byte-validated offline against the cap4 capture and confirmed on an authorized live
run against the owner's own camera (TASK-0083/0085; commits `f8d9acf`, `e1528da`).

> **The earlier "blocked" framing is superseded.** The previous status (login pending
> a fresh probe; "no working video without auth") predates the working end-to-end
> stream. The unblock was making the login request APK-faithful (form-body params,
> ET=3 AES-GCM `postData`, epoch-second `time`, UUID `requestId`) plus fixing the
> client signer — `ILLEGAL_CLIENT_ID` was a client bug, not a server attestation wall.

Offline (no camera, no network) the same decode/mux path is exercised by
`stream --replay-annexb` and asserted by the `just stream-validate` gate.

| Command | Status |
|---|---|
| `auth live-login` (`--features live`) | real login: password + email-MFA → session persisted to the store |
| `auth status` / `auth logout` | reads/clears the local session store (offline) |
| `devices list --live` (`--features live`) | signed `device.list` with the stored `sid` → finds the SCD921 |
| `devices list` / `devices show <id>` | offline against a **fixture body** (`--fixture <file>`; defaults to the synthetic fixture) |
| `stream` (`--features live`) | full live A/V → MPEG-TS over HTTP, raw stdout, **or an in-app GUI window** |

Every command supports `--json`. **Secret/PII fields** (`localKey`, `secKey`,
`p2pKey`, `initStr`, session/relay descriptors, …) are **redacted by default**;
`--show-secrets` opts in (and prints a stderr warning) — intended only for your
own authorized/synthetic data.

## Live A/V stream (`stream`)

`babymonitor-cli stream` drives the whole pipeline (login → discovery → 302
signaling → ICE → media) and renders the decoded feed. Three output modes:

| `--output` | What | Play with |
|---|---|---|
| `http` (default) | MPEG-TS served over HTTP (ffmpeg muxer) | `vlc http://127.0.0.1:8554/stream.ts` |
| `window` | in-app SDL2 video window — **in-process** libavcodec H.264 decode → YUV → GPU texture (no subprocess, no HTTP). Needs `--features live,gui`. | (opens its own window) |
| `stdout` | raw Annex-B H.264 | `mpv -` / `ffplay -f h264 -` |

```sh
# HTTP + VLC (the just recipe builds, waits for the camera, auto-opens VLC, and
# stops the pipeline when VLC closes):
nix-shell --run 'just live-stream'

# In-app GUI window (renders in our own SDL2 window — no external player):
nix-shell --run 'cargo run --manifest-path babymonitor/babymonitor-cli/Cargo.toml \
    --features live,gui --bin babymonitor-cli -- stream --output window'
```

The GUI window decodes **in-process** via the `ffmpeg-the-third` libavcodec binding
(decision + the `ffmpeg_7` pin rationale in `../re/gui_window.md`), not a subprocess,
and uploads YUV420 straight into an SDL2 IYUV texture. The bounded video queue keeps
the camera's KCP window advancing so the source never freezes (the TASK-0085 fix).

The window **closes** on the X button, Ctrl-C, or SIGTERM: `gui::close_requested` reads raw SDL
event types via a small FFI (the sdl2 0.37 `Event` enum panics on the nix `sdl2-compat` shim, so the
crate root is `deny(unsafe_code)` for that one spot), and the live presenter exits via
`process::exit(0)` — graceful-shutdown signalling is a TASK-0117 follow-up. Known v1 limit:
**video only** — downstream audio is received but not played (TASK-0116). Stream health is
observable without touching frame content via `$BABYMONITOR_STREAM_TRACE` (KCP cursors + frame
counters; no PII).

## The live gold-oracle test (gated)

The strongest acceptance signal is a live end-to-end run against the real camera:
`auth live-login` → `devices list` → find the SCD921. It lives in
`babymonitor-cli/tests/live_e2e.rs` and is **`#[ignore]`d** so it never runs in
`just e2e` / CI and makes no network call there. Today, when run manually, it
asserts the **honest no-live-credentials state**; once a fresh guarded login probe
passes or a **captured session is injected** (**TASK-0022**) it becomes the real
login-and-discover assertion.

To run it manually once fresh login or a captured session is available (single-shot,
rate-limited):

```sh
# 1. secrets/tuya_appkey.json  -> { "app_key": "...", "app_secret": "...", "ttid": "..." }
#    (gitignored; the app-cert SHA-256 is computed OFFLINE from the APK, never committed)
# 2. account credentials placed where the live harness reads them from secrets/ (never tracked)
# 3. run the ignored test serially so live calls stay single-threaded (no rate-limit trips):
nix-shell --run 'cargo test --manifest-path babymonitor/Cargo.toml \
    -p babymonitor-cli --test live_e2e -- --ignored --test-threads=1'
```

The harness asserts **shape only** (a camera is found, transport is WebRTC) and
**never prints** a device id / `sid` / `uid` (account-linked PII).

## License

MIT (see the workspace `license` field).
