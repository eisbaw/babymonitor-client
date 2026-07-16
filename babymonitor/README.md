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
end-to-end** over either cloud MQTT or local Tuya frame-32 signaling. Both paths
continue through host-direct ICE → KCP / AES-128-CBC + HMAC-SHA1 media → **H.264
video + S16LE audio**. The media back-half is byte-validated offline against cap4;
cloud and fully LAN-restricted runs are confirmed against the owner's camera.

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
| `lan provision` (`--features live`) | build a secure local config and prove its endpoint/protocol/localKey without REST or MQTT |
| `firmwareWIP info` / `firmwareWIP download` (`--features live`) | explicitly experimental: owner metadata query is live-confirmed only in a no-offer state; candidate/CDN download is loopback-tested only; neither command sends an upgrade-confirm request |
| `stream` (`--features live`) | full live A/V → MPEG-TS over HTTP, raw stdout, **or an in-app GUI window** |

Every command supports `--json`. **Secret/PII fields** (`localKey`, `secKey`,
`p2pKey`, `initStr`, session/relay descriptors, …) are **redacted by default**;
`--show-secrets` opts in (and prints a stderr warning) — intended only for your
own authorized/synthetic data.

## Read-only firmware acquisition (WIP)

The deliberately named `firmwareWIP` command follows the exact update-check path used by the current app.
It requires the owner's stored cloud session and the key-proven device ID in the
private LAN config. It does not call Tuya's separate confirm/start endpoint:

```sh
# Inspect server-reported versions and whether the metadata includes a package URL.
nix-shell --run 'cargo run --manifest-path babymonitor/Cargo.toml \
    -p babymonitor-cli --features live -- firmwareWIP info'

# If a URL is present, fetch it into private files under <SECRETS_DIR>/firmware/.
nix-shell --run 'cargo run --manifest-path babymonitor/Cargo.toml \
    -p babymonitor-cli --features live -- firmwareWIP download'
```

The authorized live validation exercised both metadata endpoints. Each returned two
no-offer records with a server-reported `currentVersion`; neither returned an offered
version, URL, size, hash, or signature, so no real package/CDN request was made. The
streaming downloader and integrity checks are covered by a literal-loopback HTTP fixture
only. Do not interpret that test as a successful real firmware acquisition. The hardened
path was not queried live again: the owner session available during that validation had
expired and was rejected, so the 2026-07-16 no-offer result remains the latest live evidence.

Before any firmware request, the client loads the session through the hardened store. On
Unix the session file is opened with `O_NOFOLLOW`, must be a regular file with mode exactly
`0600`, and must live under a real, non-symlink parent that is not group- or world-writable.
A validated parent directory descriptor is retained for the whole load/save/clear transaction;
file inspection, temporary creation, rename, unlink, and fsync are basename-relative, so an
ancestor-path swap cannot redirect session secrets after validation.
A session that is expired or within the two-minute refresh buffer is rejected before network
work. The persisted `mobileApiUrl` must parse as the exact app-evidenced HTTPS gateway shape
(allowed host, port 443, and `/` or `/api.json`); there is no regional fallback. Firmware
and atop clients disable redirects, and an atop metadata response is rejected if its
declared or streamed body exceeds 2 MiB.

After a successful metadata query, each `info` or `download` invocation stages a unique
private `<SECRETS_DIR>/firmware/acquisition-.../` directory (mode `0700` with mode-`0600`
files on Unix). The private manifest records the validated HTTPS gateway/request shape,
SHA-256 of the device ID
(never the raw ID), endpoint/action/version/request-field provenance, raw primary and
optional legacy response filenames, `upgrade_request_sent: false`, and per-channel metadata.
Its `completed` and optional `failure_class` fields distinguish success from a rejected URL
or integrity preflight, transport/HTTP, size, MD5, or storage failure. A successful package
also records actual size, MD5, and SHA-256; server `sign` presence is recorded while
`signature_verified` remains false because the algorithm/key are unknown.

A package-stage failure still publishes the raw response(s) and failure manifest. The
unverified package partial is removed; if an earlier sibling package in the same acquisition
already passed its size and MD5 checks, that verified sibling is retained and referenced.
The acquisition likewise retains opened descriptors for its private parent and staging
directory. Child creation, writes, verified-package installation, cleanup, publication, and
fsync are descriptor-relative. On Linux, publication uses
`renameat2(RENAME_NOREPLACE)`, so an existing acquisition or package is never replaced and a
successful publish is durable. Acquisition publication fails closed on non-Linux platforms
rather than claiming portable no-clobber behavior.

Public summaries deliberately separate `package_url_present` (a non-empty server field),
`integrity_metadata_present` (a non-empty MD5 field, not necessarily valid), and
`download_eligible` (production HTTPS URL plus a valid 32-hex-digit MD5). Eligibility does
not promise a successful transfer or bypass the 512 MiB, HTTP-status, declared-size, or
post-download MD5 checks. Public current/offered versions are shown only when they pass a
strict version-token validator; other server strings are redacted as unknown/null. Artifact
filenames use only the record index and locally derived source/channel labels, never a
server-supplied version. The only HTTP download allowance is a test-only policy restricted
to literal loopback addresses. Sensitive URLs, hashes, signatures, device IDs, and account
material remain out of terminal output and must stay gitignored.

The two observed APIs did not expose bytes for the server-reported current version. That
result does not rule out an undiscovered archive surface, and it is not a readback of the
camera's flash. Obtaining the exact installed bytes still requires device-shell access or a
physical flash dump.

The queried v1.1/v1.2 APIs deserialize `BLEUpgradeBean`/`UpgradeInfoBean`, which do not
define `diffOta`. A separate direct-AP model does define that flag, demonstrating that Tuya
has a delta-capable path, but not that a future candidate from these queried APIs is a delta.

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

For an already paired camera, provision once from the owner's private cached
device/RTC records, then select the fail-closed LAN carrier:

```sh
nix-shell --run 'cargo run --manifest-path babymonitor/babymonitor-cli/Cargo.toml \
    --features live --bin babymonitor-cli -- lan provision'
nix-shell --run 'cargo run --manifest-path babymonitor/babymonitor-cli/Cargo.toml \
    --features live --bin babymonitor-cli -- stream --signaling lan'
```

`lan provision` matches UDP discovery to the cached device ID and then requires a
key-proving camera exchange before saving mode-0600 metadata. The UDP codec is
APK-derived/offline-tested; the live camera did not advertise, so the proven run
used explicit `--camera-ip` and the same cryptographic check. The current media
route is IPv4-only. During streaming the client advertises its own numeric,
route-selected local-interface STUN responder—no public STUN/TURN, DNS, REST, or
MQTT endpoint is used. The validated SCD921 speaks Tuya LAN 3.3 on TCP 6668;
media flows separately over the negotiated ICE/KCP UDP socket.

This proves cloud-free runtime for the currently paired device, not cloud-free
factory pairing. A factory reset, account move, or re-pair may rotate `localKey`
and the cached media password; local recovery of those values is not implemented.
The 47–103 second proofs retained TCP signaling and the local responder until
teardown, but did not poll TCP after negotiation; cold camera restart,
long-session heartbeat/renegotiation, and reconnect behavior remain unvalidated.

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
