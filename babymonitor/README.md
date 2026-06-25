# babymonitor — Rust client for the Philips Avent Baby Monitor+

A from-scratch Rust client for the **Philips Avent Baby Monitor+** (hardware
SCD921 / SCD923), a white-labeled **Tuya IPC camera**. Reverse-engineered
**statically** (no live capture); see `../re/` for the analysis artifacts.

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

## Login status: TOKEN-PENDING (the client cannot log in yet)

> **The client cannot authenticate yet.** A valid Tuya request signature needs
> the `bmp_token` decoded from `assets/t_s.bmp` by an **imath-bignum + matrix
> decode (on the sign path)** that is **not yet ported** (tracked as
> **TASK-0032**). Until then,
> `auth login` and any live cloud fetch **honestly report the token-pending
> state and never fabricate a session or a response.**

What works **offline today**:

| Command | Status |
|---|---|
| `auth status` / `auth logout` | works (reads/clears the local session store) |
| `auth login` | reports **token-pending** (no real login) |
| `devices list` / `devices show <id>` | works against a **fixture body** (`--fixture <file>`; defaults to the synthetic test fixture) |
| `devices list --live` | **token-pending** (no network touched; surfaces the pending state) |

Every command supports `--json`. **Secret/PII fields** (`localKey`, `secKey`,
`p2pKey`, `initStr`, session/relay descriptors, …) are **redacted by default**;
`--show-secrets` opts in (and prints a stderr warning) — intended only for your
own authorized/synthetic data.

## The live gold-oracle test (gated)

The strongest acceptance signal is a live end-to-end run against the real camera:
`auth login` → `devices list` → find the SCD921. It lives in
`babymonitor-cli/tests/live_e2e.rs` and is **`#[ignore]`d** so it never runs in
`just e2e` / CI and makes no network call there. Today, when run manually, it
asserts the **honest token-pending state**; once **TASK-0032** lands it becomes
the real login-and-discover assertion.

To run it manually once login is unblocked (single-shot, rate-limited):

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
