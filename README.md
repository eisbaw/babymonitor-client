# Philips Avent Baby Monitor+ — reverse-engineered Rust client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Reverse-engineering the Android app **`com.philips.ph.babymonitorplus`** (Philips
Avent "Baby Monitor+", hardware **SCD921 / SCD923**) deeply enough to reimplement a
software second-screen client in **Rust** — built because the official app won't run on
the owner's phone, so they want their own client. The two hardest parts are solved: the
**live video/audio stream** and the **account/device authentication**.

**Milestone — the live stream works.** The Rust client now **logs in against the real
Tuya cloud** (password + email-MFA → an authenticated `sid` session) and **streams the
SCD921's live A/V end-to-end** — WebRTC-over-MQTT **302** signaling → host-direct ICE →
KCP / AES-128-CBC + HMAC-SHA1 media → **H.264 video + S16LE audio**. It plays in a
standard player over HTTP **or in an in-app GUI window** (`stream --output window`).
The earlier "pure-static auth is exhausted / proven identity gate" and "no working
video without auth" conclusions are **superseded**: the unblock was making the login
request APK-faithful (form-body params, ET=3 AES-GCM `postData`, epoch-second `time`,
UUID `requestId`) plus fixing the client signer — the old TASK-0050/0051
`ILLEGAL_CLIENT_ID` differential was a **client** bug, not a server attestation wall.
See `babymonitor/README.md` for the `stream` command and `re/gui_window.md` for the
in-app window.

## Quick start

All tools (jadx, Ghidra, radare2, cargo, ffmpeg) come from `shell.nix`, so everything
runs inside the project's nix shell:

```sh
nix-shell --run 'just e2e'              # build + the full offline test suite (no device needed)
nix-shell --run 'just stream-validate'  # offline demo: replay a synthetic H.264 sample through the
                                        # real RTP depacketizer + ffmpeg muxer -> a playable MPEG-TS
```

Watching a **real** SCD921 live — `just gui-stream` (in-app window) or `just live-stream`
(HTTP -> VLC) — needs the **owner's own device + an authenticated session** (the gated
`--features live` build); see [`babymonitor/README.md`](babymonitor/README.md).

## Scope / authorized use

This is a **benign, authorized personal project**. It targets **only the project
owner's own Tuya account and their own SCD921/SCD923 device** (the official app will
not run on their phone, so they want a software client). Do not point it at any
account or device you do not own. There is **no redistribution of Philips' or Tuya's
credentials** (appKey / appSecret / sign-key / per-device keys) — those are recovered
into a gitignored `secrets/` store and referenced by location only, never committed.
See `re/prd.md` ("Non-goals", "Authorized scope").

## Repo layout

| Path | What |
|---|---|
| `re/` | the reverse-engineering analysis docs (the sources cited throughout this README) and `re/scripts/` grounding gates |
| `babymonitor/` | the Rust workspace — `babymonitor-core` (library) + `babymonitor-cli` (CLI viewer); see `babymonitor/README.md` |
| `backlog/` | the task tracker (single source of truth for work items) |
| `Justfile` | build/test/lint/run + grounding recipes (run inside `nix-shell`) |
| `TESTING.md` | the grounding stance — what "good vs bad" means for both the analysis docs and the client |
| `secrets/` | gitignored store for recovered creds, fixtures, PII (never tracked) |

---

## 1. What the device/app is

The Philips Avent Baby Monitor+ is a **re-skinned Tuya Smart (ThingClips) IPC
camera** app, built on **React Native over V8**. This is confirmed by two independent
sources — the native library set (`lib/arm64-v8a/libThing*.so`) and the decompiled
package tree (`com/thingclips`, 22,377 `.java` files); the `Thing*`/`thing*` prefix is
Tuya's SDK after its rebrand to "Thing". Philips white-labeled Tuya's Smart Camera
(IPC) platform rather than building a bespoke stack. The consequence: **auth is Tuya
account auth + cloud device-binding**, not a Philips-proprietary or local-only scheme,
and the streaming stack is Tuya's IPC stack. See `re/milestone2_findings.md`.

Because it is Tuya, the protocol is a **known quantity** — the cloud auth, pairing
token flow, and P2P/WebRTC transport are documented by the public RE community, which
is the main lever for the work below.

## 2. The two core findings

### Video = WebRTC-over-MQTT

The SCD921 stack **prefers Tuya's own WebRTC, signaled over MQTT** (message code
**302**), and keeps legacy **PPCS** (TUTK/IOTC lineage) as a fallback. The transport
is chosen **per device at runtime** from a cloud-provided `p2pType` integer
(**4 = WebRTC / 2 = PPCS**) plus a `skill` capability descriptor — not hard-coded. See
`re/streaming_mode.md` (the transport verdict + the 302 envelope) and `re/p2p_triage.md`
(the exported native-symbol surface).

A Ghidra control-flow recovery of `libThingP2PSDK.so` pins the implementable spec
(see `re/webrtc_session.md`):

- The `connect_v2` control JSON, the **302 `{header,msg,token}` signaling envelope**
  (`type` = offer/answer/candidate), and the SDP the device emits are byte-exact.
- Signaling is **standard WebRTC shape** (SDP offer/answer, trickle-ICE), carried over
  Tuya's MQTT brokers via `rumqttc`. The **media is NOT DTLS-SRTP**: the live run
  confirmed Tuya's own framing — **KCP** reliability over UDP carrying **AES-128-CBC +
  20-byte HMAC-SHA1** units (the cap4-validated "suite 3"), after a full-ICE
  host-direct path is nominated.
- The media AES key is conveyed in the SDP itself — an extra `m=application` section
  with an **`a=aes-key:<hex>` line** (not a DTLS exporter). The 302 signaling payload
  is in turn AES-encrypted with the device `localKey` (AES-128/ECB/PKCS5, recovered
  and KAT-tested).

The recovered shape matches independent public Tuya WebRTC projects
(`seydx/tuya-ipc-terminal`, `tuya/webrtc-demo-go`) field-for-field, and the transport
is now **implemented and confirmed on a live run**: the client negotiates the SDP,
nominates the ICE pair, and decrypts real media end-to-end (`re/webrtc_session.md`,
`re/gui_window.md`).

### Auth = mobile-app sign, `MD5(...)`

The cloud request signature is the **Tuya mobile-app SDK sign** (not OpenAPI HMAC):

```
sign = MD5( cert_sha256_hex + "_" + bmp_token + "_" + appSecret  [ + canonical_string ] )
```

It is **plain MD5** (not HMAC), with the key parts **underscore-joined**. This was
recovered to byte level: the MD5 IV constants, the 16-byte digest width, and the `_`
separator are all confirmed in `libthing_security.so`. **Five of the six ingredients
are statically recovered:** the canonical string-to-sign construction, the `_`-join,
the MD5 primitive, the appKey/appSecret (in the DEX → `secrets/`), and the app-cert
SHA-256 (computable **offline** from the APK signing cert — no device). The sixth,
`bmp_token`, remains an **un-validated static candidate** — see the note below; it is
**not** what blocks login. See `re/tuya_sign_static.md` and
`re/review_gate_findings.md` (F1). The recovered identity tuple is also confirmed:
the `appKey` is the **real Philips-provisioned key** (R8-inlined into the production
`SmartApplication.e()` init path; the `com.thingclips.sample` module is Philips' own
app module — its `BuildConfig` carries `APPLICATION_ID=com.philips.ph.babymonitorplus`
— so it is not a Tuya demo key; TASK-0046, `re/identity_enumeration.md`), and the
on-wire identity fields are `ttid = sdk_international@<appKey>` and `channel = oem`
(the `sdk_<channel>@<appKey>` rewrite reaches the `ttid` slot via the production
`CHANNEL_OEM` init overload; `re/tuya_cloud_auth.md` §1b, `re/identity_enumeration.md`
§2a). Cloud-auth envelope, login flow, and device/camera bean shapes are in
`re/tuya_cloud_auth.md`; first-time pairing in `re/pairing_flow.md` (and the decisive
note: an **already-paired** camera needs no pairing — only login + device-list +
camera-config).

> **On the `bmp_token` (the sixth sign ingredient):** it remains a real signer input
> carried by the client in an injectable slot. The prior conclusion that login
> rejected before signature verification is superseded by the request-shape mismatch:
> the old probes did not send the APK's encrypted form-body shape, so they cannot
> prove `bmp_token` irrelevant. The native/JNI key material is now treated as
> statically reproducible unless a fresh APK-shaped probe proves otherwise.

## 3. Auth + live stream: working

The previous "server-side appKey↔app binding" conclusion was based on probes that
were not byte-faithful to the APK request. Static review of the Java and native path
found four load-bearing mismatches in the Rust live client:

1. The APK posts **all** ATOP params as `application/x-www-form-urlencoded` fields;
   `ThingApiParams.getRequestUrl()` supplies an empty query map.
2. `postData` is ET=3 AES-GCM encrypted before signing and before it is sent on the
   wire.
3. `time` is epoch seconds, not milliseconds.
4. `requestId` is UUID-shaped and is also sent as `x-client-trace-id`.

That means the older corrupted-sign differential (TASK-0050) and "final wire diffs"
task (TASK-0051) were testing the wrong envelope. They remain useful history, but
they no longer prove a permanent app-attestation or client-identity wall.

With that envelope corrected, the guarded `token.get` -> `password.login` -> email-MFA
flow completes against the real cloud and issues a session: `ILLEGAL_CLIENT_ID` was the
client signer/identity bug above, not a server wall. Supporting facts:

1. The appKey is the real provisioned identity, not a demo key (TASK-0046,
   `re/identity_enumeration.md`).
2. Region hosts have been broadly enumerated (TASK-0048, `re/regions_decrypt.md`).

### The full live stream now works

With the APK-faithful login the client obtains a real session and the **entire A/V
chain runs**: the authenticated `sid` connects the Tuya MQTT broker that carries the
WebRTC **302** signaling, the offer/answer + trickle-ICE establish a host-direct
path, and the KCP / AES-128-CBC + HMAC-SHA1 media decrypts to **H.264 video + S16LE
audio**. It is byte-validated offline against the cap4 capture and confirmed on an
authorized live run against the owner's own camera (TASK-0083/0085).

The earlier "no video without auth" caveat was correct about the *dependency* (no
session ⇒ no MQTT signaling ⇒ no frames) — that gate is now **passed, not bypassed**.
The **LAN path (Tuya local protocol, TCP 6668) remains datapoint-only** and is still
not an A/V source. See `babymonitor/README.md` for the `stream` command (HTTP/VLC, raw
stdout, or the in-app GUI window) and `re/gui_window.md` for the window internals.

## 4. What the Rust client does — and does not do

`babymonitor/` is a faithful, **tested** client built against the recovered protocol
(see `babymonitor/README.md`):

- `babymonitor-core` — the mobile-app ("atop") request **signer** (the 5-of-6 recovered
  ingredients; the token slot is injectable, not faked), the **session** token store,
  the **device / camera** models, and a **WebRTC-over-MQTT** protocol layer (302
  signaling envelope, the SDP/`a=aes-key` handling, and the localKey AES-128/ECB
  for the 302 payload).
- `babymonitor-cli` — a CLI viewer with `auth` and `devices` subcommands, human + `--json`
  output, and secret/PII fields redacted by default.

It is **complete and token-injectable**, and the corrected live login now works
end-to-end (password + email-MFA → session), driving signed cloud calls and the live
A/V stream. `auth login` is an offline status command; `auth live-login` is the gated
network path that performs the real login. The session-token slot is **injectable, and the consumer is wired**:
`devices list --live` (gated `--features live`, TASK-0055) **loads an injected `sid`**
from the on-disk session store and drives a byte-faithful, signed `device.list`
request with it. With no session injected it reports the no-session state honestly.
The wiring is test-backed offline
(`injected_sid_rides_device_list_envelope_and_canonical_sign`, no network); the
`#[ignore]`d live end-to-end test (`babymonitor-cli/tests/live_e2e.rs`) drives the real
login -> discover -> stream chain when run with the owner's credentials, and is kept out
of `just e2e`/CI so the offline gate needs no device.

Build and run (from the repo root, inside the nix shell):

```sh
nix-shell --run 'just build'                      # compile the workspace
nix-shell --run 'just e2e'                         # build + test + clippy -D + fmt-check + stub-grep + offline checks
nix-shell --run 'just run -- auth login'        # offline status; no fabricated session
nix-shell --run 'just run -- auth status'       # reads/clears the on-disk session store (offline)
nix-shell --run 'just run -- devices list'      # works against a synthetic fixture
nix-shell --run 'just showcase'                    # run every read-only CLI command (regression tripwire)
```

## 5. Methodology

The protocol was reverse-engineered primarily by **static analysis** of the decompiled
Java/Kotlin **and** native libraries (jadx + Ghidra/radare2). Ground-truth **gold
vectors** then came from emulator network captures (`cap0`–`cap4`), and the assembled
client was **confirmed on authorized live runs against the owner's own SCD921**. So the
original static-only constraint (`re/prd.md`) was relaxed to allow owner-authorized
capture and live validation — the recovery is static, the proof is empirical.

Tooling:

- **jadx** for DEX → Java, **apktool** for manifest/resources.
- **Ghidra-primary native decompilation, with radare2 as the cross-check.** This
  Ghidra directive corrected earlier radare2-only mischaracterizations — e.g. a
  function first called a "white-box" cipher is in fact standard AES-128-CBC, and the
  cmd-number that triggers the BMP decode was corrected (`re/bmp_token_whitebox.md`,
  `re/tuya_sign_static.md`). Two views of one `.so` (Ghidra C + r2) count as **one**
  source; `confirmed` claims pair that with an independent artifact (the decompiled
  Java bridge, or a named public Tuya reference).
- **Grounding-gate discipline** (`TESTING.md`): every protocol claim in `re/*.md`
  carries an explicit confidence label (`confirmed`/`likely`/`speculative`) and a
  symbol-anchored evidence citation; `just check-evidence` lints that shape (and runs a
  verdict-overturn guard so a superseded finding cannot survive un-flagged in a sibling
  doc); `just secret-scan` blocks any leaked credential/PII.

> Citation note: this README is a skimmable entry point — follow the `re/*.md` links for
> the per-claim evidence, confidence levels, and honest limitations. (The `re/*.md`
> docs note that jadx line hints are approximate and drift between runs; the cited
> **symbol** is authoritative.)

## 6. Optional: inject a captured session (skip `auth live-login`)

`auth live-login` performs the real login. As an alternative, exactly **one** captured
session lets the client drive the read/stream path without logging in again — handy for
reusing a session or skipping a repeat login. Tracked as **TASK-0022**; the device-list
and streaming credentials all ride the authenticated session.

**What one capture yields.** A single authorized extraction from the genuine app on the
owner's own device provides a live session token — the `sid` (plus `uid` and the
resolved `User.domain.mobileApiUrl`). The `sid` is the bearer for every subsequent atop
call **and** for the MQTT broker connection that carries the WebRTC 302 signaling, so it
is enough to drive the full read/stream path (device-list → camera-config → MQTT
signaling).

**How to use a captured `sid` with the client.** The client persists a session as JSON
(`sid`, `uid`, `mobile_api_base`, `expires_at`) in the on-disk **session store** — the
same file `auth status` reads. To validate the full chain end-to-end:

1. Find the store path:
   `nix-shell --run 'just run -- auth status'` prints `store: <path>` (the
   `SessionStore::default_path()` location under your data dir).
2. Write the captured session into that file as the `Session` JSON shape
   (`babymonitor-core` `session::Session`: `sid` / `uid` / `mobile_api_base` =
   `User.domain.mobileApiUrl` / `expires_at`). Treat `sid`/`uid` as **secrets** — they
   are account-linked PII; keep them in `secrets/` and never commit them. (A small
   `session::SessionStore::save` helper is the library entry point; there is no
   plaintext-`sid` CLI flag by design, to avoid `sid` landing in shell history.)
3. Confirm it is loaded: `nix-shell --run 'just run -- auth status'` now reports a
   stored session (with `sid`/`uid` redacted) and its `mobile_api_base`.
4. Drive the **read path** against the real account using the gated live build —
   `devices list --live` is the injected-session consumer (TASK-0055):

   ```sh
   nix-shell --run 'cargo run --manifest-path babymonitor/Cargo.toml --features live \
       --bin babymonitor-cli -- devices list --live'
   ```

   With a session in the store this **loads the injected `sid`**, builds a
   byte-faithful signed `device.list` atop request carrying that `sid` (folded into
   the envelope BEFORE signing, so it enters the canonical sign string — `sid` is in
   the sign whitelist, `re/tuya_cloud_auth.md` §3a), and sends ONE call. It reports
   SHAPE only (`camera_found`, `p2p_type`); the raw response is captured to
   gitignored `secrets/`. With NO session injected (or in the default non-`live`
   build) it reports the honest no-session/non-live state and touches no network.
   The wiring is proven by the offline test
   `injected_sid_rides_device_list_envelope_and_canonical_sign`
   (`babymonitor-cli/src/live.rs`), which asserts the injected `sid` rides the wire
   envelope AND the canonical sign string with no network call.
5. Continue the chain (per-camera `p2pType` → the MQTT **302** signaling → WebRTC)
   once a real `device.list` returns: the `#[ignore]`d live gold-oracle test
   (`babymonitor-cli/tests/live_e2e.rs`) is the assertion harness for the full
   stream run; it checks **shape only** (a camera is found, transport is WebRTC) and
   never prints a `sid`/`uid`/device id.

Either path — a fresh `auth live-login` or an injected `sid` — reaches the same place:
the read/stream chain running against the real account, with every `sid`/`uid`/device
id kept out of stdout and the repo.

## License

**MIT** — see the top-level [`LICENSE`](LICENSE) file. The Rust workspace also declares
`license = "MIT"` in `babymonitor/Cargo.toml`.
