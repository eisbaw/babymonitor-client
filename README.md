# Philips Avent Baby Monitor+ — static RE to a Rust client

Reverse-engineering the Android app **`com.philips.ph.babymonitorplus`** (Philips
Avent "Baby Monitor+", hardware **SCD921 / SCD923**) deeply enough to reimplement a
software second-screen client in Rust — focused on the two hardest parts: the **live
video/audio stream** and the **account/device authentication**.

**Status:** the pure-static reverse engineering is **complete**; the protocol is
mapped end-to-end and a tested Rust client is built against it. **Actually viewing
the baby is blocked on a single live capture that this project deliberately excludes**
(static analysis only) — see [the blocker](#3-the-honest-blocker-the-runtime-bmp_token-confirmed-in-ghidra)
below. The Rust client therefore **cannot log in or stream today** and says so
honestly everywhere — it never fabricates a session or a frame.

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
- The media path is largely **standard WebRTC** (SDP, trickle-ICE, **DTLS-SRTP** via a
  bundled mbedTLS), which maps onto `webrtc-rs` + `rumqttc`.
- One Tuya-custom twist: the SDP carries an extra `m=application` section with an
  **`a=aes-key:<hex>` line that conveys the media AES key in the SDP itself** (not a
  DTLS exporter). The 302 payload is itself AES-encrypted with the device `localKey`
  (AES-128/ECB/PKCS5, recovered and KAT-tested).

The recovered shape matches independent public Tuya WebRTC projects
(`seydx/tuya-ipc-terminal`, `tuya/webrtc-demo-go`) field-for-field. The transport is
**implementable given the runtime-gated per-session inputs**; the residual that only a
live capture closes is the actual `a=aes-key` value + the negotiated SDP bytes
(`re/webrtc_session.md` §9).

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
SHA-256 (computable **offline** from the APK signing cert — no device). See
`re/tuya_sign_static.md` and `re/review_gate_findings.md` (F1). Cloud-auth envelope,
login flow, and device/camera bean shapes are in `re/tuya_cloud_auth.md`; first-time
pairing in `re/pairing_flow.md` (and the decisive note: an **already-paired** camera
needs no pairing — only login + device-list + camera-config).

## 3. The honest blocker: the runtime `bmp_token` (confirmed in Ghidra)

The **sixth ingredient — `bmp_token`** — is the one that does **not** yield to pure
static analysis.

`bmp_token` is decoded from the embedded `assets/t_s.bmp` by an **imath-bignum +
Vandermonde-matrix** routine in `libthing_security_algorithm.so`. The matrix algorithm
**has been ported byte-exact** (Ghidra-primary, radare2-confirmed, with unit tests).
**But** the Ghidra decompilation revealed that the decode also keys off a `config`
input that is a **runtime JNI `byte[]` SDK-config blob** (`doCommandNative`'s
`param_6`, read via `GetByteArrayElements`) — **not a static asset**. That config
selects the pixel offset and the header-validity branch, and for arbitrary/static
config strings the validator rejects. So the **production token is not computable under
static analysis alone**. See `re/bmp_token_whitebox.md` §9 (the Ghidra port + the
runtime-config finding) and `re/tuya_sign_static.md`.

**What ONE live artifact would unblock it** (both excluded here by the static-only
constraint):

1. a **single accepted live sign vector** (pins the token in one place, end-to-end), or
2. a **one-time runtime-config dump** (the `byte[]` SDK-config that `doCommandNative`
   is called with).

Either closes the gap. No static oracle exists in the binary (there is no embedded test
vector), so a self-derived token is unverifiable — this is the central, reviewer-confirmed
constraint of the whole project.

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

It is **complete and token-injectable but CANNOT yet log in or stream**: the signer is
token-pending (see §3), so `auth login` and any live fetch **honestly report the
token-pending state** rather than fabricate a session. The live end-to-end test exists
but is `#[ignore]`d and asserts the honest pending state today.

Build and run (from the repo root, inside the nix shell):

```sh
nix-shell --run 'just build'                      # compile the workspace
nix-shell --run 'just e2e'                         # build + test + clippy -D + fmt-check + stub-grep + offline checks
nix-shell --run 'just run -- auth login'           # shows the honest token-pending state
nix-shell --run 'just run -- devices list'         # works against a synthetic fixture
nix-shell --run 'just showcase'                    # run every read-only CLI command (regression tripwire)
```

## 5. Methodology + constraint

**Static analysis only** — no Frida, no rooted device, no emulator, no live packet
capture (`re/prd.md`). The consequence is that the live protocol is reconstructed from
decompiled Java/Kotlin **and** native libraries.

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

## License

The Rust workspace declares **MIT** (`babymonitor/Cargo.toml`). There is **no top-level
`LICENSE` file yet** — add one before any public distribution.
