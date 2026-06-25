# Philips Avent Baby Monitor+ — static RE to a Rust client

Reverse-engineering the Android app **`com.philips.ph.babymonitorplus`** (Philips
Avent "Baby Monitor+", hardware **SCD921 / SCD923**) deeply enough to reimplement a
software second-screen client in Rust — focused on the two hardest parts: the **live
video/audio stream** and the **account/device authentication**.

**Current auth correction (2026-06-25):** the earlier "pure-static auth is
exhausted / proven identity gate" conclusion is now **superseded**. A fresh static
review found that the Rust live client did **not** match the APK's login request
shape: the app posts all signed params in the form body, encrypts `postData` with
ET=3 AES-GCM before signing, uses epoch-second `time`, and uses UUID-shaped
`requestId`. The Rust live path has been corrected to build that Java-shaped
request. A fresh guarded live `token.get` probe is still pending, so do not treat the
older TASK-0050/0051 `ILLEGAL_CLIENT_ID` differential as proof of an app-attestation
wall.

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

## 3. Current auth status: APK-shaped static login pending fresh probe

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

What is still known:

1. The appKey is the real provisioned identity, not a demo key (TASK-0046,
   `re/identity_enumeration.md`).
2. Region hosts have been broadly enumerated (TASK-0048, `re/regions_decrypt.md`).
3. The current Rust live builder now mirrors the APK's form-body/encrypted-postData
   path and needs one fresh guarded `token.get` probe before login can be called
   open or blocked.

### What remains blocked without auth: the whole live stream

This is **not** "you cannot log in but could still stream." There is **no working
video until the client has an authenticated session:

- The video transport is **cloud-brokered WebRTC-over-MQTT**: the 302 signaling
  envelope rides Tuya's MQTT brokers (`User.domain.mobile*MqttUrl`,
  `re/tuya_cloud_auth.md` §4), and connecting to those brokers needs the
  **authenticated session** (`sid`) that the blocked login issues. No session ⇒ no
  MQTT signaling ⇒ no WebRTC offer/answer ⇒ no frames.
- The **LAN path (Tuya local protocol, TCP port 6668) is datapoint-only** — it
  carries device datapoints (DPs), **not** an A/V media stream. It is not an
  alternative way to view the camera.

So either a working APK-shaped login or an injected captured session is a hard
prerequisite for the project's actual goal (seeing the baby), not merely for a green
`auth status`.

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

It is **complete and token-injectable**, and the live login request shape has now been
corrected, but it still needs a fresh guarded live probe before we can claim login
works. `auth login` is an offline status command; `auth live-login` is the gated
network path. The session-token slot is **injectable, and the consumer is wired**:
`devices list --live` (gated `--features live`, TASK-0055) **loads an injected `sid`**
from the on-disk session store and drives a byte-faithful, signed `device.list`
request with it. With no session injected it reports the no-session state honestly.
The wiring is test-backed offline
(`injected_sid_rides_device_list_envelope_and_canonical_sign`, no network), and the
`#[ignore]`d live end-to-end test asserts the honest pending state for the full
stream. So given one captured live `sid` (§6), or a successful fresh `auth live-login`,
the read path can run for real.

Build and run (from the repo root, inside the nix shell):

```sh
nix-shell --run 'just build'                      # compile the workspace
nix-shell --run 'just e2e'                         # build + test + clippy -D + fmt-check + stub-grep + offline checks
nix-shell --run 'just run -- auth login'        # offline status; no fabricated session
nix-shell --run 'just run -- auth status'       # reads/clears the on-disk session store (offline)
nix-shell --run 'just run -- devices list'      # works against a synthetic fixture
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

## 6. Alternate unblock: one injected session

A fresh APK-shaped login probe is the direct static path. Separately, exactly **one**
captured session converts the tested client from "token-injectable" to "can drive the
read path" without solving login first. This is tracked as **TASK-0022** and remains
useful because the device-list and streaming credentials ride the authenticated
session.

**What one capture yields.** A single authorized extraction from the genuine app on
the owner's own device can provide:

1. **A live session token** — the `sid` (plus `uid` and the resolved
   `User.domain.mobileApiUrl`) issued by a real login. The `sid` is the bearer for
   every subsequent atop call **and** for the MQTT broker connection that carries the
   WebRTC 302 signaling.
2. If the fresh APK-shaped static probe still fails, any extra app/runtime identity
   element the genuine app presents can be compared against the static request.

A captured `sid` is enough to drive the **read path** (device-list → camera-config →
MQTT signaling) without solving login first, because the client's session slot is
injectable.

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

This is the honest seam: the static work is complete up to the server-side identity
binding, and a single owned-device capture closes it — no further reverse engineering
required, only evidence this project chose not to collect.

## License

The Rust workspace declares **MIT** (`babymonitor/Cargo.toml`). There is **no top-level
`LICENSE` file yet** — add one before any public distribution.
