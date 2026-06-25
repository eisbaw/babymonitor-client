# Live Tuya login — AUTHORIZED one-time run + signer-validation outcome (TASK-0042)

The AUTHORIZED one-time live login against the REAL Tuya/thingclips atop cloud
with the account owner's real credentials, to VALIDATE the recovered signer (the
`bmp_token` candidate + the cmd=1 MD5 fold) and, on success, capture the
device-list + signaling.

**No secret values appear in this file.** Credentials live only in
`secrets/tuya_login.json`; appKey/appSecret/cert-hash only in
`secrets/tuya_appkey.json`; the bmp_token candidate only in
`secrets/bmp_token.txt`; the raw live request/response capture only in
`secrets/tuya_live_debug.json` (all gitignored). This doc records METHOD and
OUTCOME, never a value.

> Citation note (symbol-anchored): jadx paths are `decompiled/jadx/sources/...`;
> line hints drift between runs — grep the symbol. A cross-`.md` reference is a
> navigation pointer, not an independent source.

---

## Final wire-fidelity probe — every static field matched, still rejected (TASK-0051) (confidence: confirmed)

**The last two statically-derivable wire differences between our `token.get` and
the real app were closed, and the gateway STILL returns the identical
`ILLEGAL_CLIENT_ID`. The static cloud-login avenue is now AIRTIGHT-EXHAUSTED.**

The post-0050 architect request-shape sweep found exactly TWO remaining
statically-derivable differences; both were judged very unlikely to move a
sign-insensitive reject, but were closed to remove the last wire-level doubt:

1. **`x-client-trace-id` request HEADER** = `requestId` — the app adds it
   unconditionally (`OKHttpBusinessRequest.java`: `CLIENT_TRACE_ID =
   "x-client-trace-id"` @:23, `addHeader(CLIENT_TRACE_ID, getRequestId())` @:342).
   Our CLI omitted it; now `send_atop` adds it, reusing the `requestId` already in
   the signed envelope. It is a header, not a signed param.
2. **`deviceId` in the POST BODY** — the app's `ApiParams.getRequestBody()` puts
   `KEY_DEVICEID="deviceId"` into the request body (`ApiParams.java`:87-89), in
   addition to the signed query (`ApiParams.java`:227, which we already sent).
   Now added to the form body too. `deviceId` is a `SIGN_WHITELIST` param signed
   from the envelope map, so the canonical sign string is UNCHANGED.

Both land in the single `send_atop` path
(`babymonitor/babymonitor-cli/src/live.rs`). EXACTLY ONE signed `token.get` was
then fired against `a1.tuyaeu.com` (`--probe-only --host a1.tuyaeu.com`, no
`--corrupt-sign`, no `password.login`):

| probe | wire delta vs 0050 | HTTP | errorCode | errorMsg |
|---|---|---|---|---|
| TASK-0051 (`--probe-only`) | +`x-client-trace-id` header, +body `deviceId` | 200 | `ILLEGAL_CLIENT_ID` | `Invalid client;No access` |

(raw capture in gitignored `secrets/tuya_live_debug.json`; the captured
`request_param_keys` confirm `deviceId`+`requestId` in the envelope — the body
`deviceId` and header are added downstream in `send_atop`.)

**Probe budget:** exactly **1** signed `token.get` (this task). ZERO
`password.login` (across ALL cycles). 2FA NOT reached. Not `Accepted`.

**Verdict (confidence: confirmed):** the reject is unchanged. Combined with the
TASK-0050 corrupted-sign differential (the reject is sign-INSENSITIVE / returned
BEFORE sign-verification) and the TASK-0048 host re-sweep (every EU-family gateway
rejects), EVERY statically-derivable identity field, header, host, and the sign
itself have now been matched to the app, and the public atop gateway STILL returns
`ILLEGAL_CLIENT_ID`. The blocker is therefore a server-side identity/provisioning
gate (app-attestation / app-cert-pin / appKey↔package binding) that a standalone
static client cannot reproduce from the recovered material alone. The static
cloud-login avenue is exhausted; unblocking now requires on-device evidence
(Frida/proxy capture of a real app request, TASK-0022) or additional material
from the owner — NOT another static field to add.

---

## Corrupted-sign differential — `ILLEGAL_CLIENT_ID` is sign-INSENSITIVE (TASK-0050) (confidence: confirmed)

**The decisive test ran. `ILLEGAL_CLIENT_ID` is returned BEFORE the gateway
evaluates our `sign` — proven, no longer server-opaque.** This promotes the
"identity-layer code, returned upstream of sign-verification" claim from a
server-opaque assertion to a **confirmed** one, via a controlled differential.

Method (`babymonitor/babymonitor-cli/src/live.rs` `run_token_get_probe` +
`corrupt_one_nibble`, behind `--features live`): build the fully-signed
`token.get` envelope, then send it twice to the SAME host (`a1.tuyaeu.com`),
byte-identical EXCEPT the `sign` value, which the second probe corrupts by
flipping exactly one hex nibble (so the signature is well-formed — 32-char
lowercase hex — and the gateway parses it and would reach sign-verification, but
the signature itself is now wrong):

| probe | sign | HTTP | errorCode | errorMsg |
|---|---|---|---|---|
| 1 (`--probe-only`) | our candidate sign | 200 | `ILLEGAL_CLIENT_ID` | `Invalid client;No access` |
| 2 (`--probe-only --corrupt-sign`) | one nibble flipped | 200 | `ILLEGAL_CLIENT_ID` | `Invalid client;No access` |

The two responses are **byte-for-byte identical** (raw bodies + request param
keys compared, gitignored `secrets/tuya_live_debug_probe1_candidate.json` vs
`secrets/tuya_live_debug.json`). A WRONG signature changes NOTHING about the
response ⇒ the reject is **sign-insensitive** ⇒ the gateway rejects on **client
identity** before it ever reads/evaluates the `sign`. **Confidence `confirmed`:**
this is a controlled A/B differential (the corrupted variant is the negative
control), not a single opaque capture — two independent observations whose only
difference (the sign) provably does not move the result.

**Probe budget:** exactly **2** signed `token.get` calls (the differential pair).
ZERO `password.login` (across ALL cycles). 2FA NOT reached. Neither probe was
`Accepted` (the sign oracle is still unreachable — by design, because the
identity gate short-circuits before sign-verify).

**Two honest consequences (do not overclaim):**
1. The identity/provisioning gate (app-attestation / app-cert-pin / server-side
   appKey↔package binding) is now the CONFIRMED blocker for `token.get` — a
   standalone static client cannot clear it from the recovered material alone.
   This UNBLOCKS the TASK-0049 decision (on-device capture vs accept-block): the
   "wrong sign" alternative is now ruled OUT for THIS error.
2. This does **NOT** validate the `bmp_token` candidate or the MD5 fold — the
   server still never judged our signature (it short-circuits before that). But
   it DOES prove the `bmp_token`/fold is **not** what is blocking `token.get`:
   even a deliberately-broken sign yields the identical reject. So re-attacking
   the `bmp_token` decode would NOT clear `ILLEGAL_CLIENT_ID`; the sign oracle
   only becomes reachable once the identity gate is passed (then a corrupted vs
   correct sign WOULD diverge, finally validating the fold).

## Outcome (confidence: likely — SUPERSEDED on the "server-opaque" point by TASK-0050 above)

**The live sign oracle remains UNREACHABLE: with the chKey-corrected request the
public atop gateway STILL rejected our `token.get` with `ILLEGAL_CLIENT_ID`
("Invalid client;No access", HTTP 200, `success=false`, no `result`) — the SAME
client-identity / provisioning rejection as the pre-chKey attempt.** Whether this
is returned strictly BEFORE the gateway evaluates our `sign` ~~is a **server-opaque**
assertion we cannot prove from the capture~~ **is now CONFIRMED returned BEFORE
sign-verification by the TASK-0050 corrupted-sign differential above**:
`ILLEGAL_CLIENT_ID` is an identity-layer code. The `token.get` SIGN was neither explicitly accepted nor
explicitly rejected by a sign-error code, so the `bmp_token` candidate + MD5 fold
are STILL NEITHER validated NOR refuted. `password.login` was NOT attempted (zero
lockout-sensitive calls consumed across BOTH cycles); 2FA was NOT reached.

> **Wave-3 RESULT (TASK-0044 → TASK-0042 single re-attempt):** the recovered
> `chKey` (native getChKey@0x16000 = HMAC-SHA256(appId, packageName_"_"_certHex),
> STATIC — `re/chkey_static.md`) + the SDK-fidelity params (`channel`,
> `sdkVersion`, `deviceCoreVersion`, `osSystem`, `platform`, `timeZoneId`,
> `bizData`, `cp=gzip`) were added to the live request and the corrected request
> was sent ONCE. The captured request param-keys (`secrets/tuya_live_debug.json`)
> confirm `chKey`, `clientId`, `time`, `sign`, and every SDK-fidelity param rode
> the wire, and `chKey` is signed (it is in `SIGN_WHITELIST`). **chKey did NOT
> clear `ILLEGAL_CLIENT_ID`** — so chKey/the SDK-fidelity params were not the
> (sole) gate. Remaining live hypotheses (server-opaque): (a) a provisioning /
> app-cert-pin / app-attestation identity gate a standalone client cannot
> reproduce; (b) a still-wrong `chKey` (the §3a key/msg ordering is single-source)
> or an un-modelled signed identity input. The owner decides next (provide more
> material / authorize broader on-device capture, e.g. a Frida `getChKey` /
> request hook on the authorized device).

> **Regions/host note (TASK-0043):** the runtime `getConfig` native host-decrypt
> hypothesis (§"Likely cause") is SUPERSEDED — the `thing_domains_v1/regions`
> blob is decryptable offline by a **pure-Java AES-256-CTR** path, see
> `re/regions_decrypt.md`. So the correct datacenter `mobileApiUrl` is now
> recoverable without the device, removing one of the two unblock paths below.

Grounded by the single captured server response
(`secrets/tuya_live_debug.json`: `success=false`, `errorCode=ILLEGAL_CLIENT_ID`,
`errorMsg="Invalid client;No access"`, HTTP 200) — labelled `likely` because it
is ONE live capture (one source). The request-builder + guardrail logic that
classifies this as a non-sign `Server` error → STOP before `password.login`
(never a `SignRejected`) lives in
`babymonitor/babymonitor-cli/src/live.rs` (`do_token_get`/`classify_error`). The
error is a Tuya **identity/provisioning** rejection, distinct from the
sign-failure family this run was built to detect.

Honest consequence: this is **NOT** the "candidate/fold is wrong" result (that
would require the server to evaluate and reject our `sign`). It is a **routing /
appKey-provisioning** blocker upstream of signature verification. The signer's
own pipeline (cert-hash + bmp_token + appSecret + MD5 fold + canonical string)
was exercised and produced a `sign`, but the server never judged it.

## What was attempted (confidence: confirmed)

The flow implemented (`babymonitor/babymonitor-cli/src/live.rs`, behind the
gated `live` Cargo feature; `babymonitor/babymonitor-cli/Cargo.toml` `[features]
live`) and the calls actually made:

1. Load secrets + compute the app-cert SHA-256 OFFLINE from the APK
   (`app_cert_sha256_hex_from_apk`, `babymonitor/babymonitor-core/src/sign.rs`).
2. Non-account host reachability probe (TLS GET to the gateway root) — confirmed
   `a1.tuyaeu.com` reachable (HTTP 200, TLS verified) BEFORE any signed call.
3. Build + sign + send `thing.m.user.username.token.get` (→ wire
   `smartlife.m.user.username.token.get`), `sessionRequire=false`, fold =
   `MD5(key||canonical)` (the most-likely cmd=1 fold, `re/tuya_sign_static.md`
   §7). Result on every host tried: `ILLEGAL_CLIENT_ID`.

Hosts probed at the token.get layer (a few minimal, network-level routing
attempts — NOT login attempts; the guardrail permits cautious `token.get`
iteration): `a1.tuyaeu.com` (EU, the documented default), `a1.tuyaus.com` (US,
in case of cross-region provisioning) — both `ILLEGAL_CLIENT_ID`; `m1.tuyaeu.com`
is the MQTT/media host and does not serve `/api.json` (connection refused, as
expected — it is not the atop API host). A retry on `a1.tuyaeu.com` with the
SDK-correct `User-Agent` (`Thing-UA=APP/Android/<appVersion>/SDK/<sdkVersion>`,
`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingSmartNetWork.java`
`USER_AGENT` ~:78 + append ~:3897) also returned `ILLEGAL_CLIENT_ID` — so the UA
is not the gate. Iteration STOPPED there per the "a few calls max" guardrail.

## Host-family re-sweep (TASK-0048) (confidence: likely)

The TASK-0046 review gate caught a host false-exhaustion: only the legacy
`tuya*.com` `mobileApiUrl` family had been probed. The decrypted EU regionConfig
(`re/regions_decrypt.md`) exposes un-tried EU-family gateways — most notably the
newer **iotbing** ("bing"/Smart-Life) cloud, where a correct appKey can be
provisioned while the legacy `a1.tuyaeu.com` gateway returns `ILLEGAL_CLIENT_ID`.
TASK-0048 probes the four ranked un-tried hosts with EXACTLY ONE read-only
`token.get` each (no `password.login`, no retry). A DIFFERENT error than
`ILLEGAL_CLIENT_ID` (e.g. a sign error or a different routing code) is INFORMATIVE
— it would mean the host accepted our client identity and reached signature /
next stage, finally making the sign oracle reachable.

Outcome per host (METHOD + OUTCOME only; no secret values; raw capture in the
gitignored `secrets/tuya_live_debug.json`). Probed via
`auth live-login --probe-only --host <h>` (the new guardrail-faithful path:
ONE signed `token.get` to `/api.json`, then STOP — never `password.login`):

| rank | host (source field) | method | HTTP status | errorCode | classification |
|---|---|---|---|---|---|
| 1 | `apigw-eu.iotbing.com` (EU fusionUrl) | POST `/api.json`, 1× signed `token.get` | 200 | `ILLEGAL_CLIENT_ID` | same identity rejection (NOT cleared) |
| 2 | `a1-us.iotbing.com` (AZ mobileApiUrl) | POST `/api.json`, 1× signed `token.get` | 200 | `ILLEGAL_CLIENT_ID` | same identity rejection (NOT cleared) |
| 3 | `px.tuyaeu.com` (EU pxApiUrl) | pre-account TLS reachability probe | — (DNS NXDOMAIN) | — (no call sent) | not a public atop host — hostname does not resolve; regionConfig lists it as `http://…:80`, not an HTTPS atop API host |
| 4 | `a3.tuyaeu.com` (EU deviceHttpsPskUrl) | pre-account TLS reachability probe | — (TLS/connect fail) | — (no call sent) | not a public mobile-atop host — it is the device **HTTPS-PSK** endpoint (PSK ciphers), does not serve a cert-based `/api.json` GET; no token.get sent |

**Probe budget:** exactly **2** signed `token.get` calls were spent (hosts 1+2,
the two reachable atop-capable gateways). Hosts 3+4 were stopped by the
pre-account TLS-reachability gate, so NO `token.get` was sent to them (token
budget preserved). ZERO `password.login` calls (across all cycles). 2FA NOT
reached.

**Verdict (confidence: likely — one live capture per host):** the static host
avenue is now GENUINELY EXHAUSTED for the recovered identity. Both reachable
EU-family iotbing gateways (`apigw-eu.iotbing.com`, `a1-us.iotbing.com`) return
the SAME `ILLEGAL_CLIENT_ID` as the legacy `a1.tuyaeu.com`/`a1.tuyaus.com`, with
the corrected app-faithful envelope (wire `ttid=sdk_international@<appKey>`,
`channel=oem`, `appRnVersion=5.92`, full `initUrlParams` shape). `px.tuyaeu.com`
and `a3.tuyaeu.com` are not public mobile-atop API gateways (px does not resolve;
a3 is HTTPS-PSK), so they are not valid `token.get` targets. No host in the
decrypted EU regionConfig clears the rejection. `ILLEGAL_CLIENT_ID` is therefore
NOT a wrong-datacenter-host problem — it is an identity/provisioning gate
(app-attestation / app-cert-pin / a server-side appKey↔package binding) that a
standalone client cannot reproduce from static material alone. The sign oracle
remains unreachable; the `bmp_token` candidate + MD5 fold stay un-validated.

## Validation outcome — signer (confidence: likely)

**Signer validated? NO — the differential could not be taken.** The gold
differential (server ACCEPTS our signed `token.get`) requires the gateway to
reach signature verification; `ILLEGAL_CLIENT_ID` short-circuits before that. So
the bmp_token candidate (`secrets/bmp_token.txt`, the integral-solve result of
TASK-0032) and the MD5 fold remain **un-validated** — this run is silent on their
correctness.

Basis (single live capture → `likely`): the captured response
(`secrets/tuya_live_debug.json`) shows an identity-layer rejection, and the
classification logic (`babymonitor/babymonitor-cli/src/live.rs` `classify_error`
/ `do_token_get`) routes a non-sign server error to STOP without claiming
validation — matching the AC#1/AC#2 honesty requirement (no fabricated
"validated").

## MD5 fold resolved (confidence: likely)

**Not resolved by this run.** The fold disambiguation (`MD5(key)` vs
`MD5(key||canonical)`, `re/tuya_sign_static.md` §7) also needs a server that
evaluates the sign. The first (and only) fold tried was the most-likely
`MD5(key||canonical)` (`SignBody::KeyAndCanonical`, the default —
`babymonitor/babymonitor-core/src/sign.rs` `SignBody`), chosen because the native
cmd=1 key-builder calls MD5 twice
(`decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java`, the cmd=1
sign caller; native detail in `re/tuya_sign_static.md` §7). Because the server
never judged the sign (see `secrets/tuya_live_debug.json`), the fold remains
`likely`, not `confirmed`.

## Whitelist correction shipped (confidence: confirmed)

Two signer-whitelist entries were corrected against the recovered whitelist
during this task (load-bearing for a server-accepted sign, independent of the
gateway-routing blocker): `appId` → **`clientId`** and `t` → **`time`**. With the
old `appId`/`t`, the appKey and timestamp envelope params (keyed `clientId`/`time`
on the wire) were DROPPED from the canonical string → a wrong `sign`. Two
independent decompiled sources: the recovered whitelist field
`ThingApiSignManager.bdpdqbp`
(`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java`,
listing `clientId`/`time`) and the envelope param keys
`ThingApiParams.KEY_APP_ID`→wire `clientId` / `KEY_TIMESTAMP="time"`
(`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java`).
Fixed in `babymonitor/babymonitor-core/src/sign.rs` `SIGN_WHITELIST`.

## Likely cause + next step (confidence: speculative)

Hypothesis (NOT validated — labelled speculative): the recovered appKey
(in `secrets/tuya_appkey.json`, value/format withheld) is provisioned for a
**region-config-decrypted datacenter host**, not the legacy public
`a1.tuya{eu,us}.com` atop gateway. The candidate datacenter hosts ship
**encrypted** in `assets/thing_domains_v1/regions` and are decrypted at runtime
by native `SecureNativeApi.getConfig` (`re/tuya_cloud_config.md`), so the correct
gateway host is not the legacy default and was not decrypted here. Alternatively
the public gateway requires an additional provisioning param/header the legacy
atop envelope omits.

Next step to unblock (either is sufficient): (a) decrypt the
`thing_domains_v1/regions` blob (port native `getConfig`) to obtain the appKey's
real datacenter `mobileApiUrl`, then re-run the ONE `token.get` against it; or (b)
capture ONE real request from the app on the owner's device (Frida/proxy,
TASK-0022) to read the exact host + any missing provisioning field. Only once the
gateway reaches signature verification can the bmp_token + fold be validated (the
`password.login` step remains untouched and un-risked until then).
