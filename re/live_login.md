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

## Outcome (confidence: likely)

**The live sign oracle was UNREACHABLE: the public atop gateway rejected our
request with `ILLEGAL_CLIENT_ID` ("Invalid client; No access") at the
client-identity layer, BEFORE evaluating our `sign`. The `token.get` SIGN was
therefore neither accepted nor rejected, so the `bmp_token` candidate + MD5 fold
are NEITHER validated NOR refuted by this run.** `password.login` was NOT
attempted (zero lockout-sensitive calls consumed); 2FA was NOT reached.

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
