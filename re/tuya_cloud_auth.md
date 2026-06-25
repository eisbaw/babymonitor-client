# Tuya Cloud Auth + Device-Binding API map (TASK-0007)

Static model of the **Tuya mobile-app ("atop") cloud API** that
`com.philips.ph.babymonitorplus` uses for account login, session/token issuance,
datacenter selection, and the device-list / camera-record shape. This is the
protocol contract the Rust auth crate (TASK-0012) and device models (TASK-0013)
implement against.

**Scope/relationship to siblings.** This doc builds ON the signing scheme — it does
NOT re-derive it. The request-signing algorithm (param canonicalization, `||`
join, postData-MD5+swap, native keyed `sign`, key derivation) lives in
[`re/tuya_sign.md`](tuya_sign.md); datacenter encrypted-blob mechanics in
[`re/tuya_cloud_config.md`](tuya_cloud_config.md); corrected targets F1/F5 in
[`re/review_gate_findings.md`](review_gate_findings.md). Read those first.

**No secret values appear in this file.** Recovered appKey/appSecret/TTID live ONLY
in `secrets/tuya_appkey.json` (gitignored); this doc records *location + method*.
Any JSON field that carries a per-device or per-account secret is flagged
explicitly (see the secret table) and anonymized before it may enter a committed
fixture, per CLAUDE.md.

> Citation note (symbol-anchored — TASK-0024): cites name a **symbol**
> (class/method/field/string-constant); any `decompiled/jadx/sources/...File.java`
> path + `~:NN` line number is an **approximate hint** for the current `just
> decompile` tree, NOT an authority. **jadx line numbers drift between runs**, so
> the symbol is what to grep for (`rg 'class Foo|methodName|fieldName'`); the `~:`
> hint is "about here" in the jadx 1.5.0 `-Xmx12g --no-debug-info` output recorded
> in `re/decompile_dex.md`. The DEX is **R8-obfuscated**: many API-name string
> constants are runtime-deobfuscated to a placeholder `n`, so some exact wire
> action names are only confirmable live (flagged inline).

---

## 0. TL;DR contract (confidence: confirmed)

Two independent sources ground the overall shape: the decompiled user-API table
class `pqdbppq` (`decompiled/jadx/sources/com/thingclips/sdk/user/pqdbppq.java`,
the literal `thing.m.user.*` action string-constants, e.g. `dbppbbp =
"thing.m.user.username.token.get"` ~:52) AND the public mobile-SDK write-up
`nalajcie/tuya-sign-hacking` (review-gate F1, `re/review_gate_findings.md`),
which documents the same atop gateway + `a/v/t/sid/sign` envelope.

- **Gateway:** Tuya mobile-app "atop" API gateway (`a.*`/`api.*` family), driven by
  `apiRequestByAtop(api, version, postData)`. NOT Tuya OpenAPI (no
  `client_id`/`access_token`). Base host is **runtime-resolved per region**.
- **Login is a 2-step ticket flow:** (1) `thing.m.user.username.token.get` returns a
  `TokenBean` (RSA pubkey + `token`/ticket); (2) `thing.m.user.email.password.login`
  (or `.mobile.passwd.login` / uid variants) submits the RSA-encrypted password +
  that `token`, and returns a `User` (carrying `sid`, `uid`, `ecode`, `domain`).
- **Session token = `sid`** (issued in the login `User`). No OAuth refresh-token
  rotation in the mobile flow; on session-invalid the client RE-LOGINS.
- **Datacenter = `User.domain.*Url`** returned by the login response (F5), not a
  static asset host.
- **Device list = `HomeBean.deviceList`** (list of `DeviceBean`); the camera P2P
  credentials come from a per-device **CameraInfoBean** config fetch.

---

## 1. Request envelope (atop gateway) (confidence: confirmed)

Two independent sources: the `ThingApiParams.KEY_*` param-key string-constants +
the `ThingApiParams.initUrlParams` body
(`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java`;
`KEY_API="a"` ~:33, `initUrlParams` ~:1771) AND the JS-bridge atop entry
`TUNIAPIRequestManager.apiRequestByAtop`
(`decompiled/jadx/sources/com/thingclips/smart/plugin/tuniapirequestmanager/TUNIAPIRequestManager.java`
~:161; takes `api`, `version`, `postData`). These agree on the same gateway, so it
is `confirmed`.

A request is a set of **URL/GET params** (the signed envelope) plus a **`postData`**
body. The envelope keys (constant → wire name) are:

| Wire param | Const (`ThingApiParams`) | Value / source | Notes |
|---|---|---|---|
All cells below cite symbols in
`ThingApiParams.java`/`LoginBusiness.java`/`ApiParams.java`; `~:NN` line hints are
approximate (jadx-run-dependent) — grep the symbol name.

| Wire param | Const (`ThingApiParams`) | Value / source | Notes |
|---|---|---|---|
| `a` | `KEY_API` (~:33) | the action name (e.g. `thing.m.user.email.password.login`) | rewritten `thing*`→`smartlife*` on wire by `ThingApiParams.checkAPIName()` (~:192) — see §1a |
| `v` | `KEY_VERSION` | per-call version string (e.g. `"1.0"`,`"4.0"`) | from the `ApiParams` ctor |
| `t` / `time` | `KEY_TIMESTAMP="time"` | server-synced epoch (`TimeStampManager.getCurrentTimeStamp()`) | added in the body path, `ThingApiParams.java` `KEY_TIMESTAMP` put ~:1408 |
| `sid` | `KEY_SESSION="sid"` | the session token (empty pre-login) | injected from `IBaseUser.getSid()` (`ApiParams.getSession`) |
| `requestId` | `KEY_REQUEST_ID` | `UUID.randomUUID()` per request | `ThingApiParams.initUrlParams`, `KEY_REQUEST_ID` put ~:1782 |
| `et` | `KEY_ET` | `"3"` (`ET_VERSION_3`, ~:31) | set in `initUrlParams` |
| `lang` | `KEY_APP_LANG` | device language | `ThingApiParams.initUrlParams` (~:1771) |
| `os` | `KEY_APP_OS` | `"Android"` | `ThingApiParams.initUrlParams` (~:1771) |
| `appVersion` | `KEY_APP_VERSION` | app version string | `ThingApiParams.initUrlParams` (~:1771) |
| `ttid` | `KEY_TTID` | rewritten `sdk_<channel>@<appKey>` form (NOT raw `philipsclnightowl`) — see §1b | `ThingApiParams.initUrlParams` (~:1771) |
| `clientId` | `KEY_APP_ID` | the appKey/appId (value in `secrets/`) | `ThingApiParams.initUrlParams` (~:1771) |
| `deviceId` | `KEY_DEVICEID` | per-install device id (`PhoneUtil.getDeviceID`) | `ApiParams.getRequestBody`/`initUrlParams` |
| `sign` | `KEY_APP_SIGN="sign"` | the keyed signature | computed last; algorithm in `re/tuya_sign.md` |
| `postData` | `KEY_POST="postData"` | JSON body (per-action fields) | folded into the sign as swapped-MD5 (`re/tuya_sign.md` §2-3) |
| `lat`/`lon` | `KEY_LAT`/`KEY_LON` | optional, only if location switch on | `ApiParams.getUrlParams` |

Defaults set in the `ThingApiParams` ctor: `sessionRequire=true`,
`locationRequire=true`, `apiVersion="*"`, `ET_VERSION="3"` (`ThingApiParams`
ctors ~:114-176). Login token-create explicitly sets `setSessionRequire(false)`
(`LoginBusiness.y(...)`, ~:903-909) because there is no sid yet.

### 1a. `thing.*` → `smartlife.*` wire rewrite (confidence: confirmed)

`ThingApiParams.checkAPIName()`
(`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java`
~:192) rewrites any `apiName` that `startsWith("thing")`: it maps the leading
`thing` token to `smartlife`. Two sources: the method body itself AND the
consistent `thing.m.*` literal table in class `pqdbppq`
(`decompiled/jadx/sources/com/thingclips/sdk/user/pqdbppq.java`). **Consequence for the Rust client:** the constants read as
`thing.m.user.*` in the DEX, but the value the signer sees / that may go on the
wire as `a=` is the `smartlife.m.user.*`-rewritten form. The exact on-wire spelling
must be confirmed against a live capture / Frida hook (TASK-0022) — flagged in §6.

---

### 1b. Wire `ttid` value: the `sdk_<channel>@<appKey>` rewrite (TASK-0047 RESOLVED) (confidence: confirmed)

The wire `ttid` the SDK sends is **`sdk_international@<appKey>`**, NOT the raw
`philipsclnightowl` ttid/scheme. This was the open question in TASK-0047 (and was
mis-traced in `re/identity_enumeration.md` §2a, now corrected). RESOLVED by a
full static dataflow trace through the production init path; ≥2 independent
methods (the `AppInitializer.d`/`j` body AND the `ThingSdk.init` overload routing
+ `initThingData`/`initialize` assignment), all jadx ground truth:

1. **Production entry** — `SmartApplication.e()`/`onCreate` calls
   `AppInitializer.d(this, appKey, appSecret, apiConfig, getString(R.string.b),
   c(this), false)`
   (`decompiled/jadx/sources/com/smart/app/SmartApplication.java:121`). Here
   `str3 = R.string.b` is the raw ttid/scheme (`philipsclnightowl`) and
   `str4 = c(this)` is the channel.
2. **The channel arg is what gets the `sdk_…@appKey` rewrite, NOT str3** —
   inside `AppInitializer.d`
   (`.../com/thingclips/smart/initializer/AppInitializer.java:317-341`):
   `GlobalConfig.d(MicroContext.b(), str4, z)` first stores the channel (so
   `GlobalConfig.b()` later returns it), then
   `if (ThingSmartNetWork.mSdk) { str4 = "sdk_" + GlobalConfig.b() + "@" + str; }`
   rewrites the **channel arg** `str4` (`:334-335`). The raw `str3`
   (philipsclnightowl) only flows to `UrlRouter.o(str3)` (`:340`) — a router
   tag, never the wire ttid.
3. **The rewritten channel lands in the ttid slot** — `d()` then calls
   `j(str=appKey, str2=appSecret, str4=rewritten, RNAPIUtil.a(), z)` (`:341`).
   In `j` (`:1247-1323`) this becomes `j`'s `str3`, passed to
   `ThingSdk.init(ctx, appKey, appSecret, str3, str4_rn, apiUrlProvider)`
   (`:1323`). That 6-arg overload
   (`decompiled/jadx/sources/com/thingclips/smart/sdk/ThingSdk.java:1152-1153`)
   forwards to `init(..., str3, CHANNEL_OEM, str4_rn, provider)` — i.e. it puts
   `str3` (the rewritten `sdk_…@appKey`) into the **ttid** position and FORCES the
   channel to `"oem"`.
4. **Assignment to `mTtid`** — `initThingData(... str3 ...)`
   (`ThingSdk.java:1512-1529`) calls
   `ThingSmartNetWork.initialize(ctx, appKey, appSecret, str3, str4, null, str5, provider)`,
   which assigns `mTtid = str3`
   (`.../ThingSmartNetWork.java:3870-3874`) and `mChannel = str4 = "oem"`
   (`:3892-3895`). `getTtid()` (`:3358`) returns `mTtid` verbatim → wire `ttid`.
5. **`<channel>` value** — `GlobalConfig.b()`
   (`.../com/thingclips/stencil/app/GlobalConfig.java:103` returns field `d`, set
   by `GlobalConfig.d(ctx,str,z)` at `:206`) = the channel `c(this)`, and
   `SmartApplication.c()` reads the `UMENG_CHANNEL` manifest meta-data =
   `"international"` (`decompiled/apktool/AndroidManifest.xml:91`). So
   `<channel> = international`.

**Net wire ttid = `sdk_international@<appKey>`; wire channel = `oem`.** Caveat
(confidence note): the trace assumes `ThingSmartNetWork.mSdk == true` — its
default initializer is `true` (`.../ThingSmartNetWork.java:103`) and no setter to
`false` is reached on the production init path; if a build flag flipped it, the
ttid would instead be the raw `philipsclnightowl` and channel the original
`international`. The `mSdk==true` default is the documented production case. The
appKey is secret, so `re/*` records only the FORM; the assembled value lives at
runtime in the live path (`babymonitor/babymonitor-cli/src/live.rs` `wire_ttid`).

---

## 2. Account LOGIN flow end-to-end (confidence: confirmed)

Two independent sources: the request-builder bodies in
`decompiled/jadx/sources/com/thingclips/smart/login/skt/business/LoginBusiness.java`
AND the action-name constants in
`decompiled/jadx/sources/com/thingclips/sdk/user/pqdbppq.java`. They name the same
endpoints, so the flow is `confirmed`.

Tuya mobile login is a **two-step ticket/token flow** (the "onTicketSuccess" step
carried forward from TASK-0005):

**Step 1 — get the login ticket + RSA key** (`LoginBusiness.y(...)`,
`decompiled/jadx/sources/com/thingclips/smart/login/skt/business/LoginBusiness.java`
~:873; the `thing.m.user.username.token.get` `ApiParams` is built ~:903):
- action `thing.m.user.username.token.get` v`2.0`; postData `countryCode`,
  `username`, `isUid` (bool); `setSessionRequire(false)`.
- returns a **`TokenBean`** (`com/thingclips/sdk/user/bean/TokenBean.java`) with
  fields `token` (the ticket), `publicKey`, `exponent`, `pExponent`. The
  `publicKey`+`exponent` are an **RSA public key** used to encrypt the password in
  step 2 (this is the `ifencrypt=1` path). This is the "ticket success" callback:
  on `TokenBean` success the UI proceeds to submit credentials.

**Step 2 — submit credentials + ticket** (credential-type-specific):
- **email + password:** `LoginBusiness.s(...)` (~:451; `ApiParams` built ~:452) → action
  `thing.m.user.email.password.login` v`GwBroadcastMonitorService.mVersion`
  (a build-version constant); postData `countryCode`, `email`, `passwd`
  (RSA-encrypted with the step-1 key when `ifencrypt`), `token` (ticket),
  `ifencrypt` (0/1), and an MFA blob `{"group":1,"mfaCode":"…"}`. Returns **`User`**.
- **mobile + password:** `LoginBusiness.r(...)` (~:423; `ApiParams` built ~:440) → action
  `thing.m.user.mobile.passwd.login` v`4.0`; postData `countryCode`, `mobile`,
  `passwd`, `token`, `ifencrypt`, MFA blob. Returns `User`.
- **email code login:** action `thing.m.user.email.code.login`
  (`pqdbppq` ~:42); **uid+password:** `thing.m.user.uid.password.login`
  (~:43); **uid token create:** `thing.m.user.uid.token.create` (~:66).

**Credential types supported** (from the action-constant table in class `pqdbppq`,
`decompiled/jadx/sources/com/thingclips/sdk/user/pqdbppq.java`; each is a named
`thing.m.user.*` string-constant, e.g. `email.code.login` ~:42,
`uid.password.login` ~:43):
email+password, email+code, mobile+password, mobile+code, uid+password,
uid+token, QR-token, SSO ticket (`thing.m.user.sso.ticket.user.get`, ~:88), and
third-party (wx/qq/facebook/twitter/google/instagram). The baby-monitor app's
primary path is **email/uid + region**, which is the `username.token.get` →
`email.password.login` pair above.

**`region` / country selection at login:** the `countryCode` postData field and
the third `ApiParams(api, ver, region)` ctor arg
(`LoginBusiness.s` ~:452; the 3-arg ctor `ThingApiParams(String,String,String)`
~:172) carry the region into the request; the response
`User.domain` pins the datacenter (§4).

### 2a. JS-bridge / RN path (confidence: confirmed)

Two sources: `TUNIAPIRequestManager.apiRequestByAtop`
(`decompiled/jadx/sources/com/thingclips/smart/plugin/tuniapirequestmanager/TUNIAPIRequestManager.java`
~:161; builds `MiniAtopApiParams(api, version, ctx)` + `setPostData(...)` ~:233)
AND the RN login manager `TUNILoginManager.onTicketSuccess`
(`decompiled/jadx/sources/com/thingclips/smart/plugin/tuniloginmanager/TUNILoginManager.java`;
carries a `TicketModel`, matching the ticket flow). The React-Native mini-apps reach the SAME atop gateway
through this bridge, so a Rust client that speaks the native atop envelope (§1)
covers both the native and RN code paths.

---

## 3. TOKEN / session model (confidence: confirmed)

Two independent sources: the `User` bean fields (class `User`,
`decompiled/jadx/sources/com/thingclips/smart/android/user/bean/User.java`)
AND the on-device persistence (class `qdddbpp`,
`decompiled/jadx/sources/com/thingclips/sdk/user/qdddbpp.java`). They agree
that the session is the `User.sid` string persisted as JSON, so this is `confirmed`.

- **Session token = `User.sid`** (`User.sid` field ~:255, getter `User.getSid()`
  ~:1297). The login response `User` also carries `uid` (~:259), `ecode` (~:242, an
  encrypt code used for some encrypted endpoints), `domain` (~:241, the datacenter
  — §4), `email` (~:243), `username` (~:263), `timezoneId`, `partnerIdentity`,
  `publicSession`. The `sid` is then injected into every subsequent request as the
  `sid` envelope param (`ApiParams.getSession` → `IBaseUser.getSid`).
- **Storage on device:** the `User` (including `sid`) is serialized to JSON and
  stored via MMKV-backed `UserPreferenceUtil`
  (`qdddbpp.store(...)`: `UserPreferenceUtil.putString(key, JSON.toJSONString(user))`
  ~:160; load via `UserPreferenceUtil.getString` ~:19).
  For the Rust client the equivalent is a token file under
  `~/.local/share/babymonitor/` (per TESTING.md / skill phase 5) — the `sid`+`uid`
  are the minimum to persist; both are **secrets**.
- **Refresh / expiry (confidence: likely):** there is **no OAuth-style refresh
  token rotation** in the mobile flow. Session-invalid is signalled by an
  application error code on a normal atop response (the network layer records it
  via `SessionInvalidStat`,
  `decompiled/jadx/sources/com/thingclips/smart/android/network/stat/SessionInvalidStat.java`,
  and `Business.java` emits a localized "Session is not exist and need login
  again" string) → the client must **re-run the login flow** to obtain a fresh
  `sid`. Labelled `likely` (single decompiled path; the exact error code that
  triggers re-login is matched in obfuscated code and is cleanest to confirm from
  a live 401-equivalent capture).
- **`thing.m.app.user.oauth2.token.get`** (`pbpdbqp.java:23`) exists as an
  app-level OAuth2 token endpoint (confidence: likely — present as a constant; its
  exact role vs `sid` is not exercised on the email-login path we traced, so do not
  assume it refreshes `sid` without a live check).

---

## 4. DATACENTER / region selection — runtime-from-login (confidence: confirmed)

This reconciles review-gate **F5** (`re/review_gate_findings.md`) and the
encrypted-regions analysis (`re/tuya_cloud_config.md`). Two independent
sources: the `Domain` bean carried inside the login `User` (class `Domain`,
`decompiled/jadx/sources/com/thingclips/smart/android/user/bean/Domain.java`;
`mobileApiUrl` ~:191, `gwApiUrl` ~:187, `regionCode` ~:197)
AND the absence of any plaintext datacenter host in assets/DEX/JS
(`re/tuya_cloud_config.md`). Together they confirm the base URLs are
**chosen at runtime and delivered by the login response**, not read statically.

The login `User.domain` is a `Domain` object whose fields ARE the datacenter base
URLs for this account's region:

| `Domain` field | Role |
|---|---|
| `mobileApiUrl` | the **atop mobile API base** the Rust client posts to |
| `gwApiUrl` | gateway API base |
| `gwMqttUrl` / `mobileMqttUrl` / `mobileMqttsUrl` / `mobileMediaMqttUrl` | MQTT brokers (relevant to the WebRTC-over-MQTT path, F2) |
| `mobileQuicUrl` / `mqttQuicUrl` | QUIC transports |
| `regionCode` | the resolved region (e.g. EU/US/CN) |
| `aispeechHttpsUrl`, `thingImagesUrl`, `logUrl`, `dnsUrl`/`dns2Url`/`dnsIps` | ancillary services |

**Selection mechanism (confidence: confirmed):** the country/region is supplied at
login (the `countryCode` postData + `region` arg, §2), the server resolves it to a
datacenter, and returns the concrete hosts in `User.domain`. The candidate
country→datacenter map lives inside the **encrypted** `assets/thing_domains_v1/regions`
blob decrypted by native `SecureNativeApi.getConfig`
(`re/tuya_cloud_config.md:11-25`), so it is not statically enumerable here.

**Rust client consequence:** do NOT hardcode a base URL. Either (a) bootstrap the
login against Tuya's publicly-known regional mobile gateway candidate for the
user's region and then switch to `User.domain.mobileApiUrl` for all subsequent
calls, or (b) reproduce the native `getConfig` decrypt (needs the native key — see
`re/tuya_sign.md`). The user can also seed the region from a single login capture.
A pre-login helper action `thing.m.user.region.list` (`pqdbppq` ~:102) /
`thing.m.app.domain.query` (~:46) enumerates regions/domains.

---

## 5. DEVICE LIST + camera record shape (confidence: confirmed for bean shape)

Two independent sources for the device-list container: class `HomeBean`
(`decompiled/jadx/sources/com/thingclips/smart/home/sdk/bean/HomeBean.java`; fields
`deviceList` ~:24 + `sharedDeviceList` ~:38, keyed by `homeId`) AND class `DeviceBean`
(`decompiled/jadx/sources/com/thingclips/smart/sdk/bean/DeviceBean.java`).
The bean shape is `confirmed`; the exact wire **action name** that returns the home
detail is obfuscated to `n` in the DEX and is `likely`/needs-live (see §6).

### 5a. Device-list container
- `HomeBean.getDeviceList()` returns `List<DeviceBean>` (~:168); `getSharedDeviceList()`
  returns devices shared into the home. Populated from a home-detail / device-list
  atop call via `IThingHomePlugin.getDataInstance().getHomeDeviceList(homeId)` (~:169).
- The home-detail action name is R8-obfuscated (`thing.m.n` placeholders in
  `com/thingclips/sdk/home/*`); the canonical Tuya mobile action is the
  `*.app.location.*` / `*.home.*` family but the exact `a=` value here is
  **needs-live-capture** (§6).

### 5b. `DeviceBean` core fields (the device record) (confidence: likely)
Single decompiled source: the `DeviceBean` field declarations (class `DeviceBean`,
`decompiled/jadx/sources/com/thingclips/smart/sdk/bean/DeviceBean.java`; `devId`
~:49, `localKey` ~:106, `secKey` ~:159, `uuid` ~:192, `productId` ~:131). The
`localKey`/`secKey` secrecy is additionally NOTED — not independently grounded — in
`re/review_gate_findings.md` (a sibling doc derived from the same decompile, so it
is a navigation pointer, not a second source). This is one decompiled source, hence
`likely`, not `confirmed`. Selected fields:

| Field | Type | Role | Secret? |
|---|---|---|---|
| `devId` | String | device id (the P2P/MQTT addressing key) | no (but a real value is account-linked PII — anonymize) |
| `name` | String | display name | no (may be PII) |
| `localKey` | String | **per-device AES local key** (LAN proto, DP decrypt) | **YES — secret** |
| `secKey` | String | secondary key material | **YES — secret** |
| `uuid` | String | device uuid | no (anonymize) |
| `pv` | String | protocol version | no |
| `productId` | String | product/profile id | no |
| `productVer` | String | product firmware/profile version | no |
| `schema` / `schemaMap` | String / Map | DP schema (datapoint model) | no |
| `skills` | Map | device capability skill map | no |
| `category` / `categoryCode` | String | device category (camera = `sp`/ipc family) | no |
| `dps` / `dpCodes` / `dpName` | Map | live datapoint state | values may be sensitive |
| `mac` / `ip` / `lat` / `lon` | String | LAN + location | `lat`/`lon` are PII |
| `iconUrl`, `uiType`, `ui`, `bv`, `gwType` | String | UI/gateway metadata | no |

`localKey` and `secKey` are the device-list secrets called out by review-gate
(`re/review_gate_findings.md`, `DeviceBean.localKey`/`DeviceBean.secKey`). For the
Rust models (TASK-0013) treat both as
secret; the device-list fixture must be anonymized before it enters any committed
file.

### 5c. Camera P2P / WebRTC record — `CameraInfoBean` (confidence: confirmed)
Two independent sources: the bean (class `CameraInfoBean` + nested
`CameraInfoBean.P2pConfig`,
`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/bean/CameraInfoBean.java`;
top-level fields `p2pId` ~:19, `password` ~:23, `sessionTid` ~:24; nested
`P2pConfig` class ~:1459)
AND a Tuya **example config payload** embedded in the camera middleware
`decompiled/jadx/sources/com/thingclips/smart/camera/middleware/pqpbpqd.java`
(a `JSON.parseObject("{… p2pId … p2pType … skill …}")` demo string). The bean and
the example payload agree on the field set, so the shape is `confirmed`. NOTE the
literal `id`/`p2pId`/`password` values in that embedded payload are **Tuya SDK
sample/demo values, not this account's secrets** — they are documented as
*structure only* and are NOT copied as real credentials.

The per-camera config (fetched per `devId`, separate from `DeviceBean`) carries the
fields the WebRTC/P2P path needs:

| Field (`CameraInfoBean`) | Type | Role | Secret? |
|---|---|---|---|
| `id` | String | camera/session id | no (anonymize) |
| `p2pId` | String | the P2P device handle (IOTC UID) | **sensitive** (per-device) |
| `p2pType` | int | P2P transport type (e.g. 4) | no |
| `p2pSpecifiedType` | int | specified P2P type | no |
| `p2pPolicy` | int | P2P policy selector | no |
| `password` | String | **P2P session password** | **YES — secret** |
| `sessionTid` | String | session ticket id | **YES — secret** |
| `skill` | String (JSON) | capability manifest: `videos[]`,`audios[]`,`p2p`,`cloudGW`,`localStorage`,`sdk_version`,`video_num` (codec/resolution/streamType) | no |
| `mediaConsumerSkill` | String | negotiated media skill | no |
| `vedioClarity` / `vedioClaritys` | int / int[] | clarity levels | no |
| `audioAttributes` | obj | `hardwareCapability[]`, `callMode[]` | no |
| `p2pConfig` | JSONObject | nested `P2pConfig` | mixed |
| `panoramicInfo` | String | fisheye/panoramic params | no |

Nested `CameraInfoBean.P2pConfig` (`CameraInfoBean.java`, `P2pConfig` ~:1459;
`p2pKey` ~:1462, `initStr` ~:1461, `ices` ~:1460, `session` ~:1463) — the
WebRTC/P2P credential handles:

| Field | Type | Role | Secret? |
|---|---|---|---|
| `p2pKey` | String | **P2P session key** | **YES — secret** |
| `initStr` | String | P2P init string (consumed as `lnInitStr + "/" + lnKeyStr` in `ThingSmartCameraP2PSync.java`) | **YES — secret** |
| `ices` | List | ICE server list (WebRTC) | endpoints (sensitive) |
| `session` | Object | session descriptor (the `session` JSONObject read in `ThingSmartCameraP2PSync.java`) | **YES — secret** |
| `tcpRelay` / `udpRelay` | Object | TURN/relay descriptors | sensitive |

The presence of `ices` + `session` + `tcpRelay`/`udpRelay` corroborates the F2
WebRTC-over-MQTT hypothesis (`re/review_gate_findings.md:26`, `re/streaming_mode.md`):
this is a WebRTC-shaped signaling record, not only legacy IOTC P2P.

**`moto_id` note (confidence: confirmed — absence):** a whole-tree grep for
`moto_id`/`motoId`/`getMotoId` returns **no hit** in this app's camera beans; the
moto handle is not a field of `CameraInfoBean`/`DeviceBean` here. The equivalent
P2P credential handles in THIS app are `p2pId` + `P2pConfig.p2pKey` +
`initStr`/`session`. TASK-0013 should model those, not `moto_id`.

---

## 6. Signing TEST-VECTOR plan (confidence: confirmed — plan, not a vector)

Per `re/tuya_sign.md` (verdict **needs-runtime-hook**, since SUPERSEDED →
**`partially-recoverable`** by TASK-0023, `re/tuya_sign_static.md`), the byte-exact
`sign` was held NOT statically reproducible: the keyed step is native (cmd=1 in
`libthing_security.so`) and the key mixes the app-cert SHA-256 + the `t_s.bmp`
token + appSecret (`re/tuya_sign.md:87-171`). The static dive has since shown the
cert-SHA-256 is offline-computable and the hash is plain MD5, leaving only the
deterministic `t_s.bmp` token decode (TASK-0029) un-ported — so a device is not
required, though a byte-exact vector still awaits that port. Therefore this doc
**does not fabricate** a signature vector. AC #5 forbids a self-derived vector. What the later
Rust differential test (TESTING.md Part-2 signal #2; TASK-0012) needs, to be
produced by an INDEPENDENT reference (`nalajcie/tuya-sign-hacking` tooling or a
live Frida capture on the user's own device, TASK-0022):

**Inputs the differential vector must pin (synthetic / PII-free):**
1. The full ordered envelope param set actually present at sign time — from §1:
   `a, v, t(time), sid, requestId, et, lang, os, appVersion, ttid, clientId,
   deviceId` (+ `lat`/`lon` if location on), with fixed synthetic values.
2. A fixed synthetic `postData` JSON string (so its MD5→swap is deterministic).
3. The exact **string-to-sign** the signer builds (sorted whitelist keys joined by
   `||`, postData replaced by `swapSignString(md5AsBase64(body))`) —
   reproducible per `re/tuya_sign.md` §1-3.
4. The derived sign **key** (or, equivalently, a known string-to-sign → `sign`
   pair) captured from `JNICLibrary.doCommandNative(ctx, 1, str2Bytes, …)` /
   `pbddddb.bdpdqbp(str2)` via the Frida hook (`re/tuya_sign.md:173-186`).
5. Metadata to make the vector reproducible: appKey/appSecret (from `secrets/`),
   the app-cert SHA-256 (computable offline from the APK signing cert), and the
   confirmed hash primitive (HMAC-SHA256 is `likely`, `re/tuya_sign.md:146-156`).

The vector's **expected output** = the `sign` value returned by the hook / the
independent `nalajcie` reimplementation for those fixed inputs — NOT a value
derived from our own decompilation. This keeps the differential test honest
(non-circular), exactly as AC #5 / `re/review_gate_findings.md:76` require.

---

## 7. What is NOT statically confirmable here (honest limitations) (confidence: confirmed)

This section is a scoping record, not a protocol claim; each row's basis is cited
in the sections above (esp. `re/tuya_sign.md:87-186` for the native sign and
`re/tuya_cloud_config.md:11-48` for the encrypted region/datacenter blob).

| Unknown | Why | Unblock |
|---|---|---|
| Exact on-wire action names (`a=`) after the `thing→smartlife` rewrite, and for R8-obfuscated home/device/pairing actions (placeholder `n`) | string constants deobfuscated at runtime | live capture / Frida (TASK-0022) |
| The byte-exact `sign` | native keyed step, runtime cert + BMP token | Frida hook (TASK-0022), per `re/tuya_sign.md` |
| The session-invalid error code that forces re-login; role of `oauth2.token.get` | matched in obfuscated network code; not exercised on the path traced | one live 401-equivalent capture |
| Country→datacenter map | inside the encrypted `regions` blob | native `getConfig` decrypt or one login capture |
| The device-list / camera-config response **values** (real `localKey`, `p2pKey`, `password`, `sessionTid`) | per-account, not in the APK | live call on the user's authorized account → anonymized fixture (TASK-0013) |

These are filed/forward-carried, not hidden. The bean **shapes** above are enough
for TASK-0012 (envelope + login endpoints) and TASK-0013 (typed device/camera
models) to be written now; the live unknowns are validated when the user runs the
Rust client against the real account (TESTING.md gold oracle).

## 8. Captcha / `verifyToken` is NOT an atop `token.get` header (TASK-0050 Stage B) (confidence: confirmed)

**Question:** does the atop `token.get` request get decorated with a
`verifyToken` / risk / device-fingerprint header that a from-scratch client
omits (a candidate explanation for `ILLEGAL_CLIENT_ID`)? **Resolved
definitively: NO.** The captcha/`verifyToken` machinery is a SEPARATE service on
a SEPARATE HTTP stack, gating the auth-CODE-send action — not `token.get`, not
`password.login`, and it adds nothing to the atop envelope.

Method + evidence (jadx; symbol-anchored, line hints drift):

1. **`verifyToken` is a captcha-service request PARAMETER, not an atop header.**
   `CaptchaBusiness.l(...)` (`com/thingclips/smart/login/captcha/business/CaptchaBusiness.java`,
   the `initConfig` method) POSTs to `apiServer + "/verify/app/initConfig"` and
   puts `verifyToken` (plus `verifyId`/`verifyAppKey`/`appClientType`/
   `verifyUniqueCode`/`systemName`/`systemVersion`) into the JSON body of THAT
   request. The sibling endpoints are `/verify/initJs` (`m`) and
   `/verify/app/clickPass` (`n`). `apiServer` is the captcha verify host, a
   DIFFERENT base URL from the atop `/api.json` gateway.

2. **Separate HTTP stack.** `CaptchaBusiness` holds its OWN raw
   `okhttp3.OkHttpClient` field (`new OkHttpClient()`) and builds raw
   `Request.Builder()` calls — it does NOT go through `Business`/`ThingApiParams`/
   the signed atop pipeline. So nothing it does touches the atop `sign`, `clientId`,
   or envelope.

3. **The atop network/sign layer never reads any captcha/risk/fingerprint field.**
   A grep of `com/thingclips/smart/android/network/` and
   `com/thingclips/sdk/network/` for `verifyToken|captchaToken|riskToken|x-risk|
   ticket|fingerprint` returns ZERO hits. `verifyToken` occurs in the WHOLE tree in
   only 5 files, ALL under `com/thingclips/smart/login/captcha/`.

4. **Captcha gates code-SENDING, reactively, via UI — not `token.get`.** The
   verify-result `Map<String,String>` produced by `CaptchaServiceManager.k0(...)`
   (`verifyCaptcha`) is fed via `AuthCodeRequestEntity.j(map)` into the entity's
   `ticket` map and used by `AuthCodeUseCase.sendAuthCodeByType` (the
   send-verification-code action). A null-safe cross-check confirms **zero files**
   reference BOTH the captcha-verify API and `token.get`/`password.login` — the two
   are disjoint code paths. The captcha is shown by `CaptchaServiceImpl.verifyCaptcha`
   in a WebView (`jscore/impl/WebViewImpl`), i.e. an interactive anti-bot challenge
   triggered ON-DEMAND when the server flags risk on code-sending.

**Verdict (confirmed):** there is NO statically-derivable `verifyToken`/risk/
fingerprint header that the atop `token.get` requires and our from-scratch client
omits. The captcha path is (a) a different service/host, (b) a different request
shape, (c) reached only for code-sending, and (d) WebView-interactive
(**runtime-only**, needs a human + the JS challenge — it cannot be precomputed
statically). It is therefore NOT the cause of `ILLEGAL_CLIENT_ID` on `token.get`,
and there is no follow-up "add a missing header" task to file from this trace.
This corroborates the TASK-0050 Stage A differential (`re/live_login.md`):
`ILLEGAL_CLIENT_ID` is a sign-insensitive identity/provisioning gate, not a
missing-request-decoration problem.
