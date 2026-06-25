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

> Citation note: `decompiled/jadx/sources/...:line` paths resolve only after a
> local `just decompile` (the jadx tree is gitignored but the paths are stable).
> Line numbers index the jadx 1.5.0 `-Xmx12g` output recorded in
> `re/decompile_dex.md`. The DEX is **R8-obfuscated**: many API-name string
> constants are runtime-deobfuscated to a placeholder `n`, so some exact wire
> action names are only confirmable live (flagged inline).

---

## 0. TL;DR contract (confidence: confirmed)

Two independent sources ground the overall shape: the decompiled user-API table
`decompiled/jadx/sources/com/thingclips/sdk/user/pqdbppq.java:36-106` (the literal
`thing.m.user.*` action constants) AND the public mobile-SDK write-up
`nalajcie/tuya-sign-hacking` (review-gate F1, `re/review_gate_findings.md:10-24`),
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

Two independent sources: the param-key constants + `initUrlParams` body in
`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java:30-77,407-421`
AND the JS-bridge atop entry
`decompiled/jadx/sources/com/thingclips/smart/plugin/tuniapirequestmanager/TUNIAPIRequestManager.java:161,225-234`
(`apiRequestByAtop` takes `api`, `version`, `postData`). These agree on the same
gateway, so it is `confirmed`.

A request is a set of **URL/GET params** (the signed envelope) plus a **`postData`**
body. The envelope keys (constant → wire name) are:

| Wire param | Const (`ThingApiParams`) | Value / source | Notes |
|---|---|---|---|
| `a` | `KEY_API` | the action name (e.g. `thing.m.user.email.password.login`) | rewritten `thing*`→`smartlife*` on wire by `checkAPIName()` (`ThingApiParams.java:185-191`) — see §1a |
| `v` | `KEY_VERSION` | per-call version string (e.g. `"1.0"`,`"4.0"`) | from the `ApiParams` ctor |
| `t` / `time` | `KEY_TIMESTAMP="time"` | server-synced epoch (`TimeStampManager.getCurrentTimeStamp()`) | added in the sign/body path `ThingApiParams.java:307` |
| `sid` | `KEY_SESSION="sid"` | the session token (empty pre-login) | injected from `IBaseUser.getSid()` (`ApiParams.java:getSession`) |
| `requestId` | `KEY_REQUEST_ID` | `UUID.randomUUID()` per request | `ThingApiParams.java:418` |
| `et` | `KEY_ET` | `"3"` (default ET version) | `ThingApiParams.java:421` |
| `lang` | `KEY_APP_LANG` | device language | `:413` |
| `os` | `KEY_APP_OS` | `"Android"` | `:411` |
| `appVersion` | `KEY_APP_VERSION` | app version string | `:412` |
| `ttid` | `KEY_TTID` | channel TTID (value in `secrets/`) | `:416` |
| `clientId` | `KEY_APP_ID` | the appKey/appId (value in `secrets/`) | `:410` |
| `deviceId` | `KEY_DEVICEID` | per-install device id (`PhoneUtil.getDeviceID`) | `ApiParams.java:getRequestBody`/`initUrlParams` |
| `sign` | `KEY_APP_SIGN="sign"` | the keyed signature | computed last; algorithm in `re/tuya_sign.md` |
| `postData` | `KEY_POST="postData"` | JSON body (per-action fields) | folded into the sign as swapped-MD5 (`re/tuya_sign.md` §2-3) |
| `lat`/`lon` | `KEY_LAT`/`KEY_LON` | optional, only if location switch on | `ApiParams.java:getUrlParams` |

Defaults set in the `ThingApiParams` ctor: `sessionRequire=true`,
`locationRequire=true`, `apiVersion="*"`, `ET_VERSION="3"`
(`ThingApiParams.java:111-145`). Login token-create explicitly sets
`setSessionRequire(false)` (`LoginBusiness.java:907`) because there is no sid yet.

### 1a. `thing.*` → `smartlife.*` wire rewrite (confidence: confirmed)

`checkAPIName()` (`ThingApiParams.java:185-191`) rewrites any `apiName` that
`startsWith("thing")`: it maps the leading `thing` token to `smartlife`. Two
sources: the method body itself AND the consistent `thing.m.*` literal table in
`pqdbppq.java:36-106`. **Consequence for the Rust client:** the constants read as
`thing.m.user.*` in the DEX, but the value the signer sees / that may go on the
wire as `a=` is the `smartlife.m.user.*`-rewritten form. The exact on-wire spelling
must be confirmed against a live capture / Frida hook (TASK-0022) — flagged in §6.

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
`LoginBusiness.java:873-909`):
- action `thing.m.user.username.token.get` v`2.0`; postData `countryCode`,
  `username`, `isUid` (bool); `setSessionRequire(false)`.
- returns a **`TokenBean`** (`com/thingclips/sdk/user/bean/TokenBean.java`) with
  fields `token` (the ticket), `publicKey`, `exponent`, `pExponent`. The
  `publicKey`+`exponent` are an **RSA public key** used to encrypt the password in
  step 2 (this is the `ifencrypt=1` path). This is the "ticket success" callback:
  on `TokenBean` success the UI proceeds to submit credentials.

**Step 2 — submit credentials + ticket** (credential-type-specific):
- **email + password:** `LoginBusiness.s(...)` (`:451-460`) → action
  `thing.m.user.email.password.login` v`GwBroadcastMonitorService.mVersion`
  (a build-version constant); postData `countryCode`, `email`, `passwd`
  (RSA-encrypted with the step-1 key when `ifencrypt`), `token` (ticket),
  `ifencrypt` (0/1), and an MFA blob `{"group":1,"mfaCode":"…"}`. Returns **`User`**.
- **mobile + password:** `LoginBusiness.r(...)` (`:423-447`) → action
  `thing.m.user.mobile.passwd.login` v`4.0`; postData `countryCode`, `mobile`,
  `passwd`, `token`, `ifencrypt`, MFA blob. Returns `User`.
- **email code login:** action `thing.m.user.email.code.login`
  (`pqdbppq.java:42`); **uid+password:** `thing.m.user.uid.password.login`
  (`:43`); **uid token create:** `thing.m.user.uid.token.create` (`:66`).

**Credential types supported** (from the action table `pqdbppq.java:36-106`):
email+password, email+code, mobile+password, mobile+code, uid+password,
uid+token, QR-token, SSO ticket (`thing.m.user.sso.ticket.user.get`, `:88`), and
third-party (wx/qq/facebook/twitter/google/instagram). The baby-monitor app's
primary path is **email/uid + region**, which is the `username.token.get` →
`email.password.login` pair above.

**`region` / country selection at login:** the `countryCode` postData field and
the third `ApiParams(api, ver, region)` ctor arg
(`LoginBusiness.java:452`, `ApiParams(String,String,String)`
`ThingApiParams.java:165`) carry the region into the request; the response
`User.domain` pins the datacenter (§4).

### 2a. JS-bridge / RN path (confidence: confirmed)

Two sources: `TUNIAPIRequestManager.apiRequestByAtop`
(`.../tuniapirequestmanager/TUNIAPIRequestManager.java:161,233-234` builds a
`MiniAtopApiParams(api, version, ctx)` + `setPostData(...)`) AND the RN login
manager `.../tuniloginmanager/TUNILoginManager.java` (carries a `TicketModel`,
matching the ticket flow). The React-Native mini-apps reach the SAME atop gateway
through this bridge, so a Rust client that speaks the native atop envelope (§1)
covers both the native and RN code paths.

---

## 3. TOKEN / session model (confidence: confirmed)

Two independent sources: the `User` bean fields
`decompiled/jadx/sources/com/thingclips/smart/android/user/bean/User.java:34-57`
AND the on-device persistence
`decompiled/jadx/sources/com/thingclips/sdk/user/qdddbpp.java:16,44-47`. They agree
that the session is the `User.sid` string persisted as JSON, so this is `confirmed`.

- **Session token = `User.sid`** (`User.java:49`, getter `:157`). The login
  response `User` also carries `uid` (`:53`), `ecode` (`:36`, an encrypt code used
  for some encrypted endpoints), `domain` (`:35`, the datacenter — §4),
  `timezoneId`, `email`, `username`, `partnerIdentity`, `publicSession`. The `sid`
  is then injected into every subsequent request as the `sid` envelope param
  (`ApiParams.getSession` → `IBaseUser.getSid`).
- **Storage on device:** the `User` (including `sid`) is serialized to JSON and
  stored via MMKV-backed `UserPreferenceUtil`
  (`ThingUserStorageMMKV` = `qdddbpp.java:44-47`:
  `UserPreferenceUtil.putString(key, JSON.toJSONString(user))`; load at `:16-23`).
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

This reconciles review-gate **F5** (`re/review_gate_findings.md:53`) and the
encrypted-regions analysis (`re/tuya_cloud_config.md:11-48`). Two independent
sources: the `Domain` bean carried inside the login `User`
(`decompiled/jadx/sources/com/thingclips/smart/android/user/bean/Domain.java:35-54`)
AND the absence of any plaintext datacenter host in assets/DEX/JS
(`re/tuya_cloud_config.md:26-31`). Together they confirm the base URLs are
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
A pre-login helper action `thing.m.user.region.list` / `thing.m.app.domain.query`
(`pqdbppq.java:46,102`) enumerates regions/domains.

---

## 5. DEVICE LIST + camera record shape (confidence: confirmed for bean shape)

Two independent sources for the device-list container: `HomeBean`
(`decompiled/jadx/sources/com/thingclips/smart/home/sdk/bean/HomeBean.java`, fields
`deviceList` + `sharedDeviceList`, keyed by `homeId`) AND `DeviceBean`
(`decompiled/jadx/sources/com/thingclips/smart/sdk/bean/DeviceBean.java:29-157`).
The bean shape is `confirmed`; the exact wire **action name** that returns the home
detail is obfuscated to `n` in the DEX and is `likely`/needs-live (see §6).

### 5a. Device-list container
- `HomeBean.getDeviceList()` returns `List<DeviceBean>`; `getSharedDeviceList()`
  returns devices shared into the home. Populated from a home-detail / device-list
  atop call via `IThingHomePlugin.getDataInstance().getHomeDeviceList(homeId)`.
- The home-detail action name is R8-obfuscated (`thing.m.n` placeholders in
  `com/thingclips/sdk/home/*`); the canonical Tuya mobile action is the
  `*.app.location.*` / `*.home.*` family but the exact `a=` value here is
  **needs-live-capture** (§6).

### 5b. `DeviceBean` core fields (the device record) (confidence: confirmed)
Two independent sources: the `DeviceBean` field declarations
(`decompiled/jadx/sources/com/thingclips/smart/sdk/bean/DeviceBean.java:29-157`)
AND the device-list secrets call-out in `re/review_gate_findings.md:81`
(`localKey` / P2P creds are secrets). Selected fields (`DeviceBean.java:29-157`):

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
(`re/review_gate_findings.md:81`). For the Rust models (TASK-0013) treat both as
secret; the device-list fixture must be anonymized before it enters any committed
file.

### 5c. Camera P2P / WebRTC record — `CameraInfoBean` (confidence: confirmed)
Two independent sources: the bean
`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/bean/CameraInfoBean.java:9-26,140-175`
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

Nested `CameraInfoBean.P2pConfig` (`CameraInfoBean.java:140-175`) — the WebRTC/P2P
credential handles:

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

Per `re/tuya_sign.md` (verdict **needs-runtime-hook**), the byte-exact `sign` is
NOT statically reproducible: the keyed step is native (cmd=1 in
`libthing_security.so`) and the key mixes the app-cert SHA-256 + the `t_s.bmp`
token + appSecret (`re/tuya_sign.md:87-171`). Therefore this doc **does not
fabricate** a signature vector. AC #5 forbids a self-derived vector. What the later
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
