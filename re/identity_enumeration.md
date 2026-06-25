# Tuya identity enumeration — which appKey does the SDK actually use? (TASK-0046)

Batched STATIC enumeration of EVERY candidate Tuya identity (appKey / appSecret /
ttid / clientId / channel) in the APK, to settle the `ILLEGAL_CLIENT_ID`
("Invalid client;No access") root-cause hypothesis: *did TASK-0005 extract the
WRONG appKey from a Tuya SDK sample BuildConfig?*

**No secret values appear in this file.** Real recovered values live ONLY in
`secrets/tuya_appkey.json` (the in-use tuple) and `secrets/tuya_appkey_candidates.json`
(the ranked enumeration). This doc records LOCATION + METHOD + confidence only,
referencing values by `file:line` + a non-secret fingerprint (char-count / field
name).

> Citation note (symbol-anchored): jadx line hints drift between runs — grep the
> SYMBOL. Smali (apktool) is post-R8 BYTECODE = ground truth for literal values;
> jadx renders R8-stripped string constants as `oh`/`ln`/`n` placeholders and is
> therefore UNRELIABLE for literal enumeration — the smali was used for every
> value-bearing claim below.

---

## 0. Verdict — the "wrong sample-key" hypothesis is REFUTED (confidence: confirmed)

**The appKey already in `secrets/tuya_appkey.json` (20-char, fingerprint "…syhm")
IS the app's real provisioned identity. It is NOT a Tuya SDK demo key.**

Two independent ground-truth sources prove the literal is the LIVE key, not a dead
constant in a sample module:
1. The post-R8 bytecode declares it as the app's build constant:
   `BuildConfig.THING_SMART_APPKEY`
   (`decompiled/apktool/smali_classes8/com/thingclips/sample/BuildConfig.smali:25`).
2. **R8 INLINED that exact literal into the real Application class's init path** —
   `const-string` in `SmartApplication.e()`
   (`decompiled/apktool/smali_classes8/com/smart/app/SmartApplication.smali:551`
   for the appKey, `:555` for the appSecret). R8 would not inline a sample/demo
   value into the production launcher's SDK-init; the inline site is the very call
   that feeds `ThingSmartNetWork.mAppId`.

Corroboration that `com.thingclips.sample` is the APP's OWN module (not a vendored
SDK demo): its BuildConfig carries the real app coordinates —
`APPLICATION_ID = "com.philips.ph.babymonitorplus"`, `VERSION_NAME = "1.9.0"`,
`VERSION_CODE = 41`, `FLAVOR = "international"`
(`decompiled/apktool/smali_classes8/com/thingclips/sample/BuildConfig.smali:7,33,37`)
— matching the manifest `package=` + `versionName`
(`decompiled/apktool/AndroidManifest.xml:2`). `com.thingclips.sample` is simply the
Gradle namespace Philips' white-label fork kept for its app module.

**Consequence:** `ILLEGAL_CLIENT_ID` is NOT a wrong-appKey-extraction problem. The
chKey derived from this appId is therefore also derived from the CORRECT appId
(`re/chkey_static.md`). The remaining `ILLEGAL_CLIENT_ID` hypotheses are
provisioning/app-cert-attestation gates, not a mis-extracted key (`re/live_login.md`,
`re/regions_decrypt.md` PART "FEED-FORWARD").

---

## 1. The SDK init chain — where the appKey/appSecret/ttid actually come from (confidence: confirmed)

Two independent sources: the smali bytecode of the real Application init AND the
jadx reconstruction of the same method.

- Real Application = `com.smart.app.SmartApplication`
  (manifest `android:name`, `decompiled/apktool/AndroidManifest.xml:89`;
  class `decompiled/jadx/sources/com/smart/app/SmartApplication.java:39`).
- `SmartApplication.e()` (jadx `:117-121`) selects, in the NON-DAILY (production)
  branch: `str = BuildConfig.THING_SMART_APPKEY`, `str2 = BuildConfig.THING_SMART_SECRET`.
  The smali shows R8 inlined both literals at this exact branch
  (`decompiled/apktool/smali_classes8/com/smart/app/SmartApplication.smali:551,555`).
- Wiring (NOTE the ttid-vs-channel arg routing, see §2a + `re/tuya_cloud_auth.md`
  §1b): `AppInitializer.d(application, appKey, appSecret, apiConfig,
  getString(R.string.b)=rawTtid, c(this)=channel, false)`
  (`decompiled/jadx/sources/com/smart/app/SmartApplication.java:121`). Inside `d`
  the channel arg is rewritten to `sdk_<channel>@<appKey>` (`:334-335`) and the
  raw ttid goes only to `UrlRouter.o()` (`:340`), then
  → `AppInitializer.j(appKey, appSecret, rewrittenChannel, RNAPIUtil.a(), z)`
  (`decompiled/jadx/sources/com/thingclips/smart/initializer/AppInitializer.java:341`)
  → `ThingSdk.init(ctx, appKey, appSecret, rewrittenChannel, rnVersion, apiUrlProvider)`
  (`:1323`); the 6-arg overload forces channel `CHANNEL_OEM` and routes
  `rewrittenChannel` into the ttid position (`ThingSdk.java:1152-1153`)
  → `ThingSmartNetWork.initialize(ctx, appKey, appSecret, ttid=rewrittenChannel, channel="oem", …)` which
  assigns `mAppId = appKey`, `mAppSecret = appSecret`,
  `mTtid = sdk_international@<appKey>`, `mChannel = "oem"`
  (`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingSmartNetWork.java:3872-3895`).

No `THING_SMART_APPKEY`/`TUYA_SMART_APPKEY` `<meta-data>` exists in the manifest
(`decompiled/apktool/AndroidManifest.xml` — only `UMENG_CHANNEL`/`region`), so the
`ThingSmartSdk.java:49,69` metaData fallback path is NOT taken; the BuildConfig
literal is the sole source.

---

## 2. Wire param mapping at sign time (confidence: confirmed)

Two independent sources: the param-key constants + `initUrlParams` body in
`ThingApiParams` AND the live capture's recorded request param keys.

`ThingApiParams.initUrlParams`
(`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java`):
- `clientId` ← `ThingSmartNetWork.mAppId` (`KEY_APP_ID="clientId"` :39; put :1774)
- `ttid` ← `ThingSmartNetWork.getTtid()` (`KEY_TTID="ttid"` :78; put :1780)
- `channel` ← `ThingSmartNetWork.mChannel` (`KEY_CHANNEL="channel"` :49; put :1789)
- `chKey` ← `ThingNetworkSecurity.getChKey(mAppContext, mAppId.getBytes())` (:1828)

The prior live capture (`secrets/tuya_live_debug.json`, request param keys only —
no values) is OUR client's outgoing request (it shows the param NAMES our
`live.rs` emits), so it confirms the param-key SET matches initUrlParams but is
NOT evidence of the APP's param VALUES. The key set carried:
`a, appVersion, bizData, chKey, channel, clientId, cp, deviceCoreVersion, deviceId,
et, lang, os, osSystem, platform, requestId, sdkVersion, sign, time, timeZoneId,
ttid, v`.

> **CORRECTED by TASK-0048 (the `channel` value).** An earlier revision of this
> section asserted `channel == "sdk"` (`CHANNEL_SDK`), citing the SDK-internal
> 7-arg `initialize` overload default
> (`.../ThingSmartNetWork.java:3867,3893`). That overload is NOT the production
> path. The production path
> (`SmartApplication`→`AppInitializer.d`→`j`→`ThingSdk.init` 6-arg) forces
> `CHANNEL_OEM`, so the app's wire **`channel == "oem"`** and the rewritten
> `sdk_…@appKey` rides the **`ttid`** instead (full trace: §2a +
> `re/tuya_cloud_auth.md` §1b). `live.rs` now sends `channel=oem` +
> `ttid=sdk_international@<appKey>` accordingly.

### 2a. ttid value: RESOLVED — `sdk_international@<appKey>` (TASK-0047) (confidence: confirmed)

> **CORRECTED by TASK-0048.** This section previously concluded the wire ttid was
> `single-source-traced` / unresolved and implied the raw `philips…owl` might ride
> the wire. That was wrong: the `sdk_<channel>@<appKey>` rewrite DOES reach the
> wire ttid (it lands in the ttid slot via the `CHANNEL_OEM` init overload), while
> the raw `philips…owl` only reaches `UrlRouter.o()`. Full trace +
> ≥2 independent methods now in `re/tuya_cloud_auth.md` §1b.

`BuildConfig.THING_SMART_TTID` and the `app_scheme` string resource are BOTH the
raw fingerprint ("philips…owl",
`decompiled/apktool/smali_classes8/com/thingclips/sample/BuildConfig.smali:33` +
`decompiled/apktool/res/values/strings.xml:577`) — but that raw value flows only
to `UrlRouter.o(str3)` (`AppInitializer.java:340`), NOT to `mTtid`. The wire
`ttid` is the REWRITTEN channel `"sdk_" + GlobalConfig.b() + "@" + appKey`
(`AppInitializer.java:334-335`, `mSdk==true` by default), routed into the ttid
position by the `ThingSdk.init` 6-arg→`CHANNEL_OEM` overload
(`ThingSdk.java:1152-1153`) and assigned `mTtid = str3`
(`ThingSmartNetWork.java:3873`). `GlobalConfig.b()` = the `UMENG_CHANNEL`
meta-data `"international"` (`AndroidManifest.xml:91`). **Net wire `ttid =
sdk_international@<appKey>`, wire `channel = oem`** (full derivation:
`re/tuya_cloud_auth.md` §1b). This is SECONDARY to the
`ILLEGAL_CLIENT_ID` gate (a clientId-identity rejection, not a ttid one,
`re/live_login.md`), but the live request now sends the app-faithful ttid form
(`babymonitor/babymonitor-cli/src/live.rs` `wire_ttid`).

---

## 3. Full candidate enumeration across the APK (confidence: confirmed)

Two independent sweeps: an exhaustive smali `const-string` scan for 20-char (Tuya
appKey shape) and 32-char (appSecret shape) lowercase-alnum literals
(`decompiled/apktool/smali_classes8/**`), AND the targeted constant-name grep for
`THING_SMART_APPKEY|SECRET|TTID` across `decompiled/jadx/sources`. Results
(values masked; see `secrets/tuya_appkey_candidates.json`):

| Candidate (fingerprint) | chars | Location | Role | Is it the atop appKey? |
|---|---|---|---|---|
| appKey "…syhm" | 20 | `…/thingclips/sample/BuildConfig.smali:25` + inlined `…/smart/app/SmartApplication.smali:551` | `THING_SMART_APPKEY` → `mAppId` → wire `clientId` | **YES (rank 1)** |
| appSecret "…58qx" | 32 | `…/thingclips/sample/BuildConfig.smali:29` + inlined `…/smart/app/SmartApplication.smali:555` | `THING_SMART_SECRET` → `mAppSecret` | **YES (rank 1, paired)** |
| ttid "philips…owl" | — | `…/thingclips/sample/BuildConfig.smali:33` + `res/values/strings.xml:577` (app_scheme) | raw ttid/scheme → `UrlRouter.o()` only; the WIRE `ttid` is the rewritten `sdk_international@<appKey>` (§2a) | NOT the wire ttid (raw value) |
| "…epv8" | 20 | `…/smart/app/ThingNGConfig.smali:68` (`appEncryptKeyProdV2`) | encryptImage/media key | NO — wrong purpose (rank 2) |
| "…gerk" | 20 | `…/smart/app/ThingNGConfig.smali:64` (`appEncryptKeyCvProdV2`) | camera/CV encrypt-image key | NO — wrong purpose (rank 3) |
| "vdevo…1961" | — | apktool smali const-string | Tuya `vdevo` virtual-device id (test/demo) | NO — ruled out |
| meizu/mi/oppo/qq/sim AppKey | — | `decompiled/apktool/res/values/strings.xml:5553,5618,6852,7198,7723` | push-vendor / 3rd-party SDK slots | NO — all EMPTY |

The only 20-char literal wired to `setAppkey`/`mAppId` is the rank-1 appKey. The two
`appEncryptKey*ProdV2` values are 20-char alnum but their field NAME marks them as
Tuya `encryptImage` keys (no wiring to `mAppId`/`setAppkey` was found), so they are
ranked low-and-wrong-purpose, retained only as rule-out fallbacks.

---

## 4. No encrypted/obfuscated appKey exists (confidence: confirmed)

Two independent sources: the plaintext init chain (§1, the appKey is a plaintext
const-string reaching `mAppId`, no AES/Base64 hop) AND the scope of the two
asset-decrypt paths that DO exist, neither of which feeds the appKey:
- `thing_domains_v1/regions`/`pins` = pure-Java AES-256-CTR over an asset-embedded
  key/IV (`re/regions_decrypt.md`; `DomainHelper.parseDomainsConfig` +
  `AESCTRUtil.decrypt`,
  `decompiled/jadx/sources/com/thingclips/smart/android/base/provider/DomainHelper.java`)
  — decrypts DATACENTER host config, not an appKey.
- `t_cdc.tcfg` = native `getConfig@0x136e0` AES-128-GCM-as-CTR
  (Ghidra C `re/ghidra/getconfig/getConfig.c`; pure-Java parallel
  `decompiled/jadx/sources/com/thingclips/smart/android/network/http/AssetsConfig.java`)
  — a custom-domain OVERRIDE asset (not shipped here), not an appKey.

So there is no encrypted appKey/ttid to recover and no decryptor to port. The
appKey is in cleartext bytecode (`decompiled/apktool/smali_classes8/com/smart/app/SmartApplication.smali:551`).

---

## 5. Native libs carry no identity literal (confidence: confirmed)

Two independent sources: a `strings` sweep of the security/network native libs
finds NO 20-char appKey-shaped or 32-char secret-shaped lowercase-alnum literal in
`libthing_security.so` / `libthingsmart.so` / `libthingnetsec.so`
(`decompiled/nativelibs/*.so`); AND a direct grep for the rank-1 appKey/appSecret
literal returns ZERO hits in any native lib. Consistent with §1: the appKey is
injected from Java at `ThingSmartNetWork.initialize`, never baked into native code.
The BMP assets (`assets/t_s.bmp`, `assets/fixed_key.bmp`) feed the native sign-KEY
derivation (`re/bmp_token_whitebox.md`), not an alternate appKey.

---

## 6. Honest limitations (confidence: likely — scoping)

- The rank-1 appKey/sign identity is `confirmed` as the IN-USE one (R8 inline +
  init chain), but it being in-use does NOT explain `ILLEGAL_CLIENT_ID` — that gate
  is server-opaque (`re/live_login.md`). This enumeration's job was to RULE OUT the
  wrong-key hypothesis, which it does; it does not by itself produce a working
  login.
- The §2a ttid-value resolution (`philips…owl` vs a `sdk_…@appKey` rewrite) is
  now RESOLVED statically (`confirmed`, TASK-0047/0048): wire `ttid =
  sdk_international@<appKey>` via the full `AppInitializer.d`→`j`→`ThingSdk.init`
  (6-arg→`CHANNEL_OEM`)→`initialize` dataflow (≥2 methods,
  `re/tuya_cloud_auth.md` §1b;
  `decompiled/jadx/sources/com/thingclips/smart/initializer/AppInitializer.java:334-341`,
  `decompiled/jadx/sources/com/thingclips/smart/sdk/ThingSdk.java:1152-1529`). A
  live capture would still be the only thing that promotes it from a static trace
  to an observed-on-wire fact, but the static derivation is unambiguous.
- Smali addresses/line hints are for THIS build; re-anchor on the symbol landmarks
  (`THING_SMART_APPKEY`, `SmartApplication.e`, `AppInitializer.d/j`,
  `ThingSmartNetWork.initialize`) if the APK version shifts.
