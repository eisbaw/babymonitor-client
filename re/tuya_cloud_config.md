# Tuya Cloud Config — datacenter domains, region selection, API gateway (TASK-0005)

Non-secret cloud configuration for `com.philips.ph.babymonitorplus` (Tuya mobile-app
SDK reskin). **No secret values appear in this file** (appKey/appSecret/sign-key are
recorded only by location in `secrets/tuya_appkey.json`). Every section carries a
confidence label and an evidence citation per TESTING.md Part 1.

> Citation note (symbol-anchored — TASK-0024): cites name a **symbol**
> (class/method/field); any `...File.java ~:NN` line is an **approximate hint** for
> the current `just decompile` tree — jadx line numbers drift, so grep the symbol.
> `decompiled/jadx/sources/...` and `decompiled/apktool/...` paths resolve only
> after a local `just decompile` (those trees are gitignored).

> **UPDATE (TASK-0043) — the `regions`/`pins` blob IS now decrypted (STATICALLY).**
> The encrypted-but-not-enumerable claim below is SUPERSEDED: the regions/pins decrypt
> is **AES-256-CTR with the key+IV embedded in the asset's own 48-byte header** (pure-Java
> `DomainHelper.parseDomainsConfig` → `AESCTRUtil.decrypt`), so it is fully static —
> no runtime input, no appKey, no native call. The native `SecureNativeApi.getConfig`
> @0x136e0 is the decryptor for a DIFFERENT asset (`t_cdc.tcfg`, the unshipped
> custom-domain override; AES-128-GCM keyed on appKey/appSecret). Recovered EU host =
> `a1.tuyaeu.com`. See `re/regions_decrypt.md` + `re/ghidra/getconfig/`.

## Datacenter domains are NOT static plaintext — they are encrypted in an asset (confidence: confirmed)

The candidate datacenter domains are shipped **encrypted** in the asset bundle
`assets/thing_domains_v1/`, not as plaintext literals.

- Two independent sources: (1) the on-disk asset
  `decompiled/apktool/assets/thing_domains_v1/regions` decodes to a binary
  ciphertext blob (~1940 bytes) whose head is a `4db6…` hex envelope header
  followed by binary ciphertext (no commas, no plaintext host present); the sibling
  `decompiled/apktool/assets/thing_domains_v1/pins` (cert-pin set, ~5743 bytes)
  shares the same leading `4db6…` envelope header; and (2) the decrypt entrypoint
  `SecureNativeApi.getConfig(Context, String,
  String)` is declared native
  (`decompiled/jadx/sources/com/thingclips/smart/security/jni/SecureNativeApi.java` ~:22),
  i.e. the config is decrypted at runtime inside `libthing_security*.so`.
- A whole-tree grep for plaintext Tuya datacenter hosts
  (`*.tuyaeu/us/cn/in.com`, `wgine`, `a1.tuya*`, `m1.tuya*`) across the DEX, the JS
  mini-app bundles (`decompiled/js/assets/kit_js/*`) and `decompiled/apktool/assets`
  returns **no datacenter host literal** — only unrelated `promotion.tuya.com`. So the
  base/datacenter URLs cannot be read statically from this APK; they materialise only
  after the native `getConfig` decrypt at runtime.
- Consequence: the Rust client (TASK-0007/0012) must obtain the datacenter base URLs
  either by (a) reproducing the `getConfig` asset-decrypt (needs the native key — see
  `re/tuya_sign.md`), or (b) using Tuya's publicly-known mobile gateway hosts per region
  as candidates and letting the login response pin the live one (see next section).

## Datacenter is selected at runtime from region/country, not static (confidence: likely — corroborates review-gate F5)

- The `regions` asset holds *candidates*; the actual datacenter is chosen by
  country/region and pinned by the login response. Evidence: region plumbing exists
  (`regionCode` referenced in the JS kit bundles `decompiled/js/assets/kit_js/`;
  class `LocationBean`/country-code beans
  (`decompiled/jadx/sources/com/thingclips/stencil/bean/location/LocationBean.java`),
  while no static default-datacenter host literal exists (previous section). This is
  the standard Tuya behaviour documented by review-gate F5 (`re/review_gate_findings.md:53`).
- Limitation: the exact selection function (country→datacenter map) is inside the
  decrypted `regions` blob, so the country→host mapping is not statically enumerable
  here; it is recoverable at runtime or from a single login capture.

## API gateway shape — mobile-app "atop" gateway, not OpenAPI (confidence: confirmed)

- The cloud request path is the Tuya **mobile-app API gateway** (the `a.*/api.*` "atop"
  family), driven by `apiRequestByAtop` (api name + version + postData). Two sources:
  the RN bridge entry `TUNIAPIRequestManager.apiRequestByAtop`
  (`decompiled/jadx/sources/com/thingclips/smart/plugin/tuniapirequestmanager/TUNIAPIRequestManager.java` ~:161)
  (+ its spec `ITUNIAPIRequestManagerSpec.java`) and the request signer's
  whitelist field `ThingApiSignManager.bdpdqbp`
  (`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java` ~:66),
  whose signed-parameter set (`a`, `v`, `t`, `sid`, `appVersion`, `os`,
  `deviceId`, `lang`, `requestId`, …) is the mobile-atop parameter set, NOT the
  OpenAPI `client_id`/`access_token` set. This matches review-gate F1
  (`re/review_gate_findings.md:10`).
- The request URL is built by `ThingApiSignManager.getUrlWithQueryString(...)`
  (~:314): scheme+host come from the (runtime-resolved) base
  URL, query params are appended, and the `sign` param is the value produced by the
  signing path documented in `re/tuya_sign.md`.

## TTID / channel (confidence: confirmed — non-secret build identifier)

- The build ships a Tuya **TTID** channel tag (a non-secret distribution identifier,
  format `philips...`) wired via the field `BuildConfig.THING_SMART_TTID`
  (`decompiled/jadx/sources/com/thingclips/sample/BuildConfig.java` ~:18)
  into `ThingSmartNetWork` (`mAppId`/init plumbing,
  `decompiled/jadx/sources/com/thingclips/smart/android/network/ThingSmartNetWork.java` ~:3872).
  The literal value is recorded in `secrets/tuya_appkey.json` (kept out of this file as
  a precaution even though TTID is not itself a credential).

## TLS pinning (confidence: likely)

- `assets/thing_domains_v1/pins` carries the pinned cert set (same encrypted envelope as
  `regions`), plus a plaintext `assets/thing_domains_v1/h2.ca.der` (786-byte DER CA).
  Evidence: `decompiled/apktool/assets/thing_domains_v1/pins` and `.../h2.ca.der`. A Rust
  client talking to the real gateway must either honour these pins or the device/app may
  reject — but pinning is enforced app-side, so a from-scratch Rust client over system
  trust roots is unaffected unless Tuya rejects the TLS handshake.
