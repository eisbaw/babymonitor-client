//! AUTHORIZED one-time LIVE Tuya login path (TASK-0042).
//!
//! This module is compiled ONLY under the `live` Cargo feature, so the default
//! build (`just e2e` / `just assert-offline`) never pulls reqwest/rsa or touches
//! the network. It performs an account-owner-authorized one-time login against
//! the REAL Tuya mobile-app ("atop") cloud to VALIDATE the recovered signer (the
//! `bmp_token` candidate + the cmd=1 MD5 fold) and, on success, capture the
//! device-list — strictly READ-ONLY.
//!
//! # Hard guardrails (mirrored from the task; violating any is failure)
//! - **READ-ONLY:** only `token.get`, `password.login`, device-list fetch. NEVER
//!   a write/control/unbind/pairing API.
//! - **password.login AT MOST ONCE:** if it fails we STOP and report — no retry,
//!   no fold/region sweep against the account.
//! - **2FA:** on the emailed-code challenge we STOP, capture the challenge state
//!   to `secrets/tuya_2fa_state.json`, and return [`LiveOutcome::Needs2fa`]. We
//!   NEVER guess a code.
//! - **Secrets:** creds are read from `secrets/` and every captured value
//!   (session/uid/device-list/2FA state) is written ONLY under `secrets/`
//!   (gitignored). No secret value is ever logged, printed, or returned in a
//!   human-facing message.
//!
//! # What "validated" means (the gold differential)
//! The lockout-sensitive step is `password.login`. `token.get` is a pre-login
//! RSA-pubkey fetch and is the SIGN ORACLE: if the server ACCEPTS our signed
//! `token.get` (returns the pubkey + ticket), the recovered signer — the master
//! key G (incl. the `bmp_token`-derived matrixKey0) feeding
//! `HMAC-SHA256(G, str2)` — is VALIDATED. If the server rejects the SIGN, the
//! candidate is wrong and we STOP before ever attempting `password.login`.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use babymonitor_core::session::SessionStore;
use babymonitor_core::sign::{
    app_cert_sha256_digest_from_apk, assemble_master_key_g, ch_key, et3_encrypto_key,
    generate_phone_util_device_id, post_data_digest_hex, Signer, SigningKeyMaterial,
    StaticBmpToken, APP_PACKAGE_NAME,
};
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde::Deserialize;

// ─────────────────────────────────────────────────────────────────────────────
// Constants (non-secret; runtime-resolvable but seeded for the EU region)
// ─────────────────────────────────────────────────────────────────────────────

/// EU mobile-app atop gateway host (the user is in Denmark → EU datacenter,
/// `re/tuya_cloud_config.md`). This is the publicly-known Tuya EU mobile gateway
/// candidate; the login response's `User.domain.mobileApiUrl` pins the live host
/// for any subsequent call (F5). NOT a secret.
const EU_ATOP_HOST: &str = "a1.tuyaeu.com";

/// The atop request path on the mobile gateway.
const ATOP_PATH: &str = "/api.json";

/// Country code for Denmark (the `countryCode` postData field + region arg).
const COUNTRY_CODE_DK: &str = "45";

/// `et` envelope param: `ET_VERSION_3` (`re/tuya_cloud_auth.md` §1).
const ET_VERSION: &str = "3";

/// `os` envelope param.
const OS_ANDROID: &str = "Android";

/// `lang` envelope param (the app's device language; EU default).
const LANG: &str = "en";

/// thingclips SDK version embedded in the `User-Agent`
/// (`Thing-UA=APP/Android/<appVersion>/SDK/<sdkVersion>`). Resolved statically:
/// `ThingSdk.getSdkVersion()` parses
/// `com.thingclips.smart.device.core.sdk.BuildConfig.VERSION_NAME = "6.7.0"`.
const THING_SDK_VERSION: &str = "6.7.0";

// ── SDK-fidelity envelope params (TASK-0044) ─────────────────────────────────
// The real `ThingApiParams.initUrlParams` (~:1771-1831,
// `decompiled/.../ThingApiParams.java`) sends these in addition to the core
// envelope. They make the request indistinguishable from the app. Several are
// runtime/device-specific (`ThingSmartNetWork.m*` set at `ThingSdk.init`,
// `Build.*` device fields); we use the app's documented defaults and note where
// a value is a representative stand-in (overriding any has no effect on the
// `sign`, since `requestId`/`postData`/etc. dominate the canonical string —
// but `chKey` IS signed, see below).

/// `sdkVersion` (`KEY_SDK_VERSION`) — `ThingSmartNetWork.mSdkVersion`, the
/// thingclips SDK version passed at `ThingSdk.init`. Runtime-set, not a static
/// literal in the DEX; we reuse [`THING_SDK_VERSION`] (same value as in the UA).
const SDK_VERSION: &str = THING_SDK_VERSION;

/// `deviceCoreVersion` (`KEY_DEVICE_CORE_VERSION`) —
/// `ThingSmartNetWork.mDeviceCoreVersion`, from
/// `ThingSdk.getDeviceCoreVersion()` → `com.thingclips.smart.device.core.sdk.BuildConfig`
/// `VERSION_NAME = "6.7.0"`.
const DEVICE_CORE_VERSION: &str = THING_SDK_VERSION;

/// `nd` (`KEY_NEUTRAL_DOMAINS`) — production `SmartApplication.e()` enables the
/// neutral domain switch before SDK init, and `initUrlParams` emits `nd=1` both
/// as a top-level form param and inside `bizData`.
const NEUTRAL_DOMAINS_ENABLED: &str = "1";

/// `channel` (`"channel"` key) — `ThingSmartNetWork.mChannel`, the channel arg
/// reaching `ThingSmartNetWork.initialize`. RESOLVED statically (TASK-0047,
/// `re/tuya_cloud_auth.md` §1b): the production init path
/// `SmartApplication.e()` → `AppInitializer.d` → `j()` →
/// `ThingSdk.init(6-arg)` routes through the `CHANNEL_OEM` overload
/// (`ThingSdk.java:1152-1153`), so `mChannel == "oem"`, NOT `"sdk"`. The earlier
/// `"sdk"` value was the SDK-internal default of the unused 7-arg overload.
const CHANNEL: &str = "oem";

/// `appRnVersion` (`KEY_APP_RN_VERSION`) — `ThingSmartNetWork.mAppRNVersion`,
/// emitted by `initUrlParams` ONLY when non-empty
/// (`ThingApiParams.java`: `if (!TextUtils.isEmpty(mAppRNVersion))`). RESOLVED
/// statically (TASK-0048): the production init wires it from `RNAPIUtil.a()`
/// (`AppInitializer.j` → `ThingSdk.init`), which returns the NON-EMPTY public
/// build constant `BuildConfig.appRNVersion = "5.92"`
/// (`com/thingclips/smart/rnplugin/rnpluginapi/BuildConfig.java:8`). So the app
/// DOES send `appRnVersion=5.92` on the wire — we send it too. Non-secret. (The
/// app may append `.160` in some branch, `RNAPIUtil.a():226-228`; the base
/// `5.92` is the documented constant and is what we send.)
const APP_RN_VERSION: &str = "5.92";

/// Default `osSystem` (`KEY_OS_SYSTEM`) — `Build.VERSION.RELEASE`.
/// Pixel 8 Pro on a current stable Android release.
const DEFAULT_OS_SYSTEM: &str = "16";

/// Default `platform` (`KEY_PLATFORM`) — `Build.MODEL`.
const DEFAULT_PLATFORM: &str = "Pixel 8 Pro";

/// Default `sdkInt` (`KEY_SDK_INT`) — `Build.VERSION.SDK_INT`.
const DEFAULT_SDK_INT: &str = "36";

/// Default `brand` (`KEY_BRAND`) — `Build.BRAND`.
const DEFAULT_BRAND: &str = "google";

/// `timeZoneId` (`KEY_TIME_ZONE_ID`) — `ThingCommonUtil.getTimeZoneId()`. The
/// account owner is in Denmark (`COUNTRY_CODE_DK`), so the matching zone.
const TIME_ZONE_ID: &str = "UTC";

/// `cp` (`KEY_CP`) — set to `VALUE_CP_GZIP="gzip"` whenever `et == "3"`
/// (`ThingApiParams.initUrlParams` ~:1786-1788). Our `et` is always `3`.
const CP_GZIP: &str = "gzip";

/// The UMENG channel fingerprint that the wire `ttid` rewrite embeds. RESOLVED
/// statically (TASK-0047): in `AppInitializer.d`, when `ThingSmartNetWork.mSdk`
/// is its default `true` (`ThingSmartNetWork.java:103`), the channel arg is
/// rewritten to `"sdk_" + GlobalConfig.b() + "@" + appKey`
/// (`AppInitializer.java:334-335`); that rewritten string then lands in the
/// `mTtid` slot via the `CHANNEL_OEM` init overload (see [`wire_ttid`]).
/// `GlobalConfig.b()` returns the channel set by `GlobalConfig.d(ctx, c(this), z)`
/// (`AppInitializer.java:333`, BEFORE the rewrite), and `SmartApplication.c()`
/// reads the `UMENG_CHANNEL` manifest meta-data =
/// `"international"` (`AndroidManifest.xml:91`). Non-secret.
const TTID_CHANNEL_FINGERPRINT: &str = "international";

/// token.get action + version (`re/tuya_cloud_auth.md` §2 step 1). The wire `a`
/// is the `thing.*`→`smartlife.*`-rewritten form (§1a); we sign over the
/// rewritten name.
const TOKEN_GET_ACTION: &str = "thing.m.user.username.token.get";
const TOKEN_GET_VERSION: &str = "2.0";

/// password.login action + version (`re/tuya_cloud_auth.md` §2 step 2, email
/// path). Version is a build constant; `4.0` is the documented mobile value.
const PASSWORD_LOGIN_ACTION: &str = "thing.m.user.email.password.login";
const PASSWORD_LOGIN_VERSION: &str = "4.0";

/// device-list (home-detail) action + version. CONFIDENCE: `likely` — the exact
/// `a=` value is R8-obfuscated to `thing.m.n` in `com/thingclips/sdk/home/*`
/// (`re/tuya_cloud_auth.md` §5a/§6: "the home-detail action name is R8-obfuscated
/// … the exact `a=` value here is needs-live-capture"). We use the documented
/// Tuya mobile device-list action as the single best-known candidate; a real
/// capture (TASK-0022) confirms or corrects it. This is the ONE single-source,
/// `likely` value on the injected-sid read path — every other envelope ingredient
/// is `confirmed`. Defined once here so both the post-login and the injected-sid
/// builders sign byte-identically.
const DEVICE_LIST_ACTION: &str = "thing.m.my.group.device.list";
const DEVICE_LIST_VERSION: &str = "1.0";

// ─────────────────────────────────────────────────────────────────────────────
// Loaded secrets (from secrets/, never echoed)
// ─────────────────────────────────────────────────────────────────────────────

/// Login credentials read from `secrets/tuya_login.json`. NEVER printed.
#[derive(Deserialize)]
struct LoginCreds {
    email: String,
    password: String,
}

/// App key material read from `secrets/tuya_appkey.json`. The cert hash is NOT in
/// this file — it is computed offline from the APK.
#[derive(Deserialize)]
struct AppKey {
    #[serde(rename = "appKey")]
    app_key: String,
    #[serde(rename = "appSecret")]
    app_secret: String,
    ttid: String,
    #[serde(rename = "version_name", default)]
    version_name: Option<String>,
}

/// Runtime Android build identity used by `ThingApiParams.initUrlParams` and
/// `PhoneUtil.getRemoteDeviceID`. The APK reads these from `android.os.Build`;
/// the CLI reads an optional gitignored `secrets/android_profile.json` so a user
/// can pin their real device profile without packet capture.
#[derive(Clone, Deserialize)]
struct AndroidProfile {
    #[serde(
        rename = "osSystem",
        alias = "release",
        alias = "androidRelease",
        default = "default_os_system"
    )]
    os_system: String,
    #[serde(rename = "platform", alias = "model", default = "default_platform")]
    model: String,
    #[serde(rename = "sdkInt", alias = "sdk_int", default = "default_sdk_int")]
    sdk_int: String,
    #[serde(default = "default_brand")]
    brand: String,
    /// Optional exact app/device store value. If supplied, this wins over the
    /// generated PhoneUtil-shaped fallback.
    #[serde(rename = "deviceId", alias = "device_id", default)]
    device_id: Option<String>,
}

impl Default for AndroidProfile {
    fn default() -> Self {
        Self {
            os_system: default_os_system(),
            model: default_platform(),
            sdk_int: default_sdk_int(),
            brand: default_brand(),
            device_id: None,
        }
    }
}

fn default_os_system() -> String {
    DEFAULT_OS_SYSTEM.to_string()
}

fn default_platform() -> String {
    DEFAULT_PLATFORM.to_string()
}

fn default_sdk_int() -> String {
    DEFAULT_SDK_INT.to_string()
}

fn default_brand() -> String {
    DEFAULT_BRAND.to_string()
}

/// Resolved live config: secrets + the offline-computed cert hash + a stable
/// per-install deviceId. Carries secrets; constructed once, never logged.
struct LiveConfig {
    creds: LoginCreds,
    material: SigningKeyMaterial,
    bmp_token: String,
    app_version: String,
    /// The app-faithful `deviceId` sent AND SIGNED on every atop request. The
    /// genuine Philips/Tuya app ALWAYS sends+signs a `deviceId` on `token.get`
    /// (and every request): its `ApiParams` subclass injects
    /// `PhoneUtil.getDeviceID` into BOTH `getRequestBody` (`ApiParams.java:89`)
    /// AND `initUrlParams` (`ApiParams.java:227`), and `KEY_DEVICEID` is in the
    /// sign whitelist `bdpdqbp` (`ThingApiSignManager.java:66`). It is therefore
    /// ALWAYS present, never gated. The value is a stable per-install
    /// PhoneUtil-shaped 44-hex id — caller-pinned (`secrets/android_profile.json`)
    /// or generated-and-persisted (`secrets/device_id.txt`); see
    /// [`load_or_create_device_id`] (TASK-0064 restored this after TASK-0060
    /// wrongly removed it on a round-1 misreading of the BASE ThingApiParams).
    device_id: String,
    android: AndroidProfile,
    /// The per-app channel-auth token (native `getChKey@0x16000`,
    /// `re/chkey_static.md`). Wire `chKey` param AND a SIGNED whitelist param.
    /// Secret-by-policy (derived from appKey + cert hash) — never logged.
    ch_key: String,
    secrets_dir: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors / outcomes
// ─────────────────────────────────────────────────────────────────────────────

/// A live-path error. Distinct from [`CoreError`] so the live wiring's own
/// failure modes (config load, network, server-rejected sign) are typed and
/// contextful. NO variant ever carries a secret value.
#[derive(Debug)]
pub enum LiveError {
    /// A `secrets/` file is missing or malformed (path + parse context, no value).
    Config(String),
    /// The offline cert-hash derivation failed.
    Cert(String),
    /// A network/transport failure talking to the gateway.
    Network(String),
    /// The server returned a body we could not parse as an atop response.
    Protocol(String),
    /// The server REJECTED our signed request (sign invalid / permission deny).
    /// Carries the server error code + message (server-supplied, non-secret).
    SignRejected { code: String, msg: String },
    /// A non-sign application error from the server (carries code + message).
    Server { code: String, msg: String },
    /// RSA encryption of the password failed.
    Crypto(String),
}

impl std::fmt::Display for LiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "live config error: {m}"),
            Self::Cert(m) => write!(f, "live cert-hash error: {m}"),
            Self::Network(m) => write!(f, "live network error: {m}"),
            Self::Protocol(m) => write!(f, "live protocol error: {m}"),
            Self::SignRejected { code, msg } => {
                write!(f, "live SIGN REJECTED by server: code={code} msg={msg}")
            }
            Self::Server { code, msg } => {
                write!(f, "live server error: code={code} msg={msg}")
            }
            Self::Crypto(m) => write!(f, "live crypto error: {m}"),
        }
    }
}

impl std::error::Error for LiveError {}

/// The terminal outcome of the live login. NONE carries a secret value.
///
/// There is deliberately no standalone "signer validated" terminal: a sign
/// acceptance at `token.get` is a MIDPOINT (the flow always proceeds to the one
/// `password.login`), reported via stderr. The terminal outcomes are the three
/// the task cares about: 2FA reached, full login, or (as an `Err`) sign-rejected.
#[derive(Debug)]
pub enum LiveOutcome {
    /// We reached the 2FA email-code challenge. The challenge state has been
    /// written to `secrets/tuya_2fa_state.json`; the caller must STOP and emit
    /// NEED 2FA CODE. (`token.get` was accepted, so the signer is VALIDATED.)
    Needs2fa,
    /// Full login succeeded (no 2FA) and the device-list was captured to
    /// `secrets/`. Carries non-secret shape facts: whether the SCD921 camera was
    /// found and its `p2pType` (transport selector), for honest reporting.
    LoggedIn {
        camera_found: bool,
        p2p_type: Option<i32>,
    },
}

/// The outcome of a PROBE-ONLY run (TASK-0048 Stage B). A probe sends EXACTLY ONE
/// `token.get` to ONE host and STOPS — it NEVER proceeds to `password.login`,
/// even on success. This is the guardrail-faithful path for sweeping the
/// un-tried iotbing/px datacenter gateways: the whole point is to learn whether a
/// host clears `ILLEGAL_CLIENT_ID`, not to log in. No variant carries a secret.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// `token.get` was ACCEPTED (success=true). The sign oracle is reachable on
    /// this host — the signer (bmp_token + fold) can finally be validated. We
    /// STOP here (the caller must NOT chain into password.login).
    Accepted,
    /// The server returned an application error (success=false). Carries the
    /// server-supplied code + message (non-secret) so the caller can classify
    /// `ILLEGAL_CLIENT_ID` vs a DIFFERENT (informative) error.
    ServerError { code: String, msg: String },
}

/// The outcome of the INJECTED-SESSION read path (TASK-0055). This path bypasses
/// `password.login` entirely: it LOADS a SEPARATELY-captured `sid` from the
/// on-disk [`SessionStore`] (the user supplies it into gitignored `secrets/`) and
/// drives one signed `device.list` atop call with that `sid`. It NEVER attempts a
/// login and NEVER fabricates a session — if no session is injected it reports
/// [`InjectedOutcome::NoSession`] honestly. No variant carries a secret value.
#[derive(Debug)]
pub enum InjectedOutcome {
    /// No session is injected in the store. The read path is honestly unavailable:
    /// there is no `sid` to drive `device.list`. The caller reports the
    /// no-session state.
    NoSession,
    /// An injected `sid` drove a real `device.list` call. Carries non-secret shape
    /// facts: whether the SCD921 camera was found and its `p2pType` (transport
    /// selector). The raw response is captured to `secrets/` (gitignored).
    Fetched {
        camera_found: bool,
        p2p_type: Option<i32>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret loading + offline ingredient assembly
// ─────────────────────────────────────────────────────────────────────────────

fn read_secret_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, LiveError> {
    let bytes = std::fs::read(path)
        .map_err(|e| LiveError::Config(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| LiveError::Config(format!("parse {}: {e}", path.display())))
}

/// Assemble the live config from `secrets/` + the offline cert hash.
///
/// `secrets_dir` is the `secrets/` directory; `apk_path` is the extracted APK the
/// cert hash is computed from (offline, no device). No value is logged.
fn load_config(secrets_dir: &Path, apk_path: &Path) -> Result<LiveConfig, LiveError> {
    let creds: LoginCreds = read_secret_json(&secrets_dir.join("tuya_login.json"))?;
    let appkey: AppKey = read_secret_json(&secrets_dir.join("tuya_appkey.json"))?;

    let bmp_token = std::fs::read_to_string(secrets_dir.join("bmp_token.txt"))
        .map_err(|e| LiveError::Config(format!("read bmp_token.txt: {e}")))?
        .trim()
        .to_string();
    if bmp_token.is_empty() {
        return Err(LiveError::Config("bmp_token.txt is empty".into()));
    }

    // Offline app-cert SHA-256 RAW digest (re/tuya_sign_static.md §4). The native
    // master key G + chKey consume it as colon-upper 95-hex, NOT lowercase 64-hex.
    // Value never printed.
    let app_cert_sha256 =
        app_cert_sha256_digest_from_apk(apk_path).map_err(|e| LiveError::Cert(format!("{e}")))?;

    // appVersion is a SIGNED whitelist param (`SIGN_WHITELIST` contains
    // "appVersion") — a wrong value yields a wrong `sign`. The REAL build
    // version_name MUST come from secrets/tuya_appkey.json; we NEVER silently ship
    // the old hardcoded "1.9.0" placeholder on a signed request (TASK-0064). Fail
    // LOUD if it is missing/empty rather than inventing a version.
    let app_version = appkey
        .version_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            LiveError::Config(
                "tuya_appkey.json has no non-empty \"version_name\"; appVersion is SIGNED, so \
                 refusing to ship a placeholder version. Add the real app build version_name."
                    .into(),
            )
        })?
        .to_string();
    let android = load_android_profile(secrets_dir)?;

    let material = SigningKeyMaterial {
        app_key: appkey.app_key,
        app_secret: appkey.app_secret,
        app_cert_sha256,
        ttid: appkey.ttid,
    };

    // chKey: the per-app channel-auth token. A PURE function of STATIC inputs
    // (appKey + package name + offline cert hash) per native getChKey@0x16000 —
    // one HMAC-SHA256, fully recomputable on every call. We therefore ALWAYS derive
    // it and keep NO on-disk copy: the former secrets/chkey.txt cache was redundant
    // state and a second source of truth (architect Finding 4), and its write
    // silently swallowed errors. `ch_key` formats the raw cert digest to the
    // colon-upper 95-hex form internally. The value is secret-by-policy, never logged.
    let ch_key_value = ch_key(
        &material.app_key,
        APP_PACKAGE_NAME,
        &material.app_cert_sha256,
    );

    // The atop envelope ALWAYS carries a `deviceId` (and signs it): the real app's
    // ApiParams subclass injects PhoneUtil.getDeviceID into both getRequestBody
    // (:89) and initUrlParams (:227), and KEY_DEVICEID is whitelisted. We resolve a
    // stable per-install PhoneUtil-shaped id (caller-pinned, else generated +
    // persisted) — never a per-request random (TASK-0064).
    let device_id = load_or_create_device_id(secrets_dir, &android)?;

    Ok(LiveConfig {
        creds,
        material,
        bmp_token,
        app_version,
        device_id,
        android,
        ch_key: ch_key_value,
        secrets_dir: secrets_dir.to_path_buf(),
    })
}

fn load_android_profile(secrets_dir: &Path) -> Result<AndroidProfile, LiveError> {
    let path = secrets_dir.join("android_profile.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| LiveError::Config(format!("parse {}: {e}", path.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(AndroidProfile::default()),
        Err(e) => Err(LiveError::Config(format!("read {}: {e}", path.display()))),
    }
}

/// Resolve the app-faithful `deviceId` that every atop request sends AND signs.
///
/// Order of preference:
/// 1. A caller-PINNED value in `secrets/android_profile.json` (`deviceId`) — if the
///    user captured their device's real cached id, prefer it verbatim.
/// 2. The stable per-install id persisted at `secrets/device_id.txt` (gitignored).
/// 3. Otherwise GENERATE a `PhoneUtil.getRemoteDeviceID`-shaped 44-char
///    lowercase-hex id ([`generate_phone_util_device_id`]), persist it (0600), and
///    reuse it thereafter.
///
/// This mirrors the real app exactly: `PhoneUtil.getDeviceID`
/// (`PhoneUtil.java:326-333`) generates the id ONCE and caches it in
/// `SecuredPreferenceStore`; the genuine app ALWAYS sends+signs that deviceId (the
/// `ApiParams` subclass override injects it into both `getRequestBody` and
/// `initUrlParams`, and `KEY_DEVICEID` is in the sign whitelist). So it is always
/// present and stable per install.
///
/// HONESTY (TASK-0064): the generated value is a STAND-IN for the device's real
/// cached id, not a captured one. The server does NOT validate the deviceId VALUE
/// (it is merely SIGNED, and the gateway recomputes the sign over received
/// params), so a stable, correctly-shaped, generated, persisted id is app-faithful
/// — NOT a fabrication or workaround. We never emit a per-request random id.
fn load_or_create_device_id(
    secrets_dir: &Path,
    android: &AndroidProfile,
) -> Result<String, LiveError> {
    // 1. Caller-pinned (real captured) id wins.
    if let Some(pinned) = android
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(pinned.to_string());
    }

    // 2. Stable persisted id (reused across runs — stable per install).
    let path = secrets_dir.join("device_id.txt");
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let s = s.trim();
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(LiveError::Config(format!("read {}: {e}", path.display()))),
    }

    // 3. Generate ONCE, persist (0600), reuse. The two random seeds drive the
    // per-install entropy of segments 2 and 3 (the app feeds getRandomId* UUIDs);
    // seg1 is fixed by brand+model, exactly as PhoneUtil.getRemoteDeviceID.
    let mut rand_a = [0u8; 32];
    let mut rand_b = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut rand_a);
    rng.fill_bytes(&mut rand_b);
    let device_id = generate_phone_util_device_id(&android.brand, &android.model, &rand_a, &rand_b);
    std::fs::write(&path, &device_id)
        .map_err(|e| LiveError::Config(format!("write {}: {e}", path.display())))?;
    restrict_permissions(&path);
    Ok(device_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// Atop request envelope + signing
// ─────────────────────────────────────────────────────────────────────────────

/// Build the signed atop param map for one pre-login action.
///
/// `action` is the `thing.*` name; it is rewritten to `smartlife.*` for the wire
/// `a` (and the rewritten name is what gets signed, `re/tuya_cloud_auth.md` §1a).
/// `post_data` is raw JSON; the returned body string is the ET=3 encrypted
/// `postData` form value, and the returned map contains every other form param
/// including `sign`.
fn build_signed_envelope(
    cfg: &LiveConfig,
    action: &str,
    version: &str,
    post_data: &str,
) -> Result<(BTreeMap<String, String>, String), LiveError> {
    build_signed_envelope_with(cfg, action, version, post_data, &BTreeMap::new(), None)
}

/// Like [`build_signed_envelope`] but folds `extra` params (e.g. the post-login
/// `sid`) into the SIGNED form params before signing. Only whitelisted, non-empty
/// extras affect the canonical string (the signer filters); they all ride in the
/// POST form body. `ecode` is the optional second arg to native
/// `getEncryptoKey(requestId, ecode)` for session-required requests; login calls
/// pass `None` because their Java path sets `setSessionRequire(false)`.
fn build_signed_envelope_with(
    cfg: &LiveConfig,
    action: &str,
    version: &str,
    post_data: &str,
    extra: &BTreeMap<String, String>,
    ecode: Option<&str>,
) -> Result<(BTreeMap<String, String>, String), LiveError> {
    let wire_action = rewrite_action(action);
    let now_s = chrono::Utc::now().timestamp();
    let request_id = new_request_id();

    // Params that ride in the POST form body (sid empty pre-login → dropped).
    let mut envelope: BTreeMap<String, String> = BTreeMap::new();
    envelope.insert("a".into(), wire_action.clone());
    envelope.insert("v".into(), version.into());
    envelope.insert("time".into(), now_s.to_string());
    envelope.insert("requestId".into(), request_id.clone());
    envelope.insert("et".into(), ET_VERSION.into());
    envelope.insert("lang".into(), LANG.into());
    envelope.insert("os".into(), OS_ANDROID.into());
    envelope.insert("appVersion".into(), cfg.app_version.clone());
    // Wire `ttid` is the rewritten `sdk_<channel>@<appKey>` (TASK-0047), NOT the
    // raw `cfg.material.ttid` (philipsclnightowl) — see [`wire_ttid`]. `ttid` is
    // a SIGNED whitelist param, so this value enters the canonical string too.
    envelope.insert("ttid".into(), wire_ttid(&cfg.material.app_key));
    envelope.insert("clientId".into(), cfg.material.app_key.clone());
    // deviceId: ALWAYS sent AND SIGNED (TASK-0064). The genuine app's ApiParams
    // subclass injects PhoneUtil.getDeviceID into BOTH getRequestBody
    // (`ApiParams.java:89`) and initUrlParams (`ApiParams.java:227`), and
    // KEY_DEVICEID is in the sign whitelist `bdpdqbp` — so every real request
    // carries+signs it. `cfg.device_id` is a stable per-install PhoneUtil-shaped
    // id (caller-pinned or generated+persisted; see load_or_create_device_id).
    envelope.insert("deviceId".into(), cfg.device_id.clone());

    // chKey: the per-app channel-auth token (native getChKey@0x16000). It is BOTH
    // a wire form param AND a SIGNED whitelist param (SIGN_WHITELIST contains
    // "chKey"), so it MUST be in the envelope BEFORE signing — the canonical
    // string then includes it. Earlier probes used it to test SDK fidelity.
    envelope.insert("chKey".into(), cfg.ch_key.clone());

    // SDK-fidelity params the real initUrlParams sends (TASK-0044). These are NOT
    // in SIGN_WHITELIST, so they ride the wire form without affecting the sign —
    // they make the request shape match the app. `cp=gzip` is set because et==3.
    envelope.insert("sdkVersion".into(), SDK_VERSION.into());
    envelope.insert("deviceCoreVersion".into(), DEVICE_CORE_VERSION.into());
    envelope.insert("channel".into(), CHANNEL.into());
    envelope.insert("nd".into(), NEUTRAL_DOMAINS_ENABLED.into());
    envelope.insert("osSystem".into(), cfg.android.os_system.clone());
    envelope.insert("platform".into(), cfg.android.model.clone());
    envelope.insert("timeZoneId".into(), TIME_ZONE_ID.into());
    envelope.insert("cp".into(), CP_GZIP.into());
    // appRnVersion: emitted by initUrlParams iff mAppRNVersion is non-empty; the
    // app wires it from RNAPIUtil.a() = BuildConfig.appRNVersion ("5.92"), which
    // IS non-empty, so the app sends it — we match (TASK-0048). Not signed.
    envelope.insert("appRnVersion".into(), APP_RN_VERSION.into());
    // bizData: matches initUrlParams (customDomainSupport + nd + sdkInt + brand).
    // NOTE (TASK-0048): initUrlParams ALSO folds ThingSmartNetWork.getCommonParams()
    // into BOTH bizData and the top-level params — but `addCommonParams` has NO
    // caller anywhere in the decompiled app, so mCommonParams is empty at
    // token.get time and getCommonParams() contributes nothing. We therefore add
    // no commonParams (adding invented ones would diverge from the app).
    envelope.insert("bizData".into(), build_biz_data(&cfg.android));

    for (k, v) in extra {
        envelope.insert(k.clone(), v.clone());
    }

    // Java default path: signWhitEncryptedBody=true and et=3, so `postData` is
    // AES-GCM encrypted with a random 12-byte nonce, base64(nonce||ciphertext||tag),
    // then that encrypted string is what enters both the form body and the sign
    // digest. See ThingApiParams.getPostBody/getEncryptPostDataString.
    let wire_post_data = encrypt_et3_post_data(cfg, &request_id, post_data, ecode)?;

    // Build the SIGN input map: a copy of the params with `postData` inserted as
    // the digest of the encrypted wire value (Tuya digests postData before sorting).
    let mut sign_params = envelope.clone();
    let pd_digest = post_data_digest_hex(wire_post_data.as_bytes())
        .map_err(|e| LiveError::Crypto(format!("{e}")))?;
    sign_params.insert("postData".into(), pd_digest);

    let signer = Signer::new(
        cfg.material.clone(),
        StaticBmpToken::new(cfg.bmp_token.clone()),
    );
    let sign = signer
        .sign(&sign_params)
        .map_err(|e| LiveError::Crypto(format!("sign failed: {e}")))?;

    // The final POST form body carries encrypted `postData` plus all params below.
    envelope.insert("sign".into(), sign);
    Ok((envelope, wire_post_data))
}

/// Assemble the native master key **G** for this config — the HMAC key for both
/// the request `sign` and the ET=3 postData AES key derivation
/// (`re/master_secret_g.md`). Built from the offline cert digest (as colon-upper
/// 95-hex), the `bmp_token` (→ raw matrixKey0), and the appSecret. No value logged.
fn master_key_g(cfg: &LiveConfig) -> Result<Vec<u8>, LiveError> {
    assemble_master_key_g(
        APP_PACKAGE_NAME,
        &cfg.material.app_cert_sha256,
        &cfg.bmp_token,
        &cfg.material.app_secret,
    )
    .map_err(|e| LiveError::Crypto(format!("assemble master key G: {e}")))
}

fn encrypt_et3_post_data(
    cfg: &LiveConfig,
    request_id: &str,
    post_data: &str,
    ecode: Option<&str>,
) -> Result<String, LiveError> {
    let mut nonce = [0u8; 12];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce);
    encrypt_et3_post_data_with_nonce(cfg, request_id, post_data, ecode, &nonce)
}

fn encrypt_et3_post_data_with_nonce(
    cfg: &LiveConfig,
    request_id: &str,
    post_data: &str,
    ecode: Option<&str>,
    nonce: &[u8; 12],
) -> Result<String, LiveError> {
    let g = master_key_g(cfg)?;
    let key = et3_encrypto_key(request_id, &g, ecode);
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|e| LiveError::Crypto(format!("AES-GCM key init: {e:?}")))?;
    let mut ciphertext_and_tag = post_data.as_bytes().to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(nonce), b"", &mut ciphertext_and_tag)
        .map_err(|e| LiveError::Crypto(format!("AES-GCM encrypt postData: {e:?}")))?;

    let mut out = Vec::with_capacity(nonce.len() + ciphertext_and_tag.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext_and_tag);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Build the wire `ttid` value the app actually sends. RESOLVED statically
/// (TASK-0047, `re/tuya_cloud_auth.md` §1b): the raw `philipsclnightowl`
/// ttid/scheme (`R.string.b` / `BuildConfig.THING_SMART_TTID`) is passed to
/// `AppInitializer.d` as `str3`, but that arg only reaches `UrlRouter.o(str3)`.
/// The value that reaches `ThingSmartNetWork.mTtid` (→ wire `ttid`) is the
/// REWRITTEN channel: `d()` sets `str4 = "sdk_" + GlobalConfig.b() + "@" + appKey`
/// when `mSdk==true`, then `j(appKey, appSecret, str4, RNAPIUtil.a(), z)` passes
/// that `str4` as `j`'s `str3`, which the `ThingSdk.init(6-arg)` overload
/// (`ThingSdk.java:1152` → forces `CHANNEL_OEM`) routes into the ttid position →
/// `initThingData` `str3` → `ThingSmartNetWork.initialize(... str3 ...)` →
/// `mTtid = str3` (`ThingSmartNetWork.java:3873`). Net: wire `ttid =
/// sdk_<channel>@<appKey>` with `<channel> = "international"`. The appKey is
/// secret-by-policy, so the ttid is assembled at runtime and NEVER logged.
fn wire_ttid(app_key: &str) -> String {
    format!("sdk_{TTID_CHANNEL_FINGERPRINT}@{app_key}")
}

/// Rewrite a `thing.*` action to its `smartlife.*` wire form
/// (`ThingApiParams.checkAPIName`, `re/tuya_cloud_auth.md` §1a).
fn rewrite_action(action: &str) -> String {
    if let Some(rest) = action.strip_prefix("thing") {
        format!("smartlife{rest}")
    } else {
        action.to_string()
    }
}

/// A per-request id matching Java `UUID.randomUUID().toString()`.
fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    uuid_v4_from_bytes(bytes)
}

fn uuid_v4_from_bytes(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Build the `bizData` envelope param: the JSON object the real
/// `ThingApiParams.initUrlParams` (~:1793-1822) assembles. It always carries
/// `customDomainSupport="1"`, carries `nd="1"` when the app's neutral-domain
/// switch is enabled, and folds in `sdkInt` (`Build.VERSION.SDK_INT`) and
/// `brand` (`Build.BRAND`). It is NOT a signed param.
fn build_biz_data(android: &AndroidProfile) -> String {
    serde_json::json!({
        "customDomainSupport": "1",
        "nd": NEUTRAL_DOMAINS_ENABLED,
        "sdkInt": &android.sdk_int,
        "brand": &android.brand,
    })
    .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP send + atop response parsing
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal parsed atop response. `success` + `t` are envelope-level; `result`
/// is the action payload; `error_code`/`error_msg` carry server errors.
#[derive(Debug)]
struct AtopResponse {
    success: bool,
    error_code: Option<String>,
    error_msg: Option<String>,
    result: serde_json::Value,
    raw: serde_json::Value,
}

/// POST a signed atop request and parse the response envelope.
///
/// The SDK posts to `/api.json` with no query string; `ApiParams.getRequestBody()`
/// returns a form body containing encrypted `postData`, `sign`, and the params
/// commonly described as the envelope (`a`, `v`, `clientId`, `time`, etc.). We use
/// reqwest BLOCKING (no async runtime) over HTTPS (rustls). No secret is logged.
fn send_atop(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
    params: &BTreeMap<String, String>,
    wire_post_data: &str,
) -> Result<AtopResponse, LiveError> {
    let url = format!("https://{host}{ATOP_PATH}");

    let body_form = form_body(params, wire_post_data);

    let mut req = client
        .post(&url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::CONNECTION, "keep-alive")
        .body(body_form);

    // App-faithful telemetry header: `OKHttpBusinessRequest` UNCONDITIONALLY adds
    // `x-client-trace-id` = `thingApiParams.getRequestId()`
    // (`decompiled/.../OKHttpBusinessRequest.java:23,342`; CLIENT_TRACE_ID =
    // "x-client-trace-id"). `getRequestId()` returns the SAME `requestId` already
    // in our signed envelope, so we reuse that value verbatim. It is a per-request
    // handle, not a secret, but we don't log it. It rides as a request HEADER, not
    // a signed param, so it does not affect the canonical sign string.
    if let Some(request_id) = params.get("requestId") {
        req = req.header("x-client-trace-id", request_id.clone());
    }

    let resp = req
        .send()
        .map_err(|e| LiveError::Network(format!("POST {url}: {}", scrub_url_secrets(&e))))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| LiveError::Network(format!("read body: {}", scrub_url_secrets(&e))))?;

    // Diagnostic capture to secrets/ ONLY (the request envelope carries the
    // appKey/sign — both secret-by-policy — so it must never hit stdout/logs).
    // This is the single source of truth for debugging a routing/sign rejection
    // without ever echoing a value. Overwritten each call (last-call wins).
    {
        let mut form_param_keys = vec!["postData".to_string()];
        form_param_keys.extend(params.keys().cloned());
        let dbg = serde_json::json!({
            "host": host,
            "form_param_keys": form_param_keys,
            "http_status": status.as_u16(),
            "response_body": text,
        });
        let path = cfg.secrets_dir.join("tuya_live_debug.json");
        if let Ok(bytes) = serde_json::to_vec_pretty(&dbg) {
            let _ = std::fs::write(&path, bytes);
            restrict_permissions(&path);
        }
    }

    let raw: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        // Do NOT echo the body (could contain account data); report status only.
        LiveError::Protocol(format!("non-JSON atop response (HTTP {status}): {e}"))
    })?;

    let success = raw
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let error_code = raw
        .get("errorCode")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let error_msg = raw
        .get("errorMsg")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let result = raw
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(AtopResponse {
        success,
        error_code,
        error_msg,
        result,
        raw,
    })
}

fn form_body(params: &BTreeMap<String, String>, wire_post_data: &str) -> String {
    let mut pairs = Vec::with_capacity(params.len() + 1);
    pairs.push(format!("postData={}", urlencode(wire_post_data)));
    for (k, v) in params {
        pairs.push(format!("{}={}", urlencode(k), urlencode(v)));
    }
    pairs.join("&")
}

/// Minimal OkHttp `FormBody.Builder.add` value encoder (no extra dep).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Flip exactly ONE hex nibble of a lowercase-hex string (the Tuya `sign` is a
/// 64-char lowercase HMAC-SHA256 hex). Returns a string of the SAME length and the
/// same hex alphabet, differing from the input in exactly one character — so the
/// gateway still parses it as a well-formed signature and proceeds to verify it.
///
/// The flip is deterministic (mutates the FIRST hex digit, XOR-ing its 4-bit
/// value with 1 — `0<->1`, `2<->3`, …, `e<->f`), which always yields a different
/// character. A non-hex / empty input is a programmer error here (the sign is
/// always hex), so we return a typed [`LiveError`] rather than corrupting blindly.
/// The input and output are signature material and are NEVER logged.
fn corrupt_one_nibble(hex: &str) -> Result<String, LiveError> {
    if hex.is_empty() {
        return Err(LiveError::Crypto("cannot corrupt an empty sign".into()));
    }
    let mut chars: Vec<char> = hex.chars().collect();
    let first = chars[0];
    let val = first
        .to_digit(16)
        .ok_or_else(|| LiveError::Crypto("sign is not lowercase hex; cannot corrupt".into()))?;
    // XOR the low bit to guarantee a different nibble (0<->1, 2<->3, ... e<->f).
    let flipped = val ^ 1;
    let new_char = std::char::from_digit(flipped, 16)
        .ok_or_else(|| LiveError::Crypto("nibble flip produced a non-hex digit".into()))?;
    chars[0] = new_char;
    Ok(chars.into_iter().collect())
}

/// Render a reqwest error WITHOUT leaking the request URL — which carries the
/// signed query string (`clientId` = appKey, `sign` = the signature: BOTH
/// secret-by-policy). reqwest's default `Display` embeds the full effective URL
/// (with query) in transport errors, so a raw `{e}` would leak those values into
/// stderr/logs. We strip the URL via [`reqwest::Error::without_url`] and then
/// belt-and-braces redact any residual `?query` in the message string.
fn scrub_url_secrets(e: &reqwest::Error) -> String {
    let stripped = e.to_string();
    // `without_url` consumes a clone via the source chain; reqwest exposes it on
    // the error itself, but we only have a ref — so redact defensively at the
    // string level: cut everything from the first '?' of any embedded URL.
    redact_query(&stripped)
}

/// Replace any `scheme://host/path?<query>` query portion with `?<redacted>` so a
/// signed query string can never appear in a message.
fn redact_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_query = false;
    for c in s.chars() {
        if in_query {
            // End the query at whitespace or a closing paren/quote; otherwise the
            // char is part of the (redacted) query and is dropped.
            if c.is_whitespace() || c == ')' || c == '"' || c == '\'' {
                in_query = false;
                out.push(c);
            }
        } else if c == '?' {
            in_query = true;
            out.push_str("?<redacted-signed-query>");
        } else {
            out.push(c);
        }
    }
    out
}

/// Classify a non-success atop response: is it a SIGN rejection (the gold
/// negative) or another server error? Tuya signals sign failures via known error
/// codes / messages. We match conservatively and surface the exact code+msg.
fn classify_error(resp: &AtopResponse) -> LiveError {
    let code = resp.error_code.clone().unwrap_or_default();
    let msg = resp.error_msg.clone().unwrap_or_default();
    let lc = code.to_ascii_lowercase();
    let lm = msg.to_ascii_lowercase();
    let is_sign = lc.contains("sign")
        || lm.contains("sign invalid")
        || lm.contains("signature")
        || lm.contains("permission")
        || lm.contains("deny");
    if is_sign {
        LiveError::SignRejected { code, msg }
    } else {
        LiveError::Server { code, msg }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: token.get  (the SIGN ORACLE)
// ─────────────────────────────────────────────────────────────────────────────

/// The parsed token.get result (`TokenBean`): RSA pubkey parts + the ticket.
struct TokenBean {
    public_key: String,
    exponent: String,
    token: String,
}

/// Send the ONE `token.get` and, on success, return the [`TokenBean`]. A server
/// SIGN rejection here means the candidate signer (bmp_token + fold) is WRONG.
fn do_token_get(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
) -> Result<TokenBean, LiveError> {
    // postData: countryCode + username(email) + isUid=false (§2 step 1).
    let post_data = serde_json::json!({
        "countryCode": COUNTRY_CODE_DK,
        "username": cfg.creds.email,
        "isUid": false,
    })
    .to_string();

    let (envelope, body) =
        build_signed_envelope(cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, &post_data)?;
    let resp = send_atop(client, host, cfg, &envelope, &body)?;

    if !resp.success {
        return Err(classify_error(&resp));
    }

    // result carries publicKey, exponent, token (the ticket).
    let public_key = resp
        .result
        .get("publicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LiveError::Protocol("token.get result missing publicKey".into()))?
        .to_string();
    let exponent = resp
        .result
        .get("exponent")
        .and_then(|v| v.as_str())
        .unwrap_or("65537")
        .to_string();
    let token = resp
        .result
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LiveError::Protocol("token.get result missing token".into()))?
        .to_string();

    Ok(TokenBean {
        public_key,
        exponent,
        token,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: RSA-encrypt password + THE ONE password.login
// ─────────────────────────────────────────────────────────────────────────────

/// RSA-encrypt the password with the token.get pubkey (the `ifencrypt=1` path).
///
/// Tuya's `TokenBean.publicKey`/`exponent` are decimal-string RSA modulus +
/// exponent; we build an [`RsaPublicKey`] from them and PKCS#1 v1.5-encrypt the
/// UTF-8 password, returning lowercase hex (the app sends the hex of the
/// ciphertext). The password value never appears in any log.
fn rsa_encrypt_password(pubkey: &TokenBean, password: &str) -> Result<String, LiveError> {
    // The publicKey may be a decimal modulus string (Tuya's TokenBean form) or a
    // PEM/DER SPKI. Try decimal modulus+exponent first (the documented form).
    let key = build_rsa_key(&pubkey.public_key, &pubkey.exponent)?;
    let mut rng = OsRng;
    let ct = key
        .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|e| LiveError::Crypto(format!("rsa encrypt: {e}")))?;
    Ok(hex::encode(ct))
}

/// Build an [`RsaPublicKey`] from Tuya's `publicKey`/`exponent`. Accepts either a
/// decimal modulus string (+ decimal exponent) or a PEM SPKI blob.
fn build_rsa_key(public_key: &str, exponent: &str) -> Result<RsaPublicKey, LiveError> {
    let pk = public_key.trim();
    if pk.starts_with("-----BEGIN") {
        return RsaPublicKey::from_public_key_pem(pk)
            .map_err(|e| LiveError::Crypto(format!("parse RSA PEM: {e}")));
    }
    // Decimal modulus + exponent (Tuya TokenBean form). Hex fallback if not
    // all-decimal (some deployments hex-encode the modulus).
    let n =
        parse_biguint(pk).ok_or_else(|| LiveError::Crypto("RSA modulus not parseable".into()))?;
    let e = parse_biguint(exponent.trim())
        .or_else(|| Some(BigUint::from(65537u32)))
        .unwrap();
    RsaPublicKey::new(n, e).map_err(|e| LiveError::Crypto(format!("build RSA key: {e}")))
}

/// Parse a BigUint from a decimal OR hex string (hex if it has non-decimal hex
/// digits). Returns None on empty / invalid.
fn parse_biguint(s: &str) -> Option<BigUint> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        BigUint::parse_bytes(s.as_bytes(), 10)
    } else {
        BigUint::parse_bytes(s.as_bytes(), 16)
    }
}

/// The classification of a password.login response.
enum LoginResult {
    /// 2FA email-code challenge: STOP. Carries the raw result so the challenge
    /// state (session/ticket needed to submit the code) can be captured.
    Needs2fa(serde_json::Value),
    /// Login succeeded: carries the `User` (sid/uid/domain) result object.
    Success(serde_json::Value),
}

/// Send THE ONE `password.login`. Per the guardrail this is attempted exactly
/// once; any failure STOPS (the caller does not retry).
fn do_password_login(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
    token: &TokenBean,
) -> Result<LoginResult, LiveError> {
    let enc_password = rsa_encrypt_password(token, &cfg.creds.password)?;

    // postData: countryCode, email, passwd(RSA-enc hex), token(ticket),
    // ifencrypt=1 (§2 step 2, email path).
    let post_data = serde_json::json!({
        "countryCode": COUNTRY_CODE_DK,
        "email": cfg.creds.email,
        "passwd": enc_password,
        "token": token.token,
        "ifencrypt": 1,
    })
    .to_string();

    let (envelope, body) = build_signed_envelope(
        cfg,
        PASSWORD_LOGIN_ACTION,
        PASSWORD_LOGIN_VERSION,
        &post_data,
    )?;
    let resp = send_atop(client, host, cfg, &envelope, &body)?;

    if !resp.success {
        // Detect a 2FA challenge: Tuya signals MFA/2-step via a specific error
        // code/flag carrying a challenge ticket rather than a hard failure.
        if is_2fa_challenge(&resp) {
            return Ok(LoginResult::Needs2fa(resp.raw.clone()));
        }
        return Err(classify_error(&resp));
    }

    // Some deployments return success=true but with an MFA/next-step marker in
    // the result rather than a full User; treat that as a 2FA challenge too.
    if result_indicates_2fa(&resp.result) {
        return Ok(LoginResult::Needs2fa(resp.raw.clone()));
    }

    Ok(LoginResult::Success(resp.result.clone()))
}

/// Whether a non-success response is a 2FA/MFA challenge (not a hard error).
fn is_2fa_challenge(resp: &AtopResponse) -> bool {
    let code = resp
        .error_code
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let msg = resp
        .error_msg
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    code.contains("mfa")
        || code.contains("2step")
        || code.contains("two_step")
        || code.contains("verify")
        || msg.contains("verification code")
        || msg.contains("two-step")
        || msg.contains("2-step")
        || msg.contains("mfa")
        // Tuya's known code for "needs email/SMS verification" on login.
        || code == "user_need_mfa"
        || code == "need_mfa"
}

/// Whether a success result body itself indicates a pending 2FA step.
fn result_indicates_2fa(result: &serde_json::Value) -> bool {
    // A challenge carries a ticket/session but no sid/uid yet.
    let has_session = result.get("sid").and_then(|v| v.as_str()).is_some();
    let mfa_marker = result.get("mfaToken").is_some()
        || result
            .get("needMfa")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || result.get("flowId").is_some()
        || result.get("nextStep").is_some();
    mfa_marker && !has_session
}

// ─────────────────────────────────────────────────────────────────────────────
// Capture to secrets/ (values withheld from logs)
// ─────────────────────────────────────────────────────────────────────────────

/// Write a captured JSON value to `secrets/<name>` (0600). NEVER logged.
fn capture_to_secrets(
    cfg: &LiveConfig,
    name: &str,
    value: &serde_json::Value,
) -> Result<(), LiveError> {
    let path = cfg.secrets_dir.join(name);
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| LiveError::Config(format!("serialize {name}: {e}")))?;
    std::fs::write(&path, bytes)
        .map_err(|e| LiveError::Config(format!("write {}: {e}", path.display())))?;
    restrict_permissions(&path);
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

// ─────────────────────────────────────────────────────────────────────────────
// PROBE-ONLY path (TASK-0048 Stage B): ONE token.get to ONE host, then STOP.
// ─────────────────────────────────────────────────────────────────────────────

/// Send EXACTLY ONE `token.get` to ONE host and STOP. This is the
/// guardrail-faithful probe for the un-tried iotbing/px datacenter gateways: it
/// NEVER proceeds to `password.login` (not even on success), NEVER retries, and
/// makes exactly one signed account call.
///
/// Returns:
/// - [`ProbeOutcome::Accepted`] if the gateway accepted our `token.get`
///   (success=true) — the sign oracle is reachable; the caller MUST stop.
/// - [`ProbeOutcome::ServerError`] with the server code+msg if the gateway
///   returned success=false (e.g. still `ILLEGAL_CLIENT_ID`, or a DIFFERENT —
///   informative — error meaning our identity was accepted and a later stage was
///   reached).
/// - `Err` only for transport/parse/config failures (no account semantics).
///
/// The raw response is captured to `secrets/tuya_live_debug.json` by
/// [`send_atop`] (gitignored); no secret/value is ever logged.
pub fn run_token_get_probe(
    secrets_dir: &Path,
    apk_path: &Path,
    host: &str,
    corrupt_sign: bool,
) -> Result<ProbeOutcome, LiveError> {
    let cfg = load_config(secrets_dir, apk_path)?;
    eprintln!("probe: config loaded (all secret values withheld).");

    // Non-account reachability check first (NOT a signed call).
    probe_host(host)?;
    eprintln!("probe: host {host} reachable (non-account TLS probe ok).");

    let user_agent = format!(
        "Thing-UA=APP/Android/{}/SDK/{}",
        cfg.app_version, THING_SDK_VERSION
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(user_agent)
        .build()
        .map_err(|e| LiveError::Network(format!("build http client: {e}")))?;

    // Build the SAME signed token.get envelope the login path uses, send it ONCE.
    // We deliberately do NOT call do_token_get (which maps !success to a typed
    // Err and discards code/msg) — we want the raw code/msg for classification
    // and we must NOT treat a server error as a hard failure that hides the code.
    let post_data = serde_json::json!({
        "countryCode": COUNTRY_CODE_DK,
        "username": cfg.creds.email,
        "isUid": false,
    })
    .to_string();
    let (mut envelope, body) =
        build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, &post_data)?;

    // TASK-0050 corrupted-sign differential: flip exactly ONE hex nibble of the
    // already-built `sign` value, leaving everything else byte-identical. The
    // corrupted sign keeps its 64-char lowercase-hex (HMAC-SHA256) shape, so the
    // gateway parses it and reaches sign-verification — only the signature itself
    // is wrong. This
    // is the decisive test: if the SAME `ILLEGAL_CLIENT_ID` comes back for both the
    // candidate and the corrupted sign, the reject is sign-INSENSITIVE (an identity
    // gate upstream of sign-verify); if a DIFFERENT (sign/access) code comes back,
    // the reject is sign-SENSITIVE and our candidate sign is the real blocker.
    if corrupt_sign {
        let sign = envelope
            .get("sign")
            .cloned()
            .ok_or_else(|| LiveError::Crypto("envelope has no sign to corrupt".into()))?;
        let corrupted = corrupt_one_nibble(&sign)?;
        // Sanity: same length/shape, but a different value (never log either).
        debug_assert_eq!(corrupted.len(), sign.len());
        debug_assert_ne!(corrupted, sign);
        envelope.insert("sign".into(), corrupted);
        eprintln!(
            "probe: --corrupt-sign active — flipped ONE hex nibble of the sign \
             (value withheld); shape/length preserved so the gateway reaches \
             sign-verification."
        );
    }

    eprintln!(
        "probe: sending ONE token.get to {host} (variant={}, no password.login will follow)...",
        if corrupt_sign {
            "corrupt-sign"
        } else {
            "candidate-sign"
        }
    );
    let resp = send_atop(&client, host, &cfg, &envelope, &body)?;

    if resp.success {
        // The sign oracle is reachable. STOP — do NOT chain into password.login.
        eprintln!("probe: token.get ACCEPTED by {host} — sign oracle reachable. STOP (no login).");
        return Ok(ProbeOutcome::Accepted);
    }

    let code = resp.error_code.clone().unwrap_or_default();
    let msg = resp.error_msg.clone().unwrap_or_default();
    eprintln!(
        "probe: {host} returned server error (success=false). code+msg captured to \
         secrets/tuya_live_debug.json (not echoed here beyond the code)."
    );
    Ok(ProbeOutcome::ServerError { code, msg })
}

// ─────────────────────────────────────────────────────────────────────────────
// INJECTED-SESSION read path (TASK-0055): a SEPARATELY-captured sid drives
// device.list, BYPASSING password.login. The login identity gate is NOT solved
// here — this is the honest "token-injectable" design: a real captured session
// the user supplies into gitignored secrets/ drives the read side.
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the atop host for the injected session. The login `User` carries
/// `domain.mobileApiUrl` (persisted as [`Session::mobile_api_base`]); that is the
/// authoritative gateway for every subsequent call (`re/tuya_cloud_auth.md` §4).
/// We parse its host; if it is empty/unparseable we fall back to the EU gateway.
/// NOT a secret (region-revealing only).
fn host_from_mobile_api_base(mobile_api_base: &str) -> String {
    // reqwest re-exports the `url` crate as `reqwest::Url`, so we parse without
    // adding a separate dependency (this fn is live-feature-only anyway).
    reqwest::Url::parse(mobile_api_base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| EU_ATOP_HOST.to_string())
}

/// Drive `device.list` using a SEPARATELY-CAPTURED session injected into the
/// on-disk [`SessionStore`], BYPASSING `password.login` entirely (TASK-0055).
///
/// This is the consumer that makes "token-injectable" literally true: it LOADS the
/// `sid` from the store (the user writes a real captured session into gitignored
/// `secrets/` → the store), builds the byte-faithful signed `device.list` request
/// via [`build_device_list_request`] (the SAME builder the post-login path uses,
/// with the `sid` signed into the canonical string), and sends ONE call. It NEVER
/// attempts a login and NEVER fabricates a session:
/// - no session in the store → [`InjectedOutcome::NoSession`] (honest blocked);
/// - an injected session → [`InjectedOutcome::Fetched`] with SHAPE-only facts.
///
/// `store` is injected (a real default-path store in production, a temp store in
/// tests) so this is testable offline. The host is taken from the session's
/// `mobile_api_base` (`User.domain.mobileApiUrl`), the authoritative gateway. No
/// secret value (sid/uid) is ever logged or returned.
pub fn run_injected_device_list(
    secrets_dir: &Path,
    apk_path: &Path,
    store: &SessionStore,
) -> Result<InjectedOutcome, LiveError> {
    // LOAD the injected session. A corrupt store errors loud (it does NOT mask as
    // "no session"). No session → honest no-session state, no network touched.
    let session = store
        .load()
        .map_err(|e| LiveError::Config(format!("session store: {e}")))?;
    let Some(session) = session else {
        eprintln!(
            "live: no session injected in the store — read path is blocked (no captured sid). \
             No network touched."
        );
        return Ok(InjectedOutcome::NoSession);
    };

    let cfg = load_config(secrets_dir, apk_path)?;
    eprintln!("live: config + injected session loaded (all secret values withheld).");

    // The injected session pins the gateway (User.domain.mobileApiUrl).
    let host = host_from_mobile_api_base(&session.mobile_api_base);

    // Non-account reachability check (NOT a signed call).
    probe_host(&host)?;
    eprintln!("live: host {host} reachable (non-account TLS probe ok).");

    let user_agent = format!(
        "Thing-UA=APP/Android/{}/SDK/{}",
        cfg.app_version, THING_SDK_VERSION
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(user_agent)
        .build()
        .map_err(|e| LiveError::Network(format!("build http client: {e}")))?;

    // Build the device.list request carrying the INJECTED sid (signed into the
    // canonical string), send it ONCE. No password.login is performed.
    eprintln!("live: sending ONE device.list with the INJECTED sid (no password.login)...");
    let (envelope, body) = build_device_list_request(&cfg, &session.sid, session.ecode.as_deref())?;
    let resp = send_atop(&client, &host, &cfg, &envelope, &body)?;
    capture_to_secrets(&cfg, "tuya_device_list.json", &resp.raw)?;
    if !resp.success {
        eprintln!("live: device.list returned a server error (captured raw to secrets/).");
    }
    let (camera_found, p2p_type) = inspect_device_list(&resp.raw);
    Ok(InjectedOutcome::Fetched {
        camera_found,
        p2p_type,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration: the one-shot live login
// ─────────────────────────────────────────────────────────────────────────────

/// Run the AUTHORIZED one-time live login. See the module docs for guardrails.
///
/// Flow:
/// 1. Load secrets + offline cert hash.
/// 2. Probe the EU atop host reachability (DNS/TCP) — NOT a signed account call.
/// 3. Send the ONE `token.get`. Sign-rejected → STOP (candidate/fold wrong).
///    Accepted → signer VALIDATED.
/// 4. RSA-encrypt the password + send THE ONE `password.login`. 2FA → capture
///    state + return [`LiveOutcome::Needs2fa`]. Success → capture session + the
///    device-list, confirm the SCD921 + p2pType. Any failure → STOP.
///
/// `secrets_dir` / `apk_path` are injected (testability + no hardcoded paths).
/// Returns the terminal [`LiveOutcome`] or a typed [`LiveError`] (no secrets in
/// either).
pub fn run_live_login(
    secrets_dir: &Path,
    apk_path: &Path,
    host_override: Option<&str>,
) -> Result<LiveOutcome, LiveError> {
    let cfg = load_config(secrets_dir, apk_path)?;

    eprintln!("live: config loaded (all secret values withheld).");

    // Host: the EU mobile-atop gateway by default; `--host` lets the operator
    // pin the correct regional gateway if the appKey is provisioned elsewhere
    // (this is network-level routing, not an extra account login attempt).
    let host = host_override.unwrap_or(EU_ATOP_HOST);

    // ── Step 0: non-account host reachability probe (NOT a signed call). ──────
    probe_host(host)?;
    eprintln!("live: host {host} reachable (non-account TLS probe ok).");

    // Single blocking client, short timeout, single-shot use. The User-Agent
    // MUST match the SDK's: `Thing-UA=APP/Android/<appVersion>/SDK/<sdkVersion>`
    // (`ThingSmartNetWork.USER_AGENT` = "Thing-UA=APP/Android", appended with
    // `/<appVersion>/SDK/<sdkVersion>` at init; `decompiled/.../ThingSmartNetWork.java`
    // ~:78/3897). Keep it byte-faithful to the SDK request shape.
    let user_agent = format!(
        "Thing-UA=APP/Android/{}/SDK/{}",
        cfg.app_version, THING_SDK_VERSION
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(user_agent)
        .build()
        .map_err(|e| LiveError::Network(format!("build http client: {e}")))?;

    // ── Step 1: the ONE token.get (the sign oracle). ─────────────────────────
    eprintln!("live: sending ONE token.get (sign oracle; HMAC-SHA256(G, str2))...");
    let token = match do_token_get(&client, host, &cfg) {
        Ok(t) => t,
        Err(e @ LiveError::SignRejected { .. }) => {
            // The candidate signer (master key G, incl. bmp_token) is WRONG. STOP —
            // do not proceed to password.login, do not retry/sweep.
            eprintln!("live: token.get SIGN REJECTED — candidate signer needs revisiting. STOP.");
            return Err(e);
        }
        Err(e) => {
            eprintln!("live: token.get failed (non-sign). STOP.");
            return Err(e);
        }
    };
    eprintln!("live: token.get ACCEPTED — signer VALIDATED (master key G + bmp_token candidate).");

    // We have the gold differential. Record it; values withheld.
    // (We continue to the ONE password.login per the task.)

    // ── Step 2: THE ONE password.login. ──────────────────────────────────────
    eprintln!("live: sending THE ONE password.login (single attempt, no retry)...");
    match do_password_login(&client, host, &cfg, &token)? {
        LoginResult::Needs2fa(raw) => {
            // Capture the challenge state needed to submit the code later.
            // We persist the WHOLE raw response (it holds the ticket/session the
            // resume task needs); it is written to secrets/ only.
            capture_to_secrets(&cfg, "tuya_2fa_state.json", &raw)?;
            eprintln!("live: reached 2FA email-code challenge. Challenge state captured to secrets/tuya_2fa_state.json. STOP.");
            Ok(LiveOutcome::Needs2fa)
        }
        LoginResult::Success(user) => {
            // Capture session/uid (withheld) to secrets/.
            capture_to_secrets(&cfg, "tuya_session.json", &user)?;
            eprintln!("live: login SUCCESS. Session captured to secrets/tuya_session.json (values withheld).");

            // READ-ONLY: fetch the device list, capture it, confirm SCD921.
            let (camera_found, p2p_type) =
                fetch_and_capture_device_list(&client, host, &cfg, &user)?;
            Ok(LiveOutcome::LoggedIn {
                camera_found,
                p2p_type,
            })
        }
    }
}

/// Non-account host reachability: open a TLS connection (HEAD-equivalent) to the
/// gateway. This is a NETWORK-level check, NOT a signed account request, so it is
/// safe to do before validating the host.
fn probe_host(host: &str) -> Result<(), LiveError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| LiveError::Network(format!("build probe client: {e}")))?;
    // A bare GET to the host root with no signed params is not an account call;
    // any HTTP response (even 4xx) proves reachability + TLS.
    //
    // SECRET-LEAK HARDENING (TASK-0042): although this probe URL carries NO signed
    // query (no clientId/sign/chKey), we STILL route the error through
    // `scrub_url_secrets` so EVERY reqwest-error path in this module is uniformly
    // URL-redacted — a defence-in-depth invariant (no error path may ever embed a
    // request URL), not a per-call judgement that this one is safe.
    match client.get(format!("https://{host}/")).send() {
        Ok(_) => Ok(()),
        Err(e) => Err(LiveError::Network(format!(
            "host {host} not reachable: {}",
            scrub_url_secrets(&e)
        ))),
    }
}

/// Build the SIGNED `device.list` atop request carrying the injected/post-login
/// `sid`. PURE — no network, no I/O. This is the SINGLE SOURCE OF TRUTH for the
/// device-list request shape, used by BOTH the post-login fetch
/// ([`fetch_and_capture_device_list`]) and the injected-sid read path
/// ([`run_injected_device_list`]), so the two produce a byte-identical envelope.
///
/// The `sid` is folded into the envelope BEFORE signing (it is in the sign
/// whitelist `bdpdqbp`, `re/tuya_sign.md` §1 line ~:82: `… sid, chKey …`), so a
/// non-empty `sid` enters the canonical string `str2` and the signature covers it
/// — exactly where the SDK puts it (`ApiParams.getSession` → wire `sid`,
/// `re/tuya_cloud_auth.md` §1 line ~:84). An empty `sid` is dropped (the signer
/// filters empty whitelist values), which is the pre-login shape.
fn build_device_list_request(
    cfg: &LiveConfig,
    sid: &str,
    ecode: Option<&str>,
) -> Result<(BTreeMap<String, String>, String), LiveError> {
    let post_data = "{}";
    let extra = if sid.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([("sid".to_string(), sid.to_string())])
    };
    build_signed_envelope_with(
        cfg,
        DEVICE_LIST_ACTION,
        DEVICE_LIST_VERSION,
        post_data,
        &extra,
        ecode,
    )
}

/// READ-ONLY device-list fetch + capture. Returns (camera_found, p2p_type).
///
/// Builds the request via [`build_device_list_request`] (the shared builder) with
/// the post-login `sid` taken from the in-process login `User`. On any failure we
/// surface it but do NOT retry-spam.
fn fetch_and_capture_device_list(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
    user: &serde_json::Value,
) -> Result<(bool, Option<i32>), LiveError> {
    let sid = user.get("sid").and_then(|v| v.as_str()).unwrap_or("");
    let ecode = user.get("ecode").and_then(|v| v.as_str());
    let (envelope, body) = build_device_list_request(cfg, sid, ecode)?;

    let resp = send_atop(client, host, cfg, &envelope, &body)?;
    capture_to_secrets(cfg, "tuya_device_list.json", &resp.raw)?;
    if !resp.success {
        // Surface (no retry) but still report the captured shape if any.
        eprintln!("live: device-list fetch returned a server error (captured raw to secrets/).");
    }
    Ok(inspect_device_list(&resp.raw))
}

/// Inspect a captured device-list response for the SCD921 camera + p2pType.
/// Returns (camera_found, p2p_type) — SHAPE only, no values echoed.
///
/// The atop envelope wraps the payload under `result`; the device-list container
/// (`HomeBean`) lives there. We try the core parser on the `result` sub-object
/// first (the typed path), then fall back to a direct scan that also surfaces any
/// `p2pType`. The whole-envelope is never fed to the core parser (it would parse
/// to an empty list and silently mask the camera).
fn inspect_device_list(raw: &serde_json::Value) -> (bool, Option<i32>) {
    let result = raw.get("result").unwrap_or(raw);

    // Typed path: the core parser over the `result` object (HomeBean-shaped).
    if let Ok(body) = serde_json::to_vec(result) {
        if let Ok(list) = babymonitor_core::device::parse_device_list(&body) {
            if list.find_camera_device().is_some() {
                let p2p = scan_p2p_type(result);
                return (true, p2p);
            }
        }
    }

    // Fallback scan: any device with a camera category, plus any p2pType.
    let mut found = false;
    if let Some(arr) = result.get("deviceList").and_then(|d| d.as_array()) {
        for d in arr {
            let cat = d.get("category").and_then(|v| v.as_str()).unwrap_or("");
            if cat == "sp" || cat == "ipc" {
                found = true;
            }
        }
    }
    (found, scan_p2p_type(result))
}

/// Find the first `p2pType` integer anywhere in a device-list payload (the
/// transport selector — 4=WebRTC/2=PPCS). SHAPE only.
fn scan_p2p_type(result: &serde_json::Value) -> Option<i32> {
    if let Some(arr) = result.get("deviceList").and_then(|d| d.as_array()) {
        for d in arr {
            if let Some(t) = d.get("p2pType").and_then(serde_json::Value::as_i64) {
                return Some(t as i32);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A SYNTHETIC LiveConfig for envelope tests — no real secret. The bmp_token
    /// is a placeholder so signing yields a deterministic value; chKey is a fixed
    /// synthetic native-shaped 16-hex value.
    fn synthetic_cfg() -> LiveConfig {
        LiveConfig {
            creds: LoginCreds {
                email: "user@example.com".into(),
                password: "pw".into(),
            },
            material: SigningKeyMaterial {
                app_key: "SYNTH_APPKEY_000000".into(),
                app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
                app_cert_sha256: [0xABu8; 32],
                ttid: "SYNTH_TTID".into(),
            },
            // SYNTHETIC 64-hex bmp_token → decodes to 32 raw bytes (matrixKey0), so
            // the signer produces a deterministic value instead of erroring.
            bmp_token: "cd".repeat(32),
            app_version: "1.9.0".into(),
            // Stable per-install PhoneUtil-shaped id (44 lowercase-hex): the app
            // ALWAYS sends+signs a deviceId (TASK-0064). Synthetic, deterministic.
            device_id: "ab".repeat(22),
            android: AndroidProfile::default(),
            ch_key: "cd".repeat(8), // synthetic 16-hex
            secrets_dir: std::env::temp_dir(),
        }
    }

    fn canonical_for_params(params: &BTreeMap<String, String>, wire_post_data: &str) -> String {
        use babymonitor_core::sign::{canonical_string, post_data_digest_hex};

        let mut sign_params = params.clone();
        sign_params.remove("sign");
        sign_params.insert(
            "postData".into(),
            post_data_digest_hex(wire_post_data.as_bytes()).unwrap(),
        );
        canonical_string(&sign_params)
    }

    // AC: chKey MUST be present in BOTH the wire form params AND the canonical sign
    // string (it is in SIGN_WHITELIST). This proves it rides both the APK-shaped
    // wire form and canonical string.
    #[test]
    fn envelope_carries_chkey_in_wire_and_canonical_sign() {
        let cfg = synthetic_cfg();
        let (envelope, body) =
            build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}")
                .expect("envelope build");

        // (1) chKey is in the wire form params, with the configured value.
        assert_eq!(
            envelope.get("chKey").map(String::as_str),
            Some(cfg.ch_key.as_str()),
            "chKey must ride the wire form params"
        );

        // (2) chKey enters the CANONICAL SIGN STRING. Reconstruct the exact sign
        // input the builder uses: params minus `sign`, plus digest(encrypted postData).
        let canonical = canonical_for_params(&envelope, &body);
        assert!(
            canonical.contains(&format!("chKey={}", cfg.ch_key)),
            "chKey must appear in the canonical sign string; got: {canonical}"
        );
    }

    // The SDK-fidelity params the real initUrlParams sends are all on the wire.
    #[test]
    fn envelope_carries_sdk_fidelity_params() {
        let cfg = synthetic_cfg();
        let (envelope, _body) =
            build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}")
                .expect("envelope build");
        for k in [
            "sdkVersion",
            "deviceCoreVersion",
            "channel",
            "nd",
            "osSystem",
            "platform",
            "timeZoneId",
            "cp",
            "bizData",
            "appRnVersion",
        ] {
            assert!(
                envelope.contains_key(k),
                "envelope must carry SDK-fidelity param {k}"
            );
        }
        assert_eq!(envelope.get("cp").map(String::as_str), Some("gzip"));
        assert_eq!(
            envelope.get("deviceCoreVersion").map(String::as_str),
            Some("6.7.0")
        );
        assert_eq!(envelope.get("nd").map(String::as_str), Some("1"));
        // TASK-0047: production init routes through the CHANNEL_OEM overload, so
        // the wire channel is "oem", not "sdk".
        assert_eq!(envelope.get("channel").map(String::as_str), Some("oem"));
        // TASK-0048: the app sends appRnVersion (non-empty BuildConfig value).
        assert_eq!(
            envelope.get("appRnVersion").map(String::as_str),
            Some("5.92")
        );
        let biz_data: serde_json::Value =
            serde_json::from_str(envelope.get("bizData").expect("bizData value"))
                .expect("bizData is JSON");
        assert_eq!(biz_data["customDomainSupport"], "1");
        assert_eq!(biz_data["nd"], "1");
        assert_eq!(biz_data["sdkInt"], DEFAULT_SDK_INT);
        assert_eq!(biz_data["brand"], DEFAULT_BRAND);
    }

    // TASK-0047: the wire `ttid` is the rewritten `sdk_<channel>@<appKey>`, NOT
    // the raw philipsclnightowl ttid, and because `ttid` is in SIGN_WHITELIST the
    // rewritten value must enter the canonical sign string.
    #[test]
    fn envelope_ttid_is_rewritten_sdk_channel_appkey_form_and_signed() {
        use babymonitor_core::sign::canonical_string;

        let cfg = synthetic_cfg();
        let (envelope, _b) =
            build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}").unwrap();

        let expected = format!("sdk_international@{}", cfg.material.app_key);
        assert_eq!(
            envelope.get("ttid").map(String::as_str),
            Some(expected.as_str()),
            "wire ttid must be sdk_<channel>@<appKey> (TASK-0047)"
        );
        // It must NOT be the raw configured ttid (philipsclnightowl-equivalent).
        assert_ne!(
            envelope.get("ttid").map(String::as_str),
            Some(cfg.material.ttid.as_str()),
            "wire ttid must NOT be the raw material.ttid"
        );
        // ttid is whitelisted → the rewritten value is in the canonical string.
        let canonical = canonical_string(&envelope);
        assert!(
            canonical.contains(&format!("ttid={expected}")),
            "rewritten ttid must appear in the canonical sign string; got: {canonical}"
        );
    }

    #[test]
    fn wire_ttid_helper_form() {
        assert_eq!(wire_ttid("ABC123"), "sdk_international@ABC123");
    }

    // Removing chKey from the envelope MUST change the canonical sign string —
    // proving chKey is load-bearing for the signature (it is whitelisted).
    #[test]
    fn chkey_changes_the_canonical_sign() {
        use babymonitor_core::sign::canonical_string;
        let cfg = synthetic_cfg();
        let (envelope, _b) =
            build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}").unwrap();
        let with_chkey = canonical_string(&envelope);
        let mut without = envelope.clone();
        without.remove("chKey");
        let without_chkey = canonical_string(&without);
        assert_ne!(
            with_chkey, without_chkey,
            "chKey is whitelisted → dropping it must change the canonical string"
        );
    }

    #[test]
    fn request_shape_uses_uuid_request_id_seconds_time_and_encrypted_form_body() {
        let cfg = synthetic_cfg();
        let (params, body) =
            build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}").unwrap();

        let request_id = params.get("requestId").expect("requestId");
        assert_eq!(request_id.len(), 36);
        assert_eq!(&request_id[14..15], "4", "UUID version nibble");
        assert!(
            matches!(&request_id[19..20], "8" | "9" | "a" | "b"),
            "UUID variant nibble: {request_id}"
        );
        assert_eq!(
            request_id.chars().filter(|c| *c == '-').count(),
            4,
            "UUID string has four hyphens"
        );

        let time = params.get("time").expect("time");
        assert_eq!(time.len(), 10, "Java TimeStampManager sends epoch seconds");
        assert!(time.chars().all(|c| c.is_ascii_digit()));

        assert_ne!(body, "{}", "wire postData is ET=3 encrypted, not raw JSON");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .expect("encrypted postData is standard base64");
        assert!(
            decoded.len() >= 12 + 16,
            "nonce(12) + GCM tag(16) must be present"
        );

        let form = form_body(&params, &body);
        assert!(form.starts_with("postData="));
        assert!(
            form.contains("platform=Pixel+8+Pro"),
            "OkHttp FormBody encodes spaces as '+': {form}"
        );
        // deviceId is ALWAYS on the wire (TASK-0064) — the app sends+signs it on
        // every request; see the dedicated sign-coverage test below.
        for k in [
            "sign",
            "a",
            "v",
            "clientId",
            "time",
            "requestId",
            "chKey",
            "deviceId",
        ] {
            assert!(form.contains(&format!("{k}=")), "form missing {k}: {form}");
        }
    }

    // TASK-0064: the login envelope ALWAYS sends a deviceId AND signs it (the real
    // app's ApiParams subclass injects PhoneUtil.getDeviceID into both
    // getRequestBody:89 and initUrlParams:227, and KEY_DEVICEID is in
    // SIGN_WHITELIST). It is never gated behind a caller pin.
    #[test]
    fn device_id_always_sent_and_signed() {
        let cfg = synthetic_cfg();
        let (envelope, body) =
            build_signed_envelope(&cfg, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}").unwrap();
        // (1) deviceId rides the wire with the configured stable value.
        assert_eq!(
            envelope.get("deviceId").map(String::as_str),
            Some(cfg.device_id.as_str()),
            "deviceId must always ride the wire form params"
        );
        // (2) deviceId enters the canonical SIGN string (it is whitelisted).
        assert!(
            canonical_for_params(&envelope, &body).contains(&format!("deviceId={}", cfg.device_id)),
            "deviceId must be signed into the canonical string"
        );
    }

    // TASK-0064: a different deviceId MUST change the canonical sign string —
    // proving it is genuinely an input to the keyed sign, not cosmetic.
    #[test]
    fn different_device_id_changes_the_canonical_string() {
        use babymonitor_core::sign::canonical_string;
        let mut a = synthetic_cfg();
        a.device_id = "aa".repeat(22);
        let mut b = synthetic_cfg();
        b.device_id = "bb".repeat(22);
        let (ea, _) = build_signed_envelope(&a, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}").unwrap();
        let (eb, _) = build_signed_envelope(&b, TOKEN_GET_ACTION, TOKEN_GET_VERSION, "{}").unwrap();
        let mut pa = ea.clone();
        let mut pb = eb.clone();
        pa.remove("sign");
        pb.remove("sign");
        pa.insert("postData".into(), "SAME_DIGEST".into());
        pb.insert("postData".into(), "SAME_DIGEST".into());
        assert_ne!(
            canonical_string(&pa),
            canonical_string(&pb),
            "a different deviceId must change the canonical sign string"
        );
    }

    // TASK-0064: deviceId resolution — caller-pin wins; else a generated id is
    // persisted and STABLE across calls (mirrors PhoneUtil's cached mDeviceId).
    #[test]
    fn device_id_pinned_wins_else_generated_persisted_and_stable() {
        let dir = std::env::temp_dir().join(format!(
            "bmp-devid-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // (a) Caller-pinned wins and is trimmed; no file is written for it.
        let pinned = AndroidProfile {
            device_id: Some("  PINNED_DEVICE_0001  ".into()),
            ..Default::default()
        };
        let id = load_or_create_device_id(&dir, &pinned).unwrap();
        assert_eq!(id, "PINNED_DEVICE_0001", "pinned id wins, trimmed");
        assert!(
            !dir.join("device_id.txt").exists(),
            "pinned path must not write device_id.txt"
        );

        // (b) No pin, no file -> generate + persist a 44-char lowercase-hex id.
        let android = AndroidProfile::default();
        let gen = load_or_create_device_id(&dir, &android).unwrap();
        assert_eq!(gen.len(), 44, "generated deviceId is 44 chars");
        assert!(
            gen.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "generated deviceId is lowercase hex: {gen}"
        );
        assert!(dir.join("device_id.txt").exists(), "id must be persisted");

        // (c) Stable: a second call returns the SAME persisted id (per install).
        let again = load_or_create_device_id(&dir, &android).unwrap();
        assert_eq!(again, gen, "persisted deviceId is stable across calls");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn et3_post_data_matches_java_nonce_prefix_layout() {
        let cfg = synthetic_cfg();
        let nonce = [0xa5; 12];
        let body = encrypt_et3_post_data_with_nonce(
            &cfg,
            "trace-id",
            r#"{"hello":"world"}"#,
            None,
            &nonce,
        )
        .unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("encrypted postData is standard base64");

        assert_eq!(
            &decoded[..12],
            &nonce,
            "AesGcmUtil.encryptBytes2BytesAppendNonce stores nonce first"
        );
        assert!(
            decoded.len() > 12 + r#"{"hello":"world"}"#.len(),
            "ciphertext plus GCM tag follows the nonce"
        );
    }

    #[test]
    fn uuid_v4_from_bytes_sets_java_uuid_bits() {
        let id = uuid_v4_from_bytes([0u8; 16]);
        assert_eq!(id, "00000000-0000-4000-8000-000000000000");
    }

    #[test]
    fn rewrite_action_maps_thing_to_smartlife() {
        assert_eq!(
            rewrite_action("thing.m.user.username.token.get"),
            "smartlife.m.user.username.token.get"
        );
        // Non-thing names pass through untouched.
        assert_eq!(rewrite_action("a.m.x"), "a.m.x");
    }

    #[test]
    fn urlencode_escapes_non_unreserved() {
        assert_eq!(urlencode("a b{}"), "a+b%7B%7D");
        assert_eq!(urlencode("safe-_.~"), "safe-_.~");
    }

    // corrupt_one_nibble (TASK-0050): the differential's corrupted sign MUST keep
    // the same length and hex alphabet (so the gateway parses + reaches
    // sign-verification) while differing in exactly one character.
    #[test]
    fn corrupt_one_nibble_preserves_shape_changes_one_char() {
        // A representative 64-char lowercase HMAC-SHA256 hex (the sign's shape).
        let sign = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let corrupted = corrupt_one_nibble(sign).expect("hex input must corrupt");
        assert_eq!(corrupted.len(), sign.len(), "length preserved");
        assert_ne!(corrupted, sign, "value changed");
        assert!(
            corrupted
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "still lowercase hex: {corrupted}"
        );
        // Exactly ONE character differs.
        let diffs = sign
            .chars()
            .zip(corrupted.chars())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(diffs, 1, "exactly one nibble flipped");
        // The flip is deterministic: first nibble 0 -> 1.
        assert_eq!(&corrupted[..1], "1");
    }

    // The flip must change EVERY hex digit (no fixed point), incl. 'f' -> 'e'.
    #[test]
    fn corrupt_one_nibble_handles_f_and_rejects_nonhex() {
        let flipped = corrupt_one_nibble("ffffffff").expect("hex corrupts");
        assert_eq!(&flipped[..1], "e", "f flips to e (f^1)");
        // A non-hex sign is a programmer error -> typed Crypto error, not a panic.
        assert!(matches!(
            corrupt_one_nibble("zzzz"),
            Err(LiveError::Crypto(_))
        ));
        assert!(matches!(corrupt_one_nibble(""), Err(LiveError::Crypto(_))));
    }

    // redact_query MUST strip a signed query string (clientId=appKey & sign=...)
    // from any error message so secret-by-policy values cannot leak into logs.
    #[test]
    fn redact_query_strips_signed_query() {
        let leaky = "error sending request for url (https://a1.tuyaeu.com/api.json?a=x&clientId=wxSECRETKEY123&sign=deadbeefSIGNVALUE)";
        let safe = redact_query(leaky);
        assert!(!safe.contains("wxSECRETKEY123"), "appKey leaked: {safe}");
        assert!(!safe.contains("deadbeefSIGNVALUE"), "sign leaked: {safe}");
        assert!(safe.contains("?<redacted-signed-query>"));
        // The non-secret prefix (scheme/host/path) is preserved for context.
        assert!(safe.contains("https://a1.tuyaeu.com/api.json"));
        assert!(safe.ends_with(')'));
        // No '?' query survives untouched anywhere.
        assert!(!safe.contains("clientId="));
    }

    #[test]
    fn parse_biguint_decimal_and_hex() {
        assert_eq!(parse_biguint("65537"), Some(BigUint::from(65537u32)));
        // 0xff = 255 (has hex letter 'f' so parsed as hex).
        assert_eq!(parse_biguint("ff"), Some(BigUint::from(255u32)));
        assert_eq!(parse_biguint(""), None);
    }

    // (TASK-0064 restored the always-on, stable, persisted PhoneUtil-shaped
    // deviceId: see `device_id_always_sent_and_signed`,
    // `different_device_id_changes_the_canonical_string`, and
    // `device_id_pinned_wins_else_generated_persisted_and_stable`.)

    // classify_error: a sign-shaped error is the gold negative (SignRejected);
    // an unrelated error is a plain Server error.
    #[test]
    fn classify_error_detects_sign_rejection() {
        let sign_resp = AtopResponse {
            success: false,
            error_code: Some("SIGN_INVALID".into()),
            error_msg: Some("sign invalid".into()),
            result: serde_json::Value::Null,
            raw: serde_json::Value::Null,
        };
        assert!(matches!(
            classify_error(&sign_resp),
            LiveError::SignRejected { .. }
        ));

        let other = AtopResponse {
            success: false,
            error_code: Some("USER_PASSWD_WRONG".into()),
            error_msg: Some("password wrong".into()),
            result: serde_json::Value::Null,
            raw: serde_json::Value::Null,
        };
        assert!(matches!(classify_error(&other), LiveError::Server { .. }));
    }

    #[test]
    fn is_2fa_challenge_detects_mfa_markers() {
        let r = AtopResponse {
            success: false,
            error_code: Some("USER_NEED_MFA".into()),
            error_msg: Some("verification code required".into()),
            result: serde_json::Value::Null,
            raw: serde_json::Value::Null,
        };
        assert!(is_2fa_challenge(&r));

        let not = AtopResponse {
            success: false,
            error_code: Some("USER_PASSWD_WRONG".into()),
            error_msg: Some("password wrong".into()),
            result: serde_json::Value::Null,
            raw: serde_json::Value::Null,
        };
        assert!(!is_2fa_challenge(&not));
    }

    #[test]
    fn result_indicates_2fa_when_marker_and_no_sid() {
        let chal = serde_json::json!({ "mfaToken": "x", "flowId": "y" });
        assert!(result_indicates_2fa(&chal));
        let logged_in = serde_json::json!({ "sid": "s", "uid": "u" });
        assert!(!result_indicates_2fa(&logged_in));
    }

    // inspect_device_list finds a camera by category and reports SHAPE only.
    #[test]
    fn inspect_device_list_finds_camera_shape() {
        let raw = serde_json::json!({
            "result": { "deviceList": [ { "devId": "d", "category": "sp", "p2pType": 4 } ] }
        });
        let (found, _p2p) = inspect_device_list(&raw);
        assert!(found, "an sp-category device must be reported as a camera");
    }

    // ── TASK-0055: injected-session device.list request shape (OFFLINE) ─────────

    // CORE AC#2: an INJECTED sid must ride the device.list request on BOTH the
    // wire envelope AND the canonical sign string. This is the proof the captured
    // session actually drives — and is signed into — the real read-path request,
    // with NO network call. The fake sid is obviously-synthetic.
    #[test]
    fn injected_sid_rides_device_list_envelope_and_canonical_sign() {
        let cfg = synthetic_cfg();
        let fake_sid = "FAKE_INJECTED_SID_0001"; // SYNTHETIC — never a real sid.

        let (envelope, body) =
            build_device_list_request(&cfg, fake_sid, None).expect("device.list request build");

        // (0) It is the device.list action, byte-faithful to the shared constant
        // (rewritten thing*→smartlife* on the wire), with encrypted postData.
        assert_eq!(
            envelope.get("a").map(String::as_str),
            Some(rewrite_action(DEVICE_LIST_ACTION).as_str()),
            "wire action must be the device.list action"
        );
        assert_eq!(
            envelope.get("v").map(String::as_str),
            Some(DEVICE_LIST_VERSION)
        );
        assert_ne!(body, "{}", "device.list postData is ET=3 encrypted");

        // (1) The injected sid is in the wire form params with its exact value.
        assert_eq!(
            envelope.get("sid").map(String::as_str),
            Some(fake_sid),
            "the injected sid must ride the wire form params"
        );

        // (2) The injected sid enters the CANONICAL SIGN STRING (sid is in the
        // whitelist bdpdqbp, re/tuya_sign.md §1) — so the signature covers it.
        let canonical = canonical_for_params(&envelope, &body);
        assert!(
            canonical.contains(&format!("sid={fake_sid}")),
            "injected sid must appear in the canonical sign string; got: {canonical}"
        );

        // (3) The sign value is present and non-empty (the request is fully signed).
        assert!(
            envelope.get("sign").is_some_and(|s| !s.is_empty()),
            "device.list request must carry a non-empty sign"
        );
    }

    // NEGATIVE: with an EMPTY sid (the pre-login shape) the request must NOT carry
    // a `sid` param at all — neither on the wire nor in the canonical string. This
    // proves the sid is genuinely sourced from the injection, not hardcoded.
    #[test]
    fn empty_sid_is_dropped_from_device_list_request() {
        let cfg = synthetic_cfg();
        let (envelope, _body) = build_device_list_request(&cfg, "", None).expect("build");

        assert!(
            !envelope.contains_key("sid"),
            "an empty sid must be dropped (pre-login shape), not sent empty"
        );

        let canonical = canonical_for_params(&envelope, "");
        assert!(
            !canonical.contains("sid="),
            "empty sid must not enter the canonical sign string; got: {canonical}"
        );
    }

    // A different injected sid MUST change the signature (the sid is genuinely an
    // input to the keyed sign, not cosmetic). Guards against a regression where
    // the sid is added to the wire but accidentally excluded from the sign input.
    #[test]
    fn different_injected_sid_changes_the_canonical_string() {
        use babymonitor_core::sign::canonical_string;

        let cfg = synthetic_cfg();
        let (e1, _) = build_device_list_request(&cfg, "SID_AAAA", None).unwrap();
        let (e2, _) = build_device_list_request(&cfg, "SID_BBBB", None).unwrap();
        let mut c1_params = e1.clone();
        let mut c2_params = e2.clone();
        c1_params.remove("sign");
        c2_params.remove("sign");
        c1_params.insert("postData".into(), "SAME_POSTDATA_DIGEST".into());
        c2_params.insert("postData".into(), "SAME_POSTDATA_DIGEST".into());
        assert_ne!(
            canonical_string(&c1_params),
            canonical_string(&c2_params),
            "a different injected sid must change the canonical string"
        );
    }

    // NEGATIVE / honesty: run_injected_device_list with NO session injected must
    // report the no-session state and touch NO network (it returns BEFORE building
    // any HTTP client or making any call). Uses a temp store with no session file.
    #[test]
    fn no_injected_session_reports_blocked_offline() {
        // A unique empty temp store: load() returns None → NoSession, before any
        // config load or network. apk path is irrelevant (never reached).
        let dir = std::env::temp_dir().join(format!(
            "bmp-inject-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = SessionStore::at(dir.join("session.json"));
        let out =
            run_injected_device_list(Path::new("secrets"), Path::new("nonexistent.apk"), &store)
                .expect("no-session path must not error");
        assert!(
            matches!(out, InjectedOutcome::NoSession),
            "no injected session must report NoSession (honest blocked), got {out:?}"
        );
    }

    // host_from_mobile_api_base parses the gateway host and falls back to EU.
    #[test]
    fn host_from_mobile_api_base_parses_and_falls_back() {
        assert_eq!(
            host_from_mobile_api_base("https://a1.tuyaeu.com/api.json"),
            "a1.tuyaeu.com"
        );
        // Empty / unparseable → EU fallback (never panics, never an empty host).
        assert_eq!(host_from_mobile_api_base(""), EU_ATOP_HOST);
        assert_eq!(host_from_mobile_api_base("not a url"), EU_ATOP_HOST);
    }
}
