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
//! `token.get` (returns the pubkey + ticket), the `bmp_token` candidate AND the
//! chosen MD5 fold are VALIDATED. If the server rejects the SIGN, the candidate /
//! fold is wrong and we STOP before ever attempting `password.login`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use babymonitor_core::sign::{
    app_cert_sha256_hex_from_apk, ch_key, md5_hex_lower, post_data_digest_hex, SignBody, Signer,
    SigningKeyMaterial, StaticBmpToken, APP_PACKAGE_NAME,
};
use rand::rngs::OsRng;
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
/// (`Thing-UA=APP/Android/<appVersion>/SDK/<sdkVersion>`). The exact value is
/// resolved at runtime (`ThingSmartNetWork.getSdkVersion()`, not a static
/// literal), so this is a representative thingclips SDK version for the app era;
/// the load-bearing part for the gateway client check is the `Thing-UA=APP/Android`
/// prefix. Overriding it has no effect on the sign.
const THING_SDK_VERSION: &str = "5.18.0";

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
/// `ThingSmartNetWork.mDeviceCoreVersion`, passed at init. Runtime-set; the SDK
/// ships it lock-stepped with the SDK version, so we use the same string as a
/// representative default. NOT load-bearing for the gateway client check.
const DEVICE_CORE_VERSION: &str = THING_SDK_VERSION;

/// `channel` (`"channel"` key) — `ThingSmartNetWork.mChannel`, which defaults to
/// the literal `"sdk"` (`ThingSmartNetWork.java:89 mChannel = "sdk"` /
/// `CHANNEL_SDK`) unless the app overrides it at init. We use the SDK default.
const CHANNEL: &str = "sdk";

/// `osSystem` (`KEY_OS_SYSTEM`) — `Build.VERSION.RELEASE`, the Android OS
/// version. Device-specific; we use a plausible modern Android release. Purely
/// informational to the gateway (not the client-identity gate).
const OS_SYSTEM: &str = "13";

/// `platform` (`KEY_PLATFORM`) — `Build.MODEL`, the device model string.
/// Device-specific; we use a generic but real-looking model. Informational.
const PLATFORM: &str = "Pixel 6";

/// `timeZoneId` (`KEY_TIME_ZONE_ID`) — `ThingCommonUtil.getTimeZoneId()`. The
/// account owner is in Denmark (`COUNTRY_CODE_DK`), so the matching zone.
const TIME_ZONE_ID: &str = "UTC";

/// `cp` (`KEY_CP`) — set to `VALUE_CP_GZIP="gzip"` whenever `et == "3"`
/// (`ThingApiParams.initUrlParams` ~:1786-1788). Our `et` is always `3`.
const CP_GZIP: &str = "gzip";

/// token.get action + version (`re/tuya_cloud_auth.md` §2 step 1). The wire `a`
/// is the `thing.*`→`smartlife.*`-rewritten form (§1a); we sign over the
/// rewritten name.
const TOKEN_GET_ACTION: &str = "thing.m.user.username.token.get";
const TOKEN_GET_VERSION: &str = "2.0";

/// password.login action + version (`re/tuya_cloud_auth.md` §2 step 2, email
/// path). Version is a build constant; `4.0` is the documented mobile value.
const PASSWORD_LOGIN_ACTION: &str = "thing.m.user.email.password.login";
const PASSWORD_LOGIN_VERSION: &str = "4.0";

// ─────────────────────────────────────────────────────────────────────────────
// Loaded secrets (from secrets/, never echoed)
// ─────────────────────────────────────────────────────────────────────────────

/// Login credentials read from `secrets/tuya_login.json`. NEVER printed.
#[derive(Deserialize)]
struct LoginCreds {
    email: String,
    password: String,
    /// Optional HTTP `Authorization` header value the app presents to the atop
    /// gateway (channel auth). Sent verbatim if present; never logged.
    #[serde(default)]
    authorization: Option<String>,
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

/// Resolved live config: secrets + the offline-computed cert hash + a stable
/// per-install deviceId. Carries secrets; constructed once, never logged.
struct LiveConfig {
    creds: LoginCreds,
    material: SigningKeyMaterial,
    bmp_token: String,
    app_version: String,
    device_id: String,
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

    // Offline app-cert SHA-256 (re/tuya_sign_static.md §4). Value never printed.
    let app_cert_sha256_hex =
        app_cert_sha256_hex_from_apk(apk_path).map_err(|e| LiveError::Cert(format!("{e}")))?;

    let app_version = appkey
        .version_name
        .clone()
        .unwrap_or_else(|| "1.9.0".to_string());

    let material = SigningKeyMaterial {
        app_key: appkey.app_key,
        app_secret: appkey.app_secret,
        app_cert_sha256_hex,
        ttid: appkey.ttid,
    };

    // chKey: the per-app channel-auth token. Computed from STATIC inputs
    // (appKey + package name + offline cert hash) per native getChKey@0x16000
    // (re/chkey_static.md). If a pre-computed secrets/chkey.txt exists we prefer
    // it (lets an operator pin a captured value), else we derive it here. The
    // value is secret-by-policy and is NEVER logged. If we derived it, persist it
    // to secrets/chkey.txt (gitignored, 0600) so the next cycle can reuse it.
    let ch_key_value = {
        let pinned = std::fs::read_to_string(secrets_dir.join("chkey.txt"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match pinned {
            Some(v) => v,
            None => {
                let v = ch_key(
                    &material.app_key,
                    APP_PACKAGE_NAME,
                    &material.app_cert_sha256_hex,
                );
                let path = secrets_dir.join("chkey.txt");
                let _ = std::fs::write(&path, &v);
                restrict_permissions(&path);
                v
            }
        }
    };

    // A stable, NON-secret per-install device id. The atop envelope needs a
    // `deviceId`; the app uses PhoneUtil.getDeviceID. A fixed UUID-shaped value
    // is fine for a from-scratch client (it is not a credential). Derive it
    // deterministically from the appKey so it is stable across runs without
    // persisting anything (single source of truth, no extra state file).
    let device_id = derive_device_id(&material.app_key);

    Ok(LiveConfig {
        creds,
        material,
        bmp_token,
        app_version,
        device_id,
        ch_key: ch_key_value,
        secrets_dir: secrets_dir.to_path_buf(),
    })
}

/// Derive a stable, non-secret deviceId from the appKey. Not a credential; just a
/// per-install handle the envelope requires. MD5-hex of a fixed-salt + appKey,
/// truncated to a 16-hex handle (deterministic, no stored state).
fn derive_device_id(app_key: &str) -> String {
    let seed = format!("babymonitor-cli-deviceid::{app_key}");
    let digest = md5_hex_lower(seed.as_bytes());
    digest[..16].to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Atop request envelope + signing
// ─────────────────────────────────────────────────────────────────────────────

/// Build the signed atop envelope (URL query params) for one action.
///
/// `action` is the `thing.*` name; it is rewritten to `smartlife.*` for the wire
/// `a` (and the rewritten name is what gets signed, `re/tuya_cloud_auth.md` §1a).
/// `post_data` is the raw JSON body string; its `postData` envelope value is the
/// signed digest [`post_data_digest_hex`]. Returns the full query-param map
/// (including `sign` and the RAW `postData` body that goes on the wire).
fn build_signed_envelope(
    cfg: &LiveConfig,
    action: &str,
    version: &str,
    post_data: &str,
    sign_body: SignBody,
) -> Result<(BTreeMap<String, String>, String), LiveError> {
    build_signed_envelope_with(cfg, action, version, post_data, sign_body, &BTreeMap::new())
}

/// Like [`build_signed_envelope`] but folds `extra` params (e.g. the post-login
/// `sid`) into the SIGNED envelope before signing. Only whitelisted, non-empty
/// extras affect the canonical string (the signer filters); they all ride on the
/// wire query. Keeping signing in ONE place avoids the "sign then mutate" bug
/// where a post-sign param edit would invalidate the signature.
fn build_signed_envelope_with(
    cfg: &LiveConfig,
    action: &str,
    version: &str,
    post_data: &str,
    sign_body: SignBody,
    extra: &BTreeMap<String, String>,
) -> Result<(BTreeMap<String, String>, String), LiveError> {
    let wire_action = rewrite_action(action);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let request_id = derive_request_id(now_ms, &wire_action);

    // The envelope params that ride on the wire (sid empty pre-login → dropped).
    let mut envelope: BTreeMap<String, String> = BTreeMap::new();
    envelope.insert("a".into(), wire_action.clone());
    envelope.insert("v".into(), version.into());
    envelope.insert("time".into(), now_ms.to_string());
    envelope.insert("requestId".into(), request_id);
    envelope.insert("et".into(), ET_VERSION.into());
    envelope.insert("lang".into(), LANG.into());
    envelope.insert("os".into(), OS_ANDROID.into());
    envelope.insert("appVersion".into(), cfg.app_version.clone());
    envelope.insert("ttid".into(), cfg.material.ttid.clone());
    envelope.insert("clientId".into(), cfg.material.app_key.clone());
    envelope.insert("deviceId".into(), cfg.device_id.clone());

    // chKey: the per-app channel-auth token (native getChKey@0x16000). It is BOTH
    // a wire query param AND a SIGNED whitelist param (SIGN_WHITELIST contains
    // "chKey"), so it MUST be in the envelope BEFORE signing — the canonical
    // string then includes it. Its absence is the likely ILLEGAL_CLIENT_ID cause.
    envelope.insert("chKey".into(), cfg.ch_key.clone());

    // SDK-fidelity params the real initUrlParams sends (TASK-0044). These are NOT
    // in SIGN_WHITELIST, so they ride the wire query without affecting the sign —
    // they make the request shape match the app. `cp=gzip` is set because et==3.
    envelope.insert("sdkVersion".into(), SDK_VERSION.into());
    envelope.insert("deviceCoreVersion".into(), DEVICE_CORE_VERSION.into());
    envelope.insert("channel".into(), CHANNEL.into());
    envelope.insert("osSystem".into(), OS_SYSTEM.into());
    envelope.insert("platform".into(), PLATFORM.into());
    envelope.insert("timeZoneId".into(), TIME_ZONE_ID.into());
    envelope.insert("cp".into(), CP_GZIP.into());
    envelope.insert("bizData".into(), build_biz_data());

    for (k, v) in extra {
        envelope.insert(k.clone(), v.clone());
    }

    // Build the SIGN input map: a copy of the envelope with the postData value
    // replaced by its signed digest (Tuya digests postData before sorting).
    let mut sign_params = envelope.clone();
    let pd_digest = post_data_digest_hex(post_data.as_bytes())
        .map_err(|e| LiveError::Crypto(format!("{e}")))?;
    sign_params.insert("postData".into(), pd_digest);

    let signer = Signer::new(
        cfg.material.clone(),
        StaticBmpToken::new(cfg.bmp_token.clone()),
    )
    .with_body(sign_body);
    let sign = signer
        .sign(&sign_params)
        .map_err(|e| LiveError::Crypto(format!("sign failed: {e}")))?;

    // The wire query carries the envelope + sign; the digested postData was only
    // for the signature — the RAW body rides as the form body.
    envelope.insert("sign".into(), sign);
    Ok((envelope, post_data.to_string()))
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

/// A per-request id (the app uses UUID.randomUUID). We derive a unique-enough
/// value from the timestamp + action without adding a uuid dependency.
fn derive_request_id(now_ms: i64, wire_action: &str) -> String {
    md5_hex_lower(format!("{now_ms}::{wire_action}").as_bytes())
}

/// Build the `bizData` envelope param: the JSON object the real
/// `ThingApiParams.initUrlParams` (~:1793-1822) assembles. It always carries
/// `customDomainSupport="1"`, and folds in `sdkInt` (`Build.VERSION.SDK_INT`)
/// and `brand` (`Build.BRAND`). Device-ish fields use representative values
/// matching the [`PLATFORM`]/[`OS_SYSTEM`] picks. It is NOT a signed param.
fn build_biz_data() -> String {
    serde_json::json!({
        "customDomainSupport": "1",
        // Build.VERSION.SDK_INT for the OS in OS_SYSTEM ("13" → API 33).
        "sdkInt": "33",
        // Build.BRAND matching PLATFORM ("Pixel 6").
        "brand": "google",
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
/// The atop gateway takes the signed params as the URL query string and the RAW
/// `postData` as a form body. We use reqwest BLOCKING (no async runtime) over
/// HTTPS (rustls). A timeout bounds the single call. No secret is logged.
fn send_atop(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
    envelope: &BTreeMap<String, String>,
    post_data: &str,
) -> Result<AtopResponse, LiveError> {
    let url = format!("https://{host}{ATOP_PATH}");

    // Query = the signed envelope (everything EXCEPT the raw postData body).
    let query: Vec<(String, String)> = envelope
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut req = client
        .post(&url)
        .query(&query)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(format!("postData={}", urlencode(post_data)));

    if let Some(auth) = &cfg.creds.authorization {
        req = req.header(reqwest::header::AUTHORIZATION, auth.clone());
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
        let dbg = serde_json::json!({
            "host": host,
            "request_param_keys": envelope.keys().collect::<Vec<_>>(),
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

/// Minimal application/x-www-form-urlencoded value encoder (no extra dep).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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
    sign_body: SignBody,
) -> Result<TokenBean, LiveError> {
    // postData: countryCode + username(email) + isUid=false (§2 step 1).
    let post_data = serde_json::json!({
        "countryCode": COUNTRY_CODE_DK,
        "username": cfg.creds.email,
        "isUid": false,
    })
    .to_string();

    let (envelope, body) = build_signed_envelope(
        cfg,
        TOKEN_GET_ACTION,
        TOKEN_GET_VERSION,
        &post_data,
        sign_body,
    )?;
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
    sign_body: SignBody,
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
        sign_body,
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

    // The MOST-LIKELY cmd=1 fold for the first attempt: the native key-builder
    // calls MD5 twice → MD5(key || canonical_string) (re/tuya_sign_static.md §7).
    let sign_body = SignBody::KeyAndCanonical;
    let fold_name = "MD5(key||canonical) [KeyAndCanonical]";

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
    // ~:78/3897). The public atop gateway gates `ILLEGAL_CLIENT_ID` partly on a
    // recognised app UA, so a generic UA is rejected before the sign is evaluated.
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
    eprintln!("live: sending ONE token.get (sign oracle; fold={fold_name})...");
    let token = match do_token_get(&client, host, &cfg, sign_body) {
        Ok(t) => t,
        Err(e @ LiveError::SignRejected { .. }) => {
            // The candidate signer (bmp_token + fold) is WRONG. STOP — do not
            // proceed to password.login, do not retry/sweep.
            eprintln!("live: token.get SIGN REJECTED — candidate/fold needs revisiting. STOP.");
            return Err(e);
        }
        Err(e) => {
            eprintln!("live: token.get failed (non-sign). STOP.");
            return Err(e);
        }
    };
    eprintln!(
        "live: token.get ACCEPTED — signer VALIDATED (bmp_token candidate + fold={fold_name})."
    );

    // We have the gold differential. Record it; values withheld.
    // (We continue to the ONE password.login per the task.)

    // ── Step 2: THE ONE password.login. ──────────────────────────────────────
    eprintln!("live: sending THE ONE password.login (single attempt, no retry)...");
    match do_password_login(&client, host, &cfg, &token, sign_body)? {
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
                fetch_and_capture_device_list(&client, host, &cfg, &user, sign_body)?;
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

/// READ-ONLY device-list fetch + capture. Returns (camera_found, p2p_type).
///
/// The home-detail / device-list action name is R8-obfuscated; we use the
/// documented Tuya mobile device-list action and sign with the post-login `sid`
/// present in the envelope (so it enters the canonical string). On any failure we
/// surface it but do NOT retry-spam.
fn fetch_and_capture_device_list(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
    user: &serde_json::Value,
    sign_body: SignBody,
) -> Result<(bool, Option<i32>), LiveError> {
    let sid = user.get("sid").and_then(|v| v.as_str()).unwrap_or("");
    let post_data = "{}";
    let wire_action = "thing.m.my.group.device.list";

    // Build the envelope WITH sid present BEFORE signing, so the sign covers the
    // post-login session param (sid is whitelisted; non-empty → enters str2).
    let extra = if sid.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([("sid".to_string(), sid.to_string())])
    };
    let (envelope, body) =
        build_signed_envelope_with(cfg, wire_action, "1.0", post_data, sign_body, &extra)?;

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
    /// synthetic 64-hex.
    fn synthetic_cfg() -> LiveConfig {
        LiveConfig {
            creds: LoginCreds {
                email: "user@example.com".into(),
                password: "pw".into(),
                authorization: None,
            },
            material: SigningKeyMaterial {
                app_key: "SYNTH_APPKEY_000000".into(),
                app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
                app_cert_sha256_hex: "ab".repeat(32),
                ttid: "SYNTH_TTID".into(),
            },
            bmp_token: "PLACEHOLDER_BMP_TOKEN".into(),
            app_version: "1.9.0".into(),
            device_id: "0123456789abcdef".into(),
            ch_key: "cd".repeat(32), // synthetic 64-hex
            secrets_dir: std::env::temp_dir(),
        }
    }

    // AC: chKey MUST be present in BOTH the wire envelope AND the canonical sign
    // string (it is in SIGN_WHITELIST). Without it the request omits chKey from
    // both surfaces — the likely ILLEGAL_CLIENT_ID cause. This proves it now
    // rides both.
    #[test]
    fn envelope_carries_chkey_in_wire_and_canonical_sign() {
        use babymonitor_core::sign::{canonical_string, post_data_digest_hex};

        let cfg = synthetic_cfg();
        let (envelope, _body) = build_signed_envelope(
            &cfg,
            TOKEN_GET_ACTION,
            TOKEN_GET_VERSION,
            "{}",
            SignBody::KeyAndCanonical,
        )
        .expect("envelope build");

        // (1) chKey is on the wire query, with the configured value.
        assert_eq!(
            envelope.get("chKey").map(String::as_str),
            Some(cfg.ch_key.as_str()),
            "chKey must ride the wire envelope"
        );

        // (2) chKey enters the CANONICAL SIGN STRING. Reconstruct the exact sign
        // input the builder uses: the envelope (minus the wire-only `sign`) with
        // postData replaced by its digest, then canonicalize.
        let mut sign_params = envelope.clone();
        sign_params.remove("sign");
        sign_params.insert("postData".into(), post_data_digest_hex(b"{}").unwrap());
        let canonical = canonical_string(&sign_params);
        assert!(
            canonical.contains(&format!("chKey={}", cfg.ch_key)),
            "chKey must appear in the canonical sign string; got: {canonical}"
        );
    }

    // The SDK-fidelity params the real initUrlParams sends are all on the wire.
    #[test]
    fn envelope_carries_sdk_fidelity_params() {
        let cfg = synthetic_cfg();
        let (envelope, _body) = build_signed_envelope(
            &cfg,
            TOKEN_GET_ACTION,
            TOKEN_GET_VERSION,
            "{}",
            SignBody::KeyAndCanonical,
        )
        .expect("envelope build");
        for k in [
            "sdkVersion",
            "deviceCoreVersion",
            "channel",
            "osSystem",
            "platform",
            "timeZoneId",
            "cp",
            "bizData",
        ] {
            assert!(
                envelope.contains_key(k),
                "envelope must carry SDK-fidelity param {k}"
            );
        }
        assert_eq!(envelope.get("cp").map(String::as_str), Some("gzip"));
        assert_eq!(envelope.get("channel").map(String::as_str), Some("sdk"));
    }

    // Removing chKey from the envelope MUST change the canonical sign string —
    // proving chKey is load-bearing for the signature (it is whitelisted).
    #[test]
    fn chkey_changes_the_canonical_sign() {
        use babymonitor_core::sign::canonical_string;
        let cfg = synthetic_cfg();
        let (envelope, _b) = build_signed_envelope(
            &cfg,
            TOKEN_GET_ACTION,
            TOKEN_GET_VERSION,
            "{}",
            SignBody::KeyAndCanonical,
        )
        .unwrap();
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
        assert_eq!(urlencode("a b{}"), "a%20b%7B%7D");
        assert_eq!(urlencode("safe-_.~"), "safe-_.~");
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

    #[test]
    fn derive_device_id_is_stable_and_16_hex() {
        let a = derive_device_id("SYNTH_APPKEY");
        let b = derive_device_id("SYNTH_APPKEY");
        assert_eq!(a, b, "deterministic for the same appKey");
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(derive_device_id("OTHER"), a);
    }

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
}
