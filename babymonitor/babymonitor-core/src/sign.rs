//! Tuya mobile-app ("atop") request signer.
//!
//! Re-implements the Tuya **mobile-app SDK** request-signing algorithm the native
//! `JNICLibrary.doCommandNative(ctx, cmd, str2, …)` computes, in safe Rust, so the
//! client never needs the device's native blob.
//!
//! # Ground truth (Ghidra `libthing_security.so` + jadx; TASK-0060/0061)
//!
//! The wire request `sign` is **`doCommandNative` cmd=1 = HMAC-SHA256(key =
//! master-key G, msg = str2)** rendered as **64 lowercase hex**
//! (`re/master_secret_g.md`; native `doCommandNative.c:449-489`). An earlier port
//! wrongly used `computeDigest` (MD5 → 32-hex), which is the inbound
//! response-verify path, NOT the login signer. [`Signer::sign`] implements the
//! correct HMAC path.
//!
//! `str2` is the sorted-whitelist canonical string ([`canonical_string`], literal
//! `||` join, NOT `&`), with the `postData` param value replaced by its
//! [`post_data_digest_hex`] fold (`swapSignString(md5_hex(encrypted_postData))`).
//! NOTE: the `postData` digest is STILL MD5 — only the request `sign` is
//! HMAC-SHA256. [`md5_hex_lower`]/[`swap_sign_string`] therefore remain.
//!
//! ## Master key G ([`assemble_master_key_g`]) — a RAW BYTE string
//!
//! `doCommandNative` cmd=0 assembles G once at init
//! (`doCommandNative.c:497-783`, `re/master_secret_g.md`):
//!
//! ```text
//! G = packageName ++ 0x5f ++ certColonUpper ++ 0x5f ++ matrixKey0 ++ 0x5f ++ appSecret
//! ```
//!
//! - `packageName` = [`APP_PACKAGE_NAME`] (UTF-8);
//! - `certColonUpper` = the app-cert SHA-256 as **colon-grouped UPPERCASE hex, 95
//!   chars** ([`cert_sha256_colon_upper`]) — NOT lowercase 64-hex. This is the
//!   silent-failure trap this module exists to prevent;
//! - `matrixKey0` = `hex_decode(bmp_token)` → **32 RAW bytes** (binary, NOT the
//!   ASCII hex string), decoded from `assets/t_s.bmp` (TASK-0032). The raw-bytes
//!   FORM is **confirmed (two-source)**: the native reads each key string as hex
//!   TEXT via strlen (`doCommandNative.c:546`) then runs it through the
//!   hex-DECODER `FUN_00113150` (`doCommandNative.c:572`), whose output is
//!   `input_len/2` bytes (`00113150_FUN_00113150.c:32,46-76`) — so the 64-char hex
//!   token folds into G as 32 raw bytes, exactly what [`hex::decode`] produces;
//! - `appSecret` = raw UTF-8 appSecret;
//! - `0x5f` = a single `_` byte separator (no length prefix).
//!
//! The ET=3 `postData` AES-128 key is the first **16 ASCII hex chars** of
//! `HMAC-SHA256(key = requestId, msg = G [++ 0x5f ++ ecode])` ([`et3_encrypto_key`]);
//! login (`token.get`) sets `setSessionRequire(false)`, so `ecode` is omitted and
//! the message is G alone.
//!
//! `chKey` ([`ch_key`]) = `lowercase_hex(HMAC-SHA256(key = appKey,
//! msg = packageName ++ 0x5f ++ certColonUpper))[8..16]` — same colon-upper cert
//! input as G; output shape unchanged.
//!
//! # Honest confidence
//!
//! The primitive + encoding layers are offline-validated here against PUBLISHED
//! vectors: HMAC-SHA256 vs RFC 4231 (cases 2 + 6), SHA-256 vs FIPS-180, MD5 vs
//! RFC 1321, and [`cert_sha256_colon_upper`] against an exact hand-written gold
//! string. The `matrixKey0`-as-raw-bytes FORM is also resolved — **confirmed
//! (two-source)** by the G-assembly order plus the `FUN_00113150` hex-decoder
//! (output = `input_len/2`); see [`assemble_master_key_g`]. The rest of the signer
//! RECIPE (key=G, msg=str2, the 4-part byte order) is SINGLE-SOURCE native ground
//! truth and CANNOT be validated offline end-to-end — there is NO HMAC KAT in the
//! lib and the real `bmp_token` VALUE is un-ported (TASK-0032). Until a [`BmpTokenProvider`] supplies the
//! token, [`Signer::sign`] returns [`Error::BmpTokenPending`]; it never fabricates
//! a signature.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::Error;

/// The fixed whitelist of envelope param keys the signer canonicalizes, in the
/// spelling used by `ThingApiSignManager.bdpdqbp` (`re/tuya_sign.md` §1;
/// re-confirmed verbatim in `re/bmp_token_provenance.md` §2.1). Only keys in this
/// set with a non-empty value enter the canonical string; all other params are
/// ignored by the signer. Kept as a sorted-on-use slice; the builder sorts the
/// *present* keys lexicographically (Tuya sorts `map.keySet()`).
///
/// CORRECTED (TASK-0042, live-login wiring): two entries were wrong against the
/// recovered whitelist and would have silently produced a wrong signature —
///   * `appId` → **`clientId`**: the appKey rides the envelope under the WIRE
///     param `clientId` (`KEY_APP_ID` → wire `clientId`, `re/tuya_cloud_auth.md`
///     §1; whitelist in `re/bmp_token_provenance.md` §2.1 spells it `clientId`).
///     With `appId` whitelisted but the envelope keyed `clientId`, the appKey
///     param was DROPPED from the canonical string → wrong `sign`.
///   * `t` → **`time`**: the timestamp param's WIRE name is `time`
///     (`KEY_TIMESTAMP="time"`, `re/tuya_cloud_auth.md` §1); the recovered
///     whitelist lists `time`, not `t`. Same silent-drop failure mode.
///   * `h5` → **`isH5`** (TASK-0064): the H5 flag's WIRE key is `isH5`
///     (`ThingApiParams.KEY_H5 = "isH5"`,
///     `decompiled/.../ThingApiParams.java:60`; the whitelist `bdpdqbp` lists
///     `KEY_H5`, `ThingApiSignManager.java:66`). The earlier `"h5"` spelling
///     would silently drop an `isH5` param from the canonical string. `token.get`
///     does not set it, so this was a LATENT mismatch — corrected for fidelity so
///     any future H5 path signs the right key.
///
/// These are load-bearing for a server-accepted sign; see the live path.
pub const SIGN_WHITELIST: &[&str] = &[
    "a",
    "v",
    "lat",
    "lon",
    "lang",
    "deviceId",
    "appVersion",
    "ttid",
    "isH5",
    "h5Token",
    "os",
    "clientId",
    "postData",
    "time",
    "requestId",
    "et",
    "n4h5",
    "sid",
    "chKey",
    "sp",
];

/// Literal segment separator in the canonical string: `||` (NOT `&`).
/// Source: `pbbppqb.pbpdbqp = "||"` (`re/tuya_sign.md` §1).
const SEGMENT_SEP: &str = "||";

/// Literal key/value separator in each canonical segment: `=`.
/// Source: `pbbppqb.pbpdpdp = "="` (`re/tuya_sign.md` §1).
const KV_SEP: char = '=';

/// Underscore separator joining the sign-key parts.
/// Source: `'_'` byte written in native at `libthing_security.so@0x14c30`
/// (`re/tuya_sign_static.md` §4).
const KEY_PART_SEP: char = '_';

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 1: swapSignString — the 32-char permutation
// ─────────────────────────────────────────────────────────────────────────────

/// `swapSignString(s)` — the byte permutation Tuya applies to a 32-char
/// MD5-base64 before it enters the canonical string (`re/tuya_sign.md` §3,
/// `ThingApiSignManager.swapSignString`; permutation also stated in
/// `re/tuya_cloud_auth.md` as `s[8:16]+s[0:8]+s[24:32]+s[16:24]`).
///
/// With `A=s[0:8]`, `B1=s[8:16]`, `B2=s[16:24]`, `C=s[24:32]` the output is
/// `B1 + A + C + B2`.
///
/// # Errors
/// [`Error::InvalidSignInput`] if `s` is not exactly 32 ASCII chars. We require
/// ASCII (1 byte == 1 char) because Tuya slices by byte index; a multi-byte char
/// would make byte-slicing unsound, so we reject it loudly rather than mangle it.
pub fn swap_sign_string(s: &str) -> Result<String, Error> {
    if s.len() != 32 || !s.is_ascii() {
        return Err(Error::InvalidSignInput(format!(
            "swapSignString expects 32 ASCII chars, got {} bytes (ascii={})",
            s.len(),
            s.is_ascii()
        )));
    }
    let a = &s[0..8];
    let b1 = &s[8..16];
    let b2 = &s[16..24];
    let c = &s[24..32];
    Ok(format!("{b1}{a}{c}{b2}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 2: MD5 helpers (the keyed-hash primitive is plain MD5 — §3)
// ─────────────────────────────────────────────────────────────────────────────

/// Lowercase 32-char hex MD5 of `bytes`. This is the keyed-hash primitive of the
/// signer (`re/tuya_sign_static.md` §3: plain MD5, 16-byte digest, hex via
/// `"0123456789abcdef"`). NOT HMAC.
#[must_use]
pub fn md5_hex_lower(bytes: &[u8]) -> String {
    let digest = md5::compute(bytes);
    hex::encode(digest.0)
}

/// Base64 (standard alphabet, padded) of the raw 16-byte MD5 digest of `bytes`.
/// Kept for the historical `md5AsBase64` ambiguity tests; the live ATOP builder
/// uses [`post_data_digest_hex`] because the decompiled app path feeds a 32-char
/// MD5 hex string into `swapSignString`.
#[must_use]
pub fn md5_as_base64(bytes: &[u8]) -> String {
    let digest = md5::compute(bytes);
    base64::engine::general_purpose::STANDARD.encode(digest.0)
}

/// `postDataMD5Hex(body)` = `swapSignString(md5AsBase64(body))`
/// (`re/tuya_sign.md` §2). The `postData` param's value is replaced by THIS
/// before the canonical string is built.
///
/// # Errors
/// Propagates [`Error::InvalidSignInput`] from [`swap_sign_string`]. Note the
/// raw MD5 digest is 16 bytes → standard base64 is exactly 24 chars (`"…=="` is
/// 22 data + 2 pad = 24), NOT 32 — see the honest gotcha below.
///
/// ## Gotcha (length 24 vs 32)
/// `swapSignString` was characterized on a **32**-char input, but
/// `md5AsBase64` of a 16-byte digest is **24** chars. The decompiled
/// `swapSignString` slices `[0:8],[8:24],[24:32]` (`re/tuya_sign.md` §3), which
/// only makes sense on length-32 input; on a 24-char input those slices are
/// out of range. This means EITHER (a) the digest base64 is *not* the direct
/// `swapSignString` input here, or (b) `md5AsBase64` uses a no-pad / different
/// encoding yielding 32, or (c) the slice indices differ for postData. This is
/// an OPEN ambiguity that a real captured vector (TASK-0032 / live) resolves; we
/// surface it by returning the typed error if the length is not 32, rather than
/// silently producing a wrong digest. Callers that hit this should consult the
/// gold vector before trusting the output.
pub fn post_data_digest(body: &[u8]) -> Result<String, Error> {
    let b64 = md5_as_base64(body);
    swap_sign_string(&b64)
}

/// `postData` fold via the **32-hex MD5** form: `swapSignString(md5_hex_lower(body))`.
///
/// This is the disambiguation of the length-24-vs-32 gotcha on
/// [`post_data_digest`] (which uses the 24-char base64 form and therefore cannot
/// feed the 32-char `swapSignString`). The standard Tuya mobile sign folds the
/// **32-char lowercase-hex** MD5 of `postData` through `swapSignString` (the
/// `provenance` §2.2 note: "the code substrings up to index 32, so treat it as
/// the standard Tuya 32-hex MD5 path"). 32 hex chars satisfy `swapSignString`'s
/// `[0:8]/[8:16]/[16:24]/[24:32]` block permutation exactly.
///
/// This is the variant the live login path uses for the `postData` envelope param,
/// because the decompiled app path returns a 32-char lowercase MD5 hex string from
/// the method named `md5AsBase64`, and that is the only form that yields a
/// well-defined input to `swapSignString`. A fresh server-accepted live `sign`
/// remains the final parity check; we expose BOTH forms rather than silently pick
/// one in tests.
///
/// # Errors
/// [`Error::InvalidSignInput`] only if [`md5_hex_lower`] ever produced a non-32
/// string (it cannot — MD5 hex is always 32), so in practice infallible; the
/// `Result` keeps the signature uniform with [`post_data_digest`].
pub fn post_data_digest_hex(body: &[u8]) -> Result<String, Error> {
    let hex = md5_hex_lower(body);
    swap_sign_string(&hex)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 2b: PhoneUtil.getDeviceID-shaped per-install device id
// ─────────────────────────────────────────────────────────────────────────────

/// Synthesize a `PhoneUtil.getDeviceID`-SHAPED per-install device id: a **44-char
/// LOWERCASE-HEX** string with the exact three-segment layout the app's
/// `PhoneUtil.getRemoteDeviceID` builds.
///
/// Ground truth (jadx, TASK-0064): `PhoneUtil.getRemoteDeviceID`
/// (`decompiled/.../PhoneUtil.java:770`) is
/// ```text
/// md5AsBase64(BRAND ++ MODEL).substring(4,16)
///   ++ md5AsBase64(randomId3 ++ randomId4).substring(8,24)
///   ++ md5AsBase64(randomId1 ++ randomId2).substring(16)
/// ```
/// and — despite the name — `MD5Util.md5AsBase64(byte[])` returns
/// `HexUtil.bytesToHexString(md5(..))` (`MD5Util.java:577`), i.e. a **32-char
/// lowercase-hex** MD5 digest (`HexUtil.bytesToHexString` uses
/// `Integer.toHexString`, lowercase, `HexUtil.java:138`). So the layout is:
///
/// ```text
/// deviceId = md5hex(brand ++ model)[4..16]   // 12 chars (device-model derived)
///         ++ md5hex(rand_a)[8..24]           // 16 chars (per-install random)
///         ++ md5hex(rand_b)[16..32]          // 16 chars (per-install random)
/// ```
/// = 12 + 16 + 16 = **44** lowercase-hex chars.
///
/// # HONESTY: this is a GENERATED STAND-IN, not a captured real device id.
/// The real app likewise GENERATES this id once (random per install) and CACHES it
/// in `SecuredPreferenceStore` (`PhoneUtil.getDeviceID:326-333`). The server does
/// NOT validate the deviceId VALUE — it is merely SIGNED (`KEY_DEVICEID` is in the
/// sign whitelist `bdpdqbp`), and the gateway recomputes the sign over the params
/// it receives. So a **stable, correctly-shaped, generated, persisted** id is
/// app-faithful — it is NOT a fabrication or a workaround. The CALLER must persist
/// the returned value and reuse it (stable per install) exactly as the app caches
/// `mDeviceId`.
///
/// `rand_a`/`rand_b` are caller-supplied CSPRNG seed bytes (the app feeds
/// `getRandomId*()` UUID strings; raw random bytes are equivalent for the
/// unvalidated value and keep this function pure + deterministic for tests).
#[must_use]
pub fn generate_phone_util_device_id(
    brand: &str,
    model: &str,
    rand_a: &[u8],
    rand_b: &[u8],
) -> String {
    let seg1 = md5_hex_lower(format!("{brand}{model}").as_bytes())[4..16].to_string();
    let seg2 = md5_hex_lower(rand_a)[8..24].to_string();
    let seg3 = md5_hex_lower(rand_b)[16..32].to_string();
    format!("{seg1}{seg2}{seg3}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 3: canonical string (sorted whitelist, "||"-joined)
// ─────────────────────────────────────────────────────────────────────────────

/// Build the Tuya canonical string-to-sign (`str2`) from envelope params
/// (`re/tuya_sign.md` §1).
///
/// Steps, matching `ThingApiSignManager.generateSignatureSdk`:
/// 1. keep only keys in [`SIGN_WHITELIST`] whose value is non-empty;
/// 2. sort the surviving keys lexicographically ascending;
/// 3. join `key=value` segments with the literal `||`.
///
/// The caller is responsible for having already replaced the `postData` value
/// with [`post_data_digest`] (Tuya does this before sorting); this function does
/// NOT re-digest, to keep one responsibility per function and make the digest
/// step independently testable. Pass a `BTreeMap` so iteration order is
/// deterministic regardless of insertion order.
///
/// Empty values are DROPPED (Tuya skips empty-valued keys), so passing a present
/// but empty `sid` (pre-login) correctly omits it.
#[must_use]
pub fn canonical_string(params: &BTreeMap<String, String>) -> String {
    // BTreeMap already yields keys in sorted order; filter to whitelist+non-empty.
    params
        .iter()
        .filter(|(k, v)| SIGN_WHITELIST.contains(&k.as_str()) && !v.is_empty())
        .map(|(k, v)| format!("{k}{KV_SEP}{v}"))
        .collect::<Vec<_>>()
        .join(SEGMENT_SEP)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 4: master key G assembly (4-part RAW byte string, "_" / 0x5f join)
// ─────────────────────────────────────────────────────────────────────────────

/// Assemble the native **master key G** that `doCommandNative` cmd=0 builds once
/// at init and cmd=1 uses as the HMAC-SHA256 key for the request `sign`
/// (`re/master_secret_g.md`; native `doCommandNative.c:497-783`).
///
/// G is a **raw byte string** (NOT a `String` — `matrixKey0` is binary):
///
/// ```text
/// G = packageName ++ 0x5f ++ certColonUpper ++ 0x5f ++ matrixKey0 ++ 0x5f ++ appSecret
/// ```
///
/// where the parts are joined by a single `0x5f` (`_`) byte with no length prefix:
/// - `package_name` — UTF-8, usually [`APP_PACKAGE_NAME`];
/// - `cert_digest` — the app-cert SHA-256 **raw 32-byte digest**. It is formatted
///   to the colon-grouped UPPERCASE 95-hex form ([`cert_sha256_colon_upper`])
///   INTERNALLY, so a caller cannot accidentally pass the wrong (lowercase 64-hex)
///   cert string at this boundary (architect Finding 2);
/// - `matrixKey0` = `hex_decode(bmp_token_hex)` → the **32 RAW bytes** the
///   `bmp_token` hex string decodes to (binary, not the ASCII hex);
/// - `app_secret` — raw UTF-8 appSecret.
///
/// # Errors
/// [`Error::InvalidSignInput`] if `bmp_token_hex` is not valid hex.
pub fn assemble_master_key_g(
    package_name: &str,
    cert_digest: &[u8; 32],
    bmp_token_hex: &str,
    app_secret: &str,
) -> Result<Vec<u8>, Error> {
    // Format the raw cert digest to the colon-upper 95-hex form the native
    // consumes, INTERNALLY — the lowercase-64-hex form is unconstructable at this
    // boundary (architect Finding 2: a stringly-typed `&str` let a caller pass the
    // wrong-but-plausible cert form and silently build a wrong G).
    let cert_colon_upper = cert_sha256_colon_upper(cert_digest);
    // matrixKey0 is the RAW bytes the bmp_token hex decodes to (NOT the ASCII hex
    // string). CONFIRMED raw bytes — two-source: the native reads each key string
    // as hex TEXT via strlen (`re/ghidra/doCommandNative.c:546`), then passes it
    // through the hex-DECODER FUN_00113150 (`doCommandNative.c:572`), which resizes
    // its output to input_len/2 and decodes pairs of [0-9a-fA-F] nibbles to bytes
    // (`decompiled/ghidra_security/funcs/00113150_FUN_00113150.c:32,46-76`). So the
    // 64-char hex token folds into G as 32 RAW bytes; feeding the ASCII hex here is
    // a silent wrong-G failure mode.
    let matrix_key0 = hex::decode(bmp_token_hex.trim()).map_err(|e| {
        Error::InvalidSignInput(format!(
            "bmp_token is not valid hex (matrixKey0 decode): {e}"
        ))
    })?;
    const SEP: u8 = b'_'; // 0x5f
    let mut g = Vec::with_capacity(
        package_name.len()
            + 1
            + cert_colon_upper.len()
            + 1
            + matrix_key0.len()
            + 1
            + app_secret.len(),
    );
    g.extend_from_slice(package_name.as_bytes());
    g.push(SEP);
    g.extend_from_slice(cert_colon_upper.as_bytes());
    g.push(SEP);
    g.extend_from_slice(&matrix_key0);
    g.push(SEP);
    g.extend_from_slice(app_secret.as_bytes());
    Ok(g)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 5: offline app-cert SHA-256
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the **raw** app signing-certificate SHA-256 digest (32 bytes),
/// **offline**, from raw PKCS#7 (`*.RSA`) signature-block bytes
/// (`re/tuya_sign_static.md` §4).
///
/// Tuya's native sign uses `MessageDigest.getInstance("SHA256").digest(certBytes)`
/// over `getPackageInfo(GET_SIGNATURES).signatures[0]`. The same hash is
/// reproducible from the APK's own v1 signing cert (`META-INF/BNDLTOOL.RSA`) with
/// NO device.
///
/// `pkcs7_der` is the DER PKCS#7 SignedData block. We extract the embedded leaf
/// X.509 certificate's DER bytes (see [`extract_leaf_cert_der`]) and SHA-256 them.
/// The native master key G and `chKey` consume this digest formatted via
/// [`cert_sha256_colon_upper`] (NOT the lowercase hex form); the raw digest is the
/// single source both formatters start from.
///
/// # Errors
/// [`Error::CertHash`] if no embedded certificate can be located.
pub fn app_cert_sha256_digest(pkcs7_der: &[u8]) -> Result<[u8; 32], Error> {
    use sha2::{Digest, Sha256};
    let cert_der = extract_leaf_cert_der(pkcs7_der)?;
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    Ok(hasher.finalize().into())
}

/// Read `META-INF/<name>.RSA` (or `.EC`/`.DSA`) from an APK/zip on disk and
/// return the **raw** app-cert SHA-256 digest (32 bytes) (`re/tuya_sign_static.md`
/// §4).
///
/// This is the offline ingredient entry point the live config uses: point it at
/// `extracted/xapk/com.philips.ph.babymonitorplus.apk` and it yields the digest
/// with no device. The path is a caller-supplied secret location (per CLAUDE.md,
/// the value is never committed).
///
/// # Errors
/// [`Error::CertHash`] if the zip cannot be opened, no signature block is found,
/// or the cert cannot be extracted.
pub fn app_cert_sha256_digest_from_apk(apk_path: &std::path::Path) -> Result<[u8; 32], Error> {
    let bytes = std::fs::read(apk_path)
        .map_err(|e| Error::CertHash(format!("read APK {}: {e}", apk_path.display())))?;
    let der = find_signature_block_in_zip(&bytes)?;
    app_cert_sha256_digest(&der)
}

/// Format a 32-byte cert digest as **colon-grouped UPPERCASE hex, 95 chars**:
/// `A1:B2:…:FF` (32 pairs separated by 31 colons → `32*2 + 31 = 95`).
///
/// This is the EXACT form the native master key G ([`assemble_master_key_g`]) and
/// `chKey` ([`ch_key`]) consume as their cert part (`re/master_secret_g.md`). It is
/// NOT the lowercase 64-hex form — feeding lowercase 64-hex silently produces a
/// wrong-but-plausible G/chKey (the regression this whole change fixes). Use this,
/// never [`app_cert_sha256_hex`], when building G or `chKey`.
#[must_use]
pub fn cert_sha256_colon_upper(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Compute the app signing-certificate SHA-256, **lowercase hex** (64 chars),
/// offline from raw PKCS#7 bytes. Kept for back-compat / diagnostics; the native
/// sign uses [`cert_sha256_colon_upper`], NOT this form. Thin wrapper over
/// [`app_cert_sha256_digest`].
///
/// # Errors
/// [`Error::CertHash`] if no embedded certificate can be located.
pub fn app_cert_sha256_hex(pkcs7_der: &[u8]) -> Result<String, Error> {
    Ok(hex::encode(app_cert_sha256_digest(pkcs7_der)?))
}

/// Read the app-cert SHA-256 as lowercase hex from an APK/zip on disk. Back-compat
/// wrapper; used only by the offline cert-cross-check tests. The live path uses
/// [`app_cert_sha256_digest_from_apk`].
///
/// # Errors
/// [`Error::CertHash`] if the zip/cert cannot be read or extracted.
pub fn app_cert_sha256_hex_from_apk(apk_path: &std::path::Path) -> Result<String, Error> {
    Ok(hex::encode(app_cert_sha256_digest_from_apk(apk_path)?))
}

/// Locate the first `META-INF/*.RSA|*.EC|*.DSA` entry in a ZIP byte buffer and
/// return its (stored, uncompressed) bytes.
///
/// We implement a minimal STORED-entry zip reader rather than adding a zip crate:
/// APK signature blocks are tiny and stored uncompressed in practice, but to be
/// safe we only accept compression method 0 (STORED) and error loudly otherwise
/// — failing fast beats silently mis-decoding a DEFLATE entry.
fn find_signature_block_in_zip(zip: &[u8]) -> Result<Vec<u8>, Error> {
    // Parse via the central directory (robust vs scanning local headers).
    let eocd = find_eocd(zip)?;
    // EOCD: offset 16 = central dir start, offset 10 = total entries.
    let cd_offset = read_u32(zip, eocd + 16)? as usize;
    let total = read_u16(zip, eocd + 10)? as usize;

    let mut p = cd_offset;
    for _ in 0..total {
        // Central directory file header signature 0x02014b50.
        if read_u32(zip, p)? != 0x0201_4b50 {
            return Err(Error::CertHash(format!(
                "bad central-dir header signature at {p}"
            )));
        }
        let method = read_u16(zip, p + 10)?;
        let comp_size = read_u32(zip, p + 20)? as usize;
        let name_len = read_u16(zip, p + 28)? as usize;
        let extra_len = read_u16(zip, p + 30)? as usize;
        let comment_len = read_u16(zip, p + 32)? as usize;
        let lho = read_u32(zip, p + 42)? as usize;
        let name = std::str::from_utf8(
            zip.get(p + 46..p + 46 + name_len)
                .ok_or_else(|| Error::CertHash("central-dir name out of range".into()))?,
        )
        .map_err(|e| Error::CertHash(format!("non-utf8 zip name: {e}")))?;

        let upper = name.to_ascii_uppercase();
        if upper.starts_with("META-INF/")
            && (upper.ends_with(".RSA") || upper.ends_with(".EC") || upper.ends_with(".DSA"))
        {
            // Local file header at lho: name_len@26, extra_len@28, data follows.
            if read_u32(zip, lho)? != 0x0403_4b50 {
                return Err(Error::CertHash("bad local file header signature".into()));
            }
            let l_name_len = read_u16(zip, lho + 26)? as usize;
            let l_extra_len = read_u16(zip, lho + 28)? as usize;
            let data_start = lho + 30 + l_name_len + l_extra_len;
            let raw = zip
                .get(data_start..data_start + comp_size)
                .ok_or_else(|| Error::CertHash("signature block data out of range".into()))?;
            return match method {
                // STORED: the bytes are the PKCS#7 block verbatim.
                0 => Ok(raw.to_vec()),
                // DEFLATE: inflate the raw deflate stream (no zlib header in zip).
                8 => inflate(raw),
                other => Err(Error::CertHash(format!(
                    "signature block {name} uses unsupported zip method {other}"
                ))),
            };
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    Err(Error::CertHash(
        "no META-INF/*.RSA|*.EC|*.DSA signature block found in zip".into(),
    ))
}

/// Find the End Of Central Directory record by scanning backwards for its
/// signature `0x06054b50`. The EOCD lives near the end of the file (after any
/// comment). Returns its byte offset.
fn find_eocd(zip: &[u8]) -> Result<usize, Error> {
    const SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    if zip.len() < 22 {
        return Err(Error::CertHash("file too small to be a zip".into()));
    }
    // Max comment length is 0xffff; scan that window from the end.
    let start = zip.len().saturating_sub(22 + 0xffff);
    for i in (start..=zip.len() - 22).rev() {
        if zip[i..i + 4] == SIG {
            return Ok(i);
        }
    }
    Err(Error::CertHash("no EOCD record found (not a zip?)".into()))
}

/// Inflate a raw DEFLATE stream (as stored in a zip local file, no zlib header).
fn inflate(raw: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(raw)
        .read_to_end(&mut out)
        .map_err(|e| Error::CertHash(format!("inflate signature block: {e}")))?;
    Ok(out)
}

fn read_u16(b: &[u8], at: usize) -> Result<u16, Error> {
    let s = b
        .get(at..at + 2)
        .ok_or_else(|| Error::CertHash(format!("u16 read OOB at {at}")))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b
        .get(at..at + 4)
        .ok_or_else(|| Error::CertHash(format!("u32 read OOB at {at}")))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Extract the **leaf** (end-entity) X.509 certificate's DER bytes from a PKCS#7
/// SignedData blob — the bytes Android returns as `signatures[0]`.
///
/// ## Structure navigated
/// `ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }`
/// and `SignedData ::= SEQUENCE { version, digestAlgorithms SET, contentInfo,
/// certificates [0] IMPLICIT SET-OF-or-SEQUENCE-OF Certificate OPTIONAL, ... }`.
/// We descend ContentInfo → SignedData, then locate the `certificates [0]`
/// IMPLICIT context tag (`0xA0`) and enumerate the `Certificate` `SEQUENCE`s
/// that live **inside that tag only** (NOT anywhere in the whole blob).
///
/// ## Leaf selection (the hardening — was: "first ≥64-byte SEQUENCE")
/// A signer may embed a multi-cert chain (leaf + intermediates/root). Android's
/// `signatures[0]` is the **end-entity** cert, not an arbitrary chain member.
/// We therefore:
///   * collect every cert SEQUENCE in the `[0]` block (each must have a
///     cert-shaped inner: starts with a `SEQUENCE` = tbsCertificate);
///   * if exactly ONE cert is present → it is the leaf;
///   * if MORE than one → select the end-entity: the cert whose **subject DN**
///     is NOT the **issuer DN** of any other cert in the set (a CA that signed a
///     chain member is, by definition, not the leaf). If exactly one such cert
///     exists, return it.
///   * if the leaf cannot be determined unambiguously (zero or ≥2 candidates),
///     **fail loud** with [`Error::CertHash`] rather than silently returning a
///     wrong-but-plausible cert (which would yield a wrong-but-plausible hash).
///
/// ## Limitation (documented, not silent)
/// DN comparison is done on the raw DER bytes of the issuer/subject `Name`
/// fields (byte-equality), not canonicalised RFC 4518 string matching. For the
/// chains we expect (self-signed single cert, or a leaf + distinctly-named CAs)
/// byte-equality is correct; a pathological chain using two non-byte-identical
/// encodings of the same DN could defeat it — in which case it errors loudly
/// (≥2 leaf candidates) instead of guessing. A full ASN.1 + DN-canonicalisation
/// parser is deliberately out of scope for this offline ingredient check.
///
/// # Errors
/// [`Error::CertHash`] if the PKCS#7 structure cannot be navigated, no
/// certificate is present, or the leaf is ambiguous.
pub fn extract_leaf_cert_der(pkcs7_der: &[u8]) -> Result<Vec<u8>, Error> {
    let certs = collect_certificates(pkcs7_der)?;
    match certs.len() {
        0 => Err(Error::CertHash(
            "no X.509 certificate found in PKCS#7 certificates [0] block".into(),
        )),
        1 => Ok(certs[0].to_vec()),
        _ => select_leaf(&certs),
    }
}

/// Navigate ContentInfo → SignedData → `certificates [0]` IMPLICIT and return the
/// raw DER byte-slices of every `Certificate` SEQUENCE inside that tag.
///
/// We only parse enough structure to reach the `[0]` block, then enumerate the
/// SEQUENCEs directly under it. Restricting the scan to the `[0]` block (rather
/// than the whole blob, as the old code did) prevents matching the outer
/// ContentInfo/SignedData/SignerInfo SEQUENCEs as if they were certificates.
fn collect_certificates(pkcs7_der: &[u8]) -> Result<Vec<&[u8]>, Error> {
    // ContentInfo = outer SEQUENCE.
    let (ci_content, _) = der_tlv(pkcs7_der, 0, 0x30)
        .ok_or_else(|| Error::CertHash("PKCS#7: outer ContentInfo SEQUENCE not found".into()))?;
    // Skip contentType OID (0x06), then content [0] EXPLICIT (0xA0).
    let after_oid = skip_tlv(pkcs7_der, ci_content, 0x06)
        .ok_or_else(|| Error::CertHash("PKCS#7: contentType OID not found".into()))?;
    let (c0_content, _) = der_tlv(pkcs7_der, after_oid, 0xA0)
        .ok_or_else(|| Error::CertHash("PKCS#7: content [0] EXPLICIT tag not found".into()))?;
    // SignedData = SEQUENCE inside content [0].
    let (sd_content, sd_end) = der_tlv(pkcs7_der, c0_content, 0x30)
        .ok_or_else(|| Error::CertHash("PKCS#7: SignedData SEQUENCE not found".into()))?;
    // Walk SignedData members to find the certificates [0] IMPLICIT tag (0xA0).
    // Members before it: version INTEGER (0x02), digestAlgorithms SET (0x31),
    // encapContentInfo SEQUENCE (0x30). Scan TLVs until we hit 0xA0.
    let mut p = sd_content;
    while p < sd_end {
        let tag = *pkcs7_der
            .get(p)
            .ok_or_else(|| Error::CertHash("PKCS#7: truncated SignedData".into()))?;
        let (content, end) = der_length(pkcs7_der, p + 1)
            .map(|(cs, cl)| (cs, cs + cl))
            .ok_or_else(|| Error::CertHash("PKCS#7: bad length in SignedData".into()))?;
        if end > pkcs7_der.len() {
            return Err(Error::CertHash("PKCS#7: SignedData member OOB".into()));
        }
        if tag == 0xA0 {
            // certificates [0] IMPLICIT — enumerate cert SEQUENCEs within it.
            return enumerate_cert_seqs(pkcs7_der, content, end);
        }
        p = end;
    }
    Err(Error::CertHash(
        "PKCS#7: no certificates [0] block in SignedData".into(),
    ))
}

/// Enumerate top-level `Certificate` SEQUENCEs (tag `0x30`) in `[lo, hi)`, each
/// validated to be cert-shaped (inner starts with a tbsCertificate SEQUENCE and
/// is a plausible size).
fn enumerate_cert_seqs(der: &[u8], lo: usize, hi: usize) -> Result<Vec<&[u8]>, Error> {
    let mut out = Vec::new();
    let mut p = lo;
    while p < hi {
        if der.get(p) != Some(&0x30) {
            // Not a SEQUENCE (e.g. an attribute-cert [1] / CRL); stop at the
            // first non-SEQUENCE to avoid mis-parsing trailing structures.
            break;
        }
        let (content_start, content_len) = der_length(der, p + 1)
            .ok_or_else(|| Error::CertHash("cert SEQUENCE: bad length".into()))?;
        let end = content_start + content_len;
        if end > hi {
            return Err(Error::CertHash(
                "cert SEQUENCE: length exceeds block".into(),
            ));
        }
        // Cert shape: inner must start with the tbsCertificate SEQUENCE, and be
        // a reasonable size (a real cert is well over 64 bytes).
        if content_len >= 64 && der.get(content_start) == Some(&0x30) {
            out.push(&der[p..end]);
        }
        p = end;
    }
    Ok(out)
}

/// Select the end-entity (leaf) cert from a multi-cert chain: the one whose
/// subject DN is not the issuer DN of any other cert. Fails loud if zero or ≥2
/// candidates qualify (ambiguous → do not guess).
fn select_leaf(certs: &[&[u8]]) -> Result<Vec<u8>, Error> {
    // For each cert, extract (issuer_dn, subject_dn) as raw DER byte-slices.
    let names: Vec<(&[u8], &[u8])> = certs
        .iter()
        .map(|c| cert_issuer_subject(c))
        .collect::<Result<_, _>>()?;
    let issuers: Vec<&[u8]> = names.iter().map(|(i, _)| *i).collect();
    let leaves: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(idx, (_, subject))| {
            // Leaf := its subject is not the issuer of any OTHER cert.
            !issuers
                .iter()
                .enumerate()
                .any(|(j, iss)| j != *idx && iss == subject)
        })
        .map(|(idx, _)| idx)
        .collect();
    match leaves.as_slice() {
        [only] => Ok(certs[*only].to_vec()),
        [] => Err(Error::CertHash(
            "PKCS#7 chain: no end-entity cert (every subject is an issuer — a cycle?)".into(),
        )),
        many => Err(Error::CertHash(format!(
            "PKCS#7 chain: {} candidate leaf certs — ambiguous, refusing to guess",
            many.len()
        ))),
    }
}

/// Extract the raw DER of a cert's `issuer` and `subject` `Name` fields.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`;
/// `tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber INTEGER,
/// signature AlgId SEQUENCE, issuer Name, validity SEQUENCE, subject Name, ... }`.
/// We descend into tbs, skip the optional `[0]` version, serial, the inner
/// AlgId SEQUENCE, take `issuer` (next SEQUENCE), skip `validity`, take `subject`.
fn cert_issuer_subject(cert: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    // Descend the outer Certificate SEQUENCE to its content, then into the
    // first member = tbsCertificate SEQUENCE, then walk tbs fields.
    let (cert_content, _) = der_tlv(cert, 0, 0x30)
        .ok_or_else(|| Error::CertHash("cert: outer SEQUENCE not found".into()))?;
    let (tbs, _) = der_tlv(cert, cert_content, 0x30)
        .ok_or_else(|| Error::CertHash("cert: tbsCertificate not found".into()))?;
    let mut p = tbs;
    // Optional version [0] EXPLICIT (0xA0): skip if present.
    if cert.get(p) == Some(&0xA0) {
        p = skip_any_tlv(cert, p).ok_or_else(|| Error::CertHash("cert: bad version tag".into()))?;
    }
    // serialNumber INTEGER.
    p = skip_tlv(cert, p, 0x02).ok_or_else(|| Error::CertHash("cert: serial not found".into()))?;
    // signature AlgorithmIdentifier SEQUENCE.
    p = skip_tlv(cert, p, 0x30).ok_or_else(|| Error::CertHash("cert: sig-alg not found".into()))?;
    // issuer Name (SEQUENCE).
    let issuer = der_full_tlv(cert, p, 0x30)
        .ok_or_else(|| Error::CertHash("cert: issuer Name not found".into()))?;
    p = skip_tlv(cert, p, 0x30).ok_or_else(|| Error::CertHash("cert: issuer skip".into()))?;
    // validity SEQUENCE — skip.
    p = skip_tlv(cert, p, 0x30)
        .ok_or_else(|| Error::CertHash("cert: validity not found".into()))?;
    // subject Name (SEQUENCE).
    let subject = der_full_tlv(cert, p, 0x30)
        .ok_or_else(|| Error::CertHash("cert: subject Name not found".into()))?;
    Ok((issuer, subject))
}

/// Read a TLV at `at` expecting `tag`; return `(content_start, content_end)`.
fn der_tlv(b: &[u8], at: usize, tag: u8) -> Option<(usize, usize)> {
    if *b.get(at)? != tag {
        return None;
    }
    let (cs, cl) = der_length(b, at + 1)?;
    let end = cs + cl;
    if end <= b.len() {
        Some((cs, end))
    } else {
        None
    }
}

/// Like [`der_tlv`] but return the FULL TLV byte-slice (tag+len+content).
fn der_full_tlv(b: &[u8], at: usize, tag: u8) -> Option<&[u8]> {
    let (_cs, end) = der_tlv(b, at, tag)?;
    Some(&b[at..end])
}

/// Skip one TLV at `at` expecting `tag`; return the offset just past it.
fn skip_tlv(b: &[u8], at: usize, tag: u8) -> Option<usize> {
    let (_cs, end) = der_tlv(b, at, tag)?;
    Some(end)
}

/// Skip one TLV at `at` regardless of tag; return the offset just past it.
fn skip_any_tlv(b: &[u8], at: usize) -> Option<usize> {
    b.get(at)?; // tag must exist
    let (cs, cl) = der_length(b, at + 1)?;
    let end = cs + cl;
    if end <= b.len() {
        Some(end)
    } else {
        None
    }
}

/// Decode a DER definite-length field starting at `at` (the length byte).
/// Returns `(content_start, content_len)`. Supports short form and long form.
fn der_length(b: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *b.get(at)?;
    if first & 0x80 == 0 {
        // Short form: length is the byte itself.
        Some((at + 1, first as usize))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None; // indefinite or implausibly large
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | (*b.get(at + 1 + k)? as usize);
        }
        Some((at + 1 + n, len))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 6: chKey — the per-app channel-auth token (native getChKey@0x16000)
// ─────────────────────────────────────────────────────────────────────────────

/// The app package name — the `getPackageName()` value the native `getChKey`
/// uses as the FIRST `_`-joined part of the HMAC message. STATIC: read from the
/// APK `AndroidManifest.xml` `package=` attribute (not a secret).
///
/// Source: `re/chkey_static.md` §2 (Ghidra `FUN_00116528` calls
/// `getPackageManager().getPackageName()` and stores it into the `.bss` global
/// `DAT_001390a0`, which `getChKey@0x116000` reads as the first key part).
pub const APP_PACKAGE_NAME: &str = "com.philips.ph.babymonitorplus";

/// Compute `chKey` = the per-app channel-auth token the atop envelope carries as
/// the wire param `chKey` (and that is in [`SIGN_WHITELIST`]).
///
/// # Algorithm (Ghidra-recovered, r2 cross-checked — `re/chkey_static.md`)
///
/// Native `JNICLibrary.getChKey(Context, byte[] appId)` (`getChKey@0x16000`,
/// rebased `0x116000`) computes:
///
/// ```text
/// chKey = lowercase_hex( HMAC-SHA256( key   = appId_bytes,
///                                     msg   = packageName + "_" + certColonUpper ) )[8..16]
/// ```
///
/// where:
/// - `appId` = `ThingSmartNetWork.mAppId.getBytes()` = the Tuya **appKey** (the
///   same value carried on the wire as `clientId`);
/// - `packageName` = `getPackageName()` = [`APP_PACKAGE_NAME`] (static, from the
///   manifest); stored by native `FUN_00116528` into `.bss` `DAT_001390a0`;
/// - `certColonUpper` = the app signing-cert SHA-256 as colon-grouped UPPERCASE
///   95-hex ([`cert_sha256_colon_upper`]) — the SAME cert form the native master
///   key G uses, NOT lowercase 64-hex; stored into `.bss` `DAT_00139058`.
///
/// The keyed digest is **HMAC-SHA256** (NOT plain MD5 like the request `sign`):
/// the native algo-descriptor at `0x132fe0` is `{id=6, name="SHA256",
/// digestSize=0x20, blockSize=0x40}` and the key-setup `FUN_00117780` does the
/// canonical HMAC ipad(`0x36`)/opad(`0x5c`) pad-XOR. Ghidra shows the native
/// function hex-encodes the 32-byte digest, then returns a Java string copied
/// from byte offset 8. The static Ghidra length reading (`0x10`/16 chars) was
/// WRONG — capture ground truth shows **8 chars** (`hex[8..16]`); the cap constant
/// was misread (likely `0x8` vs `0x10`). The capture overrides the static reading.
/// The `_` join byte (`0x5f`) is written at `getChKey@0x116108`. All STATIC — no
/// runtime/device/cloud input.
///
/// # Static-derivable
/// Every input is a static, offline-recoverable value (appKey from `secrets/`,
/// package name from the manifest, cert hash from the APK signing block). No
/// device, no live cloud call, no runtime config blob. See `re/chkey_static.md`
/// for the static-vs-runtime verdict.
///
/// # Arguments
/// - `app_key` — the Tuya appKey string (its UTF-8 bytes are the HMAC key);
/// - `package_name` — the app package name (usually [`APP_PACKAGE_NAME`]);
/// - `cert_digest` — the app-cert SHA-256 **raw 32-byte digest**. It is formatted
///   to the colon-grouped UPPERCASE 95-hex form ([`cert_sha256_colon_upper`])
///   INTERNALLY, so the wrong lowercase-64-hex cert string is unconstructable at
///   this boundary (architect Finding 2).
///
/// The returned `chKey` is an **app-static, non-reversible fingerprint**: the same
/// value for every install of this APK, derived one-way via HMAC from the appKey +
/// cert hash. It does NOT reveal the appKey/appSecret/cert. It is therefore safe to
/// cite in tracked RE notes (unlike `appSecret`/the raw cert hash, which stay in
/// `secrets/`). The literal value also already appears in the committed
/// `emulator_captures/` wire dumps.
#[must_use]
pub fn ch_key(app_key: &str, package_name: &str, cert_digest: &[u8; 32]) -> String {
    let cert_colon_upper = cert_sha256_colon_upper(cert_digest);
    let message = format!("{package_name}{KEY_PART_SEP}{cert_colon_upper}");
    let mac = hmac_sha256(app_key.as_bytes(), message.as_bytes());
    let hex = hex::encode(mac);
    // CAPTURE-VERIFIED (2026-06-26): the wire chKey is hex[8..16] = 8 chars, NOT
    // hex[8..24]/16. The genuine app's chKey in emulator_captures/cap1 token.get
    // (`071d81fa`) is reproduced EXACTLY by HMAC-SHA256(appKey, pkg+"_"+certColonUpper)
    // hex[8..16]. The earlier [8..24] static guess was a wrong-length value in a
    // standalone client-binding param — the prime suspect for ILLEGAL_CLIENT_ID.
    hex[8..16].to_string()
}

/// Native `SecureNativeApi.getEncryptoKey(requestId, ecode)` for ET=3 post bodies.
///
/// Ghidra export `re/ghidra/getEncryptoKey.c` shows the JNI function calls the same
/// HMAC-SHA256 helper used by `getChKey`, with:
/// - HMAC key = `requestId.getBytes()`;
/// - HMAC message = the native master key **G** bytes (`re/master_secret_g.md`);
/// - when the second Java arg (`ecode`) is non-empty, the message becomes
///   `G ++ 0x5f ++ ecode`;
/// - return value = a Java byte[16] copied from the first 16 ASCII bytes of the
///   lowercase-hex HMAC digest.
///
/// This function implements that JNI behavior for static clients. `g` is the raw
/// master-key bytes from [`assemble_master_key_g`]. For pre-login requests
/// (`token.get`, `password.login`) the app sets `setSessionRequire(false)`, so
/// pass `None` for `ecode` and the message is G alone.
#[must_use]
pub fn et3_encrypto_key(request_id: &str, g: &[u8], ecode: Option<&str>) -> [u8; 16] {
    let mut message = g.to_vec();
    if let Some(ecode) = ecode.filter(|s| !s.is_empty()) {
        message.push(b'_'); // 0x5f
        message.extend_from_slice(ecode.as_bytes());
    }
    let mac = hmac_sha256(request_id.as_bytes(), &message);
    let mac_hex = hex::encode(mac);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac_hex.as_bytes()[..16]);
    out
}

/// HMAC-SHA256 over the `sha2` primitive (no extra `hmac` dependency).
///
/// Standard construction (RFC 2104): with block size `B=64` and a key `K`,
/// `K0 = (len(K) > B) ? H(K) : K`, right-padded to `B`; then
/// `HMAC = H( (K0 ^ opad) || H( (K0 ^ ipad) || msg ) )` with `ipad=0x36`,
/// `opad=0x5c`. This matches the native key-setup `FUN_00117780`
/// (`re/chkey_static.md` §3): the >block-size pre-hash, the `0x36`/`0x5c` pads.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;

    // K0: hash an over-long key, then zero-pad to the block size.
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finalize();
        k0[..32].copy_from_slice(&d);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    // inner = H(ipad || msg)
    let mut hi = Sha256::new();
    hi.update(ipad);
    hi.update(msg);
    let inner = hi.finalize();

    // outer = H(opad || inner)
    let mut ho = Sha256::new();
    ho.update(opad);
    ho.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&ho.finalize());
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Injected key material + token provider (the clean injected interface)
// ─────────────────────────────────────────────────────────────────────────────

/// Non-secret-by-construction holder for the signer's static key material.
///
/// All four fields are loaded by the CALLER from `secrets/tuya_appkey.json` (and
/// the app-cert digest computed offline via [`app_cert_sha256_digest_from_apk`])
/// at runtime — **no value is hardcoded** in this crate. Tests construct this with
/// SYNTHETIC values only.
///
/// Feed-forward (TASK-0013): the device-list/service layer should build on THIS
/// shape — pass a borrowed `&SigningKeyMaterial` into request decoration rather
/// than re-reading secrets. `app_key` is the envelope `clientId` param; `ttid` is
/// vestigial for login (the wire `ttid` is rewritten, see the field doc);
/// `app_secret` and `app_cert_sha256` feed the master key G
/// ([`assemble_master_key_g`]) and `chKey` (via [`cert_sha256_colon_upper`]).
#[derive(Clone)]
pub struct SigningKeyMaterial {
    /// Tuya appKey (20-char) — wire `clientId` param + cmd-0 native init.
    pub app_key: String,
    /// Tuya appSecret (32-char) — the 4th part of the master key G.
    pub app_secret: String,
    /// App signing-cert SHA-256 — the **raw 32-byte digest**. Formatted via
    /// [`cert_sha256_colon_upper`] when it enters G / `chKey` (colon-upper 95-hex),
    /// NEVER the lowercase 64-hex form.
    pub app_cert_sha256: [u8; 32],
    /// Channel TTID (the raw `philipsclnightowl`-style value from
    /// `secrets/tuya_appkey.json`). **Vestigial for the login path:** the wire
    /// `ttid` the app actually sends is the rewritten `sdk_<channel>@<appKey>`
    /// (`= sdk_international@<appKey>`, built by `live::wire_ttid`), NOT this field
    /// (TASK-0047). Kept for completeness/diagnostics; the signer does not consume
    /// it.
    pub ttid: String,
}

impl std::fmt::Debug for SigningKeyMaterial {
    /// Redacts secret values: never print appSecret / cert-digest / appKey bodies.
    /// Prevents the key material leaking via `{:?}` into logs (CLAUDE.md: never
    /// leak secrets through any channel).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyMaterial")
            .field("app_key", &Redacted(self.app_key.len()))
            .field("app_secret", &Redacted(self.app_secret.len()))
            .field("app_cert_sha256", &Redacted(self.app_cert_sha256.len()))
            .field("ttid", &Redacted(self.ttid.len()))
            .finish()
    }
}

/// Debug helper that prints only a length, never the secret value.
struct Redacted(usize);
impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted len={}>", self.0)
    }
}

/// Supplies the `bmp_token` decoded from `assets/t_s.bmp` — the single
/// recovered-but-un-ported sign ingredient.
///
/// This is the **injected seam for TASK-0032**: that task's imath-bignum +
/// matrix decode (sign path) port (or a live-captured vector) implements this
/// trait and plugs in WITHOUT any change to the signer. A provider returns:
/// - `Ok(token)` — the decoded token string (the second `_`-joined key part); or
/// - `Err(Error::BmpTokenPending)` — the honest "not available yet" state.
///
/// Feed-forward (TASK-0032): your decoder must satisfy exactly this signature:
/// `fn bmp_token(&self) -> Result<String, crate::Error>`. Return the decoded
/// token on success; return [`Error::BmpTokenPending`] (NOT a panic, NOT a fake
/// value) while the port is incomplete. The token VALUE must go only to
/// `secrets/`, never a tracked file.
pub trait BmpTokenProvider {
    /// Return the decoded `bmp_token`, or [`Error::BmpTokenPending`] if the
    /// decode is not yet available.
    ///
    /// # Errors
    /// [`Error::BmpTokenPending`] when no token can be produced.
    fn bmp_token(&self) -> Result<String, Error>;
}

/// A [`BmpTokenProvider`] that always reports the token is pending. This is the
/// DEFAULT, honest provider for the current (TOKEN-PENDING) state: it makes
/// [`Signer::sign`] fail fast with [`Error::BmpTokenPending`] instead of
/// fabricating a signature. Swap it for the real TASK-0032 provider when ready.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingBmpToken;

impl BmpTokenProvider for PendingBmpToken {
    fn bmp_token(&self) -> Result<String, Error> {
        Err(Error::BmpTokenPending)
    }
}

/// A provider wrapping a known token string. Intended for TESTS (with a SYNTHETIC
/// token) and for TASK-0032 to supply a really-decoded token. Construct via
/// [`StaticBmpToken::new`].
#[derive(Clone)]
pub struct StaticBmpToken(String);

impl StaticBmpToken {
    /// Wrap a known `bmp_token`. The value must come from `secrets/` (or be a
    /// synthetic test value) — never a tracked literal.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }
}

impl BmpTokenProvider for StaticBmpToken {
    fn bmp_token(&self) -> Result<String, Error> {
        Ok(self.0.clone())
    }
}

/// The composable signer: injected key material + an injected
/// [`BmpTokenProvider`]. Build with [`Signer::new`], sign with [`Signer::sign`].
///
/// The signer holds NO secrets of its own — it borrows them from the injected
/// [`SigningKeyMaterial`] and provider, so the caller owns secret lifetimes.
pub struct Signer<P: BmpTokenProvider> {
    material: SigningKeyMaterial,
    token_provider: P,
}

impl<P: BmpTokenProvider> Signer<P> {
    /// Construct a signer from injected key material and a token provider.
    pub fn new(material: SigningKeyMaterial, token_provider: P) -> Self {
        Self {
            material,
            token_provider,
        }
    }

    /// Produce the wire `sign` value for the given envelope params.
    ///
    /// Pipeline (`re/master_secret_g.md`; native `doCommandNative.c:449-489`):
    /// `str2` = [`canonical_string`] of `params`; obtain the `bmp_token`
    /// (injected); assemble the master key **G** ([`assemble_master_key_g`]); then
    /// `sign = lowercase_hex(HMAC-SHA256(key = G, msg = str2))` (64 hex chars).
    ///
    /// The caller MUST pass `params` whose `postData` value is already the
    /// [`post_data_digest_hex`] (Tuya digests it before sorting); this method does
    /// not re-digest.
    ///
    /// # Errors
    /// - [`Error::BmpTokenPending`] if the injected provider has no token (the
    ///   honest TOKEN-PENDING state — TASK-0032). This is the CURRENT default
    ///   behaviour with [`PendingBmpToken`].
    /// - [`Error::InvalidSignInput`] if the `bmp_token` is not valid hex.
    /// - any error the provider returns.
    ///
    /// # Honesty
    /// A full, byte-valid signature is NOT yet achievable offline: it requires
    /// the real `bmp_token` (TASK-0032). With [`PendingBmpToken`] this method
    /// always returns [`Error::BmpTokenPending`] — it never returns a fabricated
    /// value.
    pub fn sign(&self, params: &BTreeMap<String, String>) -> Result<String, Error> {
        let str2 = canonical_string(params);
        let bmp_token = self.token_provider.bmp_token()?;
        let g = assemble_master_key_g(
            APP_PACKAGE_NAME,
            &self.material.app_cert_sha256,
            &bmp_token,
            &self.material.app_secret,
        )?;
        Ok(hex::encode(hmac_sha256(&g, str2.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DER test builders ──────────────────────────────────────────────────
    //
    // Minimal helpers to assemble SYNTHETIC but structurally-valid PKCS#7
    // SignedData blobs so the hardened extractor (which now navigates the real
    // ContentInfo → SignedData → certificates [0] structure) can be exercised
    // without the real (secret) cert. All bytes here are non-secret fixtures.

    /// Wrap `content` in a DER TLV with the given `tag`, definite length.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            // Long form: minimal number of length bytes.
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap();
            let n = bytes.len() - first;
            out.push(0x80 | n as u8);
            out.extend_from_slice(&bytes[first..]);
        }
        out.extend_from_slice(content);
        out
    }

    /// Build a minimal X.509-shaped cert SEQUENCE with the given issuer/subject
    /// DN payloads (raw bytes inside the Name SEQUENCE). Padded so the cert is
    /// >= 64 content bytes (the extractor's plausibility guard).
    fn fake_cert(issuer_dn: &[u8], subject_dn: &[u8]) -> Vec<u8> {
        let version = tlv(0xA0, &tlv(0x02, &[0x02])); // [0] { INTEGER 2 } (v3)
        let serial = tlv(0x02, &[0x01]);
        let sigalg = tlv(0x30, &tlv(0x06, &[0x2A]));
        let issuer = tlv(0x30, issuer_dn);
        let validity = tlv(0x30, &[]);
        let subject = tlv(0x30, subject_dn);
        // Padding to push tbs (and thus the cert) well past 64 bytes.
        let spki = tlv(0x30, &[0xAB; 80]);
        let mut tbs_body = Vec::new();
        for part in [
            &version, &serial, &sigalg, &issuer, &validity, &subject, &spki,
        ] {
            tbs_body.extend_from_slice(part);
        }
        let tbs = tlv(0x30, &tbs_body);
        let sig = tlv(0x03, &[0x00, 0xFF]); // BIT STRING
        let mut cert_body = tbs.clone();
        cert_body.extend_from_slice(&sigalg);
        cert_body.extend_from_slice(&sig);
        tlv(0x30, &cert_body)
    }

    /// Assemble a minimal PKCS#7 SignedData ContentInfo carrying `certs` in the
    /// `certificates [0]` IMPLICIT block.
    fn fake_pkcs7(certs: &[Vec<u8>]) -> Vec<u8> {
        let version = tlv(0x02, &[0x01]);
        let digest_algs = tlv(0x31, &[]);
        let encap = tlv(0x30, &tlv(0x06, &[0x2A])); // pkcs7-data-ish
        let mut cert_block = Vec::new();
        for c in certs {
            cert_block.extend_from_slice(c);
        }
        let certificates = tlv(0xA0, &cert_block); // certificates [0] IMPLICIT
        let signer_infos = tlv(0x31, &[]);
        let mut sd_body = Vec::new();
        for part in [&version, &digest_algs, &encap, &certificates, &signer_infos] {
            sd_body.extend_from_slice(part);
        }
        let signed_data = tlv(0x30, &sd_body);
        let content_0 = tlv(0xA0, &signed_data); // content [0] EXPLICIT
        let content_type = tlv(
            0x06,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02],
        );
        let mut ci_body = content_type;
        ci_body.extend_from_slice(&content_0);
        tlv(0x30, &ci_body) // ContentInfo
    }

    // ── Sub-step 1: swapSignString ─────────────────────────────────────────
    //
    // Known-vector: a constructed 32-char input lets us assert the EXACT
    // permutation B1+A+C+B2 independently of any secret.
    #[test]
    fn swap_sign_string_permutes_blocks() {
        let input = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"; // 8*4 = 32
        assert_eq!(input.len(), 32);
        // A=AAAAAAAA B1=BBBBBBBB B2=CCCCCCCC C=DDDDDDDD -> B1+A+C+B2
        let out = swap_sign_string(input).unwrap();
        assert_eq!(out, "BBBBBBBBAAAAAAAADDDDDDDDCCCCCCCC");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn swap_sign_string_distinct_index_vector() {
        // Use distinct chars so a transposition bug is visible.
        let input = "0123456789abcdefghijklmnopqrstuv"; // 32 distinct
        assert_eq!(input.len(), 32);
        // A=01234567 B1=89abcdef B2=ghijklmn C=opqrstuv
        // out = B1 A C B2 = 89abcdef 01234567 opqrstuv ghijklmn
        assert_eq!(
            swap_sign_string(input).unwrap(),
            "89abcdef01234567opqrstuvghijklmn"
        );
    }

    // NEGATIVE: prove the check bites on a wrong-length input.
    #[test]
    fn swap_sign_string_rejects_wrong_length() {
        assert!(matches!(
            swap_sign_string("tooshort"),
            Err(Error::InvalidSignInput(_))
        ));
        assert!(matches!(
            swap_sign_string(&"x".repeat(33)),
            Err(Error::InvalidSignInput(_))
        ));
    }

    // NEGATIVE: prove non-ASCII (would corrupt byte-slicing) is rejected.
    #[test]
    fn swap_sign_string_rejects_non_ascii() {
        // 'é' is 2 UTF-8 bytes, so 16 of them are 32 BYTES but only 16 chars.
        // Tuya slices by byte index; a non-ASCII input would make byte-slicing
        // land mid-codepoint, so we must reject it loudly.
        let non_ascii = "é".repeat(16); // 32 bytes, 16 chars
        assert_eq!(non_ascii.len(), 32);
        assert!(!non_ascii.is_ascii());
        assert!(matches!(
            swap_sign_string(&non_ascii),
            Err(Error::InvalidSignInput(_))
        ));
    }

    // ── Sub-step 2: MD5 ────────────────────────────────────────────────────
    //
    // Known vectors from RFC 1321 / standard MD5 test suite — INDEPENDENT of
    // our decompilation (a real differential oracle for the primitive).
    #[test]
    fn md5_hex_lower_known_vectors() {
        assert_eq!(md5_hex_lower(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex_lower(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex_lower(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    // NEGATIVE: a corrupted input must NOT match the clean digest.
    #[test]
    fn md5_hex_lower_corrupt_input_diverges() {
        let good = md5_hex_lower(b"The quick brown fox jumps over the lazy dog");
        let bad = md5_hex_lower(b"The quick brown fox jumps over the lazy dot"); // dog->dot
        assert_ne!(good, bad);
    }

    #[test]
    fn md5_as_base64_known_vector() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72; base64 of those 16 bytes.
        // Reference computed independently (python hashlib+base64), NOT from our
        // decompilation — a genuine differential for the base64 encoding.
        assert_eq!(md5_as_base64(b"abc"), "kAFQmDzST7DWlj99KOF/cg==");
        assert_eq!(md5_as_base64(b""), "1B2M2Y8AsgTpgAmY7PhCfg==");
    }

    // ── Sub-step 3: canonical string ───────────────────────────────────────
    #[test]
    fn canonical_string_sorts_filters_and_joins_with_pipes() {
        let mut p = BTreeMap::new();
        // intentionally insert out of order
        p.insert("v".into(), "1.0".into());
        p.insert("a".into(), "smartlife.m.user.email.password.login".into());
        p.insert("sid".into(), String::new()); // empty -> dropped (pre-login)
        p.insert("time".into(), "1700000000".into()); // WIRE name is `time` (not `t`)
        p.insert("t".into(), "ignored".into()); // `t` is NOT whitelisted -> dropped
        p.insert("notinwhitelist".into(), "ignored".into()); // dropped
        let s = canonical_string(&p);
        // sorted asc: a, time, v ; '||' joined ; empty sid dropped ; junk + bare
        // `t` dropped (the whitelisted timestamp key is `time`, not `t`).
        assert_eq!(
            s,
            "a=smartlife.m.user.email.password.login||time=1700000000||v=1.0"
        );
    }

    #[test]
    fn canonical_string_uses_double_pipe_not_ampersand() {
        let mut p = BTreeMap::new();
        p.insert("a".into(), "x".into());
        p.insert("v".into(), "y".into());
        let s = canonical_string(&p);
        assert_eq!(s, "a=x||v=y");
        assert!(s.contains("||"));
        assert!(!s.contains('&'), "must NOT join with '&' (Tuya uses '||')");
    }

    // NEGATIVE: a wrong separator would change the string; prove the assertion
    // bites by constructing the '&'-joined form and showing it differs.
    #[test]
    fn canonical_string_differs_from_query_string_form() {
        let mut p = BTreeMap::new();
        p.insert("a".into(), "x".into());
        p.insert("v".into(), "y".into());
        let correct = canonical_string(&p);
        let wrong_query_form = "a=x&v=y";
        assert_ne!(correct, wrong_query_form);
    }

    // ── Sub-step 2b: PhoneUtil-shaped deviceId + whitelist isH5 ─────────────

    // TASK-0064: the synthesized deviceId must be EXACTLY 44 lowercase-hex chars
    // (the PhoneUtil.getRemoteDeviceID layout 12+16+16), deterministic given its
    // inputs, with seg1 fixed by brand+model and the trailing 32 chars driven by
    // the random entropy.
    #[test]
    fn phone_util_device_id_is_44_lowercase_hex_and_segment_shaped() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let id = generate_phone_util_device_id("google", "Pixel 8 Pro", &a, &b);
        assert_eq!(id.len(), 44, "deviceId is 12+16+16 = 44 chars");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "deviceId is lowercase hex: {id}"
        );
        // Deterministic given the same inputs.
        assert_eq!(
            id,
            generate_phone_util_device_id("google", "Pixel 8 Pro", &a, &b)
        );
        // seg1 (first 12 chars) = md5hex(brand+model)[4..16] — independent of the
        // random segments; the trailing 32 chars change with different entropy.
        let id2 =
            generate_phone_util_device_id("google", "Pixel 8 Pro", &[0x99u8; 32], &[0x88u8; 32]);
        assert_eq!(&id[..12], &id2[..12], "seg1 depends only on brand+model");
        assert_ne!(&id[12..], &id2[12..], "random segments differ with entropy");
        // seg1 is exactly the documented md5hex(brand+model)[4..16].
        let expect_seg1 = &md5_hex_lower(b"googlePixel 8 Pro")[4..16];
        assert_eq!(&id[..12], expect_seg1);
    }

    // TASK-0064: the H5 flag's whitelist key is `isH5` (KEY_H5), NOT `h5`. Prove
    // an `isH5` param now enters the canonical string and a bare `h5` does not.
    #[test]
    fn whitelist_uses_is_h5_key_not_h5() {
        assert!(SIGN_WHITELIST.contains(&"isH5"));
        assert!(!SIGN_WHITELIST.contains(&"h5"));
        let mut p = BTreeMap::new();
        p.insert("isH5".into(), "true".into());
        p.insert("h5".into(), "ignored".into()); // not whitelisted -> dropped
        let s = canonical_string(&p);
        assert!(
            s.contains("isH5=true"),
            "isH5 must enter the canonical string: {s}"
        );
        assert!(!s.contains("h5=ignored"), "bare h5 must be dropped: {s}");
    }

    // ── Sub-step 4: master key G assembly ──────────────────────────────────

    // The 4-part RAW byte layout with single 0x5f separators. A synthetic 64-hex
    // bmp_token decodes to 32 raw bytes (matrixKey0). We assert the EXACT byte
    // string an INDEPENDENT manual concatenation produces.
    #[test]
    fn assemble_master_key_g_concatenates_four_raw_parts() {
        let pkg = "com.example.app";
        let digest = [0xABu8; 32];
        let cert = cert_sha256_colon_upper(&digest); // colon-upper 95-hex
        let bmp_hex = "cd".repeat(32); // 64-hex → 32 raw bytes
        let app_secret = "SYNTH_APPSECRET";
        // assemble_master_key_g takes the RAW digest and formats it internally.
        let g = assemble_master_key_g(pkg, &digest, &bmp_hex, app_secret).unwrap();

        // INDEPENDENT manual build of the same byte string.
        let matrix0 = hex::decode(&bmp_hex).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(pkg.as_bytes());
        expected.push(0x5f);
        expected.extend_from_slice(cert.as_bytes());
        expected.push(0x5f);
        expected.extend_from_slice(&matrix0); // RAW 32 bytes, NOT the ascii hex
        expected.push(0x5f);
        expected.extend_from_slice(app_secret.as_bytes());
        assert_eq!(g, expected);
        // matrixKey0 is the RAW decode, so the ascii hex must NOT appear verbatim.
        assert!(
            !g.windows(bmp_hex.len()).any(|w| w == bmp_hex.as_bytes()),
            "matrixKey0 must be the RAW bytes, not the ascii hex string"
        );
    }

    // The exact byte-length of G for a synthetic 64-hex bmp_token: the regression
    // guard on the 4-part layout (pkg + _ + 95-char cert + _ + 32 raw + _ + secret).
    #[test]
    fn master_key_g_has_exact_layout_length() {
        let digest = [0u8; 32];
        let cert = cert_sha256_colon_upper(&digest);
        assert_eq!(cert.len(), 95);
        let bmp_hex = "ab".repeat(32); // 32 raw bytes
        let app_secret = "SYNTH_APPSECRET_0000000000000000";
        let g = assemble_master_key_g(APP_PACKAGE_NAME, &digest, &bmp_hex, app_secret).unwrap();
        assert_eq!(
            g.len(),
            APP_PACKAGE_NAME.len() + 1 + 95 + 1 + 32 + 1 + app_secret.len(),
        );
    }

    // NEGATIVE: a non-hex bmp_token must error loudly (the matrixKey0 decode is
    // the silent-wrong-G trap), not silently build a wrong G from ascii bytes.
    #[test]
    fn assemble_master_key_g_rejects_non_hex_token() {
        assert!(matches!(
            assemble_master_key_g("pkg", &[0u8; 32], "NOT_HEX_!!", "secret"),
            Err(Error::InvalidSignInput(_))
        ));
    }

    // cert_sha256_colon_upper: the EXACT 95-char colon-grouped UPPERCASE form. The
    // expected string is hand-written (a true gold vector, not computed by the fn)
    // — this is the regression test for the exact silent-failure bug (lowercase
    // 64-hex vs colon-upper 95-hex).
    #[test]
    fn cert_sha256_colon_upper_exact_gold_vector() {
        // digest = [0x00, 0x01, 0x02, …, 0x1f]
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = i as u8;
        }
        let got = cert_sha256_colon_upper(&digest);
        let expected = "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:\
                        10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F";
        assert_eq!(got, expected);
        assert_eq!(got.len(), 95, "32*2 + 31 colons = 95");
        // UPPER only (no lowercase), colon at every 3rd position except the last.
        assert!(!got.chars().any(|c| c.is_ascii_lowercase()));
        for (i, b) in got.bytes().enumerate() {
            if (i + 1) % 3 == 0 {
                assert_eq!(b, b':', "colon expected at index {i}");
            } else {
                assert!(b.is_ascii_uppercase() || b.is_ascii_digit());
            }
        }
    }

    // FIPS-180 SHA-256 known-answer vectors for the primitive that underlies both
    // the HMAC and the cert digest. INDEPENDENT of our decompilation.
    #[test]
    fn sha256_fips180_known_vectors() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ── Sub-step 6: chKey (HMAC-SHA256) ────────────────────────────────────
    //
    // INDEPENDENT differential for the HMAC primitive: RFC 4231 Test Case 2
    // (key="Jefe", data="what do ya want for nothing?"). This validates our
    // hand-rolled HMAC-SHA256 against a published vector — NOT our own
    // decompilation — so a construction bug (wrong pad, missing pre-hash) is
    // caught loudly.
    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231 Test Case 6: key longer than the 64-byte block (131 bytes of
    // 0xaa) — exercises the >block-size pre-hash branch of the key-setup, which
    // mirrors the native FUN_00117780 over-long-key path.
    #[test]
    fn hmac_sha256_rfc4231_test_case_6_long_key() {
        let key = vec![0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sha256(&key, data);
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    // chKey composition: with SYNTHETIC inputs, the recovered pipeline
    // (HMAC-SHA256(key=appId, msg=packageName_"_"_certHex) → hex[8..16]) must
    // equal an INDEPENDENT recomputation. This pins the key/message ordering and
    // native substring behavior recovered from getChKey@0x16000 (appId is the
    // HMAC KEY; packageName_cert is the MESSAGE).
    #[test]
    fn ch_key_composes_hmac_over_packagename_cert() {
        let app_key = "SYNTH_APPKEY_000000";
        let pkg = "com.example.app";
        let digest = [0xABu8; 32];
        // `cert` is the colon-upper 95-hex form used by the INDEPENDENT recompute
        // below; `ch_key` formats the raw digest to that form internally, so we
        // pass the raw `digest` to it.
        let cert = cert_sha256_colon_upper(&digest);
        let got = ch_key(app_key, pkg, &digest);

        // INDEPENDENT: HMAC-SHA256(key=appId, msg=pkg + "_" + cert), hex[8..16].
        let full = hex::encode(hmac_sha256(
            app_key.as_bytes(),
            format!("{pkg}_{cert}").as_bytes(),
        ));
        assert_eq!(got, full[8..16]);
        assert_eq!(
            got.len(),
            8,
            "wire getChKey returns hex_hmac[8..16] (capture-verified)"
        );
        assert!(got
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // The key/message roles are NOT symmetric: swapping appId and the message
    // yields a different chKey. Proves the recovered ordering is load-bearing
    // (a wrong key/msg swap would silently produce a wrong, plausible token).
    #[test]
    fn ch_key_key_message_order_is_load_bearing() {
        let digest = [0xCDu8; 32];
        let cert = cert_sha256_colon_upper(&digest);
        let correct = ch_key("APPID", "PKG", &digest);
        // Wrong: treat the message as the key and vice-versa.
        let swapped = hex::encode(hmac_sha256(format!("PKG_{cert}").as_bytes(), b"APPID"));
        assert_ne!(correct, swapped);
    }

    #[test]
    fn et3_encrypto_key_matches_native_hmac_shape() {
        let request_id = "REQ-123";
        let g = b"GGGG_master_secret_G_bytes"; // raw master-key bytes (synthetic)

        // Native getEncryptoKey returns Java byte[16] copied from the first 16
        // ASCII bytes of lowercase hex(HMAC-SHA256(key=requestId, msg=G)).
        let expected_hex = hex::encode(hmac_sha256(request_id.as_bytes(), g));
        let got = et3_encrypto_key(request_id, g, None);
        assert_eq!(&got, &expected_hex.as_bytes()[..16]);
        assert!(got.iter().all(u8::is_ascii_hexdigit));
    }

    #[test]
    fn et3_encrypto_key_appends_ecode_when_present() {
        let request_id = "REQ-123";
        let g = b"GGGG_master_secret_G_bytes";
        let ecode = "ECODE";

        let no_ecode = et3_encrypto_key(request_id, g, None);
        let with_ecode = et3_encrypto_key(request_id, g, Some(ecode));
        assert_ne!(no_ecode, with_ecode, "ecode changes the native message");

        // msg = G ++ 0x5f ++ ecode (the bytes, not a string concat of hex).
        let mut msg = g.to_vec();
        msg.push(b'_');
        msg.extend_from_slice(ecode.as_bytes());
        let expected_hex = hex::encode(hmac_sha256(request_id.as_bytes(), &msg));
        assert_eq!(&with_ecode, &expected_hex.as_bytes()[..16]);
    }

    // The default package name constant matches the manifest `package=`.
    #[test]
    fn app_package_name_is_the_manifest_package() {
        assert_eq!(APP_PACKAGE_NAME, "com.philips.ph.babymonitorplus");
    }

    // ── Sub-step 5: cert SHA-256 extraction (synthetic DER) ────────────────
    //
    // Build a structurally-valid synthetic PKCS#7 SignedData and prove the
    // hardened extractor recovers the exact embedded cert SEQUENCE bytes — no
    // real (secret) cert needed.
    #[test]
    fn extract_leaf_cert_der_finds_single_cert() {
        let cert = fake_cert(b"ISS", b"SUB");
        let blob = fake_pkcs7(std::slice::from_ref(&cert));
        let extracted = extract_leaf_cert_der(&blob).unwrap();
        assert_eq!(
            extracted, cert,
            "must recover the exact cert SEQUENCE bytes"
        );
    }

    // Multi-cert chain: leaf (subject=LEAF, issued by CA) + CA (self-signed).
    // The extractor must pick the LEAF (its subject is no other cert's issuer),
    // NOT the first SEQUENCE — this is the AC#1 multi-cert hardening.
    #[test]
    fn extract_leaf_cert_der_picks_leaf_in_chain() {
        let ca = fake_cert(b"CA", b"CA"); // self-signed root
        let leaf = fake_cert(b"CA", b"LEAF"); // issued by CA
                                              // Put the CA FIRST so the old "first SEQUENCE" path would mis-pick it.
        let blob = fake_pkcs7(&[ca.clone(), leaf.clone()]);
        let extracted = extract_leaf_cert_der(&blob).unwrap();
        assert_eq!(
            extracted, leaf,
            "must select the end-entity (leaf), not the CA"
        );
        assert_ne!(extracted, ca, "must NOT pick the CA that signed the chain");
    }

    // Ambiguous chain (two unrelated self-signed certs → two leaf candidates):
    // must FAIL LOUD, never silently pick one.
    #[test]
    fn extract_leaf_cert_der_fails_loud_on_ambiguous_chain() {
        let a = fake_cert(b"AAA", b"AAA");
        let b = fake_cert(b"BBB", b"BBB");
        let blob = fake_pkcs7(&[a, b]);
        let err = extract_leaf_cert_der(&blob).unwrap_err();
        assert!(
            matches!(&err, Error::CertHash(m) if m.contains("ambiguous")),
            "ambiguous chain must error, got {err:?}"
        );
    }

    #[test]
    fn app_cert_sha256_hex_is_64_lowercase_hex() {
        let cert = fake_cert(b"ISS", b"SUB");
        let blob = fake_pkcs7(std::slice::from_ref(&cert));
        let digest = app_cert_sha256_hex(&blob).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // NEGATIVE: a blob with no certificate must error, not silently hash junk.
    #[test]
    fn extract_leaf_cert_der_rejects_blob_without_cert() {
        let junk = vec![0x06, 0x03, 1, 2, 3, 0x05, 0x00]; // OID + NULL, no cert
        assert!(matches!(
            extract_leaf_cert_der(&junk),
            Err(Error::CertHash(_))
        ));
    }

    // ── TOKEN-PENDING discipline ───────────────────────────────────────────
    #[test]
    fn signer_is_token_pending_without_provider() {
        // SYNTHETIC key material — no real secret.
        let material = SigningKeyMaterial {
            app_key: "SYNTH_APPKEY_000000".into(),
            app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
            app_cert_sha256: [0u8; 32],
            ttid: "SYNTH_TTID".into(),
        };
        let signer = Signer::new(material, PendingBmpToken);
        let mut params = BTreeMap::new();
        params.insert("a".into(), "smartlife.m.user.email.password.login".into());
        params.insert("time".into(), "1700000000".into());

        let result = signer.sign(&params);
        assert!(
            matches!(result, Err(Error::BmpTokenPending)),
            "without a bmp_token the signer MUST report pending, not fabricate"
        );
    }

    #[test]
    fn signer_redacts_secrets_in_debug() {
        let material = SigningKeyMaterial {
            app_key: "SECRETKEY".into(),
            app_secret: "SECRETSECRET".into(),
            app_cert_sha256: [0u8; 32],
            ttid: "ttid".into(),
        };
        let dbg = format!("{material:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("SECRETKEY"));
        assert!(!dbg.contains("SECRETSECRET"));
    }

    // The wire `sign` is 64 lowercase hex chars (HMAC-SHA256 → 32 bytes → 64 hex),
    // NOT the old 32-char MD5 form. This is the headline shape AC of TASK-0060.
    #[test]
    fn sign_output_is_64_lowercase_hex() {
        let material = SigningKeyMaterial {
            app_key: "SYNTH_APPKEY_000000".into(),
            app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
            app_cert_sha256: [0xABu8; 32],
            ttid: "SYNTH_TTID".into(),
        };
        let signer = Signer::new(material, StaticBmpToken::new("cd".repeat(32)));
        let mut params = BTreeMap::new();
        params.insert("a".into(), "smartlife.m.user.username.token.get".into());
        params.insert("time".into(), "1700000000".into());

        let sign = signer.sign(&params).unwrap();
        assert_eq!(sign.len(), 64, "HMAC-SHA256 sign is 64 hex chars, not 32");
        assert!(sign
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // PARTIAL DIFFERENTIAL over the recovered sub-steps: with a SYNTHETIC
    // bmp_token the assembled G + HMAC are fully determined and reproducible. We
    // assert the composed pipeline equals an INDEPENDENT manual recomputation
    // (HMAC-SHA256(G, str2)) — proving the recovered steps compose correctly NOW,
    // without the real token. The RECIPE itself (key=G, msg=str2) is single-source
    // ground truth and cannot be offline-validated end-to-end; this only proves the
    // Rust composition is self-consistent over its sub-steps.
    #[test]
    fn partial_differential_recovered_substeps_compose() {
        let material = SigningKeyMaterial {
            app_key: "SYNTH_APPKEY_000000".into(),
            app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
            app_cert_sha256: [0xABu8; 32],
            ttid: "SYNTH_TTID".into(),
        };
        let bmp_hex = "cd".repeat(32); // synthetic 64-hex → 32 raw bytes
        let signer = Signer::new(material.clone(), StaticBmpToken::new(bmp_hex.clone()));

        let mut params = BTreeMap::new();
        params.insert("a".into(), "smartlife.m.user.email.password.login".into());
        params.insert("v".into(), "1.0".into());
        params.insert("time".into(), "1700000000".into());

        let got = signer.sign(&params).unwrap();

        // INDEPENDENT recomputation of the recovered pipeline:
        let str2 = "a=smartlife.m.user.email.password.login||time=1700000000||v=1.0";
        let g = assemble_master_key_g(
            APP_PACKAGE_NAME,
            &material.app_cert_sha256,
            &bmp_hex,
            &material.app_secret,
        )
        .unwrap();
        let expected = hex::encode(hmac_sha256(&g, str2.as_bytes()));
        assert_eq!(got, expected);
        assert_eq!(got.len(), 64);

        // A different bmp_token (→ different G) must change the sign (the token is
        // genuinely a keyed input, not cosmetic).
        let signer2 = Signer::new(material, StaticBmpToken::new("ef".repeat(32)));
        assert_ne!(got, signer2.sign(&params).unwrap());
    }

    // post_data_digest: surfaces the length-24-vs-32 ambiguity as a typed error
    // (honest), and proves the swap composes on a forced 32-char input.
    #[test]
    fn post_data_digest_reports_length_ambiguity() {
        // md5AsBase64 of any input is 24 chars (16-byte digest), so the current
        // swapSignString (32-char contract) rejects it. This documents the open
        // ambiguity rather than silently emitting a wrong digest.
        let r = post_data_digest(b"{\"countryCode\":\"45\"}");
        assert!(
            matches!(r, Err(Error::InvalidSignInput(_))),
            "24-char md5-base64 must surface the documented length ambiguity"
        );
    }

    // post_data_digest_hex: the 32-hex-MD5 fold IS well-defined for swapSignString.
    // Independent recomputation: md5_hex("{}") then the documented block swap.
    #[test]
    fn post_data_digest_hex_swaps_32_char_md5() {
        let body = b"{}";
        let got = post_data_digest_hex(body).unwrap();
        // INDEPENDENT: hex MD5 of body (32 chars), then swapSignString.
        let hex = md5_hex_lower(body);
        assert_eq!(hex.len(), 32);
        let expected = swap_sign_string(&hex).unwrap();
        assert_eq!(got, expected);
        assert_eq!(got.len(), 32);
        // The swap must actually permute (not identity) for a generic digest.
        assert_ne!(got, hex, "swapSignString must permute the 32-char md5 hex");
    }

    // Offline validation of the RECOVERED app-cert ingredient against the
    // ACTUAL APK signing cert. #[ignore]d because it needs the gitignored APK
    // (extracted/xapk/...), which is not present in every checkout / CI; run it
    // manually with `--include-ignored` against a real extraction. It asserts
    // the helper yields a 64-hex digest from the real META-INF/BNDLTOOL.RSA —
    // it does NOT print or commit the value (CLAUDE.md: cert hash is withheld).
    #[test]
    #[ignore = "needs the gitignored APK at extracted/xapk/...; run manually \
                with --include-ignored to validate the real cert ingredient"]
    fn real_app_cert_sha256_is_64_hex() {
        let apk = std::path::Path::new("../../extracted/xapk/com.philips.ph.babymonitorplus.apk");
        if !apk.exists() {
            // Be explicit rather than silently passing.
            panic!("APK not extracted at {}", apk.display());
        }
        let digest =
            app_cert_sha256_hex_from_apk(apk).expect("offline cert SHA-256 from real BNDLTOOL.RSA");
        assert_eq!(digest.len(), 64, "app-cert SHA-256 must be 64 hex chars");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        // NB: the value itself is a secret-by-policy identifier — never assert
        // or print it here.
    }

    // AC#1 CROSS-CHECK (the honesty fix): our pure-Rust extractor's cert digest
    // MUST equal an INDEPENDENT reference computed by `openssl` over the same
    // META-INF/BNDLTOOL.RSA. The reference is deliberately NOT the misleading
    // `openssl x509 -outform DER` RE-ENCODE path; it is `openssl asn1parse
    // -strparse <off>` which lifts the RAW embedded leaf-cert SEQUENCE bytes
    // verbatim — i.e. exactly Android's `signatures[0]` semantics (the cycle-14
    // review established the raw embedded SEQUENCE is the correct reference).
    //
    // The reference command, end to end (all offline, no device):
    //   1. unzip META-INF/BNDLTOOL.RSA from the APK            (zip reader)
    //   2. openssl asn1parse -inform DER -in RSA               (find cert offset)
    //         → the `certificates [0]` leaf SEQUENCE offset
    //   3. openssl asn1parse -inform DER -strparse <off> -out  (raw cert bytes)
    //   4. sha256 of those raw bytes
    // and we assert_eq! it against app_cert_sha256_hex_from_apk(apk).
    //
    // The hash VALUE is WITHHELD: we compare two computed digests, never print
    // or hardcode it (CLAUDE.md: the cert hash is a secret-by-policy id).
    //
    // #[ignore]d: needs the gitignored APK AND an `openssl` binary on PATH (both
    // present under nix-shell). Run via `just cert-crosscheck` or
    // `cargo test ... real_app_cert_matches_openssl_reference -- --ignored`.
    #[test]
    #[ignore = "needs the gitignored APK + an openssl binary on PATH; run via \
                `just cert-crosscheck` to differentially validate the extractor"]
    fn real_app_cert_matches_openssl_reference() {
        use std::process::Command;

        let apk = std::path::Path::new("../../extracted/xapk/com.philips.ph.babymonitorplus.apk");
        if !apk.exists() {
            panic!("APK not extracted at {}", apk.display());
        }

        // ── Our path: pure-Rust extractor over the real APK. ────────────────
        let ours = app_cert_sha256_hex_from_apk(apk).expect("rust cert digest from APK");

        // ── Reference path: openssl over the raw embedded leaf cert. ─────────
        // 1) Lift the PKCS#7 block out of the APK with our (already-tested) zip
        //    reader, write it to a temp file for openssl to read.
        let apk_bytes = std::fs::read(apk).expect("read APK");
        let pkcs7 = find_signature_block_in_zip(&apk_bytes).expect("PKCS#7 block from APK");
        let tmp = std::env::temp_dir().join("task0031_bndltool.p7");
        std::fs::write(&tmp, &pkcs7).expect("write temp PKCS#7");

        // 2) asn1parse to find the leaf Certificate SEQUENCE byte offset. The
        //    leaf is the FIRST `cons: SEQUENCE` at depth d=4 (inside the
        //    `cont [0]` certificates block at d=3). We parse the offset column.
        let parse = Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(&tmp)
            .output()
            .expect("run openssl asn1parse (is openssl on PATH?)");
        assert!(
            parse.status.success(),
            "openssl asn1parse failed: {}",
            String::from_utf8_lossy(&parse.stderr)
        );
        let listing = String::from_utf8(parse.stdout).expect("asn1parse utf8");
        let cert_off = leaf_cert_offset_from_asn1parse(&listing)
            .expect("locate leaf cert SEQUENCE offset in asn1parse output");

        // 3) -strparse <off> extracts the RAW DER of that SEQUENCE (no re-encode).
        let raw_cert = std::env::temp_dir().join("task0031_leaf.der");
        let strparse = Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(&tmp)
            .args(["-strparse", &cert_off.to_string(), "-noout", "-out"])
            .arg(&raw_cert)
            .output()
            .expect("run openssl asn1parse -strparse");
        assert!(
            strparse.status.success(),
            "openssl -strparse failed: {}",
            String::from_utf8_lossy(&strparse.stderr)
        );

        // 4) SHA-256 the raw embedded cert bytes = the independent reference.
        let ref_bytes = std::fs::read(&raw_cert).expect("read raw leaf cert");
        let reference = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&ref_bytes);
            hex::encode(h.finalize())
        };

        // Cleanup temp artifacts (best-effort).
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&raw_cert);

        // ── The differential assertion. VALUE WITHHELD. ─────────────────────
        assert_eq!(
            ours, reference,
            "Rust extractor digest must equal the independent openssl \
             raw-embedded-leaf reference (Android signatures[0] semantics). \
             [values intentionally not printed]"
        );
    }

    /// Parse `openssl asn1parse` output and return the byte offset of the leaf
    /// X.509 `Certificate` SEQUENCE — the first `cons: SEQUENCE` whose inner
    /// content is itself a SEQUENCE (tbsCertificate) of cert size. We pick the
    /// FIRST depth-4 (`d=4`) constructed SEQUENCE following the `cont [ 0 ]`
    /// certificates block; in a multi-cert chain that is the leaf only when it
    /// is listed first, but for THIS single-cert APK there is exactly one. The
    /// Rust extractor (not this helper) owns multi-cert leaf selection; this
    /// reference just needs the one embedded cert's raw bytes.
    fn leaf_cert_offset_from_asn1parse(listing: &str) -> Option<usize> {
        // Find the certificates `cont [ 0 ]` line at depth d=3, then the next
        // `d=4 ... cons: SEQUENCE`. Lines look like:
        //   "   56:d=3  hl=4 l= 962 cons: cont [ 0 ]"
        //   "   60:d=4  hl=4 l= 958 cons: SEQUENCE"
        let mut in_certs = false;
        for line in listing.lines() {
            let is_cont0 = line.contains("d=3") && line.contains("cont [ 0 ]");
            if is_cont0 {
                in_certs = true;
                continue;
            }
            if in_certs && line.contains("d=4") && line.contains("cons: SEQUENCE") {
                // Offset is the integer before the first ':'.
                let off_str = line.split(':').next()?.trim();
                return off_str.parse::<usize>().ok();
            }
        }
        None
    }

    // FULL byte-for-byte differential (AC#1): blocked on the real bmp_token
    // (TASK-0032) + an INDEPENDENT gold vector (nalajcie tooling or a single
    // live capture). We do NOT fabricate a gold vector. This test is #[ignore]d
    // and will be filled in when TASK-0032 lands; running it now is honest about
    // the gap rather than asserting a self-derived (circular) value.
    #[test]
    #[ignore = "AC#1 byte-for-byte sign parity is blocked on the real bmp_token \
                (TASK-0032) + an INDEPENDENT gold vector; do not fabricate one"]
    fn full_signature_byte_parity_pending_task_0032() {
        // Intentionally empty: there is NO honest assertion to make until the
        // bmp_token is ported and an independent reference vector exists. A
        // self-derived expectation would be circular (forbidden by TESTING.md
        // Part-2 signal #2 / AC#5). Left as a marked pending test, not a stub
        // returning Ok — it asserts nothing and is excluded from the suite.
    }
}
