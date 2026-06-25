//! Tuya mobile-app ("atop") request signer.
//!
//! This module re-implements the Tuya **mobile-app SDK** request-signing
//! algorithm recovered statically in `re/tuya_sign_static.md` (+ the canonical
//! string in `re/tuya_sign.md` §1-3). It is the algorithm the native
//! `JNICLibrary.doCommandNative(ctx, cmd=1, str2, …)` path computes; we reproduce
//! it in safe Rust so the client never needs the device's native blob.
//!
//! # What is recovered vs pending
//!
//! Recovered and unit-tested here (5 of 6 ingredients —
//! `re/tuya_sign_static.md` §6):
//! - the sorted-whitelist canonical string ([`canonical_string`]) — literal `||`
//!   join, NOT `&`;
//! - [`swap_sign_string`] — the 32-char permutation;
//! - [`post_data_digest`] — `swapSignString(md5AsBase64(body))`;
//! - [`md5_hex_lower`] — the keyed-hash primitive is plain **MD5** (NOT
//!   HMAC-SHA256: MD5 IV constants at `libthing_security.so@0x76c0`,
//!   `re/tuya_sign_static.md` §3);
//! - [`assemble_sign_key`] — the underscore-joined key parts; and
//! - [`app_cert_sha256_hex`] — the app-cert SHA-256, computable **offline** from
//!   the APK signing cert (`META-INF/*.RSA`).
//!
//! Pending (the 6th ingredient, TOKEN-PENDING — `re/tuya_sign_static.md` §5 +
//! `re/bmp_token_whitebox.md` §8): the `bmp_token` decoded from `assets/t_s.bmp`
//! by an imath-bignum + matrix decode (sign path:
//! `fcn.13b5c` → `read_keys_from_content@0x4974` → matrix `fcn.5eb0`), not yet
//! ported. Tracked by **TASK-0032**. Until a [`BmpTokenProvider`] yields
//! it, [`Signer::sign`] returns [`Error::BmpTokenPending`].
//!
//! # Honest confidence (per `re/tuya_sign_static.md` §7-8)
//!
//! The MD5 primitive, the `_` separator, and the offline cert-hash are
//! `confirmed` (byte-level disassembly). The exact **order** of the underscore
//! parts and whether the hash input also folds the canonical string (vs only the
//! key) are `likely` — read from control-flow shape, not executed. A single
//! differential vector (which needs the bmp_token, TASK-0032) pins them. This
//! module exposes both [`assemble_sign_key`] (the `_`-join, `confirmed`) and the
//! fold choice as an explicit [`SignBody`] so the disambiguation lands in ONE
//! place when TASK-0032 unblocks the gold vector — it is NOT silently guessed.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::Error;

/// The fixed whitelist of envelope param keys the signer canonicalizes, in the
/// spelling used by `ThingApiSignManager.bdpdqbp` (`re/tuya_sign.md` §1). Only
/// keys in this set with a non-empty value enter the canonical string; all other
/// params are ignored by the signer. Kept as a sorted-on-use slice; the builder
/// sorts the *present* keys lexicographically (Tuya sorts `map.keySet()`).
pub const SIGN_WHITELIST: &[&str] = &[
    "a",
    "v",
    "lat",
    "lon",
    "lang",
    "deviceId",
    "appVersion",
    "ttid",
    "h5",
    "h5Token",
    "os",
    "appId",
    "postData",
    "t",
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
/// This is `MD5Util.md5AsBase64` (`re/tuya_sign.md` §2): the form folded into the
/// canonical string for the `postData` param.
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
// Sub-step 4: sign-key assembly ("_"-join)
// ─────────────────────────────────────────────────────────────────────────────

/// Assemble the MD5 sign **key** from its three underscore-joined parts
/// (`re/tuya_sign_static.md` §4 / §7):
/// `cert_sha256_hex + "_" + bmp_token + "_" + appSecret`.
///
/// The **order** of these parts is labelled `likely` in the spec (read from
/// control flow, not executed); this function encodes that documented order in
/// one place so a single gold vector (TASK-0032) can correct it if wrong, rather
/// than the order being scattered across call sites.
#[must_use]
pub fn assemble_sign_key(cert_sha256_hex: &str, bmp_token: &str, app_secret: &str) -> String {
    format!("{cert_sha256_hex}{KEY_PART_SEP}{bmp_token}{KEY_PART_SEP}{app_secret}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-step 5: offline app-cert SHA-256
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the app signing-certificate SHA-256, lowercase hex, **offline** from
/// raw PKCS#7 (`*.RSA`) signature-block bytes (`re/tuya_sign_static.md` §4).
///
/// Tuya's native sign uses `MessageDigest.getInstance("SHA256").digest(certBytes)`
/// over `getPackageInfo(GET_SIGNATURES).signatures[0]`, hex-encoded, as the first
/// `_`-joined key part. The same hash is reproducible from the APK's own v1
/// signing cert (`META-INF/BNDLTOOL.RSA`) with NO device.
///
/// `pkcs7_der` is the DER PKCS#7 SignedData block. We extract the embedded leaf
/// X.509 certificate's DER bytes and SHA-256 them. To avoid pulling a full ASN.1
/// crate into the scaffold, we locate the leaf cert by scanning for the X.509
/// `Certificate` SEQUENCE that begins the `certificates [0]` context tag in the
/// SignedData — see [`extract_leaf_cert_der`].
///
/// # Errors
/// [`Error::CertHash`] if no embedded certificate can be located.
pub fn app_cert_sha256_hex(pkcs7_der: &[u8]) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    let cert_der = extract_leaf_cert_der(pkcs7_der)?;
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    Ok(hex::encode(hasher.finalize()))
}

/// Read `META-INF/<name>.RSA` (or `.EC`/`.DSA`) from an APK/zip on disk and
/// return the app-cert SHA-256 lowercase hex (`re/tuya_sign_static.md` §4).
///
/// This is the offline ingredient validation entry point: point it at
/// `extracted/xapk/com.philips.ph.babymonitorplus.apk` and it yields the 64-hex
/// digest with no device. The path is a caller-supplied secret location (per
/// CLAUDE.md, the value is never committed).
///
/// # Errors
/// [`Error::CertHash`] if the zip cannot be opened, no signature block is found,
/// or the cert cannot be extracted.
pub fn app_cert_sha256_hex_from_apk(apk_path: &std::path::Path) -> Result<String, Error> {
    let bytes = std::fs::read(apk_path)
        .map_err(|e| Error::CertHash(format!("read APK {}: {e}", apk_path.display())))?;
    let der = find_signature_block_in_zip(&bytes)?;
    app_cert_sha256_hex(&der)
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

/// Extract the leaf X.509 certificate's DER bytes from a PKCS#7 SignedData blob.
///
/// A PKCS#7 SignedData carries the signing cert inside a `certificates [0]
/// IMPLICIT` context tag, each cert a DER `SEQUENCE` (tag `0x30`). We find the
/// first DER `SEQUENCE` whose declared length spans a self-consistent
/// X.509-shaped structure (an inner `SEQUENCE` = tbsCertificate). This is a
/// pragmatic extractor (no full ASN.1 parser); it errors loudly if it cannot
/// find a plausible certificate rather than guessing.
///
/// # Errors
/// [`Error::CertHash`] if no certificate SEQUENCE is found.
pub fn extract_leaf_cert_der(pkcs7_der: &[u8]) -> Result<Vec<u8>, Error> {
    // Walk top-level/any-level DER SEQUENCEs and return the first that parses as
    // an X.509 cert shape: SEQUENCE { SEQUENCE(tbs) ... }. We scan for tag 0x30
    // followed by a definite long-form length, then check the inner content
    // starts with another 0x30 (tbsCertificate) — a strong signal for a cert vs
    // the outer ContentInfo/SignedData sequences (which start with an OID 0x06).
    let mut i = 0usize;
    while i + 4 < pkcs7_der.len() {
        if pkcs7_der[i] == 0x30 {
            if let Some((content_start, content_len)) = der_length(pkcs7_der, i + 1) {
                let end = content_start + content_len;
                if end <= pkcs7_der.len() && content_len > 0 && pkcs7_der[content_start] == 0x30 {
                    // Inner starts with SEQUENCE (tbsCertificate). Within an
                    // X.509 cert the tbs is itself followed by an algorithm-id
                    // SEQUENCE and a BIT STRING; require the whole thing be a
                    // reasonable size to avoid matching tiny inner sequences.
                    if content_len >= 64 {
                        let total = end - i;
                        return Ok(pkcs7_der[i..i + total].to_vec());
                    }
                }
            }
        }
        i += 1;
    }
    Err(Error::CertHash(
        "no X.509 certificate SEQUENCE found in PKCS#7 block".into(),
    ))
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
// Injected key material + token provider (the clean injected interface)
// ─────────────────────────────────────────────────────────────────────────────

/// Non-secret-by-construction holder for the signer's static key material.
///
/// All four fields are loaded by the CALLER from `secrets/tuya_appkey.json` (and
/// the app-cert hash computed offline via [`app_cert_sha256_hex_from_apk`]) at
/// runtime — **no value is hardcoded** in this crate. Tests construct this with
/// SYNTHETIC values only.
///
/// Feed-forward (TASK-0013): the device-list/service layer should build on THIS
/// shape — pass a borrowed `&SigningKeyMaterial` into request decoration rather
/// than re-reading secrets. `app_key`/`ttid` are the envelope `clientId`/`ttid`
/// params; `app_secret` and `app_cert_sha256_hex` are sign-key parts only.
#[derive(Clone)]
pub struct SigningKeyMaterial {
    /// Tuya appKey (20-char) — wire `clientId` param + cmd-0 native init.
    pub app_key: String,
    /// Tuya appSecret (32-char) — the third `_`-joined sign-key part.
    pub app_secret: String,
    /// App signing-cert SHA-256, lowercase hex (64 chars) — first sign-key part.
    pub app_cert_sha256_hex: String,
    /// Channel TTID — wire `ttid` param.
    pub ttid: String,
}

impl std::fmt::Debug for SigningKeyMaterial {
    /// Redacts secret values: never print appSecret / cert-hash / appKey bodies.
    /// Prevents the key material leaking via `{:?}` into logs (CLAUDE.md: never
    /// leak secrets through any channel).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyMaterial")
            .field("app_key", &Redacted(self.app_key.len()))
            .field("app_secret", &Redacted(self.app_secret.len()))
            .field(
                "app_cert_sha256_hex",
                &Redacted(self.app_cert_sha256_hex.len()),
            )
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

/// Which body the keyed MD5 hashes — the `likely`-confidence fold choice from
/// `re/tuya_sign_static.md` §7 (`MD5(key)` vs `MD5(key || canonical_string)`).
///
/// We make this EXPLICIT rather than guessing: a caller (or the TASK-0032 gold
/// vector) selects the variant, and the ambiguity is resolved in exactly one
/// place. Defaults to [`SignBody::KeyAndCanonical`] because the native code
/// computes MD5 twice (`re/tuya_sign_static.md` §7), consistent with folding the
/// canonical string — but this is `likely`, not `confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignBody {
    /// `MD5(sign_key)` only.
    KeyOnly,
    /// `MD5(sign_key + canonical_string)`.
    #[default]
    KeyAndCanonical,
}

/// The composable signer: injected key material + an injected
/// [`BmpTokenProvider`]. Build with [`Signer::new`], sign with [`Signer::sign`].
///
/// The signer holds NO secrets of its own — it borrows them from the injected
/// [`SigningKeyMaterial`] and provider, so the caller owns secret lifetimes.
pub struct Signer<P: BmpTokenProvider> {
    material: SigningKeyMaterial,
    token_provider: P,
    body: SignBody,
}

impl<P: BmpTokenProvider> Signer<P> {
    /// Construct a signer from injected key material and a token provider.
    /// Uses the default [`SignBody`]; override with [`Signer::with_body`].
    pub fn new(material: SigningKeyMaterial, token_provider: P) -> Self {
        Self {
            material,
            token_provider,
            body: SignBody::default(),
        }
    }

    /// Override the keyed-hash body choice (the `likely` fold ambiguity).
    #[must_use]
    pub fn with_body(mut self, body: SignBody) -> Self {
        self.body = body;
        self
    }

    /// Produce the wire `sign` value for the given envelope params.
    ///
    /// Pipeline (`re/tuya_sign_static.md` §7): build the canonical string,
    /// obtain the `bmp_token` (injected), assemble the `_`-joined key, then
    /// `md5_hex_lower` of the chosen [`SignBody`].
    ///
    /// The caller MUST pass `params` whose `postData` value is already the
    /// [`post_data_digest`] (Tuya digests it before sorting); this method does
    /// not re-digest.
    ///
    /// # Errors
    /// - [`Error::BmpTokenPending`] if the injected provider has no token (the
    ///   honest TOKEN-PENDING state — TASK-0032). This is the CURRENT default
    ///   behaviour with [`PendingBmpToken`].
    /// - any error the provider returns.
    ///
    /// # Honesty
    /// A full, byte-valid signature is NOT yet achievable offline: it requires
    /// the `bmp_token` (TASK-0032). With [`PendingBmpToken`] this method always
    /// returns [`Error::BmpTokenPending`] — it never returns a fabricated value.
    pub fn sign(&self, params: &BTreeMap<String, String>) -> Result<String, Error> {
        let canonical = canonical_string(params);
        let bmp_token = self.token_provider.bmp_token()?;
        let key = assemble_sign_key(
            &self.material.app_cert_sha256_hex,
            &bmp_token,
            &self.material.app_secret,
        );
        let digest_input = match self.body {
            SignBody::KeyOnly => key,
            SignBody::KeyAndCanonical => format!("{key}{canonical}"),
        };
        Ok(md5_hex_lower(digest_input.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        p.insert("t".into(), "1700000000".into());
        p.insert("notinwhitelist".into(), "ignored".into()); // dropped
        let s = canonical_string(&p);
        // sorted asc: a, t, v ; '||' joined ; empty sid dropped ; junk dropped
        assert_eq!(
            s,
            "a=smartlife.m.user.email.password.login||t=1700000000||v=1.0"
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

    // ── Sub-step 4: key assembly ───────────────────────────────────────────
    #[test]
    fn assemble_sign_key_underscore_joins_in_order() {
        // SYNTHETIC parts only.
        let key = assemble_sign_key("CERTHASH", "BMPTOKEN", "APPSECRET");
        assert_eq!(key, "CERTHASH_BMPTOKEN_APPSECRET");
        assert_eq!(key.matches('_').count(), 2);
    }

    #[test]
    fn assemble_sign_key_order_is_load_bearing() {
        // Prove the assertion bites: a different order yields a different key.
        let correct = assemble_sign_key("A", "B", "C");
        let swapped = assemble_sign_key("C", "B", "A");
        assert_ne!(correct, swapped);
    }

    // ── Sub-step 5: cert SHA-256 extraction (synthetic DER) ────────────────
    //
    // Build a minimal PKCS#7-shaped buffer: a SEQUENCE wrapping an inner cert
    // SEQUENCE that itself starts with a tbs SEQUENCE >= 64 bytes. This proves
    // the extractor + hash without needing the real (secret) cert.
    #[test]
    fn extract_leaf_cert_der_finds_cert_sequence() {
        // Inner cert: SEQUENCE(len=70) { SEQUENCE(len=68){ 68 bytes... } }
        let tbs_body = vec![0xABu8; 68];
        let mut tbs = vec![0x30, 68];
        tbs.extend_from_slice(&tbs_body); // tbs SEQUENCE, len 68 -> total 70
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs); // cert SEQUENCE wrapping tbs
                                      // Wrap in an outer "pkcs7-ish" SEQUENCE preceded by some OID noise.
        let mut blob = vec![0x06, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9]; // an OID to skip
        blob.extend_from_slice(&cert);

        let extracted = extract_leaf_cert_der(&blob).unwrap();
        assert_eq!(
            extracted, cert,
            "must recover the exact cert SEQUENCE bytes"
        );
    }

    #[test]
    fn app_cert_sha256_hex_is_64_lowercase_hex() {
        // Same synthetic cert as above; we only assert SHAPE (64 lowercase hex),
        // never a real value.
        let tbs_body = vec![0xABu8; 68];
        let mut tbs = vec![0x30, 68];
        tbs.extend_from_slice(&tbs_body);
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        let digest = app_cert_sha256_hex(&cert).unwrap();
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
            app_cert_sha256_hex: "00".repeat(32),
            ttid: "SYNTH_TTID".into(),
        };
        let signer = Signer::new(material, PendingBmpToken);
        let mut params = BTreeMap::new();
        params.insert("a".into(), "smartlife.m.user.email.password.login".into());
        params.insert("t".into(), "1700000000".into());

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
            app_cert_sha256_hex: "deadbeef".into(),
            ttid: "ttid".into(),
        };
        let dbg = format!("{material:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("SECRETKEY"));
        assert!(!dbg.contains("SECRETSECRET"));
        assert!(!dbg.contains("deadbeef"));
    }

    // PARTIAL DIFFERENTIAL over the recovered sub-steps: with a SYNTHETIC
    // placeholder bmp_token, the assembled key + MD5 are fully determined and
    // reproducible. We assert the composed pipeline equals an INDEPENDENT manual
    // recomputation (md5 of the '_'-joined key + canonical) — proving the
    // recovered steps compose correctly NOW, without the real token. This is the
    // honest partial differential of TESTING.md Part-2 signal #2.
    #[test]
    fn partial_differential_recovered_substeps_compose() {
        let material = SigningKeyMaterial {
            app_key: "SYNTH_APPKEY_000000".into(),
            app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
            app_cert_sha256_hex: "ab".repeat(32), // synthetic 64-hex
            ttid: "SYNTH_TTID".into(),
        };
        let placeholder_token = StaticBmpToken::new("PLACEHOLDER_BMP_TOKEN");
        let signer =
            Signer::new(material.clone(), placeholder_token).with_body(SignBody::KeyAndCanonical);

        let mut params = BTreeMap::new();
        params.insert("a".into(), "smartlife.m.user.email.password.login".into());
        params.insert("v".into(), "1.0".into());
        params.insert("t".into(), "1700000000".into());

        let got = signer.sign(&params).unwrap();

        // INDEPENDENT recomputation of the recovered pipeline:
        let canonical = "a=smartlife.m.user.email.password.login||t=1700000000||v=1.0";
        let key = format!(
            "{}_{}_{}",
            "ab".repeat(32),
            "PLACEHOLDER_BMP_TOKEN",
            "SYNTH_APPSECRET_0000000000000000"
        );
        let expected = md5_hex_lower(format!("{key}{canonical}").as_bytes());
        assert_eq!(got, expected);
        assert_eq!(got.len(), 32);

        // KeyOnly body must differ (proves the SignBody fold is load-bearing).
        let signer_keyonly = Signer::new(material, StaticBmpToken::new("PLACEHOLDER_BMP_TOKEN"))
            .with_body(SignBody::KeyOnly);
        let got_keyonly = signer_keyonly.sign(&params).unwrap();
        assert_ne!(got, got_keyonly);
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
