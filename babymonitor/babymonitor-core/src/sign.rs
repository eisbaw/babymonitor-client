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
//! - [`post_data_digest_hex`] — the live-path `swapSignString(md5_hex(body))`
//!   fold for `postData`;
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
    "h5",
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
///                                     msg   = packageName + "_" + certSha256Hex ) )[8..24]
/// ```
///
/// where:
/// - `appId` = `ThingSmartNetWork.mAppId.getBytes()` = the Tuya **appKey** (the
///   same value carried on the wire as `clientId`);
/// - `packageName` = `getPackageName()` = [`APP_PACKAGE_NAME`] (static, from the
///   manifest); stored by native `FUN_00116528` into `.bss` `DAT_001390a0`;
/// - `certSha256Hex` = the app signing-cert SHA-256 lowercase hex —
///   offline-computable from the APK (`re/tuya_sign_static.md` §4,
///   [`app_cert_sha256_hex_from_apk`]); stored into `.bss` `DAT_00139058`.
///
/// The keyed digest is **HMAC-SHA256** (NOT plain MD5 like the request `sign`):
/// the native algo-descriptor at `0x132fe0` is `{id=6, name="SHA256",
/// digestSize=0x20, blockSize=0x40}` and the key-setup `FUN_00117780` does the
/// canonical HMAC ipad(`0x36`)/opad(`0x5c`) pad-XOR. Ghidra shows the native
/// function hex-encodes the 32-byte digest, then returns a Java string copied
/// from byte offset 8, capped at 16 chars. The `_` join byte (`0x5f`) is written
/// at `getChKey@0x116108`. All STATIC — no runtime/device/cloud input.
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
/// - `cert_sha256_hex` — the app-cert SHA-256 lowercase hex (64 chars).
///
/// The returned `chKey` is a per-app value derived from the appKey + cert hash —
/// **secret-by-policy** (CLAUDE.md): it must only ever go to `secrets/`, never a
/// tracked file.
#[must_use]
pub fn ch_key(app_key: &str, package_name: &str, cert_sha256_hex: &str) -> String {
    let message = format!("{package_name}{KEY_PART_SEP}{cert_sha256_hex}");
    let mac = hmac_sha256(app_key.as_bytes(), message.as_bytes());
    let hex = hex::encode(mac);
    hex[8..24].to_string()
}

/// Native `SecureNativeApi.getEncryptoKey(requestId, ecode)` for ET=3 post bodies.
///
/// Ghidra export `re/ghidra/getEncryptoKey.c` shows the JNI function calls the same
/// HMAC-SHA256 helper used by `getChKey`, with:
/// - HMAC key = `requestId.getBytes()`;
/// - HMAC message = native cached sign key (`cert "_" bmpToken "_" appSecret`);
/// - when the second Java arg is non-empty, the message becomes
///   `cachedKey "_" ecode`;
/// - return value = a Java byte[16] copied from the first 16 ASCII bytes of the
///   lowercase hex HMAC digest.
///
/// This function implements that JNI behavior for static clients. For pre-login
/// login requests (`token.get`, `password.login`) the app sets
/// `setSessionRequire(false)`, so pass `None` for `ecode`.
#[must_use]
pub fn et3_encrypto_key(request_id: &str, cached_key: &str, ecode: Option<&str>) -> [u8; 16] {
    let message = match ecode.filter(|s| !s.is_empty()) {
        Some(ecode) => format!("{cached_key}{KEY_PART_SEP}{ecode}"),
        None => cached_key.to_string(),
    };
    let mac = hmac_sha256(request_id.as_bytes(), message.as_bytes());
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
    // (HMAC-SHA256(key=appId, msg=packageName_"_"_certHex) → hex[8..24]) must
    // equal an INDEPENDENT recomputation. This pins the key/message ordering and
    // native substring behavior recovered from getChKey@0x16000 (appId is the
    // HMAC KEY; packageName_cert is the MESSAGE).
    #[test]
    fn ch_key_composes_hmac_over_packagename_cert() {
        let app_key = "SYNTH_APPKEY_000000";
        let pkg = "com.example.app";
        let cert = "ab".repeat(32); // synthetic 64-hex
        let got = ch_key(app_key, pkg, &cert);

        // INDEPENDENT: HMAC-SHA256(key=appId, msg=pkg + "_" + cert), hex[8..24].
        let full = hex::encode(hmac_sha256(
            app_key.as_bytes(),
            format!("{pkg}_{cert}").as_bytes(),
        ));
        assert_eq!(got, full[8..24]);
        assert_eq!(got.len(), 16, "native getChKey returns hex_hmac[8..24]");
        assert!(got
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // The key/message roles are NOT symmetric: swapping appId and the message
    // yields a different chKey. Proves the recovered ordering is load-bearing
    // (a wrong key/msg swap would silently produce a wrong, plausible token).
    #[test]
    fn ch_key_key_message_order_is_load_bearing() {
        let correct = ch_key("APPID", "PKG", &"cd".repeat(32));
        // Wrong: treat the message as the key and vice-versa.
        let swapped = hex::encode(hmac_sha256(
            format!("PKG_{}", "cd".repeat(32)).as_bytes(),
            b"APPID",
        ));
        assert_ne!(correct, swapped);
    }

    #[test]
    fn et3_encrypto_key_matches_native_hmac_shape() {
        let request_id = "REQ-123";
        let cached_key = "cert_bmp_secret";

        // Native getEncryptoKey returns Java byte[16] copied from the first 16
        // ASCII bytes of lowercase hex(HMAC-SHA256(key=requestId, msg=cachedKey)).
        let expected_hex = hex::encode(hmac_sha256(request_id.as_bytes(), cached_key.as_bytes()));
        let got = et3_encrypto_key(request_id, cached_key, None);
        assert_eq!(&got, &expected_hex.as_bytes()[..16]);
        assert!(got.iter().all(u8::is_ascii_hexdigit));
    }

    #[test]
    fn et3_encrypto_key_appends_ecode_when_present() {
        let request_id = "REQ-123";
        let cached_key = "cert_bmp_secret";
        let ecode = "ECODE";

        let no_ecode = et3_encrypto_key(request_id, cached_key, None);
        let with_ecode = et3_encrypto_key(request_id, cached_key, Some(ecode));
        assert_ne!(no_ecode, with_ecode, "ecode changes the native message");

        let msg = format!("{cached_key}_{ecode}");
        let expected_hex = hex::encode(hmac_sha256(request_id.as_bytes(), msg.as_bytes()));
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
            app_cert_sha256_hex: "00".repeat(32),
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
        params.insert("time".into(), "1700000000".into());

        let got = signer.sign(&params).unwrap();

        // INDEPENDENT recomputation of the recovered pipeline:
        let canonical = "a=smartlife.m.user.email.password.login||time=1700000000||v=1.0";
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
