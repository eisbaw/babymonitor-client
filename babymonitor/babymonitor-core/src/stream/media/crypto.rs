//! Media-plane (PATH A) crypto: per-datagram integrity + per-KCP-segment decrypt.
//!
//! Two distinct, ordered transforms (`re/media_decode_spec.md` §1, §2):
//!
//! 1. **Datagram HMAC-SHA1 (suite 3 only)** — [`verify_and_strip_hmac`]. The
//!    whole UDP datagram carries a trailing **20-byte** `HMAC-SHA1(key16, body)`
//!    where `key16` is the 16 raw bytes of the SDP `a=aes-key` (same key as the
//!    AES below). Verified + stripped BEFORE KCP sees the bytes
//!    (`FUN_0016e350.c:66-79`, §1 step 2). **[C — cap4-pinned]**
//!
//!    cap4 correction: the trailer is **20 bytes = HMAC-SHA1**, NOT the 32-byte
//!    HMAC-SHA256 the spec first assumed. Proven two independent ways on the
//!    captured stream: (a) `HMAC-SHA1(key16, datagram[..len-20])` reproduces the
//!    real trailing 20 bytes for every sampled datagram; (b) the receiver builds
//!    the MAC via `mbedtls_md_info_from_type(5)` (`FUN_0016a004:100`) and in the
//!    device's mbedtls 3.x (PSA-aligned) enum, type `5 == SHA-1`.
//!
//! 2. **Per-segment AES decrypt** — [`decrypt_segment_cbc`] (suite 3) /
//!    [`decrypt_segment_gcm`] (suite 4). Each KCP segment payload is
//!    `[IV 16B (cleartext) | AES ciphertext]`; the IV is inline/per-segment, the
//!    cipher is AES-128 keyed by the same 16-byte SDP key, and (CBC) the
//!    plaintext is PKCS#7-padded (`ctx_session_chan_process_pkt.c:12-30`, §2).
//!    **[C for CBC; G for GCM framing]**
//!
//! Confidence tags mirror the spec: **[C]** suite 3 (CBC + HMAC-SHA1) is
//! confirmed — it is the cap3-observed default (`security_level == 3`) and the
//! cap4 media capture validates the whole transform end-to-end (the recovered
//! H.264 decodes cleanly); **[G]** suite 4 (GCM) framing is inferred from the
//! cipher vtable and NOT observed live — its exact nonce length / tag placement
//! is unconfirmed and flagged at the call site.

use crate::Error;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// AES block size (and CBC IV / GCM-nonce length used by this path), in bytes.
pub const AES_BLOCK: usize = 16;
/// The inline per-segment IV length (cleartext prefix of every segment payload).
pub const IV_LEN: usize = 16;
/// The trailing datagram HMAC-SHA1 tag length (suite 3). `md_get_size(SHA1)` =
/// 20 bytes — cap4-pinned (see the module header; mbedtls md type `5 == SHA-1`).
pub const HMAC_TAG_LEN: usize = 20;
/// The trailing per-segment GCM auth-tag length (suite 4).
pub const GCM_TAG_LEN: usize = 16;
/// The minimum AES-128 / SDP-`a=aes-key` key length this path accepts.
pub const MEDIA_KEY_LEN: usize = 16;

/// AES-128-CBC decryptor type alias (RustCrypto `cbc` over `aes`).
type Aes128CbcDec = cbc::Decryptor<Aes128>;
/// AES-128-CBC encryptor type alias (the TX direction, inverse of the RX decrypt).
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

/// TX (suite 3): PKCS#7-pad `plaintext`, AES-128-CBC-encrypt under `key16`+`iv`,
/// and return the KCP segment payload `[IV 16B | ciphertext]` — the **exact inverse
/// of [`decrypt_segment_cbc`]** (round-trip KAT'd). This is what a client-initiated
/// KCP PUSH carries on the conv=0 control channel (cap4 frames 253–255).
///
/// # Errors
/// [`Error::Transport`] if `key16` is not [`MEDIA_KEY_LEN`] bytes.
pub fn seal_segment_cbc(
    plaintext: &[u8],
    key16: &[u8],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, Error> {
    use aes::cipher::BlockEncryptMut;
    let pad = AES_BLOCK - (plaintext.len() % AES_BLOCK);
    let mut buf = Vec::with_capacity(plaintext.len() + pad);
    buf.extend_from_slice(plaintext);
    buf.extend(std::iter::repeat(pad as u8).take(pad));
    let mut enc = Aes128CbcEnc::new_from_slices(key16, iv).map_err(|_| {
        Error::Transport(format!(
            "AES-128-CBC init failed: key is {} bytes (expected {MEDIA_KEY_LEN})",
            key16.len()
        ))
    })?;
    for block in buf.chunks_mut(AES_BLOCK) {
        enc.encrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    let mut out = Vec::with_capacity(IV_LEN + buf.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// TX (suite 3): append the trailing 20-byte `HMAC-SHA1(key16, body)` datagram tag
/// — the inverse of [`verify_and_strip_hmac`]. `body` = the framed KCP datagram
/// (header + segment payload); the result is the on-wire UDP payload.
///
/// # Errors
/// [`Error::Transport`] if `key16` is rejected by HMAC init (any length is accepted
/// by HMAC, so this effectively never errors, but the signature stays uniform).
pub fn append_datagram_hmac(body: &[u8], key16: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key16)
        .map_err(|e| Error::Transport(format!("HMAC-SHA1 init: {e}")))?;
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut out = Vec::with_capacity(body.len() + HMAC_TAG_LEN);
    out.extend_from_slice(body);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Verify and strip the trailing 20-byte `HMAC-SHA1` tag from a suite-3 media
/// datagram, returning the integrity-checked body (KCP header + IV + ciphertext)
/// with the tag removed.
///
/// Mirrors the native ingress (`FUN_0016e350.c:34, 66-79`): reject a datagram
/// shorter than `tag_len + 24` (one KCP header + the tag), recompute
/// `HMAC-SHA1(key16, datagram[0 .. len-20])`, and constant-time-compare against
/// the trailing 20 bytes. A mismatch is the native `"invalid md code"` drop.
///
/// **A match alone proves the 16-byte media key and the datagram framing are
/// correct** (`re/media_decode_spec.md` §4 Step A). On cap4 this is also the
/// per-session key gate: the capture carries several overlapping sessions on the
/// same `conv`, and only the datagrams whose HMAC validates under *this* key
/// belong to *this* session — the rest are dropped here exactly as native does.
///
/// # Errors
/// - [`Error::Transport`] if the datagram is too short to carry a header + tag.
/// - [`Error::Transport`] if the HMAC does not verify (wrong media key or a
///   corrupt datagram) — we fail loud rather than forward unauthenticated bytes.
pub fn verify_and_strip_hmac<'a>(datagram: &'a [u8], key16: &[u8]) -> Result<&'a [u8], Error> {
    // The native gate is `len < tag_len + 24` (one 24-byte KCP header + the tag).
    if datagram.len() < HMAC_TAG_LEN + crate::stream::media::kcp::IKCP_OVERHEAD {
        return Err(Error::Transport(format!(
            "media datagram is {} bytes; need at least {} (24B KCP header + 20B HMAC)",
            datagram.len(),
            HMAC_TAG_LEN + crate::stream::media::kcp::IKCP_OVERHEAD
        )));
    }
    let split = datagram.len() - HMAC_TAG_LEN;
    let (body, tag) = datagram.split_at(split);
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key16)
        .map_err(|e| Error::Transport(format!("HMAC-SHA1 key init failed: {e}")))?;
    mac.update(body);
    // `verify_slice` is constant-time (mirrors `mbedtls`'s safe compare).
    mac.verify_slice(tag).map_err(|_| {
        Error::Transport(
            "media datagram HMAC-SHA1 mismatch (\"invalid md code\"): wrong media key \
             or corrupt datagram"
                .to_string(),
        )
    })?;
    Ok(body)
}

/// Decrypt one suite-3 KCP segment payload: `[IV 16B | AES-128-CBC ciphertext]`
/// → PKCS#7-unpadded plaintext.
///
/// This is the in-library per-segment decryptor (`ctx_session_chan_process_pkt`,
/// §1 step 4 / §2): `ct_len = seg_len - 16`; require `ct_len > 0 &&
/// (ct_len & 0xf) == 0` (block-aligned ⇒ block cipher); `IV = seg[0..16]`,
/// `ct = seg[16..]`; AES-128-CBC decrypt; then PKCS#7 unpad.
///
/// # Errors
/// - [`Error::Transport`] if the segment is shorter than the 16-byte IV, or the
///   ciphertext length is not a non-zero multiple of the 16-byte block.
/// - [`Error::Transport`] if the key is not 16 bytes.
/// - [`Error::Transport`] if the PKCS#7 padding is invalid after decrypt (the
///   signature of a wrong key / corrupt segment — we never return garbage).
pub fn decrypt_segment_cbc(seg_payload: &[u8], key16: &[u8]) -> Result<Vec<u8>, Error> {
    let ct_len = seg_payload.len().checked_sub(IV_LEN).ok_or_else(|| {
        Error::Transport(format!(
            "KCP segment payload is {} bytes; shorter than the 16-byte inline IV",
            seg_payload.len()
        ))
    })?;
    if ct_len == 0 || ct_len % AES_BLOCK != 0 {
        return Err(Error::Transport(format!(
            "CBC segment ciphertext is {ct_len} bytes; must be a non-zero multiple of {AES_BLOCK} \
             (the native `(ct_len & 0xf)==0` block-alignment guard)"
        )));
    }
    let (iv, ct) = seg_payload.split_at(IV_LEN);
    let mut dec = Aes128CbcDec::new_from_slices(key16, iv).map_err(|_| {
        Error::Transport(format!(
            "AES-128-CBC init failed: key is {} bytes (expected {MEDIA_KEY_LEN}) or IV is not {IV_LEN}",
            key16.len()
        ))
    })?;
    let mut buf = ct.to_vec();
    for block in buf.chunks_mut(AES_BLOCK) {
        dec.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    pkcs7_unpad(buf)
}

/// Decrypt one suite-4 KCP segment payload: `[IV 16B | AES-128-GCM ciphertext |
/// 16B tag]` → plaintext (no PKCS#7 — GCM is a stream/AEAD mode).
///
/// **[G] — suite 4 is NOT the cap3-observed path.** Its framing is inferred from
/// the cipher vtable (`re/media_decode_spec.md` §2): a 16-byte inline nonce, the
/// 16-byte GCM tag trailing the ciphertext inside the segment, and (unlike suite
/// 3) NO datagram HMAC. The exact nonce length is unconfirmed — GCM's standard
/// nonce is 96-bit, but the inline IV the encode side writes is 16 bytes, so we
/// use a 16-byte nonce here. Treat a successful decrypt as the confirmation; do
/// not assume this path is live until a capture pins `security_level == 4`.
///
/// # Errors
/// - [`Error::Transport`] if the segment is shorter than IV + tag, or the key is
///   not 16 bytes.
/// - [`Error::Transport`] if GCM authentication fails (wrong key / corrupt
///   segment, or — equally likely while [G] — the assumed framing is wrong).
pub fn decrypt_segment_gcm(seg_payload: &[u8], key16: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_gcm::aead::consts::U16;
    use aes_gcm::aead::Aead;
    use aes_gcm::{AesGcm, KeyInit};

    // AES-128-GCM with a 16-byte (inline) nonce — see the [G] note above.
    type Aes128Gcm16 = AesGcm<Aes128, U16>;

    if seg_payload.len() < IV_LEN + GCM_TAG_LEN {
        return Err(Error::Transport(format!(
            "GCM segment is {} bytes; need at least {} (16B IV + 16B tag) [suite 4 framing is [G]]",
            seg_payload.len(),
            IV_LEN + GCM_TAG_LEN
        )));
    }
    let key: [u8; MEDIA_KEY_LEN] = key16.try_into().map_err(|_| {
        Error::Transport(format!(
            "media key is {} bytes; AES-128-GCM expects {MEDIA_KEY_LEN}",
            key16.len()
        ))
    })?;
    let (iv, ct_and_tag) = seg_payload.split_at(IV_LEN);
    let cipher = Aes128Gcm16::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(iv);
    // RustCrypto AEAD `decrypt` expects ciphertext||tag, which is exactly the
    // bytes after the inline IV.
    cipher.decrypt(nonce, ct_and_tag).map_err(|_| {
        Error::Transport(
            "AES-128-GCM authentication failed (wrong key / corrupt segment, or the \
             unconfirmed [G] suite-4 framing is wrong)"
                .to_string(),
        )
    })
}

/// Strip + validate PKCS#7 padding from a CBC plaintext block sequence.
///
/// Mirrors the native unpad (`ctx_session_chan_process_pkt.c:24-30`): read the
/// last byte `pad`; require `1 <= pad <= 16 && pad <= len`; and (stricter than
/// the native length-only check, but safe) require all `pad` trailing bytes equal
/// `pad`. A wrong key makes this fail with overwhelming probability — exactly the
/// §4 Step C sanity gate.
///
/// # Errors
/// [`Error::Transport`] for an empty buffer or any invalid padding (corrupt
/// ciphertext / wrong media key).
fn pkcs7_unpad(data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let pad = *data
        .last()
        .ok_or_else(|| Error::Transport("CBC plaintext is empty after decrypt".to_string()))?
        as usize;
    if pad == 0 || pad > AES_BLOCK || pad > data.len() {
        return Err(Error::Transport(format!(
            "invalid PKCS#7 pad byte {pad} (corrupt segment or wrong media key)"
        )));
    }
    let cut = data.len() - pad;
    if data[cut..].iter().any(|&b| b as usize != pad) {
        return Err(Error::Transport(
            "inconsistent PKCS#7 padding bytes (corrupt segment or wrong media key)".to_string(),
        ));
    }
    let mut data = data;
    data.truncate(cut);
    Ok(data)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Encode-side helpers used ONLY by tests to construct ground-truth vectors
    //! (the spec's send path: inline-IV + PKCS#7 + CBC, and the datagram HMAC).
    //! These mirror `FUN_0016304c` (send IV+pad) and `FUN_0016950c` (HMAC append).
    use super::*;
    use aes::cipher::BlockEncryptMut;

    type Aes128CbcEnc = cbc::Encryptor<Aes128>;

    /// PKCS#7-pad then AES-128-CBC-encrypt `plaintext` under `key16`+`iv`, and
    /// return the segment payload `[IV | ciphertext]` (what a KCP PUSH carries).
    #[must_use]
    pub fn cbc_seal_segment(plaintext: &[u8], key16: &[u8], iv: &[u8; IV_LEN]) -> Vec<u8> {
        let pad = AES_BLOCK - (plaintext.len() % AES_BLOCK);
        let mut buf = Vec::with_capacity(plaintext.len() + pad);
        buf.extend_from_slice(plaintext);
        buf.extend(std::iter::repeat(pad as u8).take(pad));
        let mut enc = Aes128CbcEnc::new_from_slices(key16, iv).expect("test key/iv length");
        for block in buf.chunks_mut(AES_BLOCK) {
            enc.encrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        let mut out = Vec::with_capacity(IV_LEN + buf.len());
        out.extend_from_slice(iv);
        out.extend_from_slice(&buf);
        out
    }

    /// AES-128-GCM-seal `plaintext` and return `[IV | ciphertext | 16B tag]`.
    #[must_use]
    pub fn gcm_seal_segment(plaintext: &[u8], key16: &[u8], iv: &[u8; IV_LEN]) -> Vec<u8> {
        use aes_gcm::aead::consts::U16;
        use aes_gcm::aead::Aead;
        use aes_gcm::{AesGcm, KeyInit};
        type Aes128Gcm16 = AesGcm<Aes128, U16>;
        let key: [u8; MEDIA_KEY_LEN] = key16.try_into().expect("test key length");
        let cipher = Aes128Gcm16::new(GenericArray::from_slice(&key));
        let ct_and_tag = cipher
            .encrypt(GenericArray::from_slice(iv), plaintext)
            .expect("gcm encrypt");
        let mut out = Vec::with_capacity(IV_LEN + ct_and_tag.len());
        out.extend_from_slice(iv);
        out.extend_from_slice(&ct_and_tag);
        out
    }

    /// Append a trailing 20-byte `HMAC-SHA1(key16, body)` tag to `body` (suite 3).
    #[must_use]
    pub fn append_hmac(body: &[u8], key16: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key16).expect("hmac key");
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let mut out = body.to_vec();
        out.extend_from_slice(&tag);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    // A SYNTHETIC 16-byte media key (never a real device/session key — CLAUDE.md).
    const KEY: &[u8; 16] = b"0123456789abcdef"; // secret-scan:allow (synthetic test key)
    const IV: &[u8; 16] = b"IVIVIVIVIVIVIVIV"; // secret-scan:allow (synthetic test IV)

    // ── Datagram HMAC (suite 3) ────────────────────────────────────────────

    #[test]
    fn hmac_round_trips_and_strips_tag() {
        let body = b"some kcp datagram body bytes ............ 24+ bytes here!!";
        let dg = append_hmac(body, KEY);
        assert_eq!(dg.len(), body.len() + HMAC_TAG_LEN);
        let got = verify_and_strip_hmac(&dg, KEY).unwrap();
        assert_eq!(got, body, "stripped body must equal the pre-HMAC bytes");
    }

    // NEGATIVE: a one-bit flip in the body fails the HMAC (loud, never forwarded).
    #[test]
    fn hmac_rejects_tampered_body() {
        let body = b"another datagram body with enough length to pass the size gate!!";
        let mut dg = append_hmac(body, KEY);
        dg[0] ^= 0x01;
        assert!(matches!(
            verify_and_strip_hmac(&dg, KEY),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: the wrong media key fails the HMAC (proves key-binding bites).
    #[test]
    fn hmac_rejects_wrong_key() {
        let body = b"datagram body bytes for the wrong-key hmac rejection test ......";
        let dg = append_hmac(body, KEY);
        assert!(verify_and_strip_hmac(&dg, b"fedcba9876543210").is_err()); // secret-scan:allow
    }

    // NEGATIVE: a datagram too short for header+tag is rejected up front.
    #[test]
    fn hmac_rejects_too_short() {
        assert!(matches!(
            verify_and_strip_hmac(&[0u8; 10], KEY),
            Err(Error::Transport(_))
        ));
    }

    // ── Per-segment AES-128-CBC inline-IV + PKCS#7 (suite 3) ────────────────

    #[test]
    fn cbc_segment_round_trips_unaligned_plaintext() {
        let pt = b"a 12B RTP hdr + payload that is not block aligned"; // 49 bytes
        let seg = cbc_seal_segment(pt, KEY, IV);
        // seg = IV(16) + ciphertext (padded up to the next 16 boundary).
        assert_eq!(seg.len(), IV_LEN + 64);
        let got = decrypt_segment_cbc(&seg, KEY).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn cbc_segment_round_trips_block_aligned_plaintext() {
        let pt = vec![0xABu8; 32]; // already block-aligned → full extra pad block
        let seg = cbc_seal_segment(&pt, KEY, IV);
        assert_eq!(seg.len(), IV_LEN + 48); // 32 data + 16 pad block
        assert_eq!(decrypt_segment_cbc(&seg, KEY).unwrap(), pt);
    }

    // NEGATIVE: the wrong key trips PKCS#7 validation (no garbage plaintext).
    #[test]
    fn cbc_segment_wrong_key_fails_padding() {
        let seg = cbc_seal_segment(b"hello media plane", KEY, IV);
        let r = decrypt_segment_cbc(&seg, b"fedcba9876543210"); // secret-scan:allow
        assert!(
            matches!(r, Err(Error::Transport(_))),
            "wrong key must fail, got {r:?}"
        );
    }

    // TASK-0083 §S6b: the PUBLIC `seal_segment_cbc` (the TX inverse used by the
    // media-start path) round-trips a 28-byte imm control PDU through
    // `decrypt_segment_cbc`. 28 bytes → 4 bytes PKCS#7 pad → 32B ciphertext, so the
    // sealed segment is IV(16) + 32 = 48 bytes (the on-wire media-start payload len).
    #[test]
    fn seal_segment_cbc_is_exact_inverse_for_a_28b_pdu() {
        // Shape-only stand-in for an imm control PDU (28 bytes); the round-trip is
        // key/IV-agnostic, so a synthetic pattern suffices.
        let pdu: Vec<u8> = (0..28u8).collect();
        let seg = seal_segment_cbc(&pdu, KEY, IV).unwrap();
        assert_eq!(
            seg.len(),
            IV_LEN + 32,
            "16B IV + 32B CBC of the padded 28B PDU"
        );
        assert_eq!(&seg[..IV_LEN], IV, "the inline IV is the cleartext prefix");
        assert_eq!(decrypt_segment_cbc(&seg, KEY).unwrap(), pdu);
    }

    // NEGATIVE: a non-block-aligned ciphertext is rejected (the `&0xf` guard).
    #[test]
    fn cbc_segment_rejects_misaligned() {
        let mut seg = cbc_seal_segment(b"x", KEY, IV);
        seg.push(0x00); // break block alignment of the ciphertext
        assert!(matches!(
            decrypt_segment_cbc(&seg, KEY),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a segment shorter than the inline IV is rejected.
    #[test]
    fn cbc_segment_rejects_short() {
        assert!(matches!(
            decrypt_segment_cbc(&[0u8; 8], KEY),
            Err(Error::Transport(_))
        ));
    }

    // ── Per-segment AES-128-GCM (suite 4, [G]) ──────────────────────────────

    #[test]
    fn gcm_segment_round_trips() {
        let pt = b"suite-4 GCM media plaintext (unconfirmed framing)";
        let seg = gcm_seal_segment(pt, KEY, IV);
        assert_eq!(seg.len(), IV_LEN + pt.len() + GCM_TAG_LEN);
        assert_eq!(decrypt_segment_gcm(&seg, KEY).unwrap(), pt);
    }

    // NEGATIVE: a flipped ciphertext byte fails GCM authentication.
    #[test]
    fn gcm_segment_rejects_tamper() {
        let mut seg = gcm_seal_segment(b"tamper me", KEY, IV);
        let i = IV_LEN + 1;
        seg[i] ^= 0x01;
        assert!(matches!(
            decrypt_segment_gcm(&seg, KEY),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a too-short GCM segment (no room for IV+tag) is rejected.
    #[test]
    fn gcm_segment_rejects_short() {
        assert!(matches!(
            decrypt_segment_gcm(&[0u8; 20], KEY),
            Err(Error::Transport(_))
        ));
    }
}
