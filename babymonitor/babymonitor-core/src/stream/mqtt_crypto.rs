//! Crypto for the Tuya WebRTC session: the SDP `a=aes-key` hex codec (byte-exact,
//! pinned) and the 302-payload localKey-AES primitive (**now recovered + pinned**).
//!
//! Two distinct AES concerns live here; they have different confidence levels,
//! kept honestly separate:
//!
//! 1. **The SDP media-key hex codec** ([`encode_aes_key_hex`] /
//!    [`decode_aes_key_hex`]) — **byte-exact pinned** from
//!    `imm_p2p_rtc_sdp_set_aes_key` / `imm_p2p_rtc_sdp_get_aes_key`
//!    (`re/ghidra/imm_p2p_rtc_sdp_set_aes_key.c`, `…_get_aes_key.c`;
//!    `re/webrtc_session.md` §3c). These hex-encode/decode a RAW key of up to
//!    **23 bytes** (`len*2 < 0x30`, i.e. `len < 24`) as **lowercase** ASCII hex
//!    into the `a=aes-key:<hex>` SDP line — the media AES key carried
//!    plaintext-in-SDP.
//!
//! 2. **The 302-payload localKey-AES** ([`aes128_ecb_encrypt`] /
//!    [`aes128_ecb_decrypt`], wrapped by [`encrypt_302_payload`] /
//!    [`decrypt_302_payload`]) — the signaling envelope is published via
//!    `homeCamera.publish(devId, pv, localKey, jsonMsg, 302)`, AES-encrypted with
//!    the device `localKey` (`re/webrtc_session.md` §2a).
//!
//!    **The cipher IS statically pinned** (a prior claim that it was not is
//!    corrected here). Evidence, read directly from the decompile:
//!    - `decompiled/.../com/thingclips/sdk/mqtt/qpqddqd.java` calls
//!      `aESUtil.setALGO("AES")` — a CONSTANT string `"AES"` (`:133`, `:234`,
//!      `:632`), **not** a runtime numeric mode — then
//!      `aESUtil.setKeyValue(str.getBytes())` (`:134`/`:235`/`:633`), i.e. the key
//!      is the **ASCII bytes of the `localKey` string** (16 bytes).
//!    - `decompiled/.../com/thingclips/smart/android/common/utils/AESUtil.java`:
//!      `Cipher.getInstance(this.ALGO)` with `ALGO == "AES"` (`:526`, `:329`) ⇒ the
//!      JCE default transformation **`AES/ECB/PKCS5Padding`**; `cipher.init(1/2,
//!      key)` (`:527`/`:330`) with **NO `IvParameterSpec` ⇒ no IV (ECB)**; the key
//!      is `new SecretKeySpec(this.keyValue, this.ALGO)` (`:189`).
//!    - Output variant is selected by the publish bean / `pv`:
//!      `encrypt()` ⇒ **UPPERCASE hex** via `byte2hex` (`.toUpperCase()`, `:64`,
//!      `:528`); `encryptWithBase64()` ⇒ **base64** (`:586`);
//!      `encryptWithBytes()` ⇒ **raw bytes** (`:593`).
//!
//!    So [`aes128_ecb_encrypt`]/[`aes128_ecb_decrypt`] + [`Aes302Output`] are the
//!    recovered primitive, with a known-answer test (KAT) checked against an
//!    independent oracle (`openssl enc -aes-128-ecb`), NOT self-derived.
//!
//!    What GENUINELY remains live-gated — and ONLY this — is surfaced as
//!    [`crate::Error::MqttEnvelopePending`] by [`encrypt_302_payload`]: the
//!    **`pv` → output-variant binding** for message code 302 (which of
//!    hex/base64/raw the device expects at a given `pv`) and the **outer Tuya
//!    MQTT envelope framing**. There is no offline oracle / captured live 302 to
//!    pin those, so we do not guess them. The AES bytes themselves are produced.

use crate::Error;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::Engine as _;

/// AES block size in bytes (128-bit block — true for AES-128/192/256).
const AES_BLOCK: usize = 16;

/// The maximum RAW media-key length the SDP `a=aes-key` codec accepts: the
/// native `set/get_aes_key` gate is `len*2 < 0x30` ⇒ `len < 24` ⇒ **≤ 23 bytes**
/// (`re/ghidra/imm_p2p_rtc_sdp_set_aes_key.c`).
pub const MAX_SDP_AES_KEY_LEN: usize = 23;

/// Hex-encode a raw media AES key into the `a=aes-key:<hex>` SDP value
/// (the EMIT side — `imm_p2p_rtc_sdp_set_aes_key`).
///
/// The native side lowercases nibbles via `imm_p2p_misc_hex_to_char`; we match
/// with lowercase hex. The key must be ≤ [`MAX_SDP_AES_KEY_LEN`] bytes (the
/// native buffer at `sdp_ctx+0x86` holds up to 0x30/2 nibble-pairs).
///
/// # Errors
/// [`Error::SdpAesKey`] if `key` exceeds [`MAX_SDP_AES_KEY_LEN`] bytes — we
/// reject loudly rather than truncate (which would silently corrupt the key).
pub fn encode_aes_key_hex(key: &[u8]) -> Result<String, Error> {
    if key.len() > MAX_SDP_AES_KEY_LEN {
        return Err(Error::SdpAesKey(format!(
            "media AES key is {} bytes; native a=aes-key holds at most {} (len*2 < 0x30)",
            key.len(),
            MAX_SDP_AES_KEY_LEN
        )));
    }
    Ok(hex::encode(key))
}

/// Decode the `a=aes-key:<hex>` SDP value back into the raw media AES key
/// (the READ side — `imm_p2p_rtc_sdp_get_aes_key`).
///
/// The native side reads pairs of ASCII-hex chars via
/// `imm_p2p_misc_char_to_hex`; an odd-length or non-hex value is malformed.
///
/// # Errors
/// [`Error::SdpAesKey`] if `hex_str` is not valid even-length lowercase/upper
/// hex, or decodes to more than [`MAX_SDP_AES_KEY_LEN`] bytes.
pub fn decode_aes_key_hex(hex_str: &str) -> Result<Vec<u8>, Error> {
    let raw = hex::decode(hex_str)
        .map_err(|e| Error::SdpAesKey(format!("a=aes-key value is not valid hex: {e}")))?;
    if raw.len() > MAX_SDP_AES_KEY_LEN {
        return Err(Error::SdpAesKey(format!(
            "decoded a=aes-key is {} bytes; native max is {}",
            raw.len(),
            MAX_SDP_AES_KEY_LEN
        )));
    }
    Ok(raw)
}

/// The output encoding of a 302 AES payload, selected by the publish variant.
///
/// Recovered from `AESUtil.java` (the three encrypt entry points) +
/// `qpqddqd.java` (which one each publish bean calls):
/// - [`Hex`](Aes302Output::Hex) — `encrypt()` ⇒ `byte2hex` ⇒ **UPPERCASE** hex.
/// - [`Base64`](Aes302Output::Base64) — `encryptWithBase64()` ⇒ standard base64.
/// - [`Raw`](Aes302Output::Raw) — `encryptWithBytes()` ⇒ the raw ciphertext bytes.
///
/// Which variant a given `pv` / message-code-302 publish uses is the part that is
/// NOT yet pinned (no live capture); see [`encrypt_302_payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes302Output {
    /// `encrypt()` → uppercase hex (Tuya `byte2hex`, `AESUtil.java:64` `.toUpperCase()`).
    Hex,
    /// `encryptWithBase64()` → standard base64 (`AESUtil.java:586`).
    Base64,
    /// `encryptWithBytes()` → raw ciphertext bytes (`AESUtil.java:593`).
    Raw,
}

/// The recovered 302 cipher: **AES-128 / ECB / PKCS5(=PKCS7) padding, NO IV**,
/// encrypting `plaintext` under `key` (the device `localKey` ASCII bytes).
///
/// This is the byte-for-byte equivalent of `AESUtil` with `ALGO == "AES"`:
/// `Cipher.getInstance("AES")` ⇒ JCE default `AES/ECB/PKCS5Padding`,
/// `init(ENCRYPT_MODE, new SecretKeySpec(key, "AES"))`, `doFinal(plaintext)`.
/// ECB ⇒ each 16-byte block is encrypted independently with no chaining/IV.
///
/// # Errors
/// [`Error::SdpAesKey`] if `key` is not exactly 16 bytes (AES-128 / a Tuya
/// `localKey`). We reject other AES sizes here on purpose: the recovered device
/// path is always a 16-ASCII-byte `localKey`, so a non-16 key is a caller bug we
/// fail loud on rather than silently encrypt under a different key schedule.
pub fn aes128_ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = aes128(key)?;
    // PKCS#7 pad to a whole number of blocks (PKCS5 in the JCE name is identical
    // for an 8/16-byte block — the pad value is the number of padding bytes, and
    // a FULL extra block is added when already aligned).
    let mut buf = pkcs7_pad(plaintext);
    for chunk in buf.chunks_mut(AES_BLOCK) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(buf)
}

/// Inverse of [`aes128_ecb_encrypt`]: AES-128/ECB decrypt + PKCS7 unpad.
///
/// Mirrors `AESUtil.decrypt*` (`Cipher.init(DECRYPT_MODE, key); doFinal(ct)`).
///
/// # Errors
/// - [`Error::SdpAesKey`] if `key` is not exactly 16 bytes.
/// - [`Error::StreamConfig`] if `ciphertext` is empty or not a multiple of the
///   16-byte block, or if the trailing PKCS7 padding is invalid (a corrupt /
///   wrong-key ciphertext). We fail loud rather than return garbage plaintext.
pub fn aes128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = aes128(key)?;
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK != 0 {
        return Err(Error::StreamConfig(format!(
            "AES-ECB ciphertext is {} bytes; must be a non-zero multiple of {}",
            ciphertext.len(),
            AES_BLOCK
        )));
    }
    let mut buf = ciphertext.to_vec();
    for chunk in buf.chunks_mut(AES_BLOCK) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    pkcs7_unpad(buf)
}

/// Build an AES-128 cipher from a 16-byte key, rejecting any other length.
fn aes128(key: &[u8]) -> Result<Aes128, Error> {
    let key: [u8; AES_BLOCK] = key.try_into().map_err(|_| {
        Error::SdpAesKey(format!(
            "localKey is {} bytes; the recovered 302 cipher is AES-128 (expects 16)",
            key.len()
        ))
    })?;
    Ok(Aes128::new(&key.into()))
}

/// PKCS#7 padding to the 16-byte AES block (== JCE PKCS5Padding for AES). When
/// the input is already block-aligned, a FULL extra block of `0x10` bytes is
/// appended — this is what `AESUtil`'s `Cipher` does and what `openssl` emits.
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = AES_BLOCK - (data.len() % AES_BLOCK);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(pad as u8).take(pad));
    out
}

/// Strip + validate PKCS#7 padding. Rejects a zero pad byte, a pad length larger
/// than the block, or trailing bytes that do not all equal the pad value — the
/// signature of a corrupt ciphertext or a wrong decryption key.
fn pkcs7_unpad(mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let pad = *data.last().ok_or_else(|| {
        Error::StreamConfig("AES-ECB plaintext is empty after decrypt".to_string())
    })? as usize;
    if pad == 0 || pad > AES_BLOCK || pad > data.len() {
        return Err(Error::StreamConfig(format!(
            "invalid PKCS7 padding byte {pad} (corrupt ciphertext or wrong localKey)"
        )));
    }
    let cut = data.len() - pad;
    if data[cut..].iter().any(|&b| b as usize != pad) {
        return Err(Error::StreamConfig(
            "inconsistent PKCS7 padding bytes (corrupt ciphertext or wrong localKey)".to_string(),
        ));
    }
    data.truncate(cut);
    Ok(data)
}

/// AES-128/ECB-encrypt `plaintext` under `key` and encode the ciphertext per
/// `variant` — the exact bytes one of `AESUtil.encrypt` / `encryptWithBase64` /
/// `encryptWithBytes` produces. This is the fully-recovered primitive.
///
/// # Errors
/// [`Error::SdpAesKey`] if `key` is not 16 bytes.
pub fn aes302_encrypt(
    plaintext: &[u8],
    key: &[u8],
    variant: Aes302Output,
) -> Result<Vec<u8>, Error> {
    let ct = aes128_ecb_encrypt(plaintext, key)?;
    Ok(match variant {
        // byte2hex upper-cases (AESUtil.java:64) — match it exactly.
        Aes302Output::Hex => hex::encode_upper(&ct).into_bytes(),
        Aes302Output::Base64 => base64::engine::general_purpose::STANDARD
            .encode(&ct)
            .into_bytes(),
        Aes302Output::Raw => ct,
    })
}

/// Decode an encoded 302 ciphertext per `variant`, then AES-128/ECB-decrypt it.
/// Inverse of [`aes302_encrypt`].
///
/// # Errors
/// - [`Error::SdpAesKey`] if `key` is not 16 bytes.
/// - [`Error::StreamConfig`] if the encoded input is malformed (non-hex /
///   non-base64 / wrong block alignment / bad padding).
pub fn aes302_decrypt(encoded: &[u8], key: &[u8], variant: Aes302Output) -> Result<Vec<u8>, Error> {
    let ct = match variant {
        Aes302Output::Hex => {
            let s = std::str::from_utf8(encoded)
                .map_err(|e| Error::StreamConfig(format!("302 hex payload is not UTF-8: {e}")))?;
            hex::decode(s)
                .map_err(|e| Error::StreamConfig(format!("302 payload is not valid hex: {e}")))?
        }
        Aes302Output::Base64 => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| Error::StreamConfig(format!("302 payload is not valid base64: {e}")))?,
        Aes302Output::Raw => encoded.to_vec(),
    };
    aes128_ecb_decrypt(&ct, key)
}

/// Encrypt a 302 signaling JSON payload with the device `localKey`
/// (`homeCamera.publish(devId, pv, localKey, jsonMsg, 302)`).
///
/// The AES primitive itself is recovered and applied here (AES-128/ECB/PKCS5,
/// key = `localKey` bytes, NO IV — see the module docs and [`aes128_ecb_encrypt`]).
///
/// # Honesty — what is still gated (and ONLY this)
/// This returns [`Error::MqttEnvelopePending`] because the **`pv` → output-variant
/// binding** for message code 302 is NOT yet pinned: `AESUtil` exposes three
/// outputs (`encrypt` ⇒ hex, `encryptWithBase64`, `encryptWithBytes` ⇒ raw) and
/// `qpqddqd.java` selects between them by the publish-bean type, but which one a
/// 302 publish at a given `pv` uses — and the outer Tuya MQTT framing around it —
/// needs a live 302 capture to confirm. We refuse to guess the variant (it would
/// produce a payload the device rejects). To get the actual AES bytes for a known
/// variant, call [`aes302_encrypt`] directly with an explicit [`Aes302Output`].
///
/// # Errors
/// - [`Error::SdpAesKey`] if `key` is not a 16-byte `localKey` (fails fast).
/// - [`Error::MqttEnvelopePending`] otherwise — the variant/framing is unpinned.
pub fn encrypt_302_payload(plaintext: &[u8], key: &[u8], _pv: &str) -> Result<Vec<u8>, Error> {
    // Validate the key shape we DO know (a 16-byte localKey) so a clearly wrong
    // key fails before the pending gate — fail fast, fail loud. We compute the
    // AES bytes to prove the primitive runs, but withhold the (unpinned) framing.
    let _ = aes128_ecb_encrypt(plaintext, key)?;
    Err(Error::MqttEnvelopePending)
}

/// Decrypt a 302 signaling payload with the device `localKey`.
///
/// See [`encrypt_302_payload`]: the AES primitive is recovered (use
/// [`aes302_decrypt`] for a known [`Aes302Output`]), but the full-envelope
/// variant/framing binding for code 302 is unpinned, so this returns
/// [`Error::MqttEnvelopePending`].
///
/// # Errors
/// - [`Error::SdpAesKey`] if `key` is not a 16-byte `localKey`.
/// - [`Error::MqttEnvelopePending`] otherwise — the variant/framing is unpinned.
pub fn decrypt_302_payload(_ciphertext: &[u8], key: &[u8], _pv: &str) -> Result<Vec<u8>, Error> {
    // Validate the key shape; the inbound variant/framing is the unpinned part.
    aes128(key)?;
    Err(Error::MqttEnvelopePending)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SDP a=aes-key hex codec (byte-exact pinned) ────────────────────────

    // Known synthetic vector: a 16-byte key hex-encodes to its lowercase hex,
    // and round-trips back to the same bytes. This mirrors the native
    // hex_to_char / char_to_hex pair (set/get_aes_key).
    #[test]
    fn aes_key_hex_round_trips_known_vector() {
        let key: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let hexed = encode_aes_key_hex(&key).unwrap();
        assert_eq!(hexed, "00112233445566778899aabbccddeeff");
        // lowercase, as the native hex_to_char emits.
        assert!(hexed.chars().all(|c| !c.is_ascii_uppercase()));
        let back = decode_aes_key_hex(&hexed).unwrap();
        assert_eq!(back, key);
    }

    // The native max is 23 bytes (len*2 < 0x30); 23 bytes is accepted.
    #[test]
    fn aes_key_hex_accepts_max_len() {
        let key = vec![0xABu8; MAX_SDP_AES_KEY_LEN];
        let hexed = encode_aes_key_hex(&key).unwrap();
        assert_eq!(hexed.len(), MAX_SDP_AES_KEY_LEN * 2);
        assert_eq!(decode_aes_key_hex(&hexed).unwrap(), key);
    }

    // NEGATIVE: a key longer than the native buffer must be rejected, not
    // truncated (truncation would silently corrupt the media key).
    #[test]
    fn aes_key_hex_rejects_oversized_key() {
        let key = vec![0x01u8; MAX_SDP_AES_KEY_LEN + 1];
        assert!(matches!(encode_aes_key_hex(&key), Err(Error::SdpAesKey(_))));
    }

    // NEGATIVE: a malformed (non-hex) a=aes-key value must be rejected.
    #[test]
    fn aes_key_hex_rejects_non_hex() {
        assert!(matches!(
            decode_aes_key_hex("zzzz_not_hex"),
            Err(Error::SdpAesKey(_))
        ));
    }

    // NEGATIVE: an odd-length hex string (corrupt nibble pairing) must be
    // rejected — the native reader consumes char pairs.
    #[test]
    fn aes_key_hex_rejects_odd_length() {
        assert!(matches!(
            decode_aes_key_hex("abc"),
            Err(Error::SdpAesKey(_))
        ));
    }

    // NEGATIVE: a decoded value exceeding the native max is rejected even if the
    // hex itself is valid.
    #[test]
    fn aes_key_hex_rejects_oversized_decoded() {
        let too_long = "ab".repeat(MAX_SDP_AES_KEY_LEN + 1);
        assert!(matches!(
            decode_aes_key_hex(&too_long),
            Err(Error::SdpAesKey(_))
        ));
    }

    // ── 302-payload localKey-AES primitive (recovered + KAT-pinned) ────────

    // A SYNTHETIC 16-byte localKey (no real device key is ever committed).
    const SYNTH_KEY: &[u8; 16] = b"0123456789abcdef";

    // KNOWN-ANSWER TEST. The expected ciphertext below was computed by an
    // INDEPENDENT oracle, NOT by this Rust code:
    //   printf 'Tuya302' > a.bin
    //   openssl enc -aes-128-ecb -K 30313233343536373839616263646566 -in a.bin
    //   (key hex = ASCII '0123456789abcdef'); hex upper-cased to match byte2hex.
    // openssl applies PKCS7 padding by default, matching JCE PKCS5Padding for AES.
    #[test]
    fn aes128_ecb_matches_openssl_known_answer() {
        let plaintext = b"Tuya302"; // 7 bytes → one padded block
        let ct = aes128_ecb_encrypt(plaintext, SYNTH_KEY).unwrap();
        // openssl ciphertext (lowercase) for the vector above:
        let expected = hex::decode("eef67dc369f4e9df3684dd2c314e02d6").unwrap();
        assert_eq!(ct, expected, "AES-128-ECB must match the openssl oracle");
        // Round-trip back to the exact plaintext.
        assert_eq!(aes128_ecb_decrypt(&ct, SYNTH_KEY).unwrap(), plaintext);
    }

    // KAT, block-aligned input (16 bytes → 32 bytes: data block + full pad block).
    // openssl: printf 'hello world 302!' | openssl enc -aes-128-ecb -K <keyhex>
    #[test]
    fn aes128_ecb_full_pad_block_matches_openssl() {
        let plaintext = b"hello world 302!"; // exactly 16 bytes
        let ct = aes128_ecb_encrypt(plaintext, SYNTH_KEY).unwrap();
        let expected =
            hex::decode("e44dbfa639004b562f0916437190bedb377222e061a924c591cd9c27ea163ed4")
                .unwrap();
        assert_eq!(
            ct, expected,
            "block-aligned input gets a full PKCS7 pad block"
        );
        assert_eq!(ct.len(), 32);
        assert_eq!(aes128_ecb_decrypt(&ct, SYNTH_KEY).unwrap(), plaintext);
    }

    // The hex variant must emit UPPERCASE (Tuya byte2hex `.toUpperCase()`), and
    // the base64 variant must match the independent openssl `-a` output.
    #[test]
    fn aes302_output_variants_match_oracle() {
        let plaintext = b"Tuya302";
        let hexed = aes302_encrypt(plaintext, SYNTH_KEY, Aes302Output::Hex).unwrap();
        assert_eq!(hexed, b"EEF67DC369F4E9DF3684DD2C314E02D6");
        // openssl enc -aes-128-ecb -K <keyhex> -in a.bin -a
        let b64 = aes302_encrypt(plaintext, SYNTH_KEY, Aes302Output::Base64).unwrap();
        assert_eq!(b64, b"7vZ9w2n06d82hN0sMU4C1g==");
        let raw = aes302_encrypt(plaintext, SYNTH_KEY, Aes302Output::Raw).unwrap();
        assert_eq!(
            raw,
            hex::decode("eef67dc369f4e9df3684dd2c314e02d6").unwrap()
        );
        // Every variant round-trips.
        for v in [Aes302Output::Hex, Aes302Output::Base64, Aes302Output::Raw] {
            let enc = aes302_encrypt(plaintext, SYNTH_KEY, v).unwrap();
            assert_eq!(aes302_decrypt(&enc, SYNTH_KEY, v).unwrap(), plaintext);
        }
    }

    // NEGATIVE: a wrong key-length is rejected loud (not silently re-keyed).
    #[test]
    fn aes_rejects_wrong_key_length() {
        for bad in [b"short".as_slice(), b"0123456789abcdef0123".as_slice()] {
            assert!(matches!(
                aes128_ecb_encrypt(b"x", bad),
                Err(Error::SdpAesKey(_))
            ));
        }
    }

    // NEGATIVE: decrypting with the WRONG key trips PKCS7 validation (we refuse
    // to return garbage plaintext) — proves the unpad check bites.
    #[test]
    fn aes_decrypt_wrong_key_fails_padding() {
        let ct = aes128_ecb_encrypt(b"Tuya302", SYNTH_KEY).unwrap();
        let wrong_key = b"fedcba9876543210";
        let r = aes128_ecb_decrypt(&ct, wrong_key);
        // Overwhelmingly the random plaintext has invalid PKCS7; assert it errors.
        assert!(
            matches!(r, Err(Error::StreamConfig(_))),
            "wrong-key decrypt should fail PKCS7 padding, got {r:?}"
        );
    }

    // NEGATIVE: ciphertext not a multiple of the block size is rejected.
    #[test]
    fn aes_decrypt_rejects_misaligned_ciphertext() {
        assert!(matches!(
            aes128_ecb_decrypt(b"\x00\x01\x02", SYNTH_KEY),
            Err(Error::StreamConfig(_))
        ));
        // empty is also rejected (no block to unpad).
        assert!(matches!(
            aes128_ecb_decrypt(b"", SYNTH_KEY),
            Err(Error::StreamConfig(_))
        ));
    }

    // NEGATIVE: a non-hex hex-variant payload is rejected by aes302_decrypt.
    #[test]
    fn aes302_decrypt_rejects_non_hex() {
        assert!(matches!(
            aes302_decrypt(b"zzzz_not_hex", SYNTH_KEY, Aes302Output::Hex),
            Err(Error::StreamConfig(_))
        ));
    }

    // ── 302 ENVELOPE assembly (honestly gated — pv→variant + framing) ──────

    // The AES PRIMITIVE is implemented, but the pv→output-variant binding for
    // code 302 + the outer Tuya MQTT framing need a live capture. The full
    // envelope helpers MUST surface MqttEnvelopePending — never fabricate a
    // publishable payload by guessing the variant/framing.
    #[test]
    fn envelope_assembly_is_pending_not_the_primitive() {
        let r = encrypt_302_payload(b"{\"header\":{}}", SYNTH_KEY, "2.2");
        assert!(
            matches!(r, Err(Error::MqttEnvelopePending)),
            "the pv→variant binding + framing are unpinned; must report pending"
        );
        let r = decrypt_302_payload(b"\x00\x01\x02", SYNTH_KEY, "2.2");
        assert!(matches!(r, Err(Error::MqttEnvelopePending)));
    }

    // NEGATIVE: the envelope helpers still fail fast on a clearly-wrong key length
    // BEFORE the pending gate — proving input validation, not blanket pending.
    #[test]
    fn envelope_assembly_rejects_bad_key_length() {
        assert!(matches!(
            encrypt_302_payload(b"x", b"short", "2.2"),
            Err(Error::SdpAesKey(_))
        ));
        assert!(matches!(
            decrypt_302_payload(b"x", b"short", "2.2"),
            Err(Error::SdpAesKey(_))
        ));
    }
}
