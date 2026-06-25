//! Crypto for the Tuya WebRTC session: the SDP `a=aes-key` hex codec (byte-exact,
//! pinned) and the 302-payload localKey-AES seam (mode NOT statically pinned).
//!
//! Two distinct AES-adjacent concerns live here; they have very different
//! confidence levels, kept honestly separate:
//!
//! 1. **The SDP media-key hex codec** ([`encode_aes_key_hex`] /
//!    [`decode_aes_key_hex`]) — **byte-exact pinned** from
//!    `imm_p2p_rtc_sdp_set_aes_key` / `imm_p2p_rtc_sdp_get_aes_key`
//!    (`re/ghidra/imm_p2p_rtc_sdp_set_aes_key.c`, `…_get_aes_key.c`;
//!    `re/webrtc_session.md` §3c). These functions hex-encode/decode a RAW key of
//!    up to **23 bytes** (`len*2 < 0x30`, i.e. `len < 24`) as ASCII hex into the
//!    `a=aes-key:<hex>` SDP line. This is simple, deterministic, and fully
//!    testable — it is the media AES key carried plaintext-in-SDP.
//!
//! 2. **The 302-payload localKey-AES** ([`encrypt_302_payload`] /
//!    [`decrypt_302_payload`]) — the signaling envelope is published via
//!    `homeCamera.publish(devId, pv, localKey, jsonMsg, 302)`, AES-encrypted with
//!    the device `localKey` at protocol version `pv` (`re/webrtc_session.md` §2a,
//!    `re/streaming_mode.md`). **The exact AES mode/IV/padding is NOT statically
//!    pinned**: the Tuya MQTT crypto routes through an `AESUtil` whose `ALGO` is
//!    set at runtime (`setALGO(i)` — a numeric/string mode chosen at call time),
//!    and the `Cipher.getInstance(...)` argument is jadx-mangled (`Cipher.il(…)`)
//!    in the obfuscated MQTT classes. So we DO NOT guess the mode silently:
//!    these functions return [`crate::Error::MqttCryptoPending`] and the wiring
//!    is filed as a follow-up (TASK-0037). This is the same honest discipline as
//!    the signer's TOKEN-PENDING state — never fabricate crypto we cannot pin.

use crate::Error;

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

/// Encrypt a 302 signaling JSON payload with the device `localKey`
/// (`homeCamera.publish(devId, pv, localKey, jsonMsg, 302)`).
///
/// # Honesty (NOT statically pinned — TASK-0037 follow-up)
/// The Tuya MQTT 302 payload AES **mode/IV/padding** is set at RUNTIME
/// (`AESUtil.setALGO(i)`; `Cipher.getInstance` arg jadx-mangled in the obfuscated
/// `com/thingclips/sdk/mqtt/` classes), so it cannot be pinned from static
/// analysis alone (`re/webrtc_session.md` §2a / §7 names this as a port
/// dependency). Rather than guess a mode (which would silently produce wrong
/// ciphertext the device rejects), this returns the typed
/// [`Error::MqttCryptoPending`]. The `key`/`pv` args are accepted now so the
/// signature is stable for the caller (the session driver); they are not used
/// until the mode is pinned by a capture or a port of the MQTT crypto.
///
/// # Errors
/// Always [`Error::MqttCryptoPending`] in this static-only build.
pub fn encrypt_302_payload(_plaintext: &[u8], key: &[u8], _pv: &str) -> Result<Vec<u8>, Error> {
    // Validate the key shape we DO know (AES keys are 16/24/32 bytes) so a clearly
    // wrong key fails before the (pending) crypto would — fail fast, fail loud.
    validate_aes_key_len(key)?;
    Err(Error::MqttCryptoPending)
}

/// Decrypt a 302 signaling payload with the device `localKey`.
///
/// See [`encrypt_302_payload`] — same honest gating: the mode is not statically
/// pinned, so this returns [`Error::MqttCryptoPending`] rather than guessing.
///
/// # Errors
/// Always [`Error::MqttCryptoPending`] in this static-only build.
pub fn decrypt_302_payload(_ciphertext: &[u8], key: &[u8], _pv: &str) -> Result<Vec<u8>, Error> {
    validate_aes_key_len(key)?;
    Err(Error::MqttCryptoPending)
}

/// Reject a key whose length is not a valid AES key size (16/24/32 bytes).
/// `localKey`s are typically 16 ASCII bytes; we accept all three AES sizes.
fn validate_aes_key_len(key: &[u8]) -> Result<(), Error> {
    match key.len() {
        16 | 24 | 32 => Ok(()),
        other => Err(Error::SdpAesKey(format!(
            "localKey is {other} bytes; expected an AES key size (16/24/32)"
        ))),
    }
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

    // ── 302-payload localKey-AES seam (honestly gated) ─────────────────────

    // The 302 payload AES mode is NOT statically pinned, so encrypt/decrypt MUST
    // surface MqttCryptoPending — NEVER fabricate ciphertext. Prove the gate.
    #[test]
    fn payload_crypto_is_pending_with_valid_key() {
        // 16-byte synthetic localKey (valid AES-128 size).
        let key = b"0123456789abcdef";
        let r = encrypt_302_payload(b"{\"header\":{}}", key, "2.2");
        assert!(
            matches!(r, Err(Error::MqttCryptoPending)),
            "302-payload AES mode is unpinned; must report pending, not fabricate"
        );
        let r = decrypt_302_payload(b"\x00\x01\x02", key, "2.2");
        assert!(matches!(r, Err(Error::MqttCryptoPending)));
    }

    // NEGATIVE: a clearly-wrong key length fails fast BEFORE the pending gate —
    // proving we validate the input shape we DO know rather than blindly
    // returning pending for anything.
    #[test]
    fn payload_crypto_rejects_bad_key_length() {
        let bad_key = b"short"; // 5 bytes, not an AES size
        assert!(matches!(
            encrypt_302_payload(b"x", bad_key, "2.2"),
            Err(Error::SdpAesKey(_))
        ));
    }
}
