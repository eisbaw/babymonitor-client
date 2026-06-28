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
//!    [`aes128_ecb_decrypt`], wrapped by [`build_302_frame`] /
//!    [`parse_302_frame`]) — the signaling envelope is published via
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
//!    For the **published 302 message the wire format is now byte-pinned by cap5**
//!    (`re/mqtt_2_2_frame.md`): NOT the earlier-hypothesised JSON
//!    `{data, gwId, protocol, pv, t}`, but Tuya's **binary message-2.2 frame**
//!    `pv ++ be32(crc32(body)) ++ be32(s) ++ be32(o) ++ AES-ECB(localKey, envelope)`
//!    where `envelope = {"data":<302-json>,"protocol":302,"t":t}` and the AES output
//!    is **raw bytes** (not base64). Encode `qpbpqpq.java:63`/`pbbppqb.java:493`,
//!    parse `qbpppdb.java:290-378`. Implemented + verified byte-for-byte against
//!    `cap5/offer_302_frame.bin` ([`build_302_frame`] / [`parse_302_frame`]).
//!    `crc32(frame[7:]) == frame[3:7]` reproduces exactly with [`crc32`].

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
/// The live message-302 frame ([`build_302_frame`]) uses raw ciphertext via
/// [`aes128_ecb_encrypt`] directly. This enum + [`aes302_encrypt`]/[`aes302_decrypt`]
/// document `AESUtil`'s three recovered output encodings and are validated against
/// an openssl oracle (`aes302_output_variants_match_oracle`); no other protocol in
/// THIS build calls the Hex/Base64 variants — they are kept as the openssl-KAT'd
/// model of the Tuya primitive, not a live path.
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

/// The 302 message code (Tuya WebRTC signaling over the device MQTT channel).
pub const PROTOCOL_302: i64 = 302;

/// Standard CRC-32 (zlib/PNG: reflected poly `0xEDB88320`, init/final XOR
/// `0xFFFFFFFF`) — the algorithm behind `com.thingclips...CRC32Utils.crc32`
/// (`CRC32Utils.java:97` returns `~i`). Verified: `crc32(frame[7:])` reproduces
/// the captured `frame[3:7]` of `cap5/offer_302_frame.bin` exactly.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Wrap the inner 302 signaling JSON in the Tuya `PublishBean2_2` envelope —
/// `{"data":<302-json>,"protocol":302,"t":<unix_seconds>}` — and serialize it.
/// This whole envelope (NOT the bare 302 json) is the AES plaintext of the
/// message-2.2 frame (`qpqddqd.java:628` encrypts `JSON.toJSONString(bean)`).
///
/// `inner_302_json` is embedded as a JSON **object** (`data` is `Object`, emitted
/// unquoted), not as an escaped string.
///
/// # Errors
/// [`Error::SignalingParse`] if `inner_302_json` is not valid JSON, or the
/// envelope fails to serialize.
pub fn wrap_publish_envelope(inner_302_json: &[u8], t: i64) -> Result<Vec<u8>, Error> {
    let data: serde_json::Value = serde_json::from_slice(inner_302_json)
        .map_err(|e| Error::SignalingParse(format!("302 inner json: {e}")))?;
    let envelope = serde_json::json!({ "data": data, "protocol": PROTOCOL_302, "t": t });
    serde_json::to_vec(&envelope).map_err(|e| Error::SignalingParse(e.to_string()))
}

/// Inverse of [`wrap_publish_envelope`]: parse the AES-plaintext envelope, verify
/// `protocol == 302`, and return its `data` member (the inner 302 json) re-
/// serialized. Tolerant to `protocol`/`t` arriving as a JSON string or number.
///
/// # Errors
/// - [`Error::SignalingParse`] if the envelope is not valid JSON or lacks `data`.
/// - [`Error::StreamConfig`] if `protocol` is present and not 302.
pub fn unwrap_publish_envelope(plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let env: serde_json::Value = serde_json::from_slice(plaintext)
        .map_err(|e| Error::SignalingParse(format!("302 envelope json: {e}")))?;
    // protocol may be a number or a stringified number; only enforce when present.
    if let Some(p) = env.get("protocol") {
        let code = p
            .as_i64()
            .or_else(|| p.as_str().and_then(|s| s.parse::<i64>().ok()));
        if code != Some(PROTOCOL_302) {
            return Err(Error::StreamConfig(format!(
                "302 envelope protocol is {p}, expected {PROTOCOL_302}"
            )));
        }
    }
    let data = env
        .get("data")
        .ok_or_else(|| Error::SignalingParse("302 envelope missing `data`".to_string()))?;
    serde_json::to_vec(data).map_err(|e| Error::SignalingParse(e.to_string()))
}

/// The fixed binary header before the AES ciphertext = `pv` (3 ASCII bytes for
/// the device pv, e.g. "2.2") + `crc32`(4) + `s`(4) + `o`(4). The ciphertext
/// starts at `pv.len() + 12`.
const FRAME_HEADER_TAIL: usize = 12; // crc(4) + s(4) + o(4), excludes the pv prefix

/// Build the Tuya MQTT **message-2.2 binary frame** that carries one 302 message.
///
/// Wire layout (`re/mqtt_2_2_frame.md`; encode `qpbpqpq.java:63` +
/// `pbbppqb.java:493`, big-endian throughout):
/// ```text
/// pv.getBytes() ++ be32(crc32(body)) ++ be32(s) ++ be32(o) ++ ciphertext
///   where body       = be32(s) ++ be32(o) ++ ciphertext
///         ciphertext = AES-128/ECB/PKCS7(localKey, envelope)
///         envelope   = {"data":<inner_302_json>,"protocol":302,"t":t}
/// ```
/// `s`/`o` are per-publish counters; the camera dedups `(devId,s,o)` over a 5-second
/// window (`qdddqdp.java:725`), so distinct `s` per publish is sufficient — there is
/// no monotonic-across-sessions requirement. The CRC is self-consistent (computed
/// from our own bytes), which is the camera's `12002 signature` gate.
///
/// # Errors
/// [`Error::SdpAesKey`] if `key` is not a 16-byte `localKey`;
/// [`Error::SignalingParse`] if `inner_302_json` / the envelope fails to (de)serialize.
pub fn build_302_frame(
    inner_302_json: &[u8],
    key: &[u8],
    pv: &str,
    s: u32,
    o: u32,
    t: i64,
) -> Result<Vec<u8>, Error> {
    let envelope = wrap_publish_envelope(inner_302_json, t)?;
    let ciphertext = aes128_ecb_encrypt(&envelope, key)?;

    // body = be32(s) ++ be32(o) ++ ciphertext; crc32 covers exactly the body.
    let mut body = Vec::with_capacity(8 + ciphertext.len());
    body.extend_from_slice(&s.to_be_bytes());
    body.extend_from_slice(&o.to_be_bytes());
    body.extend_from_slice(&ciphertext);

    let crc = crc32(&body);
    let mut frame = Vec::with_capacity(pv.len() + 4 + body.len());
    frame.extend_from_slice(pv.as_bytes());
    frame.extend_from_slice(&crc.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Parse a Tuya message-2.2 binary frame (inbound camera answer/candidate) and
/// return the inner 302 json. Inverse of [`build_302_frame`]. `pv` is the device
/// protocol version, whose byte length is the version-prefix size (the camera's
/// frames carry the same `pv`).
///
/// Verifies the CRC (`crc32(frame[pv+4:]) == frame[pv:pv+4]`) — the same
/// `12002 signature` check the parser does (`qbpppdb.java:294`) — then AES-ECB
/// decrypts the ciphertext and unwraps the `{data,protocol,t}` envelope.
///
/// # Errors
/// - [`Error::StreamConfig`] if the frame is too short, the `pv` prefix mismatches,
///   or the CRC fails (corrupt frame / wrong device).
/// - [`Error::SdpAesKey`] if `key` is not 16 bytes; [`Error::SignalingParse`] on a
///   malformed envelope.
pub fn parse_302_frame(frame: &[u8], key: &[u8], pv: &str) -> Result<Vec<u8>, Error> {
    let pvb = pv.as_bytes();
    let min = pvb.len() + FRAME_HEADER_TAIL + AES_BLOCK;
    if frame.len() < min {
        return Err(Error::StreamConfig(format!(
            "302 frame is {} bytes; need ≥ {min} (pv+crc+s+o+1 block)",
            frame.len()
        )));
    }
    if &frame[..pvb.len()] != pvb {
        return Err(Error::StreamConfig(format!(
            "302 frame pv prefix mismatch (expected {pv:?})"
        )));
    }
    let crc_off = pvb.len();
    let body_off = crc_off + 4; // body = s ++ o ++ ciphertext
    let crc_field = u32::from_be_bytes(frame[crc_off..body_off].try_into().unwrap());
    let crc_calc = crc32(&frame[body_off..]);
    if crc_field != crc_calc {
        return Err(Error::StreamConfig(format!(
            "302 frame CRC mismatch (field {crc_field:#010x} != computed {crc_calc:#010x}); \
             corrupt frame or wrong device"
        )));
    }
    let ciphertext = &frame[body_off + 8..]; // skip s(4) + o(4)
    let plaintext = aes128_ecb_decrypt(ciphertext, key)?;
    unwrap_publish_envelope(&plaintext)
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

    // ── CRC-32 + message-2.2 binary frame (cap5-pinned) ────────────────────

    // CRC-32 matches the canonical zlib check values (so it matches CRC32Utils).
    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    fn as_value(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    // The PublishBean2_2 envelope wraps the inner 302 json as an OBJECT under
    // `data`, with protocol:302 + a numeric t, and unwraps back to that json.
    #[test]
    fn envelope_wrap_unwrap_round_trips() {
        let inner = br#"{"header":{"type":"offer"},"msg":{"sdp":"v=0\r\n"}}"#;
        let env = wrap_publish_envelope(inner, 1782489574).unwrap();
        let v = as_value(&env);
        assert_eq!(v["protocol"], 302); // numeric, not a string
        assert_eq!(v["t"], 1782489574);
        assert!(v["data"].is_object()); // data embedded as object, not escaped string
        assert_eq!(
            unwrap_publish_envelope(&env).map(|b| as_value(&b)).unwrap(),
            as_value(inner)
        );
    }

    // The binary frame: pv prefix + self-consistent CRC + s/o + AES envelope,
    // round-tripping back to the inner json (compared structurally — wrap/unwrap
    // re-serialize, so byte order may differ but the JSON is equal).
    #[test]
    fn binary_302_frame_round_trips_and_layout() {
        let inner = br#"{"header":{"type":"offer"},"msg":{"candidate":""}}"#;
        let frame = build_302_frame(inner, SYNTH_KEY, "2.2", 4, 588790, 1782489574).unwrap();
        // pv prefix
        assert_eq!(&frame[..3], b"2.2");
        // CRC field == crc32(frame[7:]) (the camera's 12002 gate)
        let crc_field = u32::from_be_bytes(frame[3..7].try_into().unwrap());
        assert_eq!(crc_field, crc32(&frame[7..]));
        // s and o at [7:11] / [11:15], big-endian
        assert_eq!(u32::from_be_bytes(frame[7..11].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_be_bytes(frame[11..15].try_into().unwrap()),
            588790
        );
        // ciphertext is a whole number of AES blocks
        assert_eq!((frame.len() - 15) % 16, 0);
        // parse back
        assert_eq!(
            parse_302_frame(&frame, SYNTH_KEY, "2.2")
                .map(|b| as_value(&b))
                .unwrap(),
            as_value(inner)
        );
    }

    // NEGATIVE: tampering any body byte breaks the CRC -> rejected (12002).
    #[test]
    fn parse_302_rejects_crc_tamper() {
        let inner = br#"{"header":{"type":"offer"},"msg":{}}"#;
        let mut frame = build_302_frame(inner, SYNTH_KEY, "2.2", 1, 1, 1).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xFF; // mutate a ciphertext byte
        assert!(matches!(
            parse_302_frame(&frame, SYNTH_KEY, "2.2"),
            Err(Error::StreamConfig(_))
        ));
    }

    // NEGATIVE: a pv-prefix mismatch is rejected (wrong device version).
    #[test]
    fn parse_302_rejects_pv_mismatch() {
        let inner = br#"{"header":{"type":"offer"},"msg":{}}"#;
        let frame = build_302_frame(inner, SYNTH_KEY, "2.2", 1, 1, 1).unwrap();
        assert!(matches!(
            parse_302_frame(&frame, SYNTH_KEY, "2.1"),
            Err(Error::StreamConfig(_))
        ));
    }

    // NEGATIVE: build fails fast on a wrong key length.
    #[test]
    fn build_302_rejects_bad_key_length() {
        assert!(matches!(
            build_302_frame(br#"{"a":1}"#, b"short", "2.2", 0, 0, 0),
            Err(Error::SdpAesKey(_))
        ));
    }
}
