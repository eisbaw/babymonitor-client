//! The Tuya-custom SDP delta: the `m=application` section carrying
//! `a=aes-key:<hex>` (the media AES key) + the `imm` codec
//! (`re/webrtc_session.md` §3c).
//!
//! webrtc-rs builds/parses the standard `v=`/`o=`/`m=audio`/`m=video` sections.
//! The ONE Tuya-custom thing this module handles is the third media section the
//! native `imm_p2p_rtc_sdp_encode` emits (`re/ghidra/imm_p2p_rtc_sdp_encode.c`,
//! the `imm` branch):
//!
//! ```text
//! m=application 9 <fmt> <pts>
//! c=IN IP4 0.0.0.0
//! a=rtcp:9 IN IP4 0.0.0.0
//! a=ice-ufrag:<ufrag>
//! a=ice-pwd:<pwd>
//! a=ice-options:trickle
//! a=aes-key:<hex>            <-- the media AES key, plaintext-in-SDP
//! a=mid:<mid>
//! a=rtpmap:<pt> <imm-codec> <param>
//! a=ssrc:<ssrc> cname:<cname>
//! ```
//!
//! Concretely the Rust client must:
//! (a) **read** the peer's `a=aes-key` out of the ANSWER SDP, and
//! (b) **inject** its own `a=aes-key` into the application section of its OFFER.
//!
//! This module does exactly those two operations on the `a=aes-key:` line; the
//! hex⇄bytes codec lives in [`super::mqtt_crypto`] (byte-exact from
//! `set/get_aes_key`).

use crate::stream::mqtt_crypto;
use crate::Error;

/// The SDP attribute prefix carrying the media AES key
/// (`a=aes-key:%s`, string at file `0x11ac06`; `re/webrtc_session.md` §3c).
pub const AES_KEY_ATTR_PREFIX: &str = "a=aes-key:";

/// SDP lines are CRLF-terminated per RFC 4566; we split tolerantly on `\n` and
/// trim a trailing `\r` so a `\n`-only test SDP still parses.
fn sdp_lines(sdp: &str) -> impl Iterator<Item = &str> {
    sdp.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l))
}

/// Extract the RAW media AES key from an SDP's `a=aes-key:<hex>` line (the READ
/// side, used on the peer's ANSWER).
///
/// Scans for the first `a=aes-key:` attribute, decodes its hex value via the
/// byte-exact [`mqtt_crypto::decode_aes_key_hex`].
///
/// # Errors
/// - [`Error::SdpAesKey`] if no `a=aes-key:` line is present (the answer must
///   carry the media key — its absence is a hard failure, not a default).
/// - [`Error::SdpAesKey`] (propagated) if the hex value is malformed / oversized.
pub fn extract_aes_key(sdp: &str) -> Result<Vec<u8>, Error> {
    let line = sdp_lines(sdp)
        .find_map(|l| l.strip_prefix(AES_KEY_ATTR_PREFIX))
        .ok_or_else(|| {
            Error::SdpAesKey("answer SDP has no a=aes-key line (media key absent)".into())
        })?;
    let hex_val = line.trim();
    if hex_val.is_empty() {
        return Err(Error::SdpAesKey("a=aes-key line has an empty value".into()));
    }
    mqtt_crypto::decode_aes_key_hex(hex_val)
}

/// Render the `a=aes-key:<hex>` SDP line for the OFFER (the EMIT side), encoding
/// a raw media key via the byte-exact [`mqtt_crypto::encode_aes_key_hex`].
///
/// Returns the single attribute line WITHOUT a trailing CRLF, so the caller can
/// splice it into the application section at the right position.
///
/// # Errors
/// [`Error::SdpAesKey`] (propagated) if `key` exceeds the native max length.
pub fn render_aes_key_line(key: &[u8]) -> Result<String, Error> {
    let hexed = mqtt_crypto::encode_aes_key_hex(key)?;
    Ok(format!("{AES_KEY_ATTR_PREFIX}{hexed}"))
}

/// Inject an `a=aes-key:<hex>` line into the `m=application` section of an OFFER
/// SDP, immediately after the section's `a=ice-options:trickle` line (the
/// position the native encoder uses — between the ICE options and `a=mid`).
///
/// If the SDP has no `m=application` section, this is an error: the Tuya offer
/// MUST carry the application section to convey the media key. We do NOT silently
/// append a stray line.
///
/// # Errors
/// - [`Error::SdpAesKey`] if there is no `m=application` section to inject into.
/// - [`Error::SdpAesKey`] (propagated) if the key is too long to encode.
pub fn inject_aes_key(offer_sdp: &str, key: &[u8]) -> Result<String, Error> {
    let key_line = render_aes_key_line(key)?;

    let mut out = String::with_capacity(offer_sdp.len() + key_line.len() + 2);
    let mut in_application = false;
    let mut injected = false;
    let mut saw_application = false;

    for line in sdp_lines(offer_sdp) {
        if let Some(rest) = line.strip_prefix("m=") {
            // Entering a new media section; only the application one is ours.
            in_application = rest.starts_with("application");
            if in_application {
                saw_application = true;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
        // Inject right after the application section's ice-options line.
        if in_application && !injected && line.starts_with("a=ice-options") {
            out.push_str(&key_line);
            out.push_str("\r\n");
            injected = true;
        }
    }

    if !saw_application {
        return Err(Error::SdpAesKey(
            "offer SDP has no m=application section to carry the media key".into(),
        ));
    }
    if !injected {
        return Err(Error::SdpAesKey(
            "m=application section has no a=ice-options line to anchor the a=aes-key after".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic Tuya-shaped answer SDP with the application section + aes-key.
    fn synth_answer_sdp(aes_hex: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 1700000000 1 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=group:BUNDLE 0 1 2\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=mid:0\r\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
             a=rtpmap:96 H264/90000\r\n\
             a=mid:1\r\n\
             m=application 9 UDP/TLS/RTP/SAVPF 98\r\n\
             c=IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:abcd\r\n\
             a=ice-pwd:efgh\r\n\
             a=ice-options:trickle\r\n\
             a=aes-key:{aes_hex}\r\n\
             a=mid:2\r\n\
             a=rtpmap:98 imm/90000\r\n"
        )
    }

    // POSITIVE: extract the media key from a synthetic answer SDP.
    #[test]
    fn extracts_aes_key_from_answer() {
        let sdp = synth_answer_sdp("00112233445566778899aabbccddeeff");
        let key = extract_aes_key(&sdp).unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(key[0], 0x00);
        assert_eq!(key[15], 0xff);
    }

    // POSITIVE: an LF-only (no CR) SDP still parses (tolerant line splitting).
    #[test]
    fn extracts_aes_key_lf_only() {
        let sdp = "m=application 9 x 98\na=ice-options:trickle\na=aes-key:aabbcc\na=mid:2\n";
        let key = extract_aes_key(sdp).unwrap();
        assert_eq!(key, vec![0xaa, 0xbb, 0xcc]);
    }

    // NEGATIVE: an answer with NO a=aes-key line is a hard error (the media key
    // is mandatory; absence must not silently yield an empty key).
    #[test]
    fn rejects_answer_without_aes_key() {
        let sdp = "v=0\r\nm=audio 9 x 0\r\na=mid:0\r\n";
        assert!(matches!(extract_aes_key(sdp), Err(Error::SdpAesKey(_))));
    }

    // NEGATIVE: a malformed (non-hex) aes-key value must be rejected.
    #[test]
    fn rejects_malformed_aes_key_value() {
        let sdp = synth_answer_sdp("not-hex-zz");
        assert!(matches!(extract_aes_key(&sdp), Err(Error::SdpAesKey(_))));
    }

    // NEGATIVE: an empty aes-key value must be rejected.
    #[test]
    fn rejects_empty_aes_key_value() {
        let sdp = "m=application 9 x 98\na=aes-key:\na=mid:2\n";
        assert!(matches!(extract_aes_key(sdp), Err(Error::SdpAesKey(_))));
    }

    // Round-trip: inject a key into an offer, then extract it back.
    #[test]
    fn inject_then_extract_round_trips() {
        let offer = "v=0\r\n\
             m=audio 9 x 0\r\n\
             a=mid:0\r\n\
             m=application 9 x 98\r\n\
             c=IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:u\r\n\
             a=ice-pwd:p\r\n\
             a=ice-options:trickle\r\n\
             a=mid:2\r\n";
        let key = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let with_key = inject_aes_key(offer, &key).unwrap();
        assert!(with_key.contains("a=aes-key:deadbeef"));
        // The injected line sits right after ice-options, before a=mid:2.
        let idx_ice = with_key.find("a=ice-options").unwrap();
        let idx_key = with_key.find("a=aes-key").unwrap();
        let idx_mid2 = with_key.find("a=mid:2").unwrap();
        assert!(idx_ice < idx_key && idx_key < idx_mid2);
        // And the key round-trips back out.
        assert_eq!(extract_aes_key(&with_key).unwrap(), key.to_vec());
    }

    // NEGATIVE: injecting into an offer with no application section is an error,
    // not a silent no-op / stray append.
    #[test]
    fn inject_rejects_offer_without_application_section() {
        let offer = "v=0\r\nm=audio 9 x 0\r\na=ice-options:trickle\r\na=mid:0\r\n";
        assert!(matches!(
            inject_aes_key(offer, &[0x01, 0x02]),
            Err(Error::SdpAesKey(_))
        ));
    }

    // NEGATIVE: an application section lacking an ice-options anchor is an error.
    #[test]
    fn inject_rejects_application_without_ice_options() {
        let offer = "m=application 9 x 98\r\na=mid:2\r\n";
        assert!(matches!(
            inject_aes_key(offer, &[0x01, 0x02]),
            Err(Error::SdpAesKey(_))
        ));
    }
}
