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

/// The application-section media line of the Tuya `imm` offer (cap3 offer:
/// `m=application 9 imm 6001`; the answer uses `m=application 9 tuya 6001`).
pub const OFFER_MEDIA_LINE: &str = "m=application 9 imm 6001";

/// Inputs to [`build_offer_sdp`]. These come from the session (ids/stream) and a
/// freshly minted ICE/media-key set; `o_session` is the numeric in the `o=`/SDP
/// origin line (cap3 uses a unix-time-shaped value).
#[derive(Debug, Clone)]
pub struct OfferSdpParams {
    /// The numeric in `o=- <o_session> 1 IN IP4 127.0.0.1`.
    pub o_session: u64,
    /// The media stream id in `a=msid-semantic: WMS <stream_id>` (= sessionid).
    pub stream_id: String,
    /// Local ICE ufrag (`a=ice-ufrag:`).
    pub ice_ufrag: String,
    /// Local ICE pwd (`a=ice-pwd:`).
    pub ice_pwd: String,
    /// The raw per-session media AES key (hex-encoded into `a=aes-key:`).
    pub media_key: Vec<u8>,
    /// The `a=ssrc:0 cname:<cname>` value (= the app/user `from` id).
    pub cname: String,
    /// The `a=rtpmap:6001 AES/KCP <param>` trailing parameter (cap3 offer = 330).
    pub rtpmap_param: u32,
}

/// Build the Tuya `imm` **offer** SDP byte-for-byte in the cap3 shape
/// (`emulator_captures/cap3/signaling_plaintext.jsonl` message 1). This is the
/// SDP the native `imm_p2p_rtc_sdp_encode` emits for the `imm` profile
/// (`re/webrtc_session.md` §3); webrtc-rs does not produce this custom section,
/// so we build it directly.
///
/// Every line is CRLF-terminated (RFC 4566) and the section order matches the
/// capture exactly, so a builder run with the captured inputs reproduces the
/// captured offer SDP.
///
/// # Errors
/// [`Error::SdpAesKey`] (propagated) if the media key is too long to hex-encode
/// into the `a=aes-key` line.
pub fn build_offer_sdp(p: &OfferSdpParams) -> Result<String, Error> {
    let aes_key = mqtt_crypto::encode_aes_key_hex(&p.media_key)?;
    Ok(format!(
        "v=0\r\n\
         o=- {o} 1 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         a=group:BUNDLE imm0\r\n\
         a=msid-semantic: WMS {stream}\r\n\
         {media}\r\n\
         c=IN IP4 0.0.0.0\r\n\
         a=rtcp:9 IN IP4 0.0.0.0\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{pwd}\r\n\
         a=ice-options:trickle\r\n\
         a=aes-key:{aes_key}\r\n\
         a=mid:imm0\r\n\
         a=rtpmap:6001 AES/KCP {param}\r\n\
         a=ssrc:0 cname:{cname}\r\n",
        o = p.o_session,
        stream = p.stream_id,
        media = OFFER_MEDIA_LINE,
        ufrag = p.ice_ufrag,
        pwd = p.ice_pwd,
        param = p.rtpmap_param,
        cname = p.cname,
    ))
}

/// Extract `(ice-ufrag, ice-pwd)` from an SDP's application section (the READ
/// side, used on the device ANSWER to recover the remote ICE creds).
///
/// # Errors
/// [`Error::SdpAesKey`] if either `a=ice-ufrag:` or `a=ice-pwd:` is missing — a
/// valid answer must carry both for ICE to proceed; their absence is a hard
/// failure, not a silent empty cred.
pub fn extract_ice_creds(sdp: &str) -> Result<(String, String), Error> {
    let ufrag = sdp_lines(sdp)
        .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::SdpAesKey("answer SDP has no a=ice-ufrag line".into()))?;
    let pwd = sdp_lines(sdp)
        .find_map(|l| l.strip_prefix("a=ice-pwd:"))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::SdpAesKey("answer SDP has no a=ice-pwd line".into()))?;
    Ok((ufrag.to_string(), pwd.to_string()))
}

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

    // BYTE-EXACT against the cap3 offer SDP STRUCTURE (synthetic ids substituted
    // for the real session's): the builder must reproduce the captured offer SDP
    // line-for-line (m=application imm 6001, ufrag/pwd, aes-key, AES/KCP 330,
    // ssrc cname). The media key 0x55..6a is the cap3 a=aes-key value; the
    // ids/ufrag/pwd are synthetic (no real session id committed).
    #[test]
    fn build_offer_sdp_reproduces_cap3_structure() {
        let params = OfferSdpParams {
            o_session: 1782489574,
            stream_id: "SYNTHSESSID1782489574vhBJTOjV".into(),
            ice_ufrag: "SYN1".into(),
            ice_pwd: "SYNTHICEPWD1111111111111".into(),
            // cap3 a=aes-key:***REMOVED-MEDIAKEY***
            media_key: hex::decode("***REMOVED-MEDIAKEY***").unwrap(),
            cname: "SYNTH_USER_ID".into(),
            rtpmap_param: 330,
        };
        let sdp = build_offer_sdp(&params).unwrap();
        let expected = "v=0\r\n\
             o=- 1782489574 1 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=group:BUNDLE imm0\r\n\
             a=msid-semantic: WMS SYNTHSESSID1782489574vhBJTOjV\r\n\
             m=application 9 imm 6001\r\n\
             c=IN IP4 0.0.0.0\r\n\
             a=rtcp:9 IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:SYN1\r\n\
             a=ice-pwd:SYNTHICEPWD1111111111111\r\n\
             a=ice-options:trickle\r\n\
             a=aes-key:***REMOVED-MEDIAKEY***\r\n\
             a=mid:imm0\r\n\
             a=rtpmap:6001 AES/KCP 330\r\n\
             a=ssrc:0 cname:SYNTH_USER_ID\r\n";
        assert_eq!(sdp, expected, "offer SDP must match the cap3 structure");
        // And it round-trips through our own extractors.
        assert_eq!(extract_aes_key(&sdp).unwrap(), params.media_key);
        let (u, p) = extract_ice_creds(&sdp).unwrap();
        assert_eq!(u, "SYN1");
        assert_eq!(p, "SYNTHICEPWD1111111111111");
    }

    // The answer SDP (m=application tuya 6001) ICE creds extract correctly.
    #[test]
    fn extract_ice_creds_from_answer() {
        let answer = "v=0\r\nm=application 9 tuya 6001\r\n\
             a=ice-ufrag:SYN0\r\na=ice-pwd:SYNTHICEPWD0000000000000\r\n\
             a=aes-key:00112233445566778899aabbccddeeff\r\n";
        let (u, p) = extract_ice_creds(answer).unwrap();
        assert_eq!(u, "SYN0");
        assert_eq!(p, "SYNTHICEPWD0000000000000");
    }

    // NEGATIVE: an SDP missing ice-ufrag/pwd is a hard error (no silent empty).
    #[test]
    fn extract_ice_creds_rejects_missing() {
        let no_ufrag = "m=application 9 tuya 6001\r\na=ice-pwd:abc\r\n";
        assert!(matches!(
            extract_ice_creds(no_ufrag),
            Err(Error::SdpAesKey(_))
        ));
        let no_pwd = "m=application 9 tuya 6001\r\na=ice-ufrag:abc\r\n";
        assert!(matches!(
            extract_ice_creds(no_pwd),
            Err(Error::SdpAesKey(_))
        ));
    }
}
