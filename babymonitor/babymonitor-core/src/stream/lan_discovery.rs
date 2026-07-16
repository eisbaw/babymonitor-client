//! Tuya hardware-gateway UDP discovery codec.
//!
//! The APK's `GwBroadcastMonitorService` listens on UDP 6666, 6667, and 7000.
//! It additionally sends command 37 (`APP_SEND_BROADCAST`) as a protocol-3.5
//! `0x6699` AES-GCM frame to port 7000 with `{"from":"app","ip":...}`. Both
//! request and response use Tuya's fixed UDP discovery key, not a device
//! `localKey`. A decoded advertisement is therefore endpoint discovery only;
//! callers must match `gwId` and then prove the device `localKey` over TCP before
//! persisting or trusting the endpoint.
//!
//! Primary APK anchors are `GwBroadcastMonitorService.java:1304-1372` and
//! `:1735-1769`, `FrameTypeEnum.APP_SEND_BROADCAST(37)`, and native Ghidra
//! `sendBroadcast`/3.5-builder entries `0x299248`/`0x264a3c`. The fixed-key
//! derivation is independently corroborated by TinyTuya's UDP codec.

use std::net::Ipv4Addr;

use serde::Serialize;
use zeroize::Zeroize;

use crate::stream::session::RandomSource;
use crate::stream::tuya_lan::{
    aes_ecb_decrypt_padded, LanDecoder, LanEncoder, LanKey, LanMessage, LanProtocolVersion,
    StatusPresence,
};
use crate::{Error, Result};

/// Legacy unencrypted Tuya advertisements.
pub const UDP_DISCOVERY_PLAINTEXT_PORT: u16 = 6666;
/// Legacy fixed-key AES-ECB Tuya advertisements.
pub const UDP_DISCOVERY_ENCRYPTED_PORT: u16 = 6667;
/// Protocol-3.5 AES-GCM app/device discovery.
pub const UDP_DISCOVERY_APP_PORT: u16 = 7000;
/// Every UDP port monitored by the APK.
pub const UDP_DISCOVERY_PORTS: [u16; 3] = [
    UDP_DISCOVERY_PLAINTEXT_PORT,
    UDP_DISCOVERY_ENCRYPTED_PORT,
    UDP_DISCOVERY_APP_PORT,
];
/// `FrameTypeEnum.APP_SEND_BROADCAST` / TinyTuya `REQ_DEVINFO`.
pub const APP_SEND_BROADCAST: u32 = 37;

const PREFIX_55AA: &[u8; 4] = b"\0\0U\xaa";
const PREFIX_6699: &[u8; 4] = b"\0\0f\x99";
const UDP_KEY_SEED: &[u8] = b"yGAdlopoPVldABfn";

/// Identity and advertised hardware-gateway version from one UDP packet.
///
/// The device id is account-linked metadata, so `Debug` redacts it and `Drop`
/// clears its allocation. The source socket address, rather than the untrusted
/// JSON `ip` field, remains the caller's endpoint candidate.
#[derive(Clone, PartialEq, Eq)]
pub struct LanAdvertisement {
    device_id: String,
    hgw_version: Option<String>,
}

impl LanAdvertisement {
    /// Advertised Tuya gateway/device id (`gwId`).
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Advertised `HgwBean.version`, when present.
    #[must_use]
    pub fn hgw_version(&self) -> Option<&str> {
        self.hgw_version.as_deref()
    }
}

impl std::fmt::Debug for LanAdvertisement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LanAdvertisement")
            .field("device_id", &"[REDACTED]")
            .field("hgw_version", &self.hgw_version)
            .finish()
    }
}

impl Drop for LanAdvertisement {
    fn drop(&mut self) {
        self.device_id.zeroize();
    }
}

#[derive(Serialize)]
struct AppDiscoveryRequest {
    from: &'static str,
    ip: String,
}

/// Build the APK-equivalent protocol-3.5 command-37 discovery datagram.
pub fn encode_app_discovery_request<R: RandomSource>(
    local_ip: Ipv4Addr,
    random: &mut R,
) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&AppDiscoveryRequest {
        from: "app",
        ip: local_ip.to_string(),
    })
    .map_err(|error| Error::LanProtocol(format!("serialize UDP discovery request: {error}")))?;
    let message = LanMessage::request(0, APP_SEND_BROADCAST, payload);
    LanEncoder::new(LanProtocolVersion::V3_5, udp_discovery_key()).encode(&message, random)
}

/// Decode one datagram received on an APK discovery port.
///
/// Valid packets without a `gwId` (including our own `from=app` request) return
/// `Ok(None)`. Integrity/decryption/JSON failures return an error so a caller can
/// count and ignore unrelated traffic without ever accepting it as a device.
pub fn decode_udp_advertisement(
    datagram: &[u8],
    destination_port: u16,
) -> Result<Option<LanAdvertisement>> {
    let payload = match destination_port {
        UDP_DISCOVERY_APP_PORT => decode_35_payload(datagram)?,
        UDP_DISCOVERY_ENCRYPTED_PORT => decode_legacy_payload(datagram, true)?,
        UDP_DISCOVERY_PLAINTEXT_PORT => decode_legacy_payload(datagram, false)?,
        other => {
            return Err(Error::LanProtocol(format!(
                "unsupported UDP discovery destination port {other}"
            )))
        }
    };
    parse_advertisement_json(&payload)
}

fn udp_discovery_key() -> LanKey {
    LanKey::from_bytes(md5::compute(UDP_KEY_SEED).0)
}

fn decode_35_payload(datagram: &[u8]) -> Result<Vec<u8>> {
    if !datagram.starts_with(PREFIX_6699) {
        return Err(Error::LanProtocol(
            "UDP 7000 datagram is not a protocol-3.5 frame".to_string(),
        ));
    }
    let message = decode_one_frame(datagram, LanProtocolVersion::V3_5, StatusPresence::Absent)?;
    Ok(message.payload().to_vec())
}

fn decode_legacy_payload(datagram: &[u8], encrypted: bool) -> Result<Vec<u8>> {
    let payload = if datagram.starts_with(PREFIX_55AA) {
        // Decode the CRC-framed payload without stripping a presumed return code.
        // This lets the shape below distinguish status+ciphertext (4 mod 16) from
        // ciphertext-only (0 mod 16), while plaintext JSON is normalized later.
        let message = decode_one_frame(datagram, LanProtocolVersion::V3_3, StatusPresence::Absent)?;
        if encrypted {
            if message.command() == 32 {
                return Err(Error::LanProtocol(
                    "unexpected IPC_LAN_302 frame on UDP discovery port".to_string(),
                ));
            }
            let encoded = if message.payload().len() % 16 == 4 {
                &message.payload()[4..]
            } else {
                message.payload()
            };
            aes_ecb_decrypt_padded(encoded, &udp_discovery_key())?
        } else {
            message.payload().to_vec()
        }
    } else if encrypted {
        // Very old Tuya broadcasts may contain only fixed-key ciphertext.
        aes_ecb_decrypt_padded(datagram, &udp_discovery_key())?
    } else {
        datagram.to_vec()
    };
    Ok(payload)
}

fn decode_one_frame(
    datagram: &[u8],
    version: LanProtocolVersion,
    status: StatusPresence,
) -> Result<LanMessage> {
    let mut decoder = LanDecoder::new(version, udp_discovery_key(), status);
    let mut messages = decoder.push(datagram)?;
    if messages.len() != 1 || decoder.buffered_len() != 0 {
        return Err(Error::LanProtocol(format!(
            "UDP discovery datagram decoded to {} complete frame(s) with {} trailing byte(s); expected exactly one frame and no remainder",
            messages.len(),
            decoder.buffered_len()
        )));
    }
    Ok(messages.remove(0))
}

fn parse_advertisement_json(payload: &[u8]) -> Result<Option<LanAdvertisement>> {
    let payload = normalize_json_payload(payload)?;
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|error| {
        Error::LanProtocol(format!("UDP discovery payload is not valid JSON: {error}"))
    })?;
    let object = value.as_object().ok_or_else(|| {
        Error::LanProtocol("UDP discovery payload must be a JSON object".to_string())
    })?;
    let Some(device_id) = object.get("gwId").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if device_id.trim().is_empty() {
        return Err(Error::LanProtocol(
            "UDP discovery gwId must not be empty".to_string(),
        ));
    }
    let hgw_version = object.get("version").and_then(|version| match version {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    });
    Ok(Some(LanAdvertisement {
        device_id: device_id.to_string(),
        hgw_version,
    }))
}

fn normalize_json_payload(payload: &[u8]) -> Result<&[u8]> {
    let payload = trim_trailing_ascii_nul_and_whitespace(payload);
    let payload = trim_leading_ascii_whitespace(payload);
    if payload.starts_with(b"{") {
        return Ok(payload);
    }
    // GCM responses vary on whether a plaintext return code precedes JSON.
    if payload.len() >= 5 {
        let after_status = trim_leading_ascii_whitespace(&payload[4..]);
        if after_status.starts_with(b"{") {
            return Ok(trim_trailing_ascii_nul_and_whitespace(after_status));
        }
    }
    Err(Error::LanProtocol(
        "UDP discovery plaintext has neither JSON nor status+JSON shape".to_string(),
    ))
}

fn trim_leading_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    bytes
}

fn trim_trailing_ascii_nul_and_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .last()
        .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::tuya_lan::aes_ecb_encrypt_padded;

    struct PatternRandom;

    impl RandomSource for PatternRandom {
        fn fill(&self, buffer: &mut [u8]) -> Result<()> {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        }
    }

    const ADVERTISEMENT: &[u8] =
        br#"{"gwId":"SYNTH_DEVICE_0001","ip":"192.0.2.10","version":"3.5"}"#;

    #[test]
    fn app_request_uses_fixed_udp_key_command_37_and_expected_json() {
        let mut random = PatternRandom;
        let frame = encode_app_discovery_request(Ipv4Addr::new(192, 0, 2, 5), &mut random)
            .expect("encode discovery request");
        let message = decode_one_frame(&frame, LanProtocolVersion::V3_5, StatusPresence::Absent)
            .expect("fixed UDP key decrypts request");
        assert_eq!(message.sequence(), 0);
        assert_eq!(message.command(), APP_SEND_BROADCAST);
        assert_eq!(message.payload(), br#"{"from":"app","ip":"192.0.2.5"}"#);
    }

    #[test]
    fn decodes_35_advertisement_with_optional_status_word() {
        let mut random = PatternRandom;
        let frame = LanEncoder::new(LanProtocolVersion::V3_5, udp_discovery_key())
            .encode(
                &LanMessage::response(7, 0, 0, ADVERTISEMENT.to_vec()),
                &mut random,
            )
            .unwrap();
        let advertisement = decode_udp_advertisement(&frame, UDP_DISCOVERY_APP_PORT)
            .unwrap()
            .unwrap();
        assert_eq!(advertisement.device_id(), "SYNTH_DEVICE_0001");
        assert_eq!(advertisement.hgw_version(), Some("3.5"));
        assert!(!format!("{advertisement:?}").contains("SYNTH_DEVICE_0001"));
    }

    #[test]
    fn decodes_fixed_key_legacy_encrypted_advertisement() {
        let ciphertext = aes_ecb_encrypt_padded(ADVERTISEMENT, &udp_discovery_key()).unwrap();
        let mut random = PatternRandom;
        let frame = LanEncoder::new(LanProtocolVersion::V3_3, udp_discovery_key())
            .encode(&LanMessage::response(8, 0, 0, ciphertext), &mut random)
            .unwrap();
        let advertisement = decode_udp_advertisement(&frame, UDP_DISCOVERY_ENCRYPTED_PORT)
            .unwrap()
            .unwrap();
        assert_eq!(advertisement.device_id(), "SYNTH_DEVICE_0001");
    }

    #[test]
    fn decodes_plaintext_advertisement_and_ignores_app_request() {
        let advertisement = decode_udp_advertisement(ADVERTISEMENT, UDP_DISCOVERY_PLAINTEXT_PORT)
            .unwrap()
            .unwrap();
        assert_eq!(advertisement.hgw_version(), Some("3.5"));
        assert!(decode_udp_advertisement(
            br#"{"from":"app","ip":"192.0.2.5"}"#,
            UDP_DISCOVERY_PLAINTEXT_PORT
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn rejects_tampered_35_advertisement() {
        let mut random = PatternRandom;
        let mut frame = LanEncoder::new(LanProtocolVersion::V3_5, udp_discovery_key())
            .encode(
                &LanMessage::request(7, 0, ADVERTISEMENT.to_vec()),
                &mut random,
            )
            .unwrap();
        frame[30] ^= 1;
        assert!(decode_udp_advertisement(&frame, UDP_DISCOVERY_APP_PORT).is_err());
    }

    #[test]
    fn rejects_valid_frame_with_trailing_partial_frame_bytes() {
        let mut random = PatternRandom;
        let mut frame = LanEncoder::new(LanProtocolVersion::V3_5, udp_discovery_key())
            .encode(
                &LanMessage::request(7, 0, ADVERTISEMENT.to_vec()),
                &mut random,
            )
            .unwrap();
        frame.push(0);

        let error = decode_udp_advertisement(&frame, UDP_DISCOVERY_APP_PORT)
            .unwrap_err()
            .to_string();
        assert!(error.contains("1 complete frame(s) with 1 trailing byte(s)"));
    }
}
