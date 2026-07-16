//! Tuya hardware-gateway LAN framing (protocols 3.3, 3.4, and 3.5).
//!
//! This is the local TCP transport used by the APK's `normalControl` path.  In
//! particular, camera signaling uses frame type [`IPC_LAN_302`] with the raw
//! 302 JSON as its payload; video/audio do **not** travel in these frames.
//!
//! The three supported wire formats are deliberately kept distinct:
//!
//! - 3.3 IPC-LAN-302: `0x55aa`, AES-128/ECB/PKCS7 JSON, CRC32 integrity.
//! - 3.4: `0x55aa`, AES-128/ECB/PKCS7 payload, HMAC-SHA256 integrity.
//! - 3.5: `0x6699`, AES-128/GCM payload, 12-byte nonce and 14-byte AAD.
//!
//! Protocols 3.4 and 3.5 negotiate a per-connection session key using commands
//! 3/4/5. The APK's legacy 3.3 `normalControl` path instead encrypts command-32
//! JSON with `encryptAesData` and sends it through the CRC-framed `sendBytes`
//! path without a session-key handshake.
//! The handshake implementation fails closed on the device HMAC; the linked
//! `rust-async-tuyapi` 3.5 PR only logged that mismatch, which is not acceptable
//! for an authenticated camera connection.
//!
//! Native wire anchors in the APK's `libnetwork-android.so` are the legacy
//! `ThingFrame` parse constructor, serializer, CRC verifier, and outbound
//! constructor at Ghidra addresses `0x26349c`, `0x262eb4`, `0x263168`, and
//! `0x2636cc`. JNI `encryptAesData`/`parseAesData` at `0x293690`/`0x2938dc`
//! confirm raw AES-128-ECB/PKCS7 bytes without a `3.3` marker. The 3.4 builder,
//! parser, and serializer at `0x247960`, `0x253564`, and `0x26392c`; and the 3.5
//! parser, builder, and serializer at `0x263ebc`, `0x264a3c`, and `0x2647a0`.
//! The JNI `sendCMD` path at `0x292244` accepts the outer command as an arbitrary
//! `u32`. Java binds camera signaling to `IPC_LAN_302(32)` in
//! `FrameTypeEnum.java:33`, selects `lan302Publish` in
//! `P2PMQTTServiceManager.java:1537-1550`, and forwards its JSON unchanged via
//! `qqpddqd.java:1029-1033`. `sdk/device/dddpppb.java:1039-1046` supplies the
//! discovered `HgwBean.version`, local key, and frame type to `normalControl`.
//! Sanitized Ghidra outputs for every native address above are committed as
//! `re/ghidra/tuya_lan_*.c`; they are the primary APK evidence behind the
//! independent OpenSSL/Python known-answer tests in this module.

use crate::stream::mqtt_crypto::crc32;
use crate::stream::session::RandomSource;
use crate::{Error, Result};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

/// Tuya frame type used for local IPC offer/answer/candidate signaling.
pub const IPC_LAN_302: u32 = 32;

/// Session-key negotiation start command.
pub const SESSION_KEY_NEGOTIATION_START: u32 = 3;

/// Session-key negotiation response command.
pub const SESSION_KEY_NEGOTIATION_RESPONSE: u32 = 4;

/// Session-key negotiation finish command.
pub const SESSION_KEY_NEGOTIATION_FINISH: u32 = 5;

/// TCP port used by the Tuya hardware-gateway LAN protocol.
pub const TUYA_LAN_PORT: u16 = 6668;

/// Maximum accepted declared frame body, preventing unbounded allocation from
/// a corrupt or malicious peer.
pub const MAX_LAN_FRAME_BODY: usize = 8 * 1024 * 1024;

const AES_BLOCK: usize = 16;
const PREFIX_34: [u8; 4] = [0x00, 0x00, 0x55, 0xaa];
const SUFFIX_34: [u8; 4] = [0x00, 0x00, 0xaa, 0x55];
const PREFIX_35: [u8; 4] = [0x00, 0x00, 0x66, 0x99];
const SUFFIX_35: [u8; 4] = [0x00, 0x00, 0x99, 0x66];
const HEADER_34_LEN: usize = 16;
const HEADER_35_LEN: usize = 18;
const HMAC_LEN: usize = 32;
const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const SUFFIX_LEN: usize = 4;
const STATUS_LEN: usize = 4;
const CRC_LEN: usize = 4;

type HmacSha256 = Hmac<Sha256>;

/// Hardware-gateway LAN protocol selected from `HgwBean.version` discovery.
///
/// This type intentionally has no parser for the device-list/MQTT `pv` field:
/// `pv=2.2` describes a different envelope and must never select this codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanProtocolVersion {
    /// Tuya LAN protocol 3.3 IPC-LAN-302 (`0x55aa`, AES-ECB + CRC32).
    V3_3,
    /// Tuya LAN protocol 3.4 (`0x55aa`, AES-ECB + HMAC-SHA256).
    V3_4,
    /// Tuya LAN protocol 3.5 (`0x6699`, AES-GCM).
    V3_5,
}

impl LanProtocolVersion {
    /// Parse a discovered/cached hardware-gateway version.
    ///
    /// `3.3`, `3.4`, `3.5`, and numeric patch forms such as `3.5.0` are accepted.
    /// MQTT payload versions such as `2.2` are rejected.
    pub fn from_hgw_version(value: &str) -> Result<Self> {
        let mut parts = value.trim().split('.');
        let major = parts.next();
        let minor = parts.next();
        let remainder_is_numeric =
            parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
        if !remainder_is_numeric {
            return Err(Error::LanProtocol(format!(
                "invalid Hgw LAN version {value:?}"
            )));
        }
        match (major, minor) {
            (Some("3"), Some("3")) => Ok(Self::V3_3),
            (Some("3"), Some("4")) => Ok(Self::V3_4),
            (Some("3"), Some("5")) => Ok(Self::V3_5),
            _ => Err(Error::LanProtocol(format!(
                "unsupported Hgw LAN version {value:?}; expected 3.3, 3.4, or 3.5"
            ))),
        }
    }

    /// Canonical version label carried by standard Tuya DP payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V3_3 => "3.3",
            Self::V3_4 => "3.4",
            Self::V3_5 => "3.5",
        }
    }
}

/// A 16-byte Tuya local/session AES key whose debug output is always redacted.
#[derive(PartialEq, Eq)]
pub struct LanKey([u8; AES_BLOCK]);

impl LanKey {
    /// Construct a key from exactly 16 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AES_BLOCK]) -> Self {
        Self(bytes)
    }

    /// Parse the APK/device-list `localKey` as its 16 raw UTF-8 bytes.
    ///
    /// The value itself is never included in an error or debug message.
    pub fn from_local_key(value: &str) -> Result<Self> {
        let bytes: [u8; AES_BLOCK] = value.as_bytes().try_into().map_err(|_| {
            Error::LanProtocol(format!(
                "localKey is {} bytes; Tuya LAN AES-128 requires 16",
                value.len()
            ))
        })?;
        Ok(Self(bytes))
    }

    fn bytes(&self) -> &[u8; AES_BLOCK] {
        &self.0
    }
}

impl Clone for LanKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for LanKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LanKey([REDACTED])")
    }
}

impl Drop for LanKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Whether decrypted inbound plaintext begins with a four-byte status code.
///
/// This is explicit because arbitrary binary payloads make a heuristic unsafe.
/// Device responses use [`Present`](Self::Present); outbound requests use
/// [`Absent`](Self::Absent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusPresence {
    /// The plaintext starts directly with the application payload.
    Absent,
    /// A big-endian `u32` status precedes the application payload.
    Present,
}

impl StatusPresence {
    const fn byte_len(self) -> usize {
        match self {
            Self::Absent => 0,
            Self::Present => STATUS_LEN,
        }
    }
}

/// One decrypted Tuya LAN message with its outer sequence and frame type.
#[derive(Clone, PartialEq, Eq)]
pub struct LanMessage {
    sequence: u32,
    command: u32,
    status: Option<u32>,
    payload: Vec<u8>,
}

impl LanMessage {
    /// Construct an outbound/request message without a status word.
    #[must_use]
    pub fn request(sequence: u32, command: u32, payload: Vec<u8>) -> Self {
        Self {
            sequence,
            command,
            status: None,
            payload,
        }
    }

    /// Construct an inbound/response-shaped message with an explicit status.
    #[must_use]
    pub fn response(sequence: u32, command: u32, status: u32, payload: Vec<u8>) -> Self {
        Self {
            sequence,
            command,
            status: Some(status),
            payload,
        }
    }

    /// Construct an outbound camera 302 frame from a JSON object.
    ///
    /// Frame type 32 is a raw-payload exception: no protocol label plus twelve
    /// zero-byte DP header is inserted. Protocol 3.3 encryption is applied later
    /// by its encoder, matching the APK's `normalControl`/`encryptAesData` split.
    pub fn ipc_lan_302(sequence: u32, json: &[u8]) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(json).map_err(|error| {
            Error::LanProtocol(format!("IPC_LAN_302 payload is not valid JSON: {error}"))
        })?;
        if !value.is_object() {
            return Err(Error::LanProtocol(
                "IPC_LAN_302 payload must be a JSON object".to_string(),
            ));
        }
        Ok(Self::request(sequence, IPC_LAN_302, json.to_vec()))
    }

    /// Outer Tuya sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Outer Tuya frame/command type.
    #[must_use]
    pub const fn command(&self) -> u32 {
        self.command
    }

    /// Device response status, when configured as present by the decoder.
    #[must_use]
    pub const fn status(&self) -> Option<u32> {
        self.status
    }

    /// Decrypted application payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for LanMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanMessage")
            .field("sequence", &self.sequence)
            .field("command", &self.command)
            .field("status", &self.status)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Stateless encoder for one selected Tuya LAN protocol/key.
#[derive(Clone)]
pub struct LanEncoder {
    version: LanProtocolVersion,
    key: LanKey,
}

impl LanEncoder {
    /// Create an encoder using the current local or negotiated session key.
    #[must_use]
    pub fn new(version: LanProtocolVersion, key: LanKey) -> Self {
        Self { version, key }
    }

    /// Encode one message, drawing a fresh 12-byte GCM nonce for protocol 3.5.
    ///
    /// Protocol 3.4 does not consume randomness.
    pub fn encode<R: RandomSource>(&self, message: &LanMessage, random: &mut R) -> Result<Vec<u8>> {
        match self.version {
            LanProtocolVersion::V3_3 => encode_33(message, &self.key),
            LanProtocolVersion::V3_4 => encode_34(message, &self.key),
            LanProtocolVersion::V3_5 => {
                let mut nonce = [0_u8; GCM_NONCE_LEN];
                random.fill(&mut nonce)?;
                encode_35_with_nonce(message, &self.key, nonce)
            }
        }
    }

    #[cfg(test)]
    fn encode_with_nonce(
        &self,
        message: &LanMessage,
        nonce: [u8; GCM_NONCE_LEN],
    ) -> Result<Vec<u8>> {
        match self.version {
            LanProtocolVersion::V3_3 => encode_33(message, &self.key),
            LanProtocolVersion::V3_4 => encode_34(message, &self.key),
            LanProtocolVersion::V3_5 => encode_35_with_nonce(message, &self.key, nonce),
        }
    }
}

impl fmt::Debug for LanEncoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanEncoder")
            .field("version", &self.version)
            .field("key", &self.key)
            .finish()
    }
}

/// Incremental TCP decoder for validated Tuya LAN frames.
///
/// [`push`](Self::push) accepts arbitrary TCP chunks and may return zero, one,
/// or several messages. Frame boundaries come only from the declared length;
/// encrypted bytes are never scanned for a suffix marker.
pub struct LanDecoder {
    version: LanProtocolVersion,
    key: LanKey,
    status_presence: StatusPresence,
    buffer: Vec<u8>,
}

impl LanDecoder {
    /// Create a decoder using the current local or negotiated session key.
    #[must_use]
    pub fn new(version: LanProtocolVersion, key: LanKey, status_presence: StatusPresence) -> Self {
        Self {
            version,
            key,
            status_presence,
            buffer: Vec::new(),
        }
    }

    /// Replace the crypto key after successful commands 3/4/5 negotiation.
    ///
    /// Switching with a partial old-key frame buffered is rejected.
    pub fn set_key(&mut self, key: LanKey) -> Result<()> {
        if !self.buffer.is_empty() {
            return Err(Error::LanProtocol(
                "cannot change LAN session key with a partial frame buffered".to_string(),
            ));
        }
        self.key = key;
        Ok(())
    }

    /// Number of currently buffered, incomplete TCP bytes.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Feed another TCP chunk and return every newly completed message.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<LanMessage>> {
        let mut messages = Vec::new();
        loop {
            let needed = match frame_length(self.version, self.status_presence, &self.buffer)? {
                Some(total_len) if self.buffer.len() == total_len => {
                    let message = match self.version {
                        LanProtocolVersion::V3_3 => {
                            decode_33(&self.buffer, &self.key, self.status_presence)?
                        }
                        LanProtocolVersion::V3_4 => {
                            decode_34(&self.buffer, &self.key, self.status_presence)?
                        }
                        LanProtocolVersion::V3_5 => {
                            decode_35(&self.buffer, &self.key, self.status_presence)?
                        }
                    };
                    self.buffer.clear();
                    messages.push(message);
                    continue;
                }
                Some(total_len) => total_len.checked_sub(self.buffer.len()).ok_or_else(|| {
                    Error::LanProtocol("LAN receive buffer exceeded declared frame".to_string())
                })?,
                None => {
                    let header_len = match self.version {
                        LanProtocolVersion::V3_3 => HEADER_34_LEN,
                        LanProtocolVersion::V3_4 => HEADER_34_LEN,
                        LanProtocolVersion::V3_5 => HEADER_35_LEN,
                    };
                    header_len.checked_sub(self.buffer.len()).ok_or_else(|| {
                        Error::LanProtocol("LAN receive header overflow".to_string())
                    })?
                }
            };

            if bytes.is_empty() {
                break;
            }

            let take = needed.min(bytes.len());
            self.buffer.try_reserve(take).map_err(|_| {
                Error::LanProtocol("unable to reserve bounded LAN frame buffer".to_string())
            })?;
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        Ok(messages)
    }
}

impl fmt::Debug for LanDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanDecoder")
            .field("version", &self.version)
            .field("key", &self.key)
            .field("status_presence", &self.status_presence)
            .field("buffered_len", &self.buffer.len())
            .finish()
    }
}

/// In-progress authenticated commands 3/4/5 handshake.
///
/// The start frame is available immediately. Consuming this value with
/// [`accept_response`](Self::accept_response) verifies command 4 and produces a
/// finish frame still encrypted under the local key.
pub struct PendingLanHandshake {
    version: LanProtocolVersion,
    local_key: LanKey,
    client_nonce: [u8; AES_BLOCK],
    start_frame: Vec<u8>,
    finish_sequence: u32,
}

impl PendingLanHandshake {
    /// Begin negotiation at `initial_sequence` using fresh client/GCM nonces.
    pub fn begin<R: RandomSource>(
        version: LanProtocolVersion,
        local_key: LanKey,
        initial_sequence: u32,
        random: &mut R,
    ) -> Result<Self> {
        if version == LanProtocolVersion::V3_3 {
            return Err(Error::LanProtocol(
                "Tuya LAN 3.3 IPC_LAN_302 does not use the commands 3/4/5 session handshake"
                    .to_string(),
            ));
        }
        let mut client_nonce = [0_u8; AES_BLOCK];
        random.fill(&mut client_nonce)?;
        let encoder = LanEncoder::new(version, local_key.clone());
        let start = LanMessage::request(
            initial_sequence,
            SESSION_KEY_NEGOTIATION_START,
            client_nonce.to_vec(),
        );
        let start_frame = encoder.encode(&start, random)?;
        let finish_sequence = initial_sequence.checked_add(1).ok_or_else(|| {
            Error::LanProtocol("LAN handshake sequence exhausted u32".to_string())
        })?;
        Ok(Self {
            version,
            local_key,
            client_nonce,
            start_frame,
            finish_sequence,
        })
    }

    /// Encoded command-3 frame to write to the camera.
    #[must_use]
    pub fn start_frame(&self) -> &[u8] {
        &self.start_frame
    }

    /// Build a local-key decoder for the command-4 device response.
    #[must_use]
    pub fn response_decoder(&self) -> LanDecoder {
        LanDecoder::new(
            self.version,
            self.local_key.clone(),
            StatusPresence::Present,
        )
    }

    /// Verify a command-4 response and encode command 5 under the local key.
    ///
    /// The returned session key is not exposed until the finish frame has
    /// already been constructed, preventing an accidental early key switch.
    pub fn accept_response<R: RandomSource>(
        self,
        response: &LanMessage,
        random: &mut R,
    ) -> Result<FinishedLanHandshake> {
        if response.command != SESSION_KEY_NEGOTIATION_RESPONSE {
            return Err(Error::LanProtocol(format!(
                "expected session command {SESSION_KEY_NEGOTIATION_RESPONSE}, got {}",
                response.command
            )));
        }
        if response.status != Some(0) {
            return Err(Error::LanProtocol(format!(
                "session negotiation response status was {:?}, expected 0",
                response.status
            )));
        }
        if response.payload.len() != AES_BLOCK + HMAC_LEN {
            return Err(Error::LanProtocol(format!(
                "session negotiation response is {} bytes; expected 48",
                response.payload.len()
            )));
        }
        let remote_nonce: [u8; AES_BLOCK] = response.payload[..AES_BLOCK]
            .try_into()
            .map_err(|_| Error::LanProtocol("invalid remote nonce length".to_string()))?;

        let mac = <HmacSha256 as Mac>::new_from_slice(self.local_key.bytes())
            .map_err(|_| Error::LanProtocol("invalid HMAC key length".to_string()))?;
        // Use the MAC implementation's constant-time verifier, not `==`.
        let mut mac = mac;
        mac.update(&self.client_nonce);
        mac.verify_slice(&response.payload[AES_BLOCK..])
            .map_err(|_| {
                Error::LanProtocol(
                    "device failed session negotiation HMAC authentication".to_string(),
                )
            })?;
        let session_key = derive_session_key(
            self.version,
            &self.local_key,
            &self.client_nonce,
            &remote_nonce,
        )?;
        let finish_payload = hmac_sha256(&self.local_key, &remote_nonce)?;
        let finish = LanMessage::request(
            self.finish_sequence,
            SESSION_KEY_NEGOTIATION_FINISH,
            finish_payload.to_vec(),
        );
        // Crucial ordering: command 5 is encoded with localKey, not sessionKey.
        let finish_frame = LanEncoder::new(self.version, self.local_key).encode(&finish, random)?;
        let next_sequence = self.finish_sequence.checked_add(1).ok_or_else(|| {
            Error::LanProtocol("LAN handshake sequence exhausted u32".to_string())
        })?;
        Ok(FinishedLanHandshake {
            version: self.version,
            session_key,
            finish_frame,
            next_sequence,
        })
    }
}

impl fmt::Debug for PendingLanHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingLanHandshake")
            .field("version", &self.version)
            .field("local_key", &self.local_key)
            .field("client_nonce", &"[REDACTED]")
            .field("start_frame_len", &self.start_frame.len())
            .field("finish_sequence", &self.finish_sequence)
            .finish()
    }
}

/// Verified handshake result containing command 5 and the negotiated key.
///
/// The only public transition into session traffic is
/// [`complete_with`](Self::complete_with), which first requires the caller's
/// command-5 write callback to report success.
pub struct FinishedLanHandshake {
    version: LanProtocolVersion,
    session_key: LanKey,
    finish_frame: Vec<u8>,
    next_sequence: u32,
}

impl FinishedLanHandshake {
    /// Write command 5 and enter the negotiated-key session only after the
    /// supplied transport callback reports success.
    ///
    /// Consuming `self` on either outcome ensures a failed write cannot be
    /// retried accidentally with a partially-used handshake or expose the
    /// negotiated key. The callback receives the complete encoded frame and
    /// should perform the transport's equivalent of `write_all`.
    pub fn complete_with<F>(
        self,
        inbound_status: StatusPresence,
        write_finish: F,
    ) -> Result<(LanEncoder, LanDecoder, u32)>
    where
        F: FnOnce(&[u8]) -> Result<()>,
    {
        write_finish(&self.finish_frame)?;
        let encoder = LanEncoder::new(self.version, self.session_key.clone());
        let decoder = LanDecoder::new(self.version, self.session_key, inbound_status);
        Ok((encoder, decoder, self.next_sequence))
    }
}

impl fmt::Debug for FinishedLanHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinishedLanHandshake")
            .field("version", &self.version)
            .field("session_key", &self.session_key)
            .field("finish_frame_len", &self.finish_frame.len())
            .field("next_sequence", &self.next_sequence)
            .finish()
    }
}

fn frame_length(
    version: LanProtocolVersion,
    status_presence: StatusPresence,
    bytes: &[u8],
) -> Result<Option<usize>> {
    let header_len = match version {
        LanProtocolVersion::V3_3 => HEADER_34_LEN,
        LanProtocolVersion::V3_4 => HEADER_34_LEN,
        LanProtocolVersion::V3_5 => HEADER_35_LEN,
    };
    if bytes.len() < header_len {
        return Ok(None);
    }
    let expected_prefix = match version {
        LanProtocolVersion::V3_3 => PREFIX_34,
        LanProtocolVersion::V3_4 => PREFIX_34,
        LanProtocolVersion::V3_5 => PREFIX_35,
    };
    if bytes[..4] != expected_prefix {
        return Err(Error::LanProtocol(format!(
            "unexpected LAN frame prefix {}; expected {} for {}",
            hex::encode(&bytes[..4]),
            hex::encode(expected_prefix),
            version.as_str()
        )));
    }
    // Native 3.5 parser `libnetwork-android.so:0x263ebc` reads and rejects both
    // reserved bytes before sequence/command/length and before GCM decryption.
    if version == LanProtocolVersion::V3_5 && bytes[4..6] != [0, 0] {
        return Err(Error::LanProtocol(format!(
            "3.5 reserved header bytes must be zero, got {}",
            hex::encode(&bytes[4..6])
        )));
    }
    let declared = match version {
        LanProtocolVersion::V3_3 => be_u32(&bytes[12..16])? as usize,
        LanProtocolVersion::V3_4 => be_u32(&bytes[12..16])? as usize,
        LanProtocolVersion::V3_5 => be_u32(&bytes[14..18])? as usize,
    };
    if declared > MAX_LAN_FRAME_BODY {
        return Err(Error::LanProtocol(format!(
            "declared LAN frame body {declared} exceeds limit {MAX_LAN_FRAME_BODY}"
        )));
    }
    let minimum = match version {
        // Status (responses) + CRC32 + suffix. Payload shape is checked only
        // after CRC verification so malformed frames never bypass integrity.
        LanProtocolVersion::V3_3 => status_presence.byte_len() + CRC_LEN + SUFFIX_LEN,
        // Check the HMAC before rejecting a short or non-block-aligned payload.
        // Some devices return compact command errors; integrity classification
        // must happen before the AES decoder reports their payload shape.
        LanProtocolVersion::V3_4 => status_presence.byte_len() + HMAC_LEN + SUFFIX_LEN,
        // Nonce + tag; 3.5's suffix is not counted in the declared body.
        LanProtocolVersion::V3_5 => GCM_NONCE_LEN + status_presence.byte_len() + GCM_TAG_LEN,
    };
    if declared < minimum {
        let (sequence, command) = match version {
            LanProtocolVersion::V3_3 => (be_u32(&bytes[4..8])?, be_u32(&bytes[8..12])?),
            LanProtocolVersion::V3_4 => (be_u32(&bytes[4..8])?, be_u32(&bytes[8..12])?),
            LanProtocolVersion::V3_5 => (be_u32(&bytes[6..10])?, be_u32(&bytes[10..14])?),
        };
        return Err(Error::LanProtocol(format!(
            "declared {} LAN body {declared} is below minimum {minimum} \
             (sequence {sequence}, command {command})",
            version.as_str(),
        )));
    }
    let suffix_outside_length = match version {
        LanProtocolVersion::V3_3 => 0,
        LanProtocolVersion::V3_4 => 0,
        LanProtocolVersion::V3_5 => SUFFIX_LEN,
    };
    header_len
        .checked_add(declared)
        .and_then(|length| length.checked_add(suffix_outside_length))
        .map(Some)
        .ok_or_else(|| Error::LanProtocol("LAN frame length overflow".to_string()))
}

fn encode_33(message: &LanMessage, key: &LanKey) -> Result<Vec<u8>> {
    // The APK encrypts IPC_LAN_302 in Java with `encryptAesData` before calling
    // native `sendBytes`; the native legacy ThingFrame itself only adds CRC
    // framing. Preserve raw payloads for other commands (notably heartbeat),
    // whose command-specific transforms are outside this camera signaling path.
    let encoded_payload = if message.command == IPC_LAN_302 {
        aes_ecb_encrypt_padded(&message.payload, key)?
    } else {
        message.payload.clone()
    };
    let declared = message
        .status
        .map_or(0, |_| STATUS_LEN)
        .checked_add(encoded_payload.len())
        .and_then(|length| length.checked_add(CRC_LEN + SUFFIX_LEN))
        .ok_or_else(|| Error::LanProtocol("3.3 frame length overflow".to_string()))?;
    if declared > MAX_LAN_FRAME_BODY {
        return Err(Error::LanProtocol(format!(
            "3.3 frame body {declared} exceeds limit {MAX_LAN_FRAME_BODY}"
        )));
    }

    let mut frame = Vec::with_capacity(HEADER_34_LEN + declared);
    frame.extend_from_slice(&PREFIX_34);
    frame.extend_from_slice(&message.sequence.to_be_bytes());
    frame.extend_from_slice(&message.command.to_be_bytes());
    frame.extend_from_slice(&(declared as u32).to_be_bytes());
    if let Some(status) = message.status {
        frame.extend_from_slice(&status.to_be_bytes());
    }
    frame.extend_from_slice(&encoded_payload);
    let integrity = crc32(&frame);
    frame.extend_from_slice(&integrity.to_be_bytes());
    frame.extend_from_slice(&SUFFIX_34);
    Ok(frame)
}

fn decode_33(frame: &[u8], key: &LanKey, status_presence: StatusPresence) -> Result<LanMessage> {
    if frame.len() < HEADER_34_LEN + status_presence.byte_len() + CRC_LEN + SUFFIX_LEN {
        return Err(Error::LanProtocol("truncated 3.3 frame".to_string()));
    }
    if frame[frame.len() - SUFFIX_LEN..] != SUFFIX_34 {
        return Err(Error::LanProtocol("invalid 3.3 frame suffix".to_string()));
    }
    let crc_start = frame
        .len()
        .checked_sub(CRC_LEN + SUFFIX_LEN)
        .ok_or_else(|| Error::LanProtocol("truncated 3.3 CRC".to_string()))?;
    let expected_crc = be_u32(&frame[crc_start..crc_start + CRC_LEN])?;
    if crc32(&frame[..crc_start]) != expected_crc {
        return Err(Error::LanProtocol(
            "3.3 CRC32 integrity check failed".to_string(),
        ));
    }

    let payload_start = HEADER_34_LEN
        .checked_add(status_presence.byte_len())
        .ok_or_else(|| Error::LanProtocol("3.3 payload offset overflow".to_string()))?;
    if payload_start > crc_start {
        return Err(Error::LanProtocol(
            "truncated 3.3 status/payload".to_string(),
        ));
    }
    let status = match status_presence {
        StatusPresence::Absent => None,
        StatusPresence::Present => Some(be_u32(&frame[HEADER_34_LEN..payload_start])?),
    };
    let command = be_u32(&frame[8..12])?;
    let encoded_payload = &frame[payload_start..crc_start];
    let payload = if command == IPC_LAN_302 {
        if encoded_payload.is_empty() && status.is_some_and(|code| code != 0) {
            Vec::new()
        } else {
            aes_ecb_decrypt_padded(encoded_payload, key)?
        }
    } else {
        encoded_payload.to_vec()
    };
    Ok(LanMessage {
        sequence: be_u32(&frame[4..8])?,
        command,
        status,
        payload,
    })
}

fn encode_34(message: &LanMessage, key: &LanKey) -> Result<Vec<u8>> {
    let padded_len = message
        .payload
        .len()
        .checked_add(AES_BLOCK - (message.payload.len() % AES_BLOCK))
        .ok_or_else(|| Error::LanProtocol("3.4 payload length overflow".to_string()))?;
    let declared = message
        .status
        .map_or(0, |_| STATUS_LEN)
        .checked_add(padded_len)
        .and_then(|length| length.checked_add(HMAC_LEN + SUFFIX_LEN))
        .ok_or_else(|| Error::LanProtocol("3.4 frame length overflow".to_string()))?;
    if declared > MAX_LAN_FRAME_BODY {
        return Err(Error::LanProtocol(format!(
            "3.4 frame body {declared} exceeds limit {MAX_LAN_FRAME_BODY}"
        )));
    }
    let ciphertext = aes_ecb_encrypt_padded(&message.payload, key)?;
    debug_assert_eq!(ciphertext.len(), padded_len);
    let mut frame = Vec::with_capacity(HEADER_34_LEN + declared);
    frame.extend_from_slice(&PREFIX_34);
    frame.extend_from_slice(&message.sequence.to_be_bytes());
    frame.extend_from_slice(&message.command.to_be_bytes());
    frame.extend_from_slice(&(declared as u32).to_be_bytes());
    if let Some(status) = message.status {
        frame.extend_from_slice(&status.to_be_bytes());
    }
    frame.extend_from_slice(&ciphertext);
    let authentication = hmac_sha256(key, &frame)?;
    frame.extend_from_slice(&authentication);
    frame.extend_from_slice(&SUFFIX_34);
    Ok(frame)
}

fn decode_34(frame: &[u8], key: &LanKey, status_presence: StatusPresence) -> Result<LanMessage> {
    if frame.len() < HEADER_34_LEN + HMAC_LEN + SUFFIX_LEN {
        return Err(Error::LanProtocol("truncated 3.4 frame".to_string()));
    }
    if frame[frame.len() - SUFFIX_LEN..] != SUFFIX_34 {
        return Err(Error::LanProtocol("invalid 3.4 frame suffix".to_string()));
    }
    let hmac_start = frame
        .len()
        .checked_sub(HMAC_LEN + SUFFIX_LEN)
        .ok_or_else(|| Error::LanProtocol("truncated 3.4 authentication".to_string()))?;
    let mut verifier = <HmacSha256 as Mac>::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid HMAC key length".to_string()))?;
    verifier.update(&frame[..hmac_start]);
    verifier
        .verify_slice(&frame[hmac_start..hmac_start + HMAC_LEN])
        .map_err(|_| Error::LanProtocol("3.4 HMAC authentication failed".to_string()))?;

    // Native parser `libnetwork-android.so:0x253564` leaves the response status
    // in plaintext between the 16-byte header and AES-ECB ciphertext; its HMAC
    // authenticates header + status + ciphertext.
    let payload_start = HEADER_34_LEN
        .checked_add(status_presence.byte_len())
        .ok_or_else(|| Error::LanProtocol("3.4 payload offset overflow".to_string()))?;
    if payload_start > hmac_start {
        return Err(Error::LanProtocol(
            "truncated 3.4 status/payload".to_string(),
        ));
    }
    let status = match status_presence {
        StatusPresence::Absent => None,
        StatusPresence::Present => Some(be_u32(&frame[HEADER_34_LEN..payload_start])?),
    };
    let payload = aes_ecb_decrypt_padded(&frame[payload_start..hmac_start], key)?;
    Ok(LanMessage {
        sequence: be_u32(&frame[4..8])?,
        command: be_u32(&frame[8..12])?,
        status,
        payload,
    })
}

fn encode_35_with_nonce(
    message: &LanMessage,
    key: &LanKey,
    nonce: [u8; GCM_NONCE_LEN],
) -> Result<Vec<u8>> {
    let plaintext_len = message
        .payload
        .len()
        .checked_add(message.status.map_or(0, |_| STATUS_LEN))
        .ok_or_else(|| Error::LanProtocol("3.5 payload length overflow".to_string()))?;
    let declared = GCM_NONCE_LEN
        .checked_add(plaintext_len)
        .and_then(|length| length.checked_add(GCM_TAG_LEN))
        .ok_or_else(|| Error::LanProtocol("3.5 frame length overflow".to_string()))?;
    if declared > MAX_LAN_FRAME_BODY {
        return Err(Error::LanProtocol(format!(
            "3.5 frame body {declared} exceeds limit {MAX_LAN_FRAME_BODY}"
        )));
    }

    let mut plaintext = Vec::with_capacity(plaintext_len);
    if let Some(status) = message.status {
        plaintext.extend_from_slice(&status.to_be_bytes());
    }
    plaintext.extend_from_slice(&message.payload);
    debug_assert_eq!(plaintext.len(), plaintext_len);

    let mut header = Vec::with_capacity(HEADER_35_LEN);
    header.extend_from_slice(&PREFIX_35);
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&message.sequence.to_be_bytes());
    header.extend_from_slice(&message.command.to_be_bytes());
    header.extend_from_slice(&(declared as u32).to_be_bytes());
    let cipher = Aes128Gcm::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid AES-GCM key length".to_string()))?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header[4..], &mut plaintext)
        .map_err(|_| Error::LanProtocol("3.5 AES-GCM encryption failed".to_string()))?;

    let mut frame = Vec::with_capacity(HEADER_35_LEN + declared + SUFFIX_LEN);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&plaintext);
    frame.extend_from_slice(tag.as_slice());
    frame.extend_from_slice(&SUFFIX_35);
    Ok(frame)
}

fn decode_35(frame: &[u8], key: &LanKey, status_presence: StatusPresence) -> Result<LanMessage> {
    if frame.len() < HEADER_35_LEN + GCM_NONCE_LEN + GCM_TAG_LEN + SUFFIX_LEN {
        return Err(Error::LanProtocol("truncated 3.5 frame".to_string()));
    }
    if frame[frame.len() - SUFFIX_LEN..] != SUFFIX_35 {
        return Err(Error::LanProtocol("invalid 3.5 frame suffix".to_string()));
    }
    let nonce_start = HEADER_35_LEN;
    let ciphertext_start = nonce_start + GCM_NONCE_LEN;
    let tag_start = frame
        .len()
        .checked_sub(GCM_TAG_LEN + SUFFIX_LEN)
        .ok_or_else(|| Error::LanProtocol("truncated 3.5 authentication".to_string()))?;
    if ciphertext_start > tag_start {
        return Err(Error::LanProtocol("truncated 3.5 ciphertext".to_string()));
    }
    let mut plaintext = frame[ciphertext_start..tag_start].to_vec();
    let nonce = Nonce::from_slice(&frame[nonce_start..ciphertext_start]);
    let tag = Tag::from_slice(&frame[tag_start..tag_start + GCM_TAG_LEN]);
    let cipher = Aes128Gcm::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid AES-GCM key length".to_string()))?;
    // Native 3.5 builder/parser `0x264a3c`/`0x263ebc`: status is inside the GCM
    // plaintext and the 14 bytes after the prefix are authenticated as AAD.
    cipher
        .decrypt_in_place_detached(nonce, &frame[4..HEADER_35_LEN], &mut plaintext, tag)
        .map_err(|_| Error::LanProtocol("3.5 GCM authentication failed".to_string()))?;

    let status_len = status_presence.byte_len();
    if plaintext.len() < status_len {
        return Err(Error::LanProtocol("truncated 3.5 status word".to_string()));
    }
    let status = match status_presence {
        StatusPresence::Absent => None,
        StatusPresence::Present => Some(be_u32(&plaintext[..STATUS_LEN])?),
    };
    Ok(LanMessage {
        sequence: be_u32(&frame[6..10])?,
        command: be_u32(&frame[10..14])?,
        status,
        payload: plaintext[status_len..].to_vec(),
    })
}

fn derive_session_key(
    version: LanProtocolVersion,
    local_key: &LanKey,
    client_nonce: &[u8; AES_BLOCK],
    remote_nonce: &[u8; AES_BLOCK],
) -> Result<LanKey> {
    let mut mixed = [0_u8; AES_BLOCK];
    for (output, (left, right)) in mixed
        .iter_mut()
        .zip(client_nonce.iter().zip(remote_nonce.iter()))
    {
        *output = left ^ right;
    }
    let derived = match version {
        LanProtocolVersion::V3_3 => {
            return Err(Error::LanProtocol(
                "Tuya LAN 3.3 has no commands 3/4/5 session-key derivation".to_string(),
            ));
        }
        LanProtocolVersion::V3_4 => aes_encrypt_block(local_key, mixed)?,
        LanProtocolVersion::V3_5 => {
            let cipher = Aes128Gcm::new_from_slice(local_key.bytes())
                .map_err(|_| Error::LanProtocol("invalid AES-GCM key length".to_string()))?;
            let mut encrypted = mixed;
            let nonce = Nonce::from_slice(&client_nonce[..GCM_NONCE_LEN]);
            // Tuya takes the 16-byte ciphertext and discards the detached tag.
            let _tag = cipher
                .encrypt_in_place_detached(nonce, b"", &mut encrypted)
                .map_err(|_| Error::LanProtocol("3.5 session-key derivation failed".to_string()))?;
            encrypted
        }
    };
    if version == LanProtocolVersion::V3_4 && derived[0] == 0 {
        return Err(Error::LanProtocol(
            "3.4 derived session key begins with 0x00; restart negotiation with a fresh nonce"
                .to_string(),
        ));
    }
    Ok(LanKey::from_bytes(derived))
}

fn aes_encrypt_block(key: &LanKey, mut block: [u8; AES_BLOCK]) -> Result<[u8; AES_BLOCK]> {
    let cipher = Aes128::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid AES-128 key length".to_string()))?;
    cipher.encrypt_block((&mut block).into());
    Ok(block)
}

pub(crate) fn aes_ecb_encrypt_padded(plaintext: &[u8], key: &LanKey) -> Result<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid AES-128 key length".to_string()))?;
    let padding = AES_BLOCK - (plaintext.len() % AES_BLOCK);
    let mut output = Vec::with_capacity(plaintext.len() + padding);
    output.extend_from_slice(plaintext);
    output.extend(std::iter::repeat(padding as u8).take(padding));
    for chunk in output.chunks_mut(AES_BLOCK) {
        cipher.encrypt_block(chunk.into());
    }
    Ok(output)
}

pub(crate) fn aes_ecb_decrypt_padded(ciphertext: &[u8], key: &LanKey) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK != 0 {
        return Err(Error::LanProtocol(format!(
            "AES-ECB ciphertext is {} bytes; expected a non-empty AES block multiple",
            ciphertext.len()
        )));
    }
    let cipher = Aes128::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid AES-128 key length".to_string()))?;
    let mut output = ciphertext.to_vec();
    for chunk in output.chunks_mut(AES_BLOCK) {
        cipher.decrypt_block(chunk.into());
    }
    let padding = usize::from(*output.last().ok_or_else(|| {
        Error::LanProtocol("AES-ECB plaintext was empty after decrypt".to_string())
    })?);
    if padding == 0 || padding > AES_BLOCK || padding > output.len() {
        return Err(Error::LanProtocol(
            "invalid AES-ECB PKCS7 padding (wrong key or corrupt frame)".to_string(),
        ));
    }
    let payload_len = output.len() - padding;
    if output[payload_len..]
        .iter()
        .any(|byte| usize::from(*byte) != padding)
    {
        return Err(Error::LanProtocol(
            "inconsistent AES-ECB PKCS7 padding (wrong key or corrupt frame)".to_string(),
        ));
    }
    output.truncate(payload_len);
    Ok(output)
}

fn hmac_sha256(key: &LanKey, data: &[u8]) -> Result<[u8; HMAC_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.bytes())
        .map_err(|_| Error::LanProtocol("invalid HMAC key length".to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn be_u32(bytes: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| Error::LanProtocol("truncated big-endian u32".to_string()))?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const OFFER_JSON: &[u8] = br#"{"header":{"type":"offer"},"msg":"x"}"#;

    struct PatternRandom(u8);

    impl RandomSource for PatternRandom {
        fn fill(&self, buffer: &mut [u8]) -> Result<()> {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = self.0.wrapping_add(index as u8);
            }
            Ok(())
        }
    }

    struct ChangingRandom(Cell<u8>);

    impl RandomSource for ChangingRandom {
        fn fill(&self, buffer: &mut [u8]) -> Result<()> {
            let start = self.0.get();
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = start.wrapping_add(index as u8);
            }
            self.0.set(start.wrapping_add(1));
            Ok(())
        }
    }

    fn synthetic_key() -> LanKey {
        LanKey::from_bytes(std::array::from_fn(|index| index as u8))
    }

    fn ascii_key() -> LanKey {
        LanKey::from_bytes(*b"0123456789abcdef")
    }

    fn decode_one(
        version: LanProtocolVersion,
        key: LanKey,
        status_presence: StatusPresence,
        frame: &[u8],
    ) -> Result<LanMessage> {
        let mut decoder = LanDecoder::new(version, key, status_presence);
        let mut messages = decoder.push(frame)?;
        if messages.len() != 1 || decoder.buffered_len() != 0 {
            return Err(Error::LanProtocol(format!(
                "test expected one complete frame, got {} with {} bytes buffered",
                messages.len(),
                decoder.buffered_len()
            )));
        }
        Ok(messages.remove(0))
    }

    #[test]
    fn hgw_version_is_the_only_supported_version_selector() {
        assert_eq!(
            LanProtocolVersion::from_hgw_version("3.3").unwrap(),
            LanProtocolVersion::V3_3
        );
        assert_eq!(
            LanProtocolVersion::from_hgw_version("3.4").unwrap(),
            LanProtocolVersion::V3_4
        );
        assert_eq!(
            LanProtocolVersion::from_hgw_version(" 3.5.0 ").unwrap(),
            LanProtocolVersion::V3_5
        );
        for invalid in ["2.2", "3.2", "3.6", "3.5-beta", "3.4.", ""] {
            assert!(LanProtocolVersion::from_hgw_version(invalid).is_err());
        }
    }

    #[test]
    fn keys_and_payloads_are_redacted_from_debug_output() {
        let key_debug = format!("{:?}", synthetic_key());
        assert_eq!(key_debug, "LanKey([REDACTED])");
        assert!(!key_debug.contains("00010203"));

        let message = LanMessage::request(7, IPC_LAN_302, b"private-payload".to_vec());
        let message_debug = format!("{message:?}");
        assert!(message_debug.contains("payload_len: 15"));
        assert!(!message_debug.contains("private-payload"));

        let error = LanKey::from_local_key("short").unwrap_err().to_string();
        assert!(error.contains("5 bytes"));
        assert!(!error.contains("short"));
    }

    #[test]
    fn ipc_lan_302_requires_an_object_and_preserves_raw_json() {
        assert!(LanMessage::ipc_lan_302(1, b"[]").is_err());
        assert!(LanMessage::ipc_lan_302(1, b"not-json").is_err());

        let message = LanMessage::ipc_lan_302(0x0102_0304, OFFER_JSON).unwrap();
        assert_eq!(message.command(), IPC_LAN_302);
        assert_eq!(message.payload(), OFFER_JSON);
        assert_eq!(message.status(), None);
    }

    #[test]
    fn protocol_33_frame_matches_independent_known_answer() {
        let message = LanMessage::ipc_lan_302(0x0102_0304, OFFER_JSON).unwrap();
        let actual = LanEncoder::new(LanProtocolVersion::V3_3, ascii_key())
            .encode_with_nonce(&message, [0; GCM_NONCE_LEN])
            .unwrap();

        // AES ciphertext generated independently with OpenSSL 3 `enc
        // -aes-128-ecb`; CRC generated with Python zlib. The APK's JNI wrappers
        // and ThingFrame serializer independently pin the same operations/order.
        let expected = hex::decode(concat!(
            "000055aa010203040000002000000038",
            "d5e72be1640d300e444da1c37fecf73c",
            "538fb59b24a177a0b7e1e4cc988cb5a5",
            "2ff08d848b44f69ca22d849beb55ba70",
            "10bc7b3a",
            "0000aa55"
        ))
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(&actual[16..19], &expected[16..19]);
        assert!(!actual.windows(3).any(|bytes| bytes == b"3.3"));

        let decoded = decode_one(
            LanProtocolVersion::V3_3,
            ascii_key(),
            StatusPresence::Absent,
            &actual,
        )
        .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn protocol_34_frame_matches_independent_known_answer() {
        let message = LanMessage::ipc_lan_302(0x0102_0304, OFFER_JSON).unwrap();
        let actual = LanEncoder::new(LanProtocolVersion::V3_4, synthetic_key())
            .encode_with_nonce(&message, [0; GCM_NONCE_LEN])
            .unwrap();

        // Generated independently with Node's OpenSSL-backed AES-ECB + HMAC.
        let expected = hex::decode(concat!(
            "000055aa010203040000002000000054",
            "39a375861555a5fb712ca45b79276b3a",
            "c2a31cd2107a76217c89d429f5feb7c",
            "8d421c5bbbea0c472156457dc6899134",
            "88c2e5127146fc957b6a4ec1214ae8c",
            "e3af8afbc09631bf71d8feef7e7e7c",
            "99980000aa55"
        ))
        .unwrap();
        assert_eq!(actual, expected);

        let decoded = decode_one(
            LanProtocolVersion::V3_4,
            synthetic_key(),
            StatusPresence::Absent,
            &actual,
        )
        .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn protocol_35_frame_matches_independent_known_answer() {
        let message = LanMessage::ipc_lan_302(0x0102_0304, OFFER_JSON).unwrap();
        let nonce: [u8; GCM_NONCE_LEN] = std::array::from_fn(|index| index as u8);
        let actual = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key())
            .encode_with_nonce(&message, nonce)
            .unwrap();

        // Generated independently with Node's OpenSSL-backed AES-128-GCM.
        let expected = hex::decode(concat!(
            "000066990000010203040000002000000041",
            "000102030405060708090a0b",
            "e84ecfab077f922669e81aa842da006d",
            "911c3889358b9884c45cdd0f7937c54e",
            "bf86a3d589",
            "c5b62a355bf632ad3534a8a538fb5a90",
            "00009966"
        ))
        .unwrap();
        assert_eq!(actual, expected);

        let decoded = decode_one(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            StatusPresence::Absent,
            &actual,
        )
        .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn response_status_and_binary_payload_round_trip_for_all_versions() {
        let payload = b"before\0\0\x99\x66middle\0\0\xaa\x55after".to_vec();
        for version in [
            LanProtocolVersion::V3_3,
            LanProtocolVersion::V3_4,
            LanProtocolVersion::V3_5,
        ] {
            let message = LanMessage::response(91, 0xdead_beef, 0x1122_3344, payload.clone());
            let frame = LanEncoder::new(version, synthetic_key())
                .encode_with_nonce(&message, [0x5a; GCM_NONCE_LEN])
                .unwrap();
            let decoded =
                decode_one(version, synthetic_key(), StatusPresence::Present, &frame).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn response_status_layout_matches_independent_known_answers() {
        let response = LanMessage::response(
            0x0a0b_0c0d,
            IPC_LAN_302,
            0x1122_3344,
            br#"{"ok":true}"#.to_vec(),
        );

        // Independently generated with Node/OpenSSL. In 3.4 the status is the
        // plaintext word after the header and before the ECB ciphertext.
        let expected_34 = hex::decode(concat!(
            "000055aa0a0b0c0d0000002000000038",
            "11223344",
            "7e36937500de68824879ceb17c461c3c",
            "99915ff4d13662f0867d511866d86ab0",
            "17e213fb111f80dc5a905618bc064b01",
            "0000aa55"
        ))
        .unwrap();
        let actual_34 = LanEncoder::new(LanProtocolVersion::V3_4, synthetic_key())
            .encode_with_nonce(&response, [0; GCM_NONCE_LEN])
            .unwrap();
        assert_eq!(actual_34, expected_34);
        assert_eq!(
            decode_one(
                LanProtocolVersion::V3_4,
                synthetic_key(),
                StatusPresence::Present,
                &expected_34,
            )
            .unwrap(),
            response
        );

        // In 3.5 the same status word is inside the authenticated ciphertext.
        let expected_35 = hex::decode(concat!(
            "0000669900000a0b0c0d000000200000002b",
            "a0a1a2a3a4a5a6a7a8a9aaab",
            "bba40bff05ab5c61a842c1723377cd",
            "8c858a42591627e07877ecaec133fd79",
            "00009966"
        ))
        .unwrap();
        let actual_35 = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key())
            .encode_with_nonce(&response, std::array::from_fn(|index| 0xa0 + index as u8))
            .unwrap();
        assert_eq!(actual_35, expected_35);
        assert_eq!(
            decode_one(
                LanProtocolVersion::V3_5,
                synthetic_key(),
                StatusPresence::Present,
                &expected_35,
            )
            .unwrap(),
            response
        );
    }

    #[test]
    fn decoder_handles_every_byte_fragmented_and_multiple_frames_coalesced() {
        for version in [
            LanProtocolVersion::V3_3,
            LanProtocolVersion::V3_4,
            LanProtocolVersion::V3_5,
        ] {
            let first = LanMessage::request(1, 32, b"first".to_vec());
            let second = LanMessage::request(2, 0xfedc_ba98, b"second".to_vec());
            let encoder = LanEncoder::new(version, synthetic_key());
            let first_frame = encoder
                .encode_with_nonce(&first, [0x11; GCM_NONCE_LEN])
                .unwrap();
            let second_frame = encoder
                .encode_with_nonce(&second, [0x22; GCM_NONCE_LEN])
                .unwrap();

            let mut fragmented = LanDecoder::new(version, synthetic_key(), StatusPresence::Absent);
            let mut fragmented_messages = Vec::new();
            for byte in &first_frame {
                fragmented_messages.extend(fragmented.push(std::slice::from_ref(byte)).unwrap());
            }
            assert_eq!(fragmented_messages, vec![first.clone()]);
            assert_eq!(fragmented.buffered_len(), 0);

            let mut combined = first_frame;
            combined.extend_from_slice(&second_frame);
            let mut coalesced = LanDecoder::new(version, synthetic_key(), StatusPresence::Absent);
            assert_eq!(coalesced.push(&combined).unwrap(), vec![first, second]);
            assert_eq!(coalesced.buffered_len(), 0);
        }
    }

    #[test]
    fn protocol_35_draws_a_fresh_nonce_for_every_frame() {
        let encoder = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key());
        let message = LanMessage::request(1, IPC_LAN_302, b"{}".to_vec());
        let mut random = ChangingRandom(Cell::new(0x40));
        let first = encoder.encode(&message, &mut random).unwrap();
        let second = encoder.encode(&message, &mut random).unwrap();
        assert_ne!(
            &first[HEADER_35_LEN..HEADER_35_LEN + GCM_NONCE_LEN],
            &second[HEADER_35_LEN..HEADER_35_LEN + GCM_NONCE_LEN]
        );
    }

    #[test]
    fn corrupt_authentication_suffix_and_lengths_fail_closed() {
        let request = LanMessage::request(4, IPC_LAN_302, b"{}".to_vec());

        let mut frame_33 = LanEncoder::new(LanProtocolVersion::V3_3, synthetic_key())
            .encode_with_nonce(&request, [0; GCM_NONCE_LEN])
            .unwrap();
        frame_33[HEADER_34_LEN] ^= 1;
        let error = decode_one(
            LanProtocolVersion::V3_3,
            synthetic_key(),
            StatusPresence::Absent,
            &frame_33,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("CRC32 integrity check failed"));

        let mut frame_34 = LanEncoder::new(LanProtocolVersion::V3_4, synthetic_key())
            .encode_with_nonce(&request, [0; GCM_NONCE_LEN])
            .unwrap();
        let hmac_byte = frame_34.len() - SUFFIX_LEN - 1;
        frame_34[hmac_byte] ^= 1;
        let error = decode_one(
            LanProtocolVersion::V3_4,
            synthetic_key(),
            StatusPresence::Absent,
            &frame_34,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("HMAC authentication failed"));

        let mut frame_35 = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key())
            .encode_with_nonce(&request, [0x33; GCM_NONCE_LEN])
            .unwrap();
        let tag_byte = frame_35.len() - SUFFIX_LEN - 1;
        frame_35[tag_byte] ^= 1;
        let error = decode_one(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            StatusPresence::Absent,
            &frame_35,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("GCM authentication failed"));

        let mut bad_suffix = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key())
            .encode_with_nonce(&request, [0x44; GCM_NONCE_LEN])
            .unwrap();
        *bad_suffix.last_mut().unwrap() ^= 1;
        let error = decode_one(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            StatusPresence::Absent,
            &bad_suffix,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid 3.5 frame suffix"));

        let mut bad_reserved = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key())
            .encode_with_nonce(&request, [0x45; GCM_NONCE_LEN])
            .unwrap();
        bad_reserved[4] = 1;
        let error = decode_one(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            StatusPresence::Absent,
            &bad_reserved,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("reserved header bytes must be zero"));

        let mut short_34 = vec![0_u8; HEADER_34_LEN];
        short_34[..4].copy_from_slice(&PREFIX_34);
        short_34[12..16].copy_from_slice(&((HMAC_LEN + SUFFIX_LEN - 1) as u32).to_be_bytes());
        let mut decoder = LanDecoder::new(
            LanProtocolVersion::V3_4,
            synthetic_key(),
            StatusPresence::Absent,
        );
        assert!(decoder.push(&short_34).is_err());

        let mut oversized_35 = vec![0_u8; HEADER_35_LEN];
        oversized_35[..4].copy_from_slice(&PREFIX_35);
        oversized_35[14..18].copy_from_slice(&((MAX_LAN_FRAME_BODY as u32) + 1).to_be_bytes());
        let mut decoder = LanDecoder::new(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            StatusPresence::Absent,
        );
        assert!(decoder.push(&oversized_35).is_err());
    }

    #[test]
    fn protocol_33_rejects_session_handshake() {
        let error = PendingLanHandshake::begin(
            LanProtocolVersion::V3_3,
            synthetic_key(),
            1,
            &mut PatternRandom(0x10),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not use the commands 3/4/5"));
    }

    fn assert_handshake(version: LanProtocolVersion, expected_session_key: [u8; AES_BLOCK]) {
        let mut random = PatternRandom(0x10);
        let pending =
            PendingLanHandshake::begin(version, synthetic_key(), 41, &mut random).unwrap();

        let start = decode_one(
            version,
            synthetic_key(),
            StatusPresence::Absent,
            pending.start_frame(),
        )
        .unwrap();
        let client_nonce: [u8; AES_BLOCK] = std::array::from_fn(|index| 0x10 + index as u8);
        assert_eq!(start.sequence(), 41);
        assert_eq!(start.command(), SESSION_KEY_NEGOTIATION_START);
        assert_eq!(start.payload(), client_nonce);

        let remote_nonce: [u8; AES_BLOCK] = std::array::from_fn(|index| 0xf0 + index as u8);
        let mut response_payload = remote_nonce.to_vec();
        response_payload.extend_from_slice(&hmac_sha256(&synthetic_key(), &client_nonce).unwrap());
        let response =
            LanMessage::response(900, SESSION_KEY_NEGOTIATION_RESPONSE, 0, response_payload);
        let response_frame = LanEncoder::new(version, synthetic_key())
            .encode_with_nonce(&response, [0xa5; GCM_NONCE_LEN])
            .unwrap();
        let mut response_decoder = pending.response_decoder();
        let response = response_decoder.push(&response_frame).unwrap().remove(0);

        let finished = pending.accept_response(&response, &mut random).unwrap();
        let (session_encoder, mut session_decoder, next_sequence) = finished
            .complete_with(StatusPresence::Absent, |finish_frame| {
                let finish = decode_one(
                    version,
                    synthetic_key(),
                    StatusPresence::Absent,
                    finish_frame,
                )?;
                assert_eq!(finish.sequence(), 42);
                assert_eq!(finish.command(), SESSION_KEY_NEGOTIATION_FINISH);
                assert_eq!(
                    finish.payload(),
                    hmac_sha256(&synthetic_key(), &remote_nonce).unwrap()
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(next_sequence, 43);
        let traffic = LanMessage::request(next_sequence, IPC_LAN_302, b"session".to_vec());

        let expected_frame = LanEncoder::new(version, LanKey::from_bytes(expected_session_key))
            .encode_with_nonce(&traffic, [0x61; GCM_NONCE_LEN])
            .unwrap();
        assert_eq!(
            session_decoder.push(&expected_frame).unwrap(),
            vec![traffic.clone()]
        );

        let actual_frame = session_encoder
            .encode_with_nonce(&traffic, [0x62; GCM_NONCE_LEN])
            .unwrap();
        assert_eq!(
            decode_one(
                version,
                LanKey::from_bytes(expected_session_key),
                StatusPresence::Absent,
                &actual_frame,
            )
            .unwrap(),
            traffic
        );
    }

    #[test]
    fn protocol_34_handshake_matches_independent_session_key_vector() {
        assert_handshake(
            LanProtocolVersion::V3_4,
            [
                0xde, 0x8e, 0x8d, 0x96, 0x2b, 0x69, 0x07, 0x4b, 0x2a, 0x38, 0x94, 0x3b, 0xad, 0x35,
                0xbc, 0x52,
            ],
        );
    }

    #[test]
    fn protocol_35_handshake_matches_independent_session_key_vector() {
        assert_handshake(
            LanProtocolVersion::V3_5,
            [
                0x24, 0xce, 0xe3, 0x4f, 0xef, 0xaf, 0x56, 0x0f, 0xf7, 0x3d, 0xbd, 0x15, 0x27, 0xc7,
                0x0b, 0xde,
            ],
        );
    }

    #[test]
    fn handshake_rejects_inner_hmac_status_command_and_bad_34_session_key() {
        let client_nonce: [u8; AES_BLOCK] = std::array::from_fn(|index| 0x10 + index as u8);
        let remote_nonce = [0xf0; AES_BLOCK];
        let mut bad_payload = remote_nonce.to_vec();
        bad_payload.extend_from_slice(&[0; HMAC_LEN]);

        for (command, status, expected) in [
            (SESSION_KEY_NEGOTIATION_RESPONSE, 0, "HMAC authentication"),
            (SESSION_KEY_NEGOTIATION_RESPONSE, 1, "status"),
            (99, 0, "expected session command"),
        ] {
            let pending = PendingLanHandshake::begin(
                LanProtocolVersion::V3_5,
                synthetic_key(),
                1,
                &mut PatternRandom(0x10),
            )
            .unwrap();
            let response = LanMessage::response(7, command, status, bad_payload.clone());
            let error = pending
                .accept_response(&response, &mut PatternRandom(0x20))
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        let mut valid_payload = remote_nonce.to_vec();
        valid_payload.extend_from_slice(&hmac_sha256(&synthetic_key(), &client_nonce).unwrap());
        let pending = PendingLanHandshake::begin(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            1,
            &mut PatternRandom(0x10),
        )
        .unwrap();
        let response = LanMessage::response(4, SESSION_KEY_NEGOTIATION_RESPONSE, 0, valid_payload);
        assert!(pending
            .accept_response(&response, &mut PatternRandom(0x20))
            .is_ok());

        let zero_prefix_remote = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x19,
        ];
        let error = derive_session_key(
            LanProtocolVersion::V3_4,
            &synthetic_key(),
            &client_nonce,
            &zero_prefix_remote,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("begins with 0x00"));
    }

    #[test]
    fn failed_finish_write_never_enters_the_negotiated_session() {
        let client_nonce: [u8; AES_BLOCK] = std::array::from_fn(|index| 0x10 + index as u8);
        let remote_nonce = [0xf0; AES_BLOCK];
        let pending = PendingLanHandshake::begin(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            17,
            &mut PatternRandom(0x10),
        )
        .unwrap();
        let mut response_payload = remote_nonce.to_vec();
        response_payload.extend_from_slice(&hmac_sha256(&synthetic_key(), &client_nonce).unwrap());
        let response =
            LanMessage::response(18, SESSION_KEY_NEGOTIATION_RESPONSE, 0, response_payload);
        let finished = pending
            .accept_response(&response, &mut PatternRandom(0x20))
            .unwrap();
        let callback_called = Cell::new(false);
        let error = finished
            .complete_with(StatusPresence::Present, |_finish_frame| {
                callback_called.set(true);
                Err(Error::Transport(
                    "synthetic command-5 write failure".to_string(),
                ))
            })
            .unwrap_err()
            .to_string();
        assert!(callback_called.get());
        assert!(error.contains("command-5 write failure"));
    }

    #[test]
    fn decoder_refuses_key_switch_with_partial_frame() {
        let message = LanMessage::request(1, IPC_LAN_302, b"{}".to_vec());
        let frame = LanEncoder::new(LanProtocolVersion::V3_5, synthetic_key())
            .encode_with_nonce(&message, [0x31; GCM_NONCE_LEN])
            .unwrap();
        let mut decoder = LanDecoder::new(
            LanProtocolVersion::V3_5,
            synthetic_key(),
            StatusPresence::Absent,
        );
        assert!(decoder.push(&frame[..7]).unwrap().is_empty());
        assert!(decoder.set_key(synthetic_key()).is_err());
    }
}
