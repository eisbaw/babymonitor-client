//! Authenticated local IPC-LAN-302 signaling transport.
//!
//! Unlike the MQTT carrier, this opens the camera's Tuya LAN TCP endpoint and
//! carries raw `{header,msg}` JSON in frame type 32.  Commands 3/4/5 establish a
//! per-connection session key before any signaling message is accepted.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::stream::session::{InboundEnvelope, OsRandom, RandomSource, SignalingTransport};
use crate::stream::signaling::SignalingPath;
use crate::stream::tuya_lan::{
    LanDecoder, LanEncoder, LanKey, LanMessage, LanProtocolVersion, PendingLanHandshake,
    StatusPresence, IPC_LAN_302,
};
use crate::Error;

const IO_TIMEOUT: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const READ_CHUNK: usize = 16 * 1024;

/// Inputs needed to authenticate one local camera connection.
#[derive(Clone)]
pub struct Lan302ConnectConfig {
    /// Camera TCP endpoint, normally `<camera-ip>:6668`.
    pub address: SocketAddr,
    /// Hardware-gateway protocol discovered as `HgwBean.version`.
    pub version: LanProtocolVersion,
    /// Camera device id used by the signaling flow sharing this connection.
    pub device_id: String,
    /// Device `localKey`; debug output is redacted by [`LanKey`].
    pub local_key: LanKey,
}

impl std::fmt::Debug for Lan302ConnectConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Lan302ConnectConfig")
            .field("address", &self.address)
            .field("version", &self.version)
            .field("device_id", &"[REDACTED]")
            .field("local_key", &self.local_key)
            .finish()
    }
}

/// Authenticated frame-32 carrier over an injected byte stream.
///
/// The generic stream makes declared-length framing and handshake behavior
/// testable without sockets.  Live callers use [`connect_tcp`](Self::connect_tcp).
pub struct Lan302Transport<S, R = OsRandom> {
    stream: S,
    random: R,
    encoder: LanEncoder,
    decoder: LanDecoder,
    next_sequence: u32,
    pending: VecDeque<LanMessage>,
}

impl<S: Read + Write, R: RandomSource> Lan302Transport<S, R> {
    /// Authenticate an already-open stream using Tuya commands 3/4/5.
    ///
    /// The device command-4 HMAC is verified before command 5 is written or the
    /// negotiated key is exposed.  Short reads are accumulated solely according
    /// to the authenticated frame's declared length.
    pub fn authenticate(
        mut stream: S,
        version: LanProtocolVersion,
        local_key: LanKey,
        mut random: R,
    ) -> Result<Self, Error> {
        let pending = PendingLanHandshake::begin(version, local_key, 1, &mut random)?;
        stream
            .write_all(pending.start_frame())
            .map_err(|error| Error::Transport(format!("write LAN command 3: {error}")))?;
        stream
            .flush()
            .map_err(|error| Error::Transport(format!("flush LAN command 3: {error}")))?;

        let mut response_decoder = pending.response_decoder();
        let response = read_one_message(&mut stream, &mut response_decoder, "command 4")?;
        let finished = pending.accept_response(&response, &mut random)?;
        let (encoder, decoder, next_sequence) =
            finished.complete_with(StatusPresence::Present, |frame| {
                stream
                    .write_all(frame)
                    .map_err(|error| Error::Transport(format!("write LAN command 5: {error}")))?;
                stream
                    .flush()
                    .map_err(|error| Error::Transport(format!("flush LAN command 5: {error}")))
            })?;

        Ok(Self {
            stream,
            random,
            encoder,
            decoder,
            next_sequence,
            pending: VecDeque::new(),
        })
    }

    fn next_sequence(&mut self) -> Result<u32, Error> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            Error::LanProtocol("LAN signaling sequence exhausted u32".to_string())
        })?;
        Ok(sequence)
    }

    fn pop_frame_32(&mut self) -> Result<Option<InboundEnvelope>, Error> {
        while let Some(message) = self.pending.pop_front() {
            if message.command() != IPC_LAN_302 {
                continue;
            }
            if message.status() != Some(0) {
                return Err(Error::LanProtocol(format!(
                    "IPC_LAN_302 response status was {:?}, expected 0",
                    message.status()
                )));
            }
            return Ok(Some(InboundEnvelope {
                source: Some("lan".to_string()),
                json: message.payload().to_vec(),
            }));
        }
        Ok(None)
    }
}

impl Lan302Transport<TcpStream, OsRandom> {
    /// Connect to the configured camera endpoint and authenticate the session.
    pub fn connect_tcp(config: &Lan302ConnectConfig) -> Result<Self, Error> {
        if config.device_id.trim().is_empty() {
            return Err(Error::StreamConfig(
                "LAN device id must not be empty".to_string(),
            ));
        }
        let stream = TcpStream::connect_timeout(&config.address, CONNECT_TIMEOUT)
            .map_err(|error| Error::Transport(format!("connect camera LAN endpoint: {error}")))?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| {
                Error::Transport(format!("set LAN handshake read timeout: {error}"))
            })?;
        stream
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| {
                Error::Transport(format!("set LAN handshake write timeout: {error}"))
            })?;
        let transport =
            Self::authenticate(stream, config.version, config.local_key.clone(), OsRandom)?;
        transport
            .stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|error| Error::Transport(format!("set LAN poll timeout: {error}")))?;
        transport
            .stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|error| {
                Error::Transport(format!("set LAN signaling write timeout: {error}"))
            })?;
        Ok(transport)
    }
}

impl<S: Read + Write, R: RandomSource> SignalingTransport for Lan302Transport<S, R> {
    fn path(&self) -> SignalingPath {
        SignalingPath::Lan
    }

    fn send_json(&mut self, json: &[u8]) -> Result<(), Error> {
        let sequence = self.next_sequence()?;
        let message = LanMessage::ipc_lan_302(sequence, json)?;
        let frame = self.encoder.encode(&message, &mut self.random)?;
        self.stream
            .write_all(&frame)
            .map_err(|error| Error::Transport(format!("write IPC_LAN_302: {error}")))?;
        self.stream
            .flush()
            .map_err(|error| Error::Transport(format!("flush IPC_LAN_302: {error}")))
    }

    fn try_recv_json(&mut self) -> Result<Option<InboundEnvelope>, Error> {
        if let Some(envelope) = self.pop_frame_32()? {
            return Ok(Some(envelope));
        }

        let mut chunk = [0_u8; READ_CHUNK];
        let read = match self.stream.read(&mut chunk) {
            Ok(0) => {
                return Err(Error::Transport(
                    "camera closed authenticated LAN signaling connection".to_string(),
                ))
            }
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None)
            }
            Err(error) => {
                return Err(Error::Transport(format!(
                    "read authenticated LAN signaling: {error}"
                )))
            }
        };
        self.pending.extend(self.decoder.push(&chunk[..read])?);
        self.pop_frame_32()
    }
}

fn read_one_message<S: Read>(
    stream: &mut S,
    decoder: &mut LanDecoder,
    context: &str,
) -> Result<LanMessage, Error> {
    let mut chunk = [0_u8; READ_CHUNK];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| Error::Transport(format!("read LAN handshake {context}: {error}")))?;
        if read == 0 {
            return Err(Error::Transport(format!(
                "camera closed LAN connection while waiting for {context}"
            )));
        }
        let messages = decoder.push(&chunk[..read])?;
        if messages.len() > 1 {
            return Err(Error::LanProtocol(format!(
                "received {} frames while waiting for one LAN handshake {context}",
                messages.len()
            )));
        }
        if let Some(message) = messages.into_iter().next() {
            return Ok(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::session::{SignalingFlow, SignalingSession};
    use crate::stream::signaling::{SignalingEnvelope, SignalingType};
    use crate::stream::tuya_lan::{
        SESSION_KEY_NEGOTIATION_FINISH, SESSION_KEY_NEGOTIATION_RESPONSE,
        SESSION_KEY_NEGOTIATION_START,
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::cell::{Cell, RefCell};
    use std::io::Cursor;
    use std::rc::Rc;

    const KEY: &[u8; 16] = b"0123456789abcdef"; // secret-scan:allow synthetic
    type CapturedWrites = Rc<RefCell<Vec<Vec<u8>>>>;
    type TestTransport = Lan302Transport<MemoryStream, FixedRandom>;

    #[derive(Clone, Copy)]
    struct FixedRandom(u8);

    impl RandomSource for FixedRandom {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(self.0);
            Ok(())
        }
    }

    struct ChangingRandom(Cell<u8>);

    impl RandomSource for ChangingRandom {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
            let start = self.0.get();
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = start.wrapping_add(index as u8);
            }
            self.0.set(start.wrapping_add(1));
            Ok(())
        }
    }

    struct MemoryStream {
        reads: Cursor<Vec<u8>>,
        read_limits: VecDeque<usize>,
        writes: CapturedWrites,
    }

    impl MemoryStream {
        fn new(reads: Vec<u8>) -> (Self, CapturedWrites) {
            let writes = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    reads: Cursor::new(reads),
                    read_limits: VecDeque::new(),
                    writes: Rc::clone(&writes),
                },
                writes,
            )
        }

        fn with_read_limits(
            reads: Vec<u8>,
            read_limits: impl IntoIterator<Item = usize>,
        ) -> (Self, CapturedWrites) {
            let (mut stream, writes) = Self::new(reads);
            stream.read_limits = read_limits.into_iter().collect();
            (stream, writes)
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let limit = self
                .read_limits
                .pop_front()
                .unwrap_or(bytes.len())
                .min(bytes.len());
            self.reads.read(&mut bytes[..limit])
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes.borrow_mut().push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn command_34(frame: &[u8]) -> u32 {
        u32::from_be_bytes(frame[8..12].try_into().unwrap())
    }

    fn command_35(frame: &[u8]) -> u32 {
        u32::from_be_bytes(frame[10..14].try_into().unwrap())
    }

    fn handshake_response(inner_hmac: [u8; 32]) -> Vec<u8> {
        let mut payload = vec![0x22; 16];
        payload.extend_from_slice(&inner_hmac);
        LanEncoder::new(LanProtocolVersion::V3_4, LanKey::from_bytes(*KEY))
            .encode(
                &LanMessage::response(1, 4, 0, payload),
                &mut FixedRandom(0x33),
            )
            .unwrap()
    }

    #[test]
    fn authentication_writes_3_then_5_before_any_frame_32() {
        let mut hmac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
        hmac.update(&[0x11; 16]);
        let response = handshake_response(hmac.finalize().into_bytes().into());
        let (stream, writes) = MemoryStream::new(response);
        let mut transport = Lan302Transport::authenticate(
            stream,
            LanProtocolVersion::V3_4,
            LanKey::from_bytes(*KEY),
            FixedRandom(0x11),
        )
        .unwrap();
        transport
            .send_json(br#"{"header":{"type":"candidate"},"msg":{"candidate":""}}"#)
            .unwrap();
        let commands: Vec<u32> = writes
            .borrow()
            .iter()
            .map(|frame| command_34(frame))
            .collect();
        assert_eq!(commands, vec![3, 5, IPC_LAN_302]);
    }

    #[test]
    fn authentication_rejects_bad_device_hmac_before_finish() {
        let (stream, writes) = MemoryStream::new(handshake_response([0x99; 32]));
        let error = Lan302Transport::authenticate(
            stream,
            LanProtocolVersion::V3_4,
            LanKey::from_bytes(*KEY),
            FixedRandom(0x11),
        )
        .err()
        .expect("bad HMAC must fail")
        .to_string();
        assert!(error.contains("HMAC authentication"), "{error}");
        assert_eq!(writes.borrow().len(), 1, "command 5 was not written");
        assert_eq!(command_34(&writes.borrow()[0]), 3);
    }

    fn established_transport(inbound: Vec<u8>) -> (TestTransport, CapturedWrites) {
        let (stream, writes) = MemoryStream::new(inbound);
        let key = LanKey::from_bytes(*KEY);
        (
            Lan302Transport {
                stream,
                random: FixedRandom(0x44),
                encoder: LanEncoder::new(LanProtocolVersion::V3_4, key.clone()),
                decoder: LanDecoder::new(LanProtocolVersion::V3_4, key, StatusPresence::Present),
                next_sequence: 10,
                pending: VecDeque::new(),
            },
            writes,
        )
    }

    fn answer_json() -> Vec<u8> {
        br#"{"header":{"from":"DEV","to":"USER","sessionid":"SESS","trace_id":"trace-1","type":"answer","path":"lan"},"msg":{"sdp":"v=0\r\nm=application 9 tuya 6001\r\na=ice-ufrag:REMOTE\r\na=ice-pwd:REMOTE_PASSWORD\r\na=aes-key:00112233445566778899aabbccddeeff\r\n"}}"#.to_vec()
    }

    #[test]
    fn lan_session_exchanges_one_path_and_feeds_candidate_plus_answer() {
        let candidate = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            "a=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\n",
            SignalingPath::Lan,
        )
        .to_json()
        .unwrap();
        let encoder = LanEncoder::new(LanProtocolVersion::V3_4, LanKey::from_bytes(*KEY));
        let mut random = FixedRandom(0x33);
        let mut inbound = encoder
            .encode(
                &LanMessage::response(1, IPC_LAN_302, 0, candidate),
                &mut random,
            )
            .unwrap();
        inbound.extend(
            encoder
                .encode(
                    &LanMessage::response(2, IPC_LAN_302, 0, answer_json()),
                    &mut random,
                )
                .unwrap(),
        );
        let (transport, writes) = established_transport(inbound);
        let flow = SignalingFlow::new("USER", "DEV", "SESS", "trace-1");
        let args = flow.make_offer_args(
            "v=0\r\nm=application 9 tuya 6001\r\n".to_string(),
            Vec::new(),
            None,
            None,
        );
        let mut session = SignalingSession::new(transport, flow);
        let outcome = session
            .negotiate_with_trickle(&args, &[], 4, 0, Duration::ZERO, |_| false)
            .unwrap();
        assert_eq!(outcome.answer.remote_ufrag, "REMOTE");
        assert_eq!(outcome.remote_candidates.len(), 1);

        // Offer + end-of-candidates, each exactly once and both labeled LAN.
        assert_eq!(writes.borrow().len(), 2);
        let decoder_key = LanKey::from_bytes(*KEY);
        for frame in writes.borrow().iter() {
            let mut decoder = LanDecoder::new(
                LanProtocolVersion::V3_4,
                decoder_key.clone(),
                StatusPresence::Absent,
            );
            let message = decoder.push(frame).unwrap().pop().unwrap();
            assert_eq!(message.command(), IPC_LAN_302);
            let envelope = SignalingEnvelope::from_json(message.payload()).unwrap();
            assert_eq!(envelope.header.path, Some(SignalingPath::Lan));
            assert!(matches!(
                envelope.header.r#type,
                SignalingType::Offer | SignalingType::Candidate
            ));
        }
    }

    #[test]
    fn protocol_35_transport_authenticates_then_negotiates_candidate_and_answer() {
        let client_nonce: [u8; 16] = std::array::from_fn(|index| 0x11 + index as u8);
        let remote_nonce = [0x22; 16];
        let mut inner_hmac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
        inner_hmac.update(&client_nonce);
        let mut command_4_payload = remote_nonce.to_vec();
        command_4_payload.extend_from_slice(&inner_hmac.finalize().into_bytes());
        let mut device_random = FixedRandom(0x31);
        let command_4 = LanEncoder::new(LanProtocolVersion::V3_5, LanKey::from_bytes(*KEY))
            .encode(
                &LanMessage::response(1, SESSION_KEY_NEGOTIATION_RESPONSE, 0, command_4_payload),
                &mut device_random,
            )
            .unwrap();

        // Independent Node/OpenSSL AES-128-GCM vector for local key KEY,
        // IV client_nonce[..12], and plaintext client_nonce XOR remote_nonce.
        // Keeping the derived bytes fixed here avoids duplicating production's
        // session-key derivation in this transport-level test.
        let session_key = LanKey::from_bytes([
            0xcb, 0x2b, 0x15, 0x60, 0x5c, 0x0c, 0xb6, 0x5e, 0x42, 0xdd, 0x78, 0xf3, 0xb2, 0xd0,
            0x6b, 0x32,
        ]);
        let candidate = SignalingEnvelope::candidate(
            "DEV",
            "USER",
            "SESS",
            "trace-1",
            "a=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\n",
            SignalingPath::Lan,
        )
        .to_json()
        .unwrap();
        let session_encoder = LanEncoder::new(LanProtocolVersion::V3_5, session_key.clone());
        let mut session_random = ChangingRandom(Cell::new(0x40));

        // The production decoder deliberately remains StatusPresence::Present.
        // Whether live Philips command-32 responses include this status word is
        // a capture-validation question for TASK-0126, not something to guess
        // or weaken in this deterministic test.
        let candidate_frame = session_encoder
            .encode(
                &LanMessage::response(3, IPC_LAN_302, 0, candidate),
                &mut session_random,
            )
            .unwrap();
        let answer_frame = session_encoder
            .encode(
                &LanMessage::response(4, IPC_LAN_302, 0, answer_json()),
                &mut session_random,
            )
            .unwrap();

        let command_4_len = command_4.len();
        let mut inbound = command_4;
        inbound.extend_from_slice(&candidate_frame);
        inbound.extend_from_slice(&answer_frame);
        // Fragment command 4 across two TCP reads. Once authentication switches
        // keys, the candidate and answer are returned in one coalesced read.
        let (stream, writes) = MemoryStream::with_read_limits(inbound, [7, command_4_len - 7]);
        let transport = Lan302Transport::authenticate(
            stream,
            LanProtocolVersion::V3_5,
            LanKey::from_bytes(*KEY),
            ChangingRandom(Cell::new(0x11)),
        )
        .unwrap();

        let flow = SignalingFlow::new("USER", "DEV", "SESS", "trace-1");
        let args = flow.make_offer_args(
            "v=0\r\nm=application 9 tuya 6001\r\n".to_string(),
            Vec::new(),
            None,
            None,
        );
        let mut session = SignalingSession::new(transport, flow);
        let outcome = session
            .negotiate_with_trickle(&args, &[], 4, 0, Duration::ZERO, |_| false)
            .unwrap();
        assert_eq!(outcome.answer.remote_ufrag, "REMOTE");
        assert_eq!(outcome.remote_candidates.len(), 1);

        let writes = writes.borrow();
        assert_eq!(writes.len(), 4, "commands 3, 5, offer, and candidate");
        assert_eq!(
            writes
                .iter()
                .map(|frame| command_35(frame))
                .collect::<Vec<_>>(),
            vec![
                SESSION_KEY_NEGOTIATION_START,
                SESSION_KEY_NEGOTIATION_FINISH,
                IPC_LAN_302,
                IPC_LAN_302,
            ]
        );

        let mut local_decoder = LanDecoder::new(
            LanProtocolVersion::V3_5,
            LanKey::from_bytes(*KEY),
            StatusPresence::Absent,
        );
        assert_eq!(
            local_decoder.push(&writes[0]).unwrap()[0].command(),
            SESSION_KEY_NEGOTIATION_START
        );
        assert_eq!(
            local_decoder.push(&writes[1]).unwrap()[0].command(),
            SESSION_KEY_NEGOTIATION_FINISH
        );

        for frame in &writes[2..] {
            let mut decoder = LanDecoder::new(
                LanProtocolVersion::V3_5,
                session_key.clone(),
                StatusPresence::Absent,
            );
            let message = decoder.push(frame).unwrap().pop().unwrap();
            assert_eq!(message.command(), IPC_LAN_302);
            let envelope = SignalingEnvelope::from_json(message.payload()).unwrap();
            assert_eq!(envelope.header.path, Some(SignalingPath::Lan));
            assert!(matches!(
                envelope.header.r#type,
                SignalingType::Offer | SignalingType::Candidate
            ));
        }
        assert_ne!(&writes[2][18..30], &writes[3][18..30]);
    }
}
