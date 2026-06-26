//! The cap3 **PATH A** media receive→decode engine: UDP datagram → (suite-3)
//! HMAC verify+strip → KCP RX with per-segment AES decrypt → `frg` reassembly →
//! RTP parse → [`MediaUnit`] (`re/media_decode_spec.md`, full spec).
//!
//! ```text
//! UDP ─▶ HMAC-SHA256 verify+strip (whole datagram, suite3) ─▶ ikcp_input
//!      ─▶ ikcp_parse_data ─▶ [per segment] strip 16B IV ─▶ AES-128-CBC ─▶ PKCS#7 unpad
//!      ─▶ KCP frg reassembly (recv) ─▶ RTP(12B) parse ─▶ MediaUnit(payload,pt,marker,seq,ts)
//! ```
//!
//! The layered submodules each carry their own spec citations + unit tests:
//! - [`crypto`] — datagram HMAC + per-segment AES-CBC/GCM (suite 3 / 4).
//! - [`kcp`] — hand-rolled ikcp RX with the per-segment decrypt hook.
//! - [`rtp`] — the 12-byte RTP header parse.
//! - [`h264`] — RFC-6184 STAP-A/FU-A → Annex-B depacketize + access-unit assembly.
//! - [`g711`] — G.711 µ-law (PCMU, PT 0) → 16-bit PCM decode (256-entry LUT).
//! - [`transport`] — ICE candidate parse/select + the UDP datagram seam.
//!
//! # Honest status (offline-validated vs live-gated)
//!
//! - **Offline-validated** (this engine + every submodule): the whole
//!   decrypt→KCP→RTP pipeline is exercised end-to-end against **synthetic
//!   vectors** built per the spec's send path (inline-IV + PKCS#7 + CBC, datagram
//!   HMAC, KCP `frg` framing) — see the e2e tests below. Suite 3 (AES-128-CBC +
//!   HMAC-SHA256) is the cap3-observed default (`security_level == 3`); suite 4
//!   (AES-128-GCM) round-trips but its on-wire framing is **[G]** unconfirmed.
//! - **Live-gated** (NOT runnable here — no live broker/camera): ICE connectivity
//!   to srflx/relay (full STUN/TURN handshake, [`transport`] docs) and the real
//!   media-bytes validation, which needs a capture (the spec's TASK-0068). There
//!   is **no `emulator_captures/cap4`** in this tree, so no captured media bytes
//!   exist to byte-validate against — the pipeline is proven on synthetic vectors
//!   only, stated plainly.

pub mod crypto;
pub mod g711;
pub mod h264;
pub mod kcp;
pub mod rtp;
pub mod transport;

use std::collections::HashMap;

use crate::stream::media::kcp::{KcpReceiver, SegmentDecryptor};
use crate::Error;

/// The negotiated media cipher suite — selected by `security_level`
/// (`session+0x3274`; `re/media_decode_spec.md` §2). The cap3 default is
/// [`AesCbcHmac`](CipherSuite::AesCbcHmac) (3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// Suites 0/1 — plaintext stub (no decrypt, no datagram tag).
    Plaintext,
    /// Suite 2 — ChaCha20. **[G]** framing unconfirmed; not implemented (a decrypt
    /// attempt returns a loud error rather than a fabricated transform).
    ChaCha20,
    /// Suite 3 — **AES-128-CBC** per segment (inline 16B IV, PKCS#7) + a trailing
    /// 32-byte datagram **HMAC-SHA256**. The cap3-observed default. **[C]**
    AesCbcHmac,
    /// Suite 4 — AES-128-GCM per segment (inline 16B IV, 16B trailing tag, NO
    /// datagram HMAC). **[G]** framing unconfirmed.
    AesGcm,
}

impl CipherSuite {
    /// Map a negotiated `security_level` (0..=4) to a [`CipherSuite`].
    ///
    /// # Errors
    /// [`Error::Transport`] for a level outside 0..=4 — we never silently default
    /// the cipher.
    pub fn from_security_level(level: i64) -> Result<Self, Error> {
        match level {
            0 | 1 => Ok(Self::Plaintext),
            2 => Ok(Self::ChaCha20),
            3 => Ok(Self::AesCbcHmac),
            4 => Ok(Self::AesGcm),
            other => Err(Error::Transport(format!(
                "unknown media security_level {other} (expected 0..=4)"
            ))),
        }
    }

    /// Whether this suite carries the trailing 32-byte datagram HMAC (suite 3).
    #[must_use]
    pub fn has_datagram_hmac(self) -> bool {
        matches!(self, Self::AesCbcHmac)
    }
}

/// One decoded media unit: the RTP payload plus the header fields the decode/
/// render layer needs (`re/media_decode_spec.md` §1 step 6 — the emit tuple
/// `(payload, pt, marker, seq, ts)` plus `ssrc`).
#[derive(Clone, PartialEq, Eq)]
pub struct MediaUnit {
    /// The RTP payload (an H.264 RTP payload — feed to [`h264::H264Depacketizer`]
    /// — or a G.711 µ-law frame for `payload_type == 0`).
    pub payload: Vec<u8>,
    /// RTP payload type (`PT`, 7-bit). `0` = PCMU.
    pub payload_type: u8,
    /// RTP marker bit (for H.264, the last packet of an access unit).
    pub marker: bool,
    /// RTP sequence number.
    pub sequence: u16,
    /// RTP timestamp.
    pub timestamp: u32,
    /// RTP SSRC.
    pub ssrc: u32,
}

impl MediaUnit {
    fn from_rtp(pkt: &rtp::RtpPacket<'_>) -> Self {
        Self {
            payload: pkt.payload.to_vec(),
            payload_type: pkt.header.payload_type,
            marker: pkt.header.marker,
            sequence: pkt.header.sequence,
            timestamp: pkt.header.timestamp,
            ssrc: pkt.header.ssrc,
        }
    }
}

impl std::fmt::Debug for MediaUnit {
    /// Prints metadata + payload LENGTH only — never the raw media bytes (the
    /// user's own A/V on the live path).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaUnit")
            .field("payload_len", &self.payload.len())
            .field("payload_type", &self.payload_type)
            .field("marker", &self.marker)
            .field("sequence", &self.sequence)
            .field("timestamp", &self.timestamp)
            .field("ssrc", &self.ssrc)
            .finish()
    }
}

/// The media receive→decode engine: per-`conv` KCP receivers + the negotiated
/// cipher suite + the 16-byte media key (the SDP `a=aes-key`). Feed it UDP
/// datagrams via [`push_datagram`](MediaEngine::push_datagram); it yields decoded
/// [`MediaUnit`]s.
///
/// The media key is held redacted (never leaked via `Debug`). Construct with
/// SYNTHETIC keys in tests (CLAUDE.md).
pub struct MediaEngine {
    suite: CipherSuite,
    media_key: Vec<u8>,
    channels: HashMap<u32, KcpReceiver>,
    rcv_wnd: u32,
}

impl std::fmt::Debug for MediaEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaEngine")
            .field("suite", &self.suite)
            .field(
                "media_key",
                &format!("<redacted len={}>", self.media_key.len()),
            )
            .field("channels", &self.channels.len())
            .field("rcv_wnd", &self.rcv_wnd)
            .finish()
    }
}

impl MediaEngine {
    /// Build an engine for a negotiated `suite` + `media_key` (the raw SDP
    /// `a=aes-key` bytes).
    ///
    /// # Errors
    /// [`Error::Transport`] if an AES suite (3/4) gets a key that is not exactly
    /// 16 bytes (AES-128) — we reject loudly rather than mis-key.
    pub fn new(suite: CipherSuite, media_key: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let media_key = media_key.into();
        if matches!(suite, CipherSuite::AesCbcHmac | CipherSuite::AesGcm)
            && media_key.len() != crypto::MEDIA_KEY_LEN
        {
            return Err(Error::Transport(format!(
                "media key is {} bytes; AES-128 (suite 3/4) expects {}",
                media_key.len(),
                crypto::MEDIA_KEY_LEN
            )));
        }
        Ok(Self {
            suite,
            media_key,
            channels: HashMap::new(),
            rcv_wnd: kcp::DEFAULT_RCV_WND,
        })
    }

    /// Build an engine from a negotiated `security_level` + `media_key`.
    ///
    /// # Errors
    /// [`Error::Transport`] for an unknown level or a wrong-length AES key.
    pub fn from_security_level(level: i64, media_key: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Self::new(CipherSuite::from_security_level(level)?, media_key)
    }

    /// The negotiated cipher suite.
    #[must_use]
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Process one received UDP datagram into zero or more decoded [`MediaUnit`]s.
    ///
    /// Runs the full §1 pipeline: (suite 3) HMAC verify+strip → `conv` demux →
    /// KCP input with the per-segment AES decrypt hook → `frg` reassembly → RTP
    /// parse. A datagram on the **control** `conv` (`0x010000f3`) is signaling,
    /// not media, and yields `[]` (handled by the MQTT signaling layer, not here).
    ///
    /// One reassembled KCP message is assumed to be exactly one bare RTP packet
    /// (`re/media_decode_spec.md` §3 caveat **[G]**: media RTP could instead be
    /// imm-length-prefixed inside the KCP message — only a media capture settles
    /// it; an RTP parse failure here surfaces that case loudly rather than
    /// silently mis-decoding).
    ///
    /// # Errors
    /// - [`Error::Transport`] on a failed HMAC (suite 3 — wrong key / corrupt),
    ///   a malformed KCP segment, a per-segment decrypt failure (wrong key / bad
    ///   PKCS#7 / GCM auth), or an RTP parse failure.
    /// - [`Error::Transport`] for the unimplemented ChaCha20 suite (2).
    pub fn push_datagram(&mut self, datagram: &[u8]) -> Result<Vec<MediaUnit>, Error> {
        // 1. Datagram integrity (suite 3 only): verify + strip the 32-byte HMAC.
        let key = self.media_key.clone();
        let body: &[u8] = if self.suite.has_datagram_hmac() {
            crypto::verify_and_strip_hmac(datagram, &key)?
        } else {
            datagram
        };

        // 2. Demux by conv. The control channel is not media.
        let conv = kcp::get_conv(body).ok_or_else(|| {
            Error::Transport("media datagram is shorter than the 4-byte conv".to_string())
        })?;
        if conv == kcp::CONTROL_CONV {
            return Ok(Vec::new());
        }

        // 3/4. Feed KCP with the per-segment decrypt hook for this suite.
        let rcv_wnd = self.rcv_wnd;
        let chan = self
            .channels
            .entry(conv)
            .or_insert_with(|| KcpReceiver::with_window(conv, rcv_wnd));
        match self.suite {
            CipherSuite::AesCbcHmac => chan.input(body, &CbcDecryptor(&key))?,
            CipherSuite::AesGcm => chan.input(body, &GcmDecryptor(&key))?,
            CipherSuite::Plaintext => chan.input(body, &PlaintextDecryptor)?,
            CipherSuite::ChaCha20 => {
                return Err(Error::Transport(
                    "suite 2 (ChaCha20) media decrypt is not implemented — its framing is \
                     unconfirmed [G]; supported: 0/1 (plaintext), 3 (AES-CBC+HMAC, cap3 default), \
                     4 (AES-GCM [G])"
                        .to_string(),
                ));
            }
        }

        // 5/6. Drain complete KCP messages → parse each as one RTP packet.
        let mut units = Vec::new();
        for msg in chan.drain_messages() {
            let pkt = rtp::parse_rtp(&msg)?;
            units.push(MediaUnit::from_rtp(&pkt));
        }
        Ok(units)
    }
}

/// Suite-3 per-segment decryptor (AES-128-CBC inline-IV + PKCS#7).
struct CbcDecryptor<'k>(&'k [u8]);
impl SegmentDecryptor for CbcDecryptor<'_> {
    fn decrypt(&self, seg_payload: &[u8]) -> Result<Vec<u8>, Error> {
        crypto::decrypt_segment_cbc(seg_payload, self.0)
    }
}

/// Suite-4 per-segment decryptor (AES-128-GCM inline-IV + trailing tag, [G]).
struct GcmDecryptor<'k>(&'k [u8]);
impl SegmentDecryptor for GcmDecryptor<'_> {
    fn decrypt(&self, seg_payload: &[u8]) -> Result<Vec<u8>, Error> {
        crypto::decrypt_segment_gcm(seg_payload, self.0)
    }
}

/// Suites 0/1 — the plaintext stub: the segment payload IS the plaintext.
struct PlaintextDecryptor;
impl SegmentDecryptor for PlaintextDecryptor {
    fn decrypt(&self, seg_payload: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(seg_payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::crypto::test_support::{append_hmac, cbc_seal_segment, gcm_seal_segment};
    use super::kcp::test_support::kcp_push;
    use super::rtp::test_support::build_rtp;
    use super::*;

    // SYNTHETIC 16-byte media key (the SDP a=aes-key) — never a real key.
    const KEY: &[u8; 16] = b"0123456789abcdef"; // secret-scan:allow (synthetic test key)
    const CONV: u32 = 0x0002_0001;

    fn iv(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    // ── CipherSuite mapping ────────────────────────────────────────────────

    #[test]
    fn security_level_maps_to_suite() {
        assert_eq!(
            CipherSuite::from_security_level(0).unwrap(),
            CipherSuite::Plaintext
        );
        assert_eq!(
            CipherSuite::from_security_level(3).unwrap(),
            CipherSuite::AesCbcHmac
        );
        assert_eq!(
            CipherSuite::from_security_level(4).unwrap(),
            CipherSuite::AesGcm
        );
        assert!(CipherSuite::AesCbcHmac.has_datagram_hmac());
        assert!(!CipherSuite::AesGcm.has_datagram_hmac());
        // NEGATIVE: an out-of-range level is rejected, not defaulted.
        assert!(CipherSuite::from_security_level(9).is_err());
    }

    #[test]
    fn aes_suite_rejects_wrong_key_length() {
        assert!(MediaEngine::new(CipherSuite::AesCbcHmac, b"short".to_vec()).is_err());
        assert!(MediaEngine::new(CipherSuite::AesGcm, vec![0u8; 15]).is_err());
        // Plaintext suite does not constrain the key.
        assert!(MediaEngine::new(CipherSuite::Plaintext, Vec::new()).is_ok());
    }

    // ── End-to-end: suite 3, single-segment RTP packet ─────────────────────
    // Builds a full §1 datagram (RTP → CBC-seal segment → KCP PUSH → +HMAC) and
    // runs it through the engine, validating §4 Steps A (HMAC) + C (PKCS#7) + D
    // (RTP V=2 + NAL-type-in-range) implicitly via a clean decode.

    #[test]
    fn suite3_single_segment_round_trips() {
        // An H.264 single-NAL (type 1) RTP payload, PT 96, marker set.
        let nal = [0x41u8, 0xDE, 0xAD, 0xBE, 0xEF];
        let rtp_bytes = build_rtp(96, true, 0x0042, 0x0001_0000, 0x1234_5678, &nal);

        let seg = cbc_seal_segment(&rtp_bytes, KEY, &iv(0xA0));
        let body = kcp_push(CONV, 0, 0, &seg);
        let datagram = append_hmac(&body, KEY);

        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        let units = engine.push_datagram(&datagram).unwrap();
        assert_eq!(units.len(), 1);
        let u = &units[0];
        assert_eq!(u.payload, nal);
        assert_eq!(u.payload_type, 96);
        assert!(u.marker);
        assert_eq!(u.sequence, 0x0042);
        assert_eq!(u.timestamp, 0x0001_0000);
        assert_eq!(u.ssrc, 0x1234_5678);
        // §4 Step D: the payload's first byte is an in-range NAL type.
        assert!(h264::is_supported_nal(u.payload[0]));
        assert_eq!(h264::nal_type(u.payload[0]), 1);
    }

    // ── End-to-end: suite 3, KCP-fragmented RTP packet (frg reassembly) ────
    // One RTP packet split across TWO KCP segments (frg 1 then 0); each segment
    // is INDEPENDENTLY IV+CBC+PKCS#7 sealed, and KCP concatenates the decrypted
    // plaintext chunks back into the whole RTP packet.

    #[test]
    fn suite3_fragmented_message_reassembles_and_decodes() {
        let payload: Vec<u8> = (0..200u32).map(|i| (i & 0xff) as u8).collect();
        let rtp_bytes = build_rtp(0, false, 7, 8000, 0xAABB_CCDD, &payload); // PCMU
        let mid = rtp_bytes.len() / 2;
        let (chunk0, chunk1) = rtp_bytes.split_at(mid);

        let seg0 = cbc_seal_segment(chunk0, KEY, &iv(0x01));
        let seg1 = cbc_seal_segment(chunk1, KEY, &iv(0x02));
        // frg counts down: first fragment frg=1, last frg=0.
        let mut body = kcp_push(CONV, 0, 1, &seg0);
        body.extend(kcp_push(CONV, 1, 0, &seg1));
        let datagram = append_hmac(&body, KEY);

        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        let units = engine.push_datagram(&datagram).unwrap();
        assert_eq!(units.len(), 1, "two KCP fragments → one RTP message");
        assert_eq!(units[0].payload, payload);
        assert_eq!(units[0].payload_type, 0); // PCMU
    }

    // ── End-to-end: suite 3 → STAP-A → H.264 depacketize (keyframe SPS/PPS) ─

    #[test]
    fn suite3_stap_a_depacketizes_to_annexb() {
        // STAP-A carrying SPS (type 7) + PPS (type 8).
        let mut stap = vec![0x78u8]; // STAP-A NAL header
        stap.extend_from_slice(&2u16.to_be_bytes());
        stap.extend_from_slice(&[0x67, 0x42]); // SPS
        stap.extend_from_slice(&3u16.to_be_bytes());
        stap.extend_from_slice(&[0x68, 0xCE, 0x3C]); // PPS
        let rtp_bytes = build_rtp(96, false, 1, 90_000, 1, &stap);

        let seg = cbc_seal_segment(&rtp_bytes, KEY, &iv(0x55));
        let datagram = append_hmac(&kcp_push(CONV, 0, 0, &seg), KEY);

        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        let units = engine.push_datagram(&datagram).unwrap();
        assert_eq!(units.len(), 1);

        let mut depay = h264::H264Depacketizer::new();
        let nals = depay.push(&units[0].payload).unwrap();
        assert_eq!(nals.len(), 2);
        assert_eq!(h264::nal_type(nals[0][4]), h264::NAL_SPS);
        assert_eq!(h264::nal_type(nals[1][4]), h264::NAL_PPS);
    }

    // ── End-to-end: suite 4 (AES-GCM, [G]) round-trips through the engine ───

    #[test]
    fn suite4_gcm_round_trips() {
        let nal = [0x41u8, 0x11, 0x22, 0x33];
        let rtp_bytes = build_rtp(96, true, 9, 90_000, 5, &nal);
        // Suite 4 has NO datagram HMAC — the segment carries the GCM tag inline.
        let seg = gcm_seal_segment(&rtp_bytes, KEY, &iv(0x07));
        let datagram = kcp_push(CONV, 0, 0, &seg);

        let mut engine = MediaEngine::from_security_level(4, KEY.to_vec()).unwrap();
        let units = engine.push_datagram(&datagram).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].payload, nal);
    }

    // ── End-to-end: suites 0/1 plaintext ───────────────────────────────────

    #[test]
    fn suite0_plaintext_round_trips() {
        let rtp_bytes = build_rtp(0, false, 1, 100, 1, b"plain pcmu frame");
        // Plaintext suite: the segment payload IS the RTP bytes, no IV, no HMAC.
        let datagram = kcp_push(CONV, 0, 0, &rtp_bytes);
        let mut engine = MediaEngine::from_security_level(0, Vec::new()).unwrap();
        let units = engine.push_datagram(&datagram).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].payload, b"plain pcmu frame");
    }

    // ── Control channel is routed away from media ──────────────────────────

    #[test]
    fn control_conv_yields_no_media() {
        // A suite-3 datagram on the control conv: even with a valid HMAC, the
        // engine returns no media (it is signaling, handled elsewhere).
        let seg = cbc_seal_segment(b"not media", KEY, &iv(0x09));
        let body = kcp_push(kcp::CONTROL_CONV, 0, 0, &seg);
        let datagram = append_hmac(&body, KEY);
        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        assert!(engine.push_datagram(&datagram).unwrap().is_empty());
    }

    // ── NEGATIVE: wrong media key fails the datagram HMAC (loud) ────────────

    #[test]
    fn suite3_wrong_key_fails_hmac() {
        let rtp_bytes = build_rtp(96, true, 1, 1, 1, &[0x41, 0x00]);
        let seg = cbc_seal_segment(&rtp_bytes, KEY, &iv(0x33));
        let datagram = append_hmac(&kcp_push(CONV, 0, 0, &seg), KEY);

        let mut engine = MediaEngine::from_security_level(3, b"fedcba9876543210".to_vec()).unwrap(); // secret-scan:allow
        assert!(matches!(
            engine.push_datagram(&datagram),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a tampered ciphertext (HMAC still valid for the tampered body)
    // trips the per-segment PKCS#7 check — proving the inner gate bites too.
    #[test]
    fn suite3_tampered_segment_fails_padding() {
        let rtp_bytes = build_rtp(96, true, 1, 1, 1, &[0x41, 0x00, 0x01, 0x02]);
        let seg = cbc_seal_segment(&rtp_bytes, KEY, &iv(0x44));
        let mut body = kcp_push(CONV, 0, 0, &seg);
        // Flip a ciphertext byte INSIDE the segment (after the 24B KCP header +
        // 16B IV), then re-HMAC so the datagram-level check passes and the fault
        // surfaces at the per-segment PKCS#7 gate.
        let flip = kcp::IKCP_OVERHEAD + crypto::IV_LEN + 1;
        body[flip] ^= 0x80;
        let datagram = append_hmac(&body, KEY);
        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        assert!(matches!(
            engine.push_datagram(&datagram),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: ChaCha20 (suite 2) is honestly unimplemented (loud error).
    #[test]
    fn suite2_chacha_is_unimplemented() {
        let mut engine = MediaEngine::new(CipherSuite::ChaCha20, KEY.to_vec()).unwrap();
        let err = engine.push_datagram(&[0u8; 48]).unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
        assert!(err.to_string().contains("ChaCha20"));
    }

    // Debug must not leak the media key or payload bytes.
    #[test]
    fn debug_redacts_key_and_payload() {
        let engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("0123456789abcdef")); // secret-scan:allow (synthetic test key)
        let u = MediaUnit {
            payload: vec![0xDE, 0xAD],
            payload_type: 96,
            marker: false,
            sequence: 1,
            timestamp: 1,
            ssrc: 1,
        };
        let udbg = format!("{u:?}");
        assert!(udbg.contains("payload_len"));
        assert!(!udbg.contains("DEAD") && !udbg.contains("dead"));
    }
}
