//! The cap3 **PATH A** media receive→decode engine: UDP datagram → (suite-3)
//! HMAC verify+strip → KCP RX with per-segment AES decrypt → `frg` reassembly →
//! imm-wrapper + fixed-12B RTP parse → [`MediaUnit`] (`re/media_decode_spec.md`,
//! full spec; framing cap4-pinned).
//!
//! ```text
//! UDP ─▶ HMAC-SHA1 verify+strip (whole datagram, suite3) ─▶ ikcp_input
//!      ─▶ ikcp_parse_data ─▶ [per segment] strip 16B IV ─▶ AES-128-CBC ─▶ PKCS#7 unpad
//!      ─▶ KCP frg reassembly (recv) ─▶ imm-wrapper + fixed-12B RTP parse
//!      ─▶ MediaUnit(payload,pt,marker,seq,ts)
//! ```
//!
//! The layered submodules each carry their own spec citations + unit tests:
//! - [`crypto`] — datagram HMAC-SHA1 + per-segment AES-CBC/GCM (suite 3 / 4).
//! - [`kcp`] — hand-rolled ikcp RX with the per-segment decrypt hook.
//! - [`frame`] — the PATH-A imm wrapper + fixed-12B RTP-like header parse.
//! - [`rtp`] — the stock RFC-3550 RTP header parse (PATH-B / CLI replay self-test).
//! - [`h264`] — RFC-6184 STAP-A/FU-A → Annex-B depacketize + access-unit assembly.
//! - [`audio`] — **downstream** camera audio (`conv = 2`): raw 16 kHz mono S16LE
//!   PCM (cap4-pinned). This is the "listen to the baby" track the muxer wants.
//! - [`g711`] — G.711 µ-law (PCMU, PT 0, 8 kHz) decode — the **talk-back**
//!   (app→camera) direction ONLY, NOT the downstream camera audio.
//! - [`stun`] — the STUN (RFC 5389) Binding codec: ICE connectivity-check
//!   encode/decode (MESSAGE-INTEGRITY HMAC-SHA1 + FINGERPRINT CRC-32) and
//!   Binding Success → XOR-MAPPED-ADDRESS (srflx). cap4-KAT'd.
//! - [`transport`] — ICE candidate parse/select, the host-direct UDP transport
//!   (cap4 primary path), srflx discovery, and the UDP datagram seam.
//!
//! # Honest status (cap4-validated end-to-end)
//!
//! - **cap4-validated** (this engine + every submodule): the whole
//!   decrypt→KCP→imm-wrapper→RTP pipeline is replayed against the **real cap4
//!   media capture** (`tests/cap4_replay.rs`, `#[ignore]`d / local-only) and
//!   produces byte-identical H.264 NAL units to the independently-pinned ground
//!   truth. Suite 3 (AES-128-CBC + **HMAC-SHA1**, 20-byte trailer) is the
//!   confirmed default (`security_level == 3`); suite 4 (AES-128-GCM) round-trips
//!   on synthetic vectors but its on-wire framing is **[G]** unconfirmed.
//! - **Live-gated** (NOT runnable here — no live broker/camera): ICE connectivity
//!   to srflx/relay (full STUN/TURN handshake, [`transport`] docs). The media
//!   decode itself is no longer synthetic-only — cap4 settled the framing that
//!   the spec had left as **[G]** (the imm wrapper + fixed-12B header, and the
//!   20-byte HMAC-SHA1 trailer that corrected the spec's 32-byte HMAC-SHA256).

pub mod audio;
pub mod control;
pub mod crypto;
pub mod frame;
pub mod g711;
pub mod h264;
pub mod kcp;
pub mod rtp;
pub mod stun;
pub mod transport;

use std::collections::HashMap;

use crate::stream::media::kcp::{KcpReceiver, KcpSender, SegmentDecryptor};
use crate::Error;

/// The first `sn` our conv=0 control **send** stream assigns. **Live-pinned to `0`**:
/// a fresh single-path session starts KCP at 0, and the camera confirmed it — with
/// `0` the camera's conv=0 ACK advanced `una` to 3 (it received our sn=0,1,2),
/// whereas with `3` (cap4's continuation value) the camera replied `una = 0` and
/// buffered our out-of-order PUSHes forever. (cap4's app starts at `sn = 3` because
/// its sn=0,1,2 were exchanged on an earlier path outside the capture window — see
/// `re/media_start_handshake.md`.) Named so the A/B is a one-line flip.
pub const MEDIA_START_SN: u32 = 0;

/// The `una` our conv=0 control PUSHes advertise (= our `rcv_nxt` for the camera's
/// conv=0 send stream at open). Coupled to [`MEDIA_START_SN`]: **live-pinned to `0`**
/// (fresh session — we have received none of the camera's conv=0 segments yet).
pub const MEDIA_START_UNA: u32 = 0;

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
    /// 20-byte datagram **HMAC-SHA1**. The cap3-observed default, cap4-validated
    /// end-to-end. **[C]**
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

    /// Whether this suite carries the trailing 20-byte datagram HMAC (suite 3).
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
    /// The KCP `conv` (channel) this unit was demultiplexed from — the
    /// AUTHORITATIVE video/audio selector. On the cap4 capture (and whenever the
    /// native `active_handle == 0`) `conv == channel id`: **`1` = video**,
    /// **`2` = downstream camera audio** (`tests/cap4_replay.rs`,
    /// `emulator_captures/cap4/stage6_extract.py`). The unified [`MediaEngine::pump`]
    /// loop routes on this so video → [`h264`] and audio → raw S16LE
    /// ([`audio`](super::audio)) without re-inspecting the payload.
    pub conv: u32,
    /// The RTP payload. For the **video** conv this is an H.264 RTP payload (feed
    /// to [`h264::H264Depacketizer`]). For the **downstream-audio** conv it is
    /// **raw 16 kHz mono S16LE PCM** — NOT G.711 (`re/media_decode_spec.md`;
    /// cap4 ground truth — see [`audio`](super::audio)). The G.711 µ-law path
    /// ([`g711`]) is the *talk-back* (app→camera) direction only.
    pub payload: Vec<u8>,
    /// RTP payload type (`PT`, 7-bit) from the fixed-12B header (cap4: `96` video,
    /// `99` downstream audio). Diagnostic — route on [`conv`](Self::conv).
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
    fn from_rtp(conv: u32, pkt: &rtp::RtpPacket<'_>) -> Self {
        Self {
            conv,
            payload: pkt.payload.to_vec(),
            payload_type: pkt.header.payload_type,
            marker: pkt.header.marker,
            sequence: pkt.header.sequence,
            timestamp: pkt.header.timestamp,
            ssrc: pkt.header.ssrc,
        }
    }

    /// Whether this unit is on the cap4 **video** conv (`1`).
    #[must_use]
    pub fn is_video(&self) -> bool {
        self.conv == kcp::VIDEO_CONV
    }

    /// Whether this unit is on the cap4 **downstream-audio** conv (`2`) — its
    /// [`payload`](Self::payload) is raw 16 kHz mono S16LE PCM.
    #[must_use]
    pub fn is_downstream_audio(&self) -> bool {
        self.conv == kcp::AUDIO_CONV
    }
}

impl std::fmt::Debug for MediaUnit {
    /// Prints metadata + payload LENGTH only — never the raw media bytes (the
    /// user's own A/V on the live path).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaUnit")
            .field("conv", &self.conv)
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
    /// The conv=0 control **send** stream (the client-initiated media-start, §S4 /
    /// `re/media_start_handshake.md`): assigns ascending `sn` from
    /// [`MEDIA_START_SN`], holds the sealed wire datagrams for retransmit, and
    /// prunes them when the camera's `una` advances.
    media_start_sender: KcpSender,
    /// Our `rcv_nxt` for the camera's conv=0 **send** stream — seeded to
    /// [`MEDIA_START_UNA`] (the `una` we advertise at open), advanced as we receive
    /// the camera's conv=0 PUSH segments. Out-of-order conv=0 PUSHes are held in
    /// [`conv0_rcv_buf`](Self::conv0_rcv_buf) until contiguous.
    conv0_rcv_nxt: u32,
    /// Out-of-order camera conv=0 PUSH `sn`s awaiting a contiguous predecessor.
    conv0_rcv_buf: Vec<u32>,
    /// The most recent camera conv=0 `una` observed in
    /// [`push_datagram`](Self::push_datagram), surfaced to the pump (which feeds it
    /// to [`on_peer_una_conv0`](Self::on_peer_una_conv0) to prune our sender).
    /// `None` once taken.
    conv0_peer_una: Option<u32>,
    /// The optional conv=0 media-start **AUTH** credentials (`(username, password)`)
    /// for the `SendAuthorizationInfo` PDU sent FIRST (KCP sn=0) by
    /// [`open_media_start`](Self::open_media_start) — set via
    /// [`set_media_auth`](Self::set_media_auth). `None` ⇒ no auth PDU is emitted
    /// (the legacy 3-PDU media-start). **SECRET** — the password is never logged
    /// (kept out of this engine's `Debug`).
    media_auth: Option<(String, String)>,
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
            media_start_sender: KcpSender::new(control::MEDIA_START_CONV, MEDIA_START_SN),
            conv0_rcv_nxt: MEDIA_START_UNA,
            conv0_rcv_buf: Vec::new(),
            conv0_peer_una: None,
            media_auth: None,
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

    /// Pull **one** datagram from a selected [`MediaTransport`](transport::MediaTransport)
    /// and decode it into zero or more [`MediaUnit`]s — the seam that wires the
    /// chosen UDP transport (host-direct via
    /// [`transport::connect_host_direct`], or a srflx/relay socket) into this
    /// engine (TASK-0037 / TASK-0075).
    ///
    /// Returns `Ok(None)` when the transport has no datagram ready (non-blocking);
    /// `Ok(Some(units))` (possibly empty, e.g. a control-conv datagram) otherwise.
    /// The caller owns the receive loop and the `buf` (size it to the path MTU).
    ///
    /// # Errors
    /// - [`Error::Transport`] on a transport receive failure.
    /// - any [`push_datagram`](Self::push_datagram) decode error (failed HMAC,
    ///   malformed KCP/segment) — surfaced to the caller, which (like
    ///   `cap4_replay`) may treat an HMAC failure as a foreign-session drop.
    pub fn pump<T: transport::MediaTransport>(
        &mut self,
        transport: &mut T,
        buf: &mut [u8],
    ) -> Result<Option<Vec<MediaUnit>>, Error> {
        match transport.recv_datagram(buf)? {
            Some(n) => Ok(Some(self.push_datagram(&buf[..n])?)),
            None => Ok(None),
        }
    }

    /// Process one received UDP datagram into zero or more decoded [`MediaUnit`]s.
    ///
    /// Runs the full §1 pipeline: (suite 3) HMAC verify+strip → `conv` demux →
    /// KCP input with the per-segment AES decrypt hook → `frg` reassembly →
    /// imm-wrapper + fixed-12B RTP parse. A datagram on the **control** `conv`
    /// (`0x010000f3`) is signaling, not media, and yields `[]` (handled by the
    /// MQTT signaling layer, not here).
    ///
    /// cap4 settled the caveat the spec had left **[G]**: a reassembled KCP
    /// message is **not** a bare RTP packet — it is an imm wrapper (28B, or 36B
    /// with a metadata block) + a *fixed* 12-byte RTP-like header + payload (see
    /// [`frame`]). A message that does not locate a media frame (a control/setup
    /// record, or a truncated frame) is skipped — it yields no [`MediaUnit`]
    /// rather than aborting the datagram — mirroring the native depacketizer,
    /// which only emits located RTP frames. (A genuine mis-decode cannot hide
    /// here: the upstream HMAC + PKCS#7 gates already rejected any wrong-key or
    /// corrupt datagram before this point.)
    ///
    /// # Errors
    /// - [`Error::Transport`] on a failed HMAC (suite 3 — wrong key / corrupt),
    ///   a malformed KCP segment, or a per-segment decrypt failure (wrong key /
    ///   bad PKCS#7 / GCM auth).
    /// - [`Error::Transport`] for the unimplemented ChaCha20 suite (2).
    pub fn push_datagram(&mut self, datagram: &[u8]) -> Result<Vec<MediaUnit>, Error> {
        // 1. Datagram integrity (suite 3 only): verify + strip the 20-byte HMAC-SHA1
        //    trailer (cap4-corrected; not the spec's original 32-byte HMAC-SHA256).
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
        // conv=0 is the imm media-start control channel (TASK-0083), a SUITE-3
        // concept (cap4). It carries no RTP media — yield no MediaUnit — but observe
        // the camera's ACK cursor + PUSH `sn` so the engine can prune our media-start
        // sender and advance our conv=0 `rcv_nxt`. Decryption of the control PDU
        // plaintext is NOT needed for the TX/ACK path, so we only peek the KCP
        // headers (the datagram-level HMAC already authenticated this body). Scoped
        // to suite 3 so RX behavior is unchanged for every other suite (e.g. a
        // non-suite-3 conv=0 datagram still reaches the suite dispatch below).
        if conv == control::MEDIA_START_CONV && self.suite == CipherSuite::AesCbcHmac {
            self.observe_conv0(body);
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

        // 5/6. Drain complete KCP messages → strip the imm wrapper + parse the
        // fixed-12B RTP-like header. Messages that do not locate a media frame
        // (control/setup records) are skipped, not errored (see the doc above).
        let mut units = Vec::new();
        for msg in chan.drain_messages() {
            if let Some(pkt) = frame::parse_media_frame(&msg) {
                units.push(MediaUnit::from_rtp(conv, &pkt));
            }
        }
        Ok(units)
    }

    /// Set the conv=0 media-start **AUTH** credentials (`SendAuthorizationInfo`).
    /// Once set, [`open_media_start`](Self::open_media_start) emits the 104-byte
    /// AUTH PDU FIRST (KCP sn=0), then the three cap4 continuation PDUs (sn=1,2,3).
    /// `username` is the hardcoded `"admin"`; `password` is the camera-info
    /// `password` (`rtc.config result.password`). **SECRET** — never logged.
    pub fn set_media_auth(&mut self, username: String, password: String) {
        self.media_auth = Some((username, password));
    }

    /// **TX (TASK-0083 / media-start AUTH): open the client-initiated media-start
    /// handshake.** When [`set_media_auth`](Self::set_media_auth) has been called,
    /// emit — IN ascending KCP `sn` order from the sender (which starts at
    /// [`MEDIA_START_SN`] `= 0`):
    ///
    /// 1. the 104-byte conv=0 **AUTH** PDU ([`control::build_auth_pdu`]) at **sn=0**
    ///    (`SendAuthorizationInfo`: magic `0x12345678`, `code`, `username="admin"`,
    ///    `password`), then
    /// 2. the three cap4 [`control::MEDIA_START_PDUS`] at **sn=1,2,3**.
    ///
    /// With no auth set, only the three continuation PDUs are emitted (sn=0,1,2) —
    /// the legacy behavior. So this returns **4** datagrams with auth, **3** without.
    /// Each is recorded for retransmit
    /// ([`media_start_retransmits`](Self::media_start_retransmits)) until the camera
    /// acks it.
    ///
    /// Each datagram is `append_datagram_hmac( encode_segment(conv=0, PUSH, frg=0,
    /// wnd=SND_WND, ts, sn, una, seal_segment_cbc(PDU, key, iv)) )`, where `sn`
    /// ascends from [`MEDIA_START_SN`] and `una` is our conv=0 `rcv_nxt`
    /// ([`MEDIA_START_UNA`] at open). On-wire size: the three 28-byte PDUs are
    /// `24` (KCP header) `+ 48` (16B IV + 32B CBC of the 28B PDU) `+ 20` (HMAC) =
    /// **92** bytes each; the AUTH datagram is `24 + (16B IV + 112B CBC of the
    /// PKCS#7-padded 104B PDU) + 20` = **172** bytes.
    ///
    /// `ivs` are the four per-segment inline IVs (caller-supplied so the bytes are
    /// reproducible in tests; production passes fresh OS entropy). Only the first
    /// `N` are consumed (`N` = number of datagrams emitted: 4 with auth, 3 without).
    /// `ts` is the KCP millisecond timestamp (caller-owned clock — keeps this
    /// offline-testable).
    ///
    /// # Errors
    /// - [`Error::Transport`] if this engine is not suite 3 ([`CipherSuite::AesCbcHmac`]):
    ///   the media-start handshake is only cap4-proven for suite 3 (AES-128-CBC +
    ///   20B HMAC-SHA1); we refuse to fabricate it for another suite.
    /// - Propagated [`crypto::seal_segment_cbc`] / [`crypto::append_datagram_hmac`]
    ///   errors (e.g. a wrong-length key — already rejected at construction).
    pub fn open_media_start(
        &mut self,
        ivs: &[[u8; crypto::IV_LEN]; 4],
        ts: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.suite != CipherSuite::AesCbcHmac {
            return Err(Error::Transport(format!(
                "media-start handshake is only implemented for suite 3 (AES-128-CBC + HMAC-SHA1, \
                 the cap4-proven default); this engine is {:?}. A non-suite-3 control framing is \
                 unconfirmed [G] and not fabricated.",
                self.suite
            )));
        }
        let key = self.media_key.clone();
        let una = self.conv0_rcv_nxt;
        let mut out = Vec::with_capacity(ivs.len());
        let mut next_iv = 0usize;

        // FIRST (sn=0, if set): the 104-byte AUTH PDU (`SendAuthorizationInfo`).
        if let Some((username, password)) = self.media_auth.clone() {
            let pdu = control::build_auth_pdu(control::MEDIA_START_AUTH_CODE, &username, &password);
            let wire = self.frame_conv0_push(&pdu, &ivs[next_iv], ts, una, &key)?;
            next_iv += 1;
            out.push(wire);
        }

        // THEN (sn continues): the three cap4 continuation PDUs.
        for pdu in &control::MEDIA_START_PDUS {
            let wire = self.frame_conv0_push(pdu, &ivs[next_iv], ts, una, &key)?;
            next_iv += 1;
            out.push(wire);
        }
        Ok(out)
    }

    /// Seal one conv=0 control `pdu` (suite 3: PKCS#7 + AES-128-CBC inline-IV),
    /// frame it as a conv=0 KCP PUSH (`frg=0`, next `sn` from the sender, the given
    /// `una`/`ts`), append the 20-byte datagram HMAC, record it for retransmit, and
    /// return the on-wire datagram. The shared inner step of
    /// [`open_media_start`](Self::open_media_start) (auth PDU + continuation PDUs).
    fn frame_conv0_push(
        &mut self,
        pdu: &[u8],
        iv: &[u8; crypto::IV_LEN],
        ts: u32,
        una: u32,
        key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let seg_payload = crypto::seal_segment_cbc(pdu, key, iv)?;
        let sn = self.media_start_sender.take_sn();
        let seg = kcp::encode_segment(
            control::MEDIA_START_CONV,
            kcp::IKCP_CMD_PUSH,
            0, // frg: each control PDU is one un-fragmented message
            kcp::SND_WND,
            ts,
            sn,
            una,
            &seg_payload,
        );
        let wire = crypto::append_datagram_hmac(&seg, key)?;
        self.media_start_sender.record_unacked(sn, wire.clone());
        Ok(wire)
    }

    /// **TX: prune the media-start sender** for everything the camera has cumulatively
    /// acknowledged (`sn < una`) — the camera's conv=0 `una` advancing past our
    /// `sn = 3,4,5` (cap4 frame 256: `una = 6`) means the handshake landed.
    pub fn on_peer_una_conv0(&mut self, una: u32) {
        self.media_start_sender.ack_through(una);
    }

    /// **TX: the still-unacknowledged media-start datagrams** to retransmit (a clone
    /// of the sender's unacked wire bytes; the originals stay recorded so a later
    /// `una` still prunes them). Empty once the camera acks all three.
    #[must_use]
    pub fn media_start_retransmits(&self) -> Vec<Vec<u8>> {
        self.media_start_sender
            .unacked()
            .map(<[u8]>::to_vec)
            .collect()
    }

    /// Whether every media-start PUSH has been acknowledged by the camera.
    #[must_use]
    pub fn media_start_acked(&self) -> bool {
        self.media_start_sender.is_drained()
    }

    /// **TX: drain pending KCP ACKs for the camera's received media segments** and
    /// frame them as wire ACK datagrams (`cmd=0x52`, `sn`=acked, `ts` echoed,
    /// `una`=our `rcv_nxt`, `len=0`, + 20B HMAC-SHA1). The camera's KCP send window
    /// only advances on these — without ACKs it streams its initial window then
    /// stalls (cap4: the app sends ~785 packets back, mostly ACKs). The pump sends
    /// these after every received datagram. Suite-3 only (the cap4-proven framing).
    ///
    /// # Errors
    /// [`Error::Transport`] if the HMAC framing fails.
    pub fn drain_media_acks(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.suite != CipherSuite::AesCbcHmac {
            return Ok(Vec::new());
        }
        let key = self.media_key.clone();
        let mut out = Vec::new();
        for (&conv, chan) in &mut self.channels {
            let una = chan.rcv_nxt();
            for (sn, ts) in chan.drain_acks() {
                let seg =
                    kcp::encode_segment(conv, kcp::IKCP_CMD_ACK, 0, kcp::SND_WND, ts, sn, una, &[]);
                out.push(crypto::append_datagram_hmac(&seg, &key)?);
            }
        }
        Ok(out)
    }

    /// Take + clear the most recent camera conv=0 `una` observed in
    /// [`push_datagram`](Self::push_datagram). The pump calls this after each
    /// datagram and, on `Some`, feeds it to
    /// [`on_peer_una_conv0`](Self::on_peer_una_conv0) to prune the sender. Pure RX
    /// surfacing — it does not itself mutate the TX sender.
    pub fn take_conv0_peer_una(&mut self) -> Option<u32> {
        self.conv0_peer_una.take()
    }

    /// Our current conv=0 `rcv_nxt` (the `una` we advertise on media-start PUSHes) —
    /// exposed for tests / diagnostics.
    #[must_use]
    pub fn conv0_rcv_nxt(&self) -> u32 {
        self.conv0_rcv_nxt
    }

    /// Observe a camera conv=0 datagram body (KCP header(s), HMAC already stripped):
    /// record its max `una` (surfaced via [`take_conv0_peer_una`](Self::take_conv0_peer_una))
    /// and advance our conv=0 `rcv_nxt` over its contiguous PUSH `sn`s. Header-only
    /// peek — the control PDU plaintext is not needed here. Tolerant of a malformed
    /// trailing header (stops scanning) since the body is already HMAC-authenticated.
    fn observe_conv0(&mut self, body: &[u8]) {
        let mut max_una: Option<u32> = None;
        let mut rest = body;
        while rest.len() >= kcp::IKCP_OVERHEAD {
            let cmd = rest[4];
            let sn = u32::from_le_bytes([rest[12], rest[13], rest[14], rest[15]]);
            let una = u32::from_le_bytes([rest[16], rest[17], rest[18], rest[19]]);
            let len = u32::from_le_bytes([rest[20], rest[21], rest[22], rest[23]]) as usize;
            max_una = Some(max_una.map_or(una, |m| m.max(una)));
            if cmd == kcp::IKCP_CMD_PUSH {
                self.advance_conv0_rcv(sn);
            }
            let next = kcp::IKCP_OVERHEAD + len;
            if rest.len() < next {
                break; // malformed trailing header (post-HMAC: shouldn't happen)
            }
            rest = &rest[next..];
        }
        if let Some(u) = max_una {
            // `una` is cumulative (monotonic); keep the max across not-yet-taken
            // datagrams so an older retransmit cannot regress the surfaced value.
            self.conv0_peer_una = Some(self.conv0_peer_una.map_or(u, |p| p.max(u)));
        }
    }

    /// Advance our conv=0 `rcv_nxt` over a received camera PUSH `sn`, buffering any
    /// out-of-order `sn` until its predecessors arrive (mirrors KCP `rcv_nxt`).
    fn advance_conv0_rcv(&mut self, sn: u32) {
        // Drop stale / out-of-window sn (the wrapping fold matches KcpReceiver).
        if sn.wrapping_sub(self.conv0_rcv_nxt) >= kcp::DEFAULT_RCV_WND {
            return;
        }
        if sn == self.conv0_rcv_nxt {
            self.conv0_rcv_nxt = self.conv0_rcv_nxt.wrapping_add(1);
            // Drain any now-contiguous buffered sn.
            while let Some(pos) = self
                .conv0_rcv_buf
                .iter()
                .position(|&s| s == self.conv0_rcv_nxt)
            {
                self.conv0_rcv_buf.swap_remove(pos);
                self.conv0_rcv_nxt = self.conv0_rcv_nxt.wrapping_add(1);
            }
        } else if !self.conv0_rcv_buf.contains(&sn) {
            self.conv0_rcv_buf.push(sn);
        }
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
    use super::frame::test_support::wrap_imm;
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

    // ── End-to-end: suite 3, single-segment media frame ────────────────────
    // Builds a full §1 datagram (imm-wrapped fixed-12B RTP → CBC-seal segment →
    // KCP PUSH → +HMAC-SHA1) and runs it through the engine, validating §4 Steps
    // A (HMAC) + C (PKCS#7) + D (frame located + NAL-type-in-range) via a clean
    // decode.

    #[test]
    fn suite3_single_segment_round_trips() {
        // An H.264 single-NAL (type 1) RTP payload, PT 96, marker set, wrapped in
        // the PATH-A imm wrapper (byte0 0x03 = video) — the cap4-pinned framing.
        let nal = [0x41u8, 0xDE, 0xAD, 0xBE, 0xEF];
        let rtp_bytes = build_rtp(96, true, 0x0042, 0x0001_0000, 0x1234_5678, &nal);
        let msg = wrap_imm(0x03, &rtp_bytes, None);

        let seg = cbc_seal_segment(&msg, KEY, &iv(0xA0));
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
                                                                             // The imm wrapper is on the WHOLE message; split the wrapped frame across
                                                                             // two KCP fragments so reassembly must restore it before the frame parse.
        let msg = wrap_imm(0x03, &rtp_bytes, None);
        let mid = msg.len() / 2;
        let (chunk0, chunk1) = msg.split_at(mid);

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
        let msg = wrap_imm(0x03, &rtp_bytes, None);

        let seg = cbc_seal_segment(&msg, KEY, &iv(0x55));
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
        let msg = wrap_imm(0x03, &rtp_bytes, None);
        // Suite 4 has NO datagram HMAC — the segment carries the GCM tag inline.
        let seg = gcm_seal_segment(&msg, KEY, &iv(0x07));
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
        let msg = wrap_imm(0x03, &rtp_bytes, None);
        // Plaintext suite: the segment payload IS the (imm-wrapped) bytes, no IV,
        // no HMAC.
        let datagram = kcp_push(CONV, 0, 0, &msg);
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

    // ── pump(): the selected transport feeds the engine (TASK-0037 seam) ────
    // A fake MediaTransport yields one prepared suite-3 datagram, then nothing;
    // pump must decode the first into a MediaUnit and report None when drained.
    #[test]
    fn pump_decodes_from_a_selected_transport() {
        use super::transport::MediaTransport;

        struct OneShot(Option<Vec<u8>>);
        impl MediaTransport for OneShot {
            fn recv_datagram(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
                match self.0.take() {
                    Some(dg) => {
                        buf[..dg.len()].copy_from_slice(&dg);
                        Ok(Some(dg.len()))
                    }
                    None => Ok(None),
                }
            }
        }

        let nal = [0x41u8, 0xDE, 0xAD];
        let rtp_bytes = build_rtp(96, true, 7, 9000, 0xABCD_1234, &nal);
        let msg = wrap_imm(0x03, &rtp_bytes, None);
        let seg = cbc_seal_segment(&msg, KEY, &iv(0x5A));
        let datagram = append_hmac(&kcp_push(CONV, 0, 0, &seg), KEY);

        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        let mut transport = OneShot(Some(datagram));
        let mut buf = [0u8; 2048];

        let units = engine.pump(&mut transport, &mut buf).unwrap().unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].payload, nal);
        // Transport drained → pump yields None (non-blocking).
        assert!(engine.pump(&mut transport, &mut buf).unwrap().is_none());
    }

    // The engine tags each decoded unit with its source conv so the unified pump
    // can route video (conv 1) → H.264 and audio (conv 2) → raw S16LE, exactly as
    // the cap4 ground-truth extractor does (route by conv, not by re-sniffing).
    #[test]
    fn engine_tags_units_with_conv_for_av_routing() {
        let key = KEY.to_vec();
        let mut engine = MediaEngine::from_security_level(3, key).unwrap();

        // Video conv (1): an H.264 single-NAL payload.
        let vid = build_rtp(96, true, 1, 90_000, 1, &[0x41u8, 0xDE, 0xAD]);
        let vid_dg = append_hmac(
            &kcp_push(
                kcp::VIDEO_CONV,
                0,
                0,
                &cbc_seal_segment(&wrap_imm(0x03, &vid, None), KEY, &iv(0x11)),
            ),
            KEY,
        );
        // Audio conv (2): a raw S16LE payload (PT 99) — NOT G.711.
        let pcm = [0x00u8, 0x80, 0x34, 0x12];
        let aud = build_rtp(99, false, 2, 1000, 1, &pcm);
        let aud_dg = append_hmac(
            &kcp_push(
                kcp::AUDIO_CONV,
                0,
                0,
                &cbc_seal_segment(&wrap_imm(0x05, &aud, None), KEY, &iv(0x22)),
            ),
            KEY,
        );

        let v = &engine.push_datagram(&vid_dg).unwrap()[0];
        assert!(v.is_video() && !v.is_downstream_audio());
        assert_eq!(v.conv, kcp::VIDEO_CONV);

        let a = &engine.push_datagram(&aud_dg).unwrap()[0];
        assert!(a.is_downstream_audio() && !a.is_video());
        // The downstream-audio payload is the raw S16LE samples, untouched.
        assert_eq!(audio::downstream_pcm_s16le(&a.payload), &pcm);
    }

    // Debug must not leak the media key or payload bytes.
    #[test]
    fn debug_redacts_key_and_payload() {
        let engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("0123456789abcdef")); // secret-scan:allow (synthetic test key)
        let u = MediaUnit {
            conv: kcp::VIDEO_CONV,
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

    // ── TASK-0083 §S6d: client-initiated media-start TX (conv=0), NO auth ───
    // With no auth set, open_media_start frames ONLY the three cap4 PDUs as conv=0
    // KCP PUSH datagrams (sn=0,1,2). Each is 24(hdr)+48(IV16+CBC32 of the 28B PDU)+
    // 20(HMAC) = 92 bytes, conv=0, cmd=PUSH, una=0, wnd=512, len=48. We parse the
    // HEADERS only (a SYNTHETIC key keeps the bytes reproducible).
    #[test]
    fn open_media_start_frames_three_conv0_push_datagrams() {
        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        assert_eq!(
            engine.conv0_rcv_nxt(),
            MEDIA_START_UNA,
            "rcv_nxt seeded to the open una"
        );
        // Four IVs are supplied even though only three are consumed (no auth set).
        let ivs = [[0xA0u8; 16], [0xA1u8; 16], [0xA2u8; 16], [0xA3u8; 16]];
        let dgs = engine.open_media_start(&ivs, 0x1111_2222).unwrap();
        assert_eq!(dgs.len(), 3, "no auth ⇒ the legacy 3 continuation PDUs");
        for (i, dg) in dgs.iter().enumerate() {
            assert_eq!(dg.len(), 92, "datagram {i}: 24 hdr + 48 payload + 20 HMAC");
            let conv = u32::from_le_bytes([dg[0], dg[1], dg[2], dg[3]]);
            assert_eq!(conv, control::MEDIA_START_CONV, "conv=0");
            assert_eq!(dg[4], kcp::IKCP_CMD_PUSH, "cmd=PUSH");
            assert_eq!(dg[5], 0, "frg=0");
            assert_eq!(u16::from_le_bytes([dg[6], dg[7]]), kcp::SND_WND, "wnd=512");
            let sn = u32::from_le_bytes([dg[12], dg[13], dg[14], dg[15]]);
            assert_eq!(sn, MEDIA_START_SN + i as u32, "sn ascends 0,1,2");
            let una = u32::from_le_bytes([dg[16], dg[17], dg[18], dg[19]]);
            assert_eq!(una, MEDIA_START_UNA, "una=0 (fresh session)");
            let len = u32::from_le_bytes([dg[20], dg[21], dg[22], dg[23]]) as usize;
            assert_eq!(len, crypto::IV_LEN + 32, "payload len = 16B IV + 32B CBC");
            // The datagram is a well-formed suite-3 datagram: its HMAC validates and
            // the inner segment decrypts back to the exact PDU under the same key.
            let body = crypto::verify_and_strip_hmac(dg, KEY).unwrap();
            let seg_payload = &body[kcp::IKCP_OVERHEAD..kcp::IKCP_OVERHEAD + len];
            let pdu = crypto::decrypt_segment_cbc(seg_payload, KEY).unwrap();
            assert_eq!(
                pdu,
                control::MEDIA_START_PDUS[i],
                "decrypts to the cap4 PDU"
            );
        }
        // All three are held for retransmit until the camera acks them.
        assert_eq!(engine.media_start_retransmits().len(), 3);
        assert!(!engine.media_start_acked());
        // The camera's cumulative una=3 drains the sender (acks sn 0,1,2).
        engine.on_peer_una_conv0(3);
        assert!(engine.media_start_acked());
        assert!(engine.media_start_retransmits().is_empty());
    }

    // ── media-start AUTH: the 104-byte SendAuthorizationInfo PDU at sn=0 ────
    // With auth set, open_media_start emits FOUR conv=0 PUSH datagrams in sn order:
    // sn=0 is the 104-byte AUTH PDU (magic/code/username/password), sn=1,2,3 are the
    // three cap4 continuation PDUs. The AUTH datagram is 24+(16+112)+20 = 172 bytes.
    #[test]
    fn open_media_start_with_auth_frames_auth_then_three_pdus() {
        // SYNTHETIC username/password (CLAUDE.md).
        let pwd = "SynthAuthPwd"; // secret-scan:allow (synthetic test password)
        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        engine.set_media_auth(
            control::MEDIA_START_AUTH_USERNAME.to_string(),
            pwd.to_string(),
        );

        let ivs = [[0xB0u8; 16], [0xB1u8; 16], [0xB2u8; 16], [0xB3u8; 16]];
        let dgs = engine.open_media_start(&ivs, 0x3333_4444).unwrap();
        assert_eq!(
            dgs.len(),
            4,
            "auth PDU (sn=0) + 3 continuation PDUs (sn=1,2,3)"
        );

        // Every datagram is a well-formed conv=0 suite-3 PUSH with ascending sn.
        for (i, dg) in dgs.iter().enumerate() {
            let conv = u32::from_le_bytes([dg[0], dg[1], dg[2], dg[3]]);
            assert_eq!(conv, control::MEDIA_START_CONV, "conv=0");
            assert_eq!(dg[4], kcp::IKCP_CMD_PUSH, "cmd=PUSH");
            assert_eq!(dg[5], 0, "frg=0");
            let sn = u32::from_le_bytes([dg[12], dg[13], dg[14], dg[15]]);
            assert_eq!(sn, MEDIA_START_SN + i as u32, "sn ascends 0,1,2,3");
        }

        // sn=0: the AUTH PDU. 104B → PKCS#7 pad to 112 → IV(16)+112 = 128 payload →
        // 24+128+20 = 172 on-wire bytes.
        let auth = &dgs[0];
        assert_eq!(
            auth.len(),
            172,
            "AUTH datagram = 24 hdr + 128 payload + 20 HMAC"
        );
        let auth_len = u32::from_le_bytes([auth[20], auth[21], auth[22], auth[23]]) as usize;
        assert_eq!(
            auth_len,
            crypto::IV_LEN + 112,
            "AUTH payload = 16B IV + 112B CBC"
        );
        let auth_body = crypto::verify_and_strip_hmac(auth, KEY).unwrap();
        let auth_seg = &auth_body[kcp::IKCP_OVERHEAD..kcp::IKCP_OVERHEAD + auth_len];
        let auth_pdu = crypto::decrypt_segment_cbc(auth_seg, KEY).unwrap();
        assert_eq!(
            auth_pdu,
            control::build_auth_pdu(
                control::MEDIA_START_AUTH_CODE,
                control::MEDIA_START_AUTH_USERNAME,
                pwd
            )
            .to_vec(),
            "sn=0 decrypts to the 104-byte SendAuthorizationInfo PDU"
        );
        // Spot-check the AUTH fields at their offsets after decrypt.
        assert_eq!(
            u32::from_le_bytes([auth_pdu[0], auth_pdu[1], auth_pdu[2], auth_pdu[3]]),
            control::MEDIA_START_AUTH_MAGIC
        );
        assert_eq!(&auth_pdu[8..8 + 5], b"admin");
        assert_eq!(&auth_pdu[0x28..0x28 + pwd.len()], pwd.as_bytes());

        // sn=1,2,3: the three cap4 continuation PDUs, decrypted in order.
        for (j, dg) in dgs[1..].iter().enumerate() {
            assert_eq!(dg.len(), 92, "continuation datagram {j}: 24 + 48 + 20");
            let len = u32::from_le_bytes([dg[20], dg[21], dg[22], dg[23]]) as usize;
            let body = crypto::verify_and_strip_hmac(dg, KEY).unwrap();
            let seg_payload = &body[kcp::IKCP_OVERHEAD..kcp::IKCP_OVERHEAD + len];
            let pdu = crypto::decrypt_segment_cbc(seg_payload, KEY).unwrap();
            assert_eq!(
                pdu,
                control::MEDIA_START_PDUS[j],
                "decrypts to the cap4 PDU"
            );
        }

        // All four are held for retransmit; the camera's cumulative una=4 drains them.
        assert_eq!(engine.media_start_retransmits().len(), 4);
        assert!(!engine.media_start_acked());
        engine.on_peer_una_conv0(4);
        assert!(engine.media_start_acked());
        assert!(engine.media_start_retransmits().is_empty());
    }

    // A non-suite-3 engine refuses the media-start (no fabricated framing).
    #[test]
    fn open_media_start_rejects_non_suite3() {
        let mut engine = MediaEngine::from_security_level(4, KEY.to_vec()).unwrap();
        let ivs = [[0u8; 16]; 4];
        assert!(matches!(
            engine.open_media_start(&ivs, 0),
            Err(Error::Transport(_))
        ));
    }

    // push_datagram surfaces the camera's conv=0 una (to prune our sender) and
    // advances our conv=0 rcv_nxt over the camera's PUSH sn — while yielding NO
    // media units (unchanged RX behavior for the control channel).
    #[test]
    fn push_datagram_observes_camera_conv0_acks() {
        let mut engine = MediaEngine::from_security_level(3, KEY.to_vec()).unwrap();
        // We have media-start PUSHes outstanding (no auth ⇒ 3 PUSHes, sn 0,1,2).
        engine
            .open_media_start(&[[1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16]], 0)
            .unwrap();
        assert!(!engine.media_start_acked());

        // Synthetic camera conv=0 PUSH at the sn we next expect (= our rcv_nxt
        // start = MEDIA_START_UNA), una acks our 3 PUSHes (= MEDIA_START_SN + 3).
        // observe_conv0 reads HEADERS only, so the payload is opaque (not decrypted)
        // — it just has to pass the datagram HMAC.
        let cam_sn = MEDIA_START_UNA;
        let cam_una = MEDIA_START_SN + 3;
        let body = kcp::encode_segment(
            control::MEDIA_START_CONV,
            kcp::IKCP_CMD_PUSH,
            0,
            kcp::SND_WND,
            0,
            cam_sn,
            cam_una,
            b"opaque conv0 control payload (header-only peek on the TX/ACK path)",
        );
        let dg = append_hmac(&body, KEY);

        let units = engine.push_datagram(&dg).unwrap();
        assert!(units.is_empty(), "conv=0 control yields no media units");
        assert_eq!(
            engine.conv0_rcv_nxt(),
            MEDIA_START_UNA + 1,
            "advanced over the camera's next conv=0 sn"
        );
        assert_eq!(
            engine.take_conv0_peer_una(),
            Some(cam_una),
            "camera una surfaced"
        );
        assert_eq!(engine.take_conv0_peer_una(), None, "taken exactly once");

        // Feeding that una to the sender prunes our outstanding media-start PUSHes.
        engine.on_peer_una_conv0(cam_una);
        assert!(engine.media_start_acked());
    }
}
