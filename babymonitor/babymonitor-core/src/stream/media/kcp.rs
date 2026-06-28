//! Hand-rolled receive side of skywind3000 **ikcp** with a per-segment decrypt
//! hook — the ~200-line ikcp RX the spec calls for (`re/media_decode_spec.md` §3,
//! §5).
//!
//! # Why hand-rolled (not the `kcp` crate)
//! Stock `kcp` exposes only `input()/recv()` and has **no per-segment
//! process-packet hook**. You cannot decrypt after `recv()` because each segment
//! carries its own inline IV + PKCS#7 and KCP concatenates segment **plaintexts**,
//! not ciphertexts (`re/media_decode_spec.md` §5). So decryption MUST happen per
//! segment, mirroring the native `ikcp_setprocesspkt(kcp,
//! ctx_session_chan_process_pkt)` hook invoked from `ikcp_parse_data`
//! (`funcs/00168f78_FUN_00168f78.c:83-87`, `funcs/0014cec4_ikcp_parse_data.c`).
//! The `kcp` crate is also absent from the offline cargo cache, so vendoring it
//! would break the `just assert-offline` gate; a focused RX is the right call.
//!
//! This is **receive-only**: ACK/WASK/WINS segments update no send state (a pure
//! decoder of captured/inbound datagrams does not retransmit), and the receive
//! window is an acceptance window, not a flow-control loop. The send/ARQ side is
//! the live transport's job and is out of scope here. Everything needed to turn a
//! coalesced UDP datagram into ordered, reassembled application messages — header
//! parse, `conv` demux, sequence window, duplicate drop, and `frg` reassembly —
//! is implemented and unit-tested.

use crate::Error;

/// KCP fixed segment header length (`ikcp_setmtu` overhead; §3 table).
pub const IKCP_OVERHEAD: usize = 24;

/// `cmd` = data-bearing PUSH segment (`0x51`).
pub const IKCP_CMD_PUSH: u8 = 0x51;
/// `cmd` = ACK (`0x52`).
pub const IKCP_CMD_ACK: u8 = 0x52;
/// `cmd` = window-probe ask (`0x53`).
pub const IKCP_CMD_WASK: u8 = 0x53;
/// `cmd` = window-size tell (`0x54`).
pub const IKCP_CMD_WINS: u8 = 0x54;

/// The control/signaling channel `conv` (`0x010000f3`) — drained with a record
/// framing, NOT media RTP (`re/media_decode_spec.md` §3). Surfaced so the engine
/// can route it away from the media RTP parse.
pub const CONTROL_CONV: u32 = 0x0100_00f3;

/// The **video** media `conv` (`1`). On cap4 (and whenever native
/// `active_handle == 0`) `conv == channel id`; channel `1` carries H.264
/// (`tests/cap4_replay.rs`, `emulator_captures/cap4/stage6_extract.py`).
pub const VIDEO_CONV: u32 = 0x0000_0001;

/// The **downstream camera audio** media `conv` (`2`). Channel `2` carries raw
/// 16 kHz mono S16LE PCM — NOT G.711 (cap4 ground truth; see
/// [`super::audio`]). The G.711 µ-law channel ([`super::g711`]) is the *talk-back*
/// (app→camera) direction only.
pub const AUDIO_CONV: u32 = 0x0000_0002;

/// Default receive **acceptance** window (segments). The native side derives the
/// window from a byte budget (`rcvbytes/0x640`); a pure decoder is not
/// flow-controlled, so we use a generous fixed window and document that segments
/// with `sn` outside `[rcv_nxt, rcv_nxt + window)` are dropped (as native does).
pub const DEFAULT_RCV_WND: u32 = 1024;

/// The per-segment decrypt hook (the native `ctx_session_chan_process_pkt`):
/// given a KCP PUSH segment payload (`[IV 16B | ciphertext]`), return the
/// decrypted plaintext that KCP reassembles. A plaintext suite returns the
/// payload unchanged.
pub trait SegmentDecryptor {
    /// Decrypt one segment payload into its plaintext.
    ///
    /// # Errors
    /// Implementation-defined (typically [`Error::Transport`]) on a wrong key /
    /// corrupt segment. The error propagates out of [`KcpReceiver::input`] so a
    /// bad key fails loud rather than yielding garbage.
    fn decrypt(&self, seg_payload: &[u8]) -> Result<Vec<u8>, Error>;
}

/// One received KCP segment, holding its **decrypted** plaintext (post-hook).
#[derive(Debug, Clone)]
struct KcpSegment {
    sn: u32,
    frg: u8,
    /// The decrypted plaintext (what reassembly concatenates).
    data: Vec<u8>,
}

/// Receive-only ikcp channel for one `conv`: header parse, window/dup handling,
/// and `frg` reassembly into application messages.
#[derive(Debug)]
pub struct KcpReceiver {
    conv: u32,
    rcv_nxt: u32,
    rcv_wnd: u32,
    /// Out-of-order holding buffer, kept sorted ascending by `sn`.
    rcv_buf: Vec<KcpSegment>,
    /// In-order, ready-to-deliver segments (a contiguous prefix from `rcv_nxt`).
    rcv_queue: Vec<KcpSegment>,
    /// Pending `(sn, ts)` to ACK back to the sender: every in-window PUSH (incl.
    /// duplicates, so a lost ACK is re-sent). The peer's KCP send window only
    /// advances on these — without ACKs the camera streams its initial window then
    /// stalls. Drained by [`drain_acks`](KcpReceiver::drain_acks).
    acklist: Vec<(u32, u32)>,
}

impl KcpReceiver {
    /// A new receiver for `conv` with the [`DEFAULT_RCV_WND`] acceptance window.
    #[must_use]
    pub fn new(conv: u32) -> Self {
        Self::with_window(conv, DEFAULT_RCV_WND)
    }

    /// A new receiver with an explicit acceptance window (segments).
    #[must_use]
    pub fn with_window(conv: u32, rcv_wnd: u32) -> Self {
        Self {
            conv,
            rcv_nxt: 0,
            rcv_wnd: rcv_wnd.max(1),
            rcv_buf: Vec::new(),
            rcv_queue: Vec::new(),
            acklist: Vec::new(),
        }
    }

    /// The next sequence number expected (the cumulative `una` to advertise back).
    #[must_use]
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt
    }

    /// Take the pending `(sn, ts)` ACKs to send back (and clear them). The caller
    /// frames each as a KCP ACK segment (`cmd=0x52`, `una = rcv_nxt`).
    pub fn drain_acks(&mut self) -> Vec<(u32, u32)> {
        std::mem::take(&mut self.acklist)
    }

    /// The `conv` (channel id) this receiver demuxes.
    #[must_use]
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Feed one UDP datagram body (KCP header(s) + segment payloads, **after** any
    /// datagram HMAC tag has been stripped). Decrypts each new PUSH segment via
    /// `decryptor` and advances reassembly. Coalesced segments are all consumed.
    ///
    /// Mirrors `ikcp_input` (`funcs/0014d338_ikcp_input.c:58-73`): walk segments
    /// while at least one header remains; validate `conv`, `cmd`, and `len`.
    ///
    /// # Errors
    /// - [`Error::Transport`] if a segment header is malformed (short, wrong
    ///   `conv`, unknown `cmd`, or `len` overruns the datagram).
    /// - Propagated decrypt errors (wrong media key / corrupt segment).
    pub fn input(
        &mut self,
        datagram: &[u8],
        decryptor: &dyn SegmentDecryptor,
    ) -> Result<(), Error> {
        if datagram.len() < IKCP_OVERHEAD {
            return Err(Error::Transport(format!(
                "KCP datagram is {} bytes; shorter than the {IKCP_OVERHEAD}-byte header",
                datagram.len()
            )));
        }
        let mut rest = datagram;
        loop {
            if rest.len() < IKCP_OVERHEAD {
                // Trailing bytes shorter than a header end the datagram (native
                // `if (size < IKCP_OVERHEAD) break;`). With the HMAC already
                // stripped there should be none, but be tolerant of zero-pad.
                break;
            }
            let conv = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
            if conv != self.conv {
                return Err(Error::Transport(format!(
                    "KCP segment conv {conv:#010x} != channel conv {:#010x}",
                    self.conv
                )));
            }
            let cmd = rest[4];
            let frg = rest[5];
            // wnd @6 (u16); ts @8 (u32) is echoed back in our ACK (RTT estimate).
            let ts = u32::from_le_bytes([rest[8], rest[9], rest[10], rest[11]]);
            let sn = u32::from_le_bytes([rest[12], rest[13], rest[14], rest[15]]);
            // una @16 (u32) — send-side ack cursor; ignored on RX decode.
            let len = u32::from_le_bytes([rest[20], rest[21], rest[22], rest[23]]) as usize;

            let body = &rest[IKCP_OVERHEAD..];
            if body.len() < len {
                return Err(Error::Transport(format!(
                    "KCP segment len {len} overruns the {} remaining datagram bytes",
                    body.len()
                )));
            }
            match cmd {
                IKCP_CMD_PUSH => {
                    // ACK every in-window PUSH (incl. duplicates — a lost ACK makes
                    // the camera retransmit, and it needs the re-ACK). Mirrors
                    // ikcp_input's `ikcp_ack_push` before parse_data.
                    if sn.wrapping_sub(self.rcv_nxt) < self.rcv_wnd {
                        self.acklist.push((sn, ts));
                    }
                    let seg_payload = &body[..len];
                    self.accept_push(sn, frg, seg_payload, decryptor)?;
                }
                IKCP_CMD_ACK | IKCP_CMD_WASK | IKCP_CMD_WINS => {
                    // Receive-only decoder: no send state to update. (These
                    // typically carry len==0; any payload is skipped below.)
                }
                other => {
                    return Err(Error::Transport(format!(
                        "KCP segment has unknown cmd {other:#04x} (expected PUSH/ACK/WASK/WINS)"
                    )));
                }
            }
            rest = &body[len..];
            if rest.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Insert a decrypted PUSH segment, applying the window + duplicate checks
    /// then the contiguous move to `rcv_queue` (mirrors `ikcp_parse_data`).
    fn accept_push(
        &mut self,
        sn: u32,
        frg: u8,
        seg_payload: &[u8],
        decryptor: &dyn SegmentDecryptor,
    ) -> Result<(), Error> {
        // Acceptance window: drop sn outside [rcv_nxt, rcv_nxt + rcv_wnd). The
        // wrapping subtraction folds "already consumed" (sn < rcv_nxt) into the
        // same `>= rcv_wnd` test, matching the native signed-diff check.
        if sn.wrapping_sub(self.rcv_nxt) >= self.rcv_wnd {
            return Ok(()); // out of window / stale → silent drop (as native)
        }
        // Locate the ordered insert position; drop exact duplicates.
        let mut insert_at = self.rcv_buf.len();
        for (i, s) in self.rcv_buf.iter().enumerate() {
            if s.sn == sn {
                return Ok(()); // duplicate already buffered
            }
            if s.sn > sn {
                insert_at = i;
                break;
            }
        }
        // Decrypt only AFTER the window/dup checks (the native hook order): a
        // wrong key/corrupt segment fails loud here rather than silently.
        let data = decryptor.decrypt(seg_payload)?;
        self.rcv_buf.insert(insert_at, KcpSegment { sn, frg, data });

        // Move every now-contiguous segment to the ready queue.
        while let Some(front) = self.rcv_buf.first() {
            if front.sn == self.rcv_nxt {
                let seg = self.rcv_buf.remove(0);
                self.rcv_queue.push(seg);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Pop the next complete application message (one or more `frg`-chained
    /// segments), concatenating their plaintexts. Returns `None` while the next
    /// message is incomplete (mirrors `ikcp_recv` / `ikcp_peeksize`).
    ///
    /// `frg` counts **down** to 0 on the last fragment, so the message ends at the
    /// first queued segment with `frg == 0`. The queue is always a contiguous
    /// prefix, so the first such segment delimits exactly one message.
    #[must_use]
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        if self.rcv_queue.is_empty() {
            return None;
        }
        let end = self.rcv_queue.iter().position(|s| s.frg == 0)?;
        let segs: Vec<KcpSegment> = self.rcv_queue.drain(..=end).collect();
        let mut out = Vec::new();
        for s in segs {
            out.extend_from_slice(&s.data);
        }
        Some(out)
    }

    /// Drain all currently-complete messages (convenience over [`recv`]).
    ///
    /// [`recv`]: KcpReceiver::recv
    pub fn drain_messages(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(m) = self.recv() {
            out.push(m);
        }
        out
    }
}

/// Read the `conv` (first 4 bytes, little-endian) of a datagram, if present.
#[must_use]
pub fn get_conv(datagram: &[u8]) -> Option<u32> {
    if datagram.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        datagram[0],
        datagram[1],
        datagram[2],
        datagram[3],
    ]))
}

/// Encode one KCP segment: the 24-byte little-endian header + `payload`
/// (`conv cmd frg wnd ts sn una len(payload)`). The TX inverse of the RX header
/// parse; `len` is set from `payload`. (cap4 wire: PUSH `cmd=0x51`, `wnd=512`.)
///
/// The seven header parameters are the **intrinsic ikcp wire fields** (`conv`,
/// `cmd`, `frg`, `wnd`, `ts`, `sn`, `una`), so the arity is a property of the
/// protocol, not an API-design smell — folding them into a struct would only
/// relocate the same seven fields. Hence the targeted `too_many_arguments` allow.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_segment(
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(IKCP_OVERHEAD + payload.len());
    s.extend_from_slice(&conv.to_le_bytes()); // 0: conv
    s.push(cmd); // 4: cmd
    s.push(frg); // 5: frg
    s.extend_from_slice(&wnd.to_le_bytes()); // 6: wnd
    s.extend_from_slice(&ts.to_le_bytes()); // 8: ts
    s.extend_from_slice(&sn.to_le_bytes()); // 12: sn
    s.extend_from_slice(&una.to_le_bytes()); // 16: una
    s.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // 20: len
    s.extend_from_slice(payload); // 24: payload
    s
}

/// The window we advertise on outbound segments (cap4: app `wnd = 0x0200 = 512`).
pub const SND_WND: u16 = 512;

/// A minimal **send-side** ikcp channel for one `conv`: assigns ascending `sn`,
/// holds unacknowledged PUSH datagrams for retransmit, and prunes them when the
/// peer's `una` advances. **Time-free** (no clock): the caller (the media pump)
/// owns the RTO and decides when to resend [`unacked`](KcpSender::unacked) — so this
/// is fully offline-testable against a [`KcpReceiver`].
pub struct KcpSender {
    conv: u32,
    snd_nxt: u32,
    /// `(sn, full-wire datagram)` for each sent-but-unacked PUSH, ascending by `sn`.
    unacked: Vec<(u32, Vec<u8>)>,
}

impl KcpSender {
    /// A new sender for `conv` whose first assigned `sn` is `start_sn` (cap4's app
    /// conv=0 stream starts at `sn = 3`; a fresh KCP would start at `0`).
    #[must_use]
    pub fn new(conv: u32, start_sn: u32) -> Self {
        Self {
            conv,
            snd_nxt: start_sn,
            unacked: Vec::new(),
        }
    }

    /// The `conv` this sender drives.
    #[must_use]
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Take the next `sn` to assign (and advance the counter).
    pub fn take_sn(&mut self) -> u32 {
        let sn = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        sn
    }

    /// Record a sent PUSH's full wire datagram for possible retransmit.
    pub fn record_unacked(&mut self, sn: u32, wire: Vec<u8>) {
        self.unacked.push((sn, wire));
    }

    /// Prune everything the peer has acknowledged: drop unacked PUSHes with
    /// `sn < peer_una` (KCP cumulative ACK).
    pub fn ack_through(&mut self, peer_una: u32) {
        self.unacked.retain(|(sn, _)| *sn >= peer_una);
    }

    /// The still-unacknowledged PUSH wire datagrams, for the caller to retransmit.
    pub fn unacked(&self) -> impl Iterator<Item = &[u8]> {
        self.unacked.iter().map(|(_, w)| w.as_slice())
    }

    /// Whether every PUSH has been acknowledged by the peer.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.unacked.is_empty()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Encode-side helper: frame a KCP PUSH segment (native little-endian header).
    use super::*;

    /// Build one KCP PUSH segment: 24-byte LE header + `payload`.
    #[must_use]
    pub fn kcp_push(conv: u32, sn: u32, frg: u8, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(IKCP_OVERHEAD + payload.len());
        s.extend_from_slice(&conv.to_le_bytes()); // 0: conv
        s.push(IKCP_CMD_PUSH); // 4: cmd
        s.push(frg); // 5: frg
        s.extend_from_slice(&0u16.to_le_bytes()); // 6: wnd
        s.extend_from_slice(&0u32.to_le_bytes()); // 8: ts
        s.extend_from_slice(&sn.to_le_bytes()); // 12: sn
        s.extend_from_slice(&0u32.to_le_bytes()); // 16: una
        s.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // 20: len
        s.extend_from_slice(payload); // 24: payload
        s
    }

    /// Build a bare cmd segment (ACK/WASK/WINS) with empty payload.
    #[must_use]
    pub fn kcp_cmd(conv: u32, cmd: u8) -> Vec<u8> {
        let mut s = Vec::with_capacity(IKCP_OVERHEAD);
        s.extend_from_slice(&conv.to_le_bytes());
        s.push(cmd);
        s.push(0); // frg
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes()); // len = 0
        s
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const CONV: u32 = 0x0002_0001;

    /// An identity "decryptor" so KCP behavior is tested without a cipher.
    struct Identity;
    impl SegmentDecryptor for Identity {
        fn decrypt(&self, seg_payload: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(seg_payload.to_vec())
        }
    }

    /// A decryptor that always fails (to prove the error propagates loud).
    struct AlwaysFail;
    impl SegmentDecryptor for AlwaysFail {
        fn decrypt(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
            Err(Error::Transport("synthetic decrypt failure".into()))
        }
    }

    #[test]
    fn single_segment_message_delivers() {
        let mut k = KcpReceiver::new(CONV);
        let dg = kcp_push(CONV, 0, 0, b"hello");
        k.input(&dg, &Identity).unwrap();
        assert_eq!(k.recv().as_deref(), Some(b"hello".as_slice()));
        assert!(k.recv().is_none());
    }

    #[test]
    fn coalesced_segments_in_one_datagram() {
        let mut k = KcpReceiver::new(CONV);
        let mut dg = kcp_push(CONV, 0, 0, b"AAA");
        dg.extend(kcp_push(CONV, 1, 0, b"BBB"));
        k.input(&dg, &Identity).unwrap();
        assert_eq!(k.recv().as_deref(), Some(b"AAA".as_slice()));
        assert_eq!(k.recv().as_deref(), Some(b"BBB".as_slice()));
        assert!(k.recv().is_none());
    }

    #[test]
    fn fragmented_message_reassembles_in_order() {
        // A 3-fragment message: frg counts DOWN (2,1,0); sn ascends (0,1,2).
        let mut k = KcpReceiver::new(CONV);
        k.input(&kcp_push(CONV, 0, 2, b"frag0-"), &Identity)
            .unwrap();
        assert!(k.recv().is_none(), "incomplete until frg==0 arrives");
        k.input(&kcp_push(CONV, 1, 1, b"frag1-"), &Identity)
            .unwrap();
        assert!(k.recv().is_none());
        k.input(&kcp_push(CONV, 2, 0, b"frag2"), &Identity).unwrap();
        assert_eq!(k.recv().as_deref(), Some(b"frag0-frag1-frag2".as_slice()));
    }

    #[test]
    fn out_of_order_segments_are_buffered_then_reassembled() {
        let mut k = KcpReceiver::new(CONV);
        // Deliver sn=2 (last frag) first, then 0, then 1.
        k.input(&kcp_push(CONV, 2, 0, b"C"), &Identity).unwrap();
        assert!(k.recv().is_none());
        k.input(&kcp_push(CONV, 0, 2, b"A"), &Identity).unwrap();
        assert!(k.recv().is_none());
        k.input(&kcp_push(CONV, 1, 1, b"B"), &Identity).unwrap();
        assert_eq!(k.recv().as_deref(), Some(b"ABC".as_slice()));
    }

    #[test]
    fn duplicate_sn_is_ignored() {
        let mut k = KcpReceiver::new(CONV);
        k.input(&kcp_push(CONV, 0, 0, b"X"), &Identity).unwrap();
        // A duplicate sn=0 with different bytes must NOT corrupt the delivered msg.
        k.input(&kcp_push(CONV, 0, 0, b"Y"), &Identity).unwrap();
        assert_eq!(k.recv().as_deref(), Some(b"X".as_slice()));
        assert!(k.recv().is_none());
    }

    #[test]
    fn ack_and_wins_segments_are_skipped() {
        let mut k = KcpReceiver::new(CONV);
        let mut dg = kcp_cmd(CONV, IKCP_CMD_ACK);
        dg.extend(kcp_push(CONV, 0, 0, b"data"));
        dg.extend(kcp_cmd(CONV, IKCP_CMD_WINS));
        k.input(&dg, &Identity).unwrap();
        assert_eq!(k.recv().as_deref(), Some(b"data".as_slice()));
    }

    // NEGATIVE: a wrong conv is rejected (no cross-channel data mixing).
    #[test]
    fn rejects_wrong_conv() {
        let mut k = KcpReceiver::new(CONV);
        let dg = kcp_push(0xdead_beef, 0, 0, b"data");
        assert!(matches!(k.input(&dg, &Identity), Err(Error::Transport(_))));
    }

    // NEGATIVE: a len that overruns the datagram is rejected.
    #[test]
    fn rejects_len_overrun() {
        let mut k = KcpReceiver::new(CONV);
        let mut dg = kcp_push(CONV, 0, 0, b"data");
        // Bump the len field (offset 20) beyond the actual payload.
        dg[20] = 0xff;
        assert!(matches!(k.input(&dg, &Identity), Err(Error::Transport(_))));
    }

    // NEGATIVE: an unknown cmd is rejected.
    #[test]
    fn rejects_unknown_cmd() {
        let mut k = KcpReceiver::new(CONV);
        let mut dg = kcp_cmd(CONV, 0x99);
        // give it a valid (zero) len so the only fault is the cmd.
        dg[4] = 0x99;
        assert!(matches!(k.input(&dg, &Identity), Err(Error::Transport(_))));
    }

    // NEGATIVE: a decrypt failure on a PUSH propagates (loud, not silent drop).
    #[test]
    fn decrypt_failure_propagates() {
        let mut k = KcpReceiver::new(CONV);
        let dg = kcp_push(CONV, 0, 0, b"ciphertext");
        assert!(matches!(
            k.input(&dg, &AlwaysFail),
            Err(Error::Transport(_))
        ));
    }

    // A segment outside the acceptance window is dropped, not delivered.
    #[test]
    fn drops_segment_outside_window() {
        let mut k = KcpReceiver::with_window(CONV, 4);
        k.input(&kcp_push(CONV, 100, 0, b"far future sn"), &Identity)
            .unwrap();
        assert!(k.recv().is_none(), "sn far beyond the window is dropped");
    }

    #[test]
    fn get_conv_reads_le_prefix() {
        let dg = kcp_push(0x0102_0304, 0, 0, b"z");
        assert_eq!(get_conv(&dg), Some(0x0102_0304));
        assert_eq!(get_conv(&[0x01, 0x02]), None);
    }

    // ── KcpSender ↔ KcpReceiver loopback (TASK-0083 §S6a) ───────────────────
    // The media-start SEND side frames conv=0 PUSH sn=3,4,5 (cap4: conv=0 starts at
    // sn=3); the receive side — pre-rolled to rcv_nxt=3 (both sides agree on the
    // start, `re/media_start_handshake.md`) — delivers their payloads in order; and
    // the camera's cumulative `una` advancing past them drains the sender.
    #[test]
    fn sender_receiver_media_start_loopback() {
        const CONV0: u32 = 0; // the imm media-start conv
        const START_SN: u32 = 3; // MEDIA_START_SN
        let mut sender = KcpSender::new(CONV0, START_SN);
        assert_eq!(sender.conv(), CONV0);
        let mut rx = KcpReceiver::new(CONV0);

        // Pre-roll the receiver to rcv_nxt=3 so the 3,4,5 PUSHes deliver in order
        // (KcpReceiver starts at rcv_nxt=0; cap4's camera-side KCP starts conv=0 at 3).
        for sn in 0..START_SN {
            let pre = encode_segment(CONV0, IKCP_CMD_PUSH, 0, SND_WND, 0, sn, 0, b"preroll");
            rx.input(&pre, &Identity).unwrap();
            let _ = rx.recv(); // discard the pre-roll payload; only rcv_nxt matters
        }

        // The sender frames the three media-start PUSHes; the receiver consumes each.
        let payloads: [&[u8]; 3] = [b"PDU-A", b"PDU-B", b"PDU-C"];
        for p in payloads {
            let sn = sender.take_sn();
            let wire = encode_segment(CONV0, IKCP_CMD_PUSH, 0, SND_WND, 0, sn, 0, p);
            // The sender holds the EXACT wire bytes for retransmit.
            sender.record_unacked(sn, wire.clone());
            rx.input(&wire, &Identity).unwrap();
        }
        assert_eq!(sender.take_sn(), START_SN + 3, "sn advanced past 3,4,5");

        // Delivered in order, payloads intact.
        assert_eq!(rx.recv().as_deref(), Some(b"PDU-A".as_slice()));
        assert_eq!(rx.recv().as_deref(), Some(b"PDU-B".as_slice()));
        assert_eq!(rx.recv().as_deref(), Some(b"PDU-C".as_slice()));
        assert!(rx.recv().is_none());

        // None acked yet → all three held; a partial ack prunes only the acked.
        assert_eq!(sender.unacked().count(), 3);
        assert!(!sender.is_drained());
        sender.ack_through(4); // camera acked sn 3 (una=4 ⇒ next expected 4)
        assert_eq!(sender.unacked().count(), 2);
        // The cumulative ack past 3,4,5 (cap4 frame 256: una=6) drains the sender.
        sender.ack_through(6);
        assert!(sender.is_drained());
        assert_eq!(sender.unacked().count(), 0);
    }
}
