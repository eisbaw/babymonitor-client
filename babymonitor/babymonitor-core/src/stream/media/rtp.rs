//! RTP (RFC 3550) 12-byte header parse — the media unit a reassembled KCP message
//! carries (`re/media_decode_spec.md` §3, §4 Step D).
//!
//! After datagram-HMAC strip → KCP reassembly → per-segment decrypt, each
//! delivered KCP message is a standard big-endian 12-byte RTP header + payload.
//! The native getters byte-swap BE→host (`imm_p2p_rtp_get_seq@17342c`,
//! `imm_p2p_rtp_get_timestamp@1733f4`); the decoder validates `(b0 & 0xc0) ==
//! 0x80` (V=2) before trusting a packet. **[C]**
//!
//! The "PT 6001" in the SDP (`a=rtpmap:6001 AES/KCP`) is the **SDP format
//! number, not the 7-bit RTP PT** (RTP PT ≤ 127) — §3. The real RTP PT here is
//! the dynamic/static value in `byte1 & 0x7f` (e.g. `0` = PCMU).

use crate::Error;

/// RTP fixed-header length (no CSRC, no extension), in bytes.
pub const RTP_HEADER_LEN: usize = 12;
/// The expected RTP version (2) — `(byte0 & 0xc0) == 0x80`.
pub const RTP_VERSION: u8 = 2;

/// A parsed RTP header (host-endian fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    /// Version — must be [`RTP_VERSION`] (2) for a valid packet.
    pub version: u8,
    /// Padding flag (`P`): a trailing pad-count byte is present + stripped.
    pub padding: bool,
    /// Extension flag (`X`): a header extension follows the CSRC list.
    pub extension: bool,
    /// CSRC count (`CC`): number of 32-bit CSRC ids after the fixed header.
    pub csrc_count: u8,
    /// Marker bit (`M`): for H.264 this flags the last packet of an access unit.
    pub marker: bool,
    /// Payload type (`PT`, 7-bit): e.g. `0` = PCMU.
    pub payload_type: u8,
    /// Sequence number (BE→host).
    pub sequence: u16,
    /// Timestamp (BE→host).
    pub timestamp: u32,
    /// Synchronization source id (BE→host).
    pub ssrc: u32,
}

/// A parsed RTP packet: its header plus the payload slice (CSRC/extension skipped
/// and any padding stripped), borrowing the input buffer.
#[derive(Debug, Clone, Copy)]
pub struct RtpPacket<'a> {
    /// The parsed header.
    pub header: RtpHeader,
    /// The media payload (e.g. an H.264 RTP payload or a G.711 µ-law frame).
    pub payload: &'a [u8],
}

/// Parse one RTP packet from a reassembled KCP message.
///
/// Validates V=2, skips the CSRC list and (if `X`) the header extension, and
/// strips trailing padding (if `P`). The returned [`RtpPacket::payload`] borrows
/// `buf`.
///
/// # Errors
/// [`Error::Transport`] if `buf` is shorter than the 12-byte header, the version
/// is not 2, the header (with CSRC/extension) overruns `buf`, or the padding
/// count is invalid.
pub fn parse_rtp(buf: &[u8]) -> Result<RtpPacket<'_>, Error> {
    if buf.len() < RTP_HEADER_LEN {
        return Err(Error::Transport(format!(
            "RTP packet is {} bytes; shorter than the {RTP_HEADER_LEN}-byte header",
            buf.len()
        )));
    }
    let b0 = buf[0];
    let version = b0 >> 6;
    if version != RTP_VERSION {
        return Err(Error::Transport(format!(
            "RTP version is {version}, expected {RTP_VERSION} ((b0 & 0xc0) != 0x80)"
        )));
    }
    let padding = b0 & 0x20 != 0;
    let extension = b0 & 0x10 != 0;
    let csrc_count = b0 & 0x0f;
    let b1 = buf[1];
    let marker = b1 & 0x80 != 0;
    let payload_type = b1 & 0x7f;
    let sequence = u16::from_be_bytes([buf[2], buf[3]]);
    let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

    let mut header_len = RTP_HEADER_LEN + (csrc_count as usize) * 4;
    if buf.len() < header_len {
        return Err(Error::Transport(format!(
            "RTP CSRC list ({csrc_count} ids) overruns the {}-byte packet",
            buf.len()
        )));
    }
    if extension {
        // Header extension: u16 profile + u16 length-in-words, then words×4.
        if buf.len() < header_len + 4 {
            return Err(Error::Transport(
                "RTP extension header overruns the packet".to_string(),
            ));
        }
        let ext_words = u16::from_be_bytes([buf[header_len + 2], buf[header_len + 3]]) as usize;
        header_len += 4 + ext_words * 4;
        if buf.len() < header_len {
            return Err(Error::Transport(
                "RTP extension body overruns the packet".to_string(),
            ));
        }
    }

    let mut end = buf.len();
    if padding {
        let pad = buf[end - 1] as usize;
        if pad == 0 || pad > end - header_len {
            return Err(Error::Transport(format!(
                "RTP padding count {pad} is invalid for a {}-byte payload",
                end - header_len
            )));
        }
        end -= pad;
    }

    Ok(RtpPacket {
        header: RtpHeader {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
        },
        payload: &buf[header_len..end],
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Encode-side helper: build a minimal 12-byte-header RTP packet.
    use super::*;

    /// Build an RTP packet with a 12-byte header (no CSRC/ext/pad) + `payload`.
    #[must_use]
    pub fn build_rtp(
        pt: u8,
        marker: bool,
        seq: u16,
        ts: u32,
        ssrc: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(RTP_HEADER_LEN + payload.len());
        p.push(0x80); // V=2, P=0, X=0, CC=0
        p.push((u8::from(marker) << 7) | (pt & 0x7f));
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn parses_minimal_packet() {
        let pkt = build_rtp(0, true, 0x1234, 0xdead_beef, 0x0102_0304, b"payload");
        let r = parse_rtp(&pkt).unwrap();
        assert_eq!(r.header.version, 2);
        assert_eq!(r.header.payload_type, 0); // PCMU
        assert!(r.header.marker);
        assert_eq!(r.header.sequence, 0x1234);
        assert_eq!(r.header.timestamp, 0xdead_beef);
        assert_eq!(r.header.ssrc, 0x0102_0304);
        assert_eq!(r.payload, b"payload");
    }

    #[test]
    fn parses_h264_pt_and_marker_clear() {
        // PT 96 (dynamic H.264), marker clear, an FU-A-shaped payload.
        let pkt = build_rtp(96, false, 1, 90_000, 7, &[0x7c, 0x85, 0xaa, 0xbb]);
        let r = parse_rtp(&pkt).unwrap();
        assert_eq!(r.header.payload_type, 96);
        assert!(!r.header.marker);
        assert_eq!(r.payload[0] & 0x1f, 28, "NAL type 28 = FU-A");
    }

    #[test]
    fn skips_csrc_list() {
        let mut pkt = build_rtp(0, false, 1, 1, 1, b"data");
        // Set CC=2 and splice in two CSRC ids after the fixed header.
        pkt[0] = 0x82; // V=2, CC=2
        pkt.splice(12..12, [0u8; 8]);
        let r = parse_rtp(&pkt).unwrap();
        assert_eq!(r.header.csrc_count, 2);
        assert_eq!(r.payload, b"data");
    }

    #[test]
    fn skips_extension_header() {
        // V=2, X=1, CC=0; ext: profile=0xBEDE, length=1 word, 1 word of ext data.
        let mut pkt = vec![0x90, 0x00];
        pkt.extend_from_slice(&1u16.to_be_bytes()); // seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ts
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ssrc
        pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01]); // ext profile + len=1
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 1 ext word
        pkt.extend_from_slice(b"realpayload");
        let r = parse_rtp(&pkt).unwrap();
        assert!(r.header.extension);
        assert_eq!(r.payload, b"realpayload");
    }

    #[test]
    fn strips_padding() {
        let mut pkt = build_rtp(0, false, 1, 1, 1, b"abc");
        pkt[0] |= 0x20; // set P
        pkt.extend_from_slice(&[0x00, 0x00, 0x03]); // 2 pad bytes + count=3
        let r = parse_rtp(&pkt).unwrap();
        assert_eq!(r.payload, b"abc");
    }

    // NEGATIVE: a non-2 version is rejected (the decoder's V=2 gate).
    #[test]
    fn rejects_bad_version() {
        let mut pkt = build_rtp(0, false, 1, 1, 1, b"x");
        pkt[0] = 0x40; // version 1
        assert!(matches!(parse_rtp(&pkt), Err(Error::Transport(_))));
    }

    // NEGATIVE: a too-short buffer is rejected.
    #[test]
    fn rejects_short_buffer() {
        assert!(matches!(
            parse_rtp(&[0x80, 0x00, 0x00]),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a CSRC count that overruns the buffer is rejected.
    #[test]
    fn rejects_csrc_overrun() {
        let mut pkt = build_rtp(0, false, 1, 1, 1, b"");
        pkt[0] = 0x8f; // CC=15 → needs 60 CSRC bytes that aren't there
        assert!(matches!(parse_rtp(&pkt), Err(Error::Transport(_))));
    }

    // NEGATIVE: an invalid padding count is rejected.
    #[test]
    fn rejects_bad_padding() {
        let mut pkt = build_rtp(0, false, 1, 1, 1, b"ab");
        pkt[0] |= 0x20; // set P
        let last = pkt.len() - 1;
        pkt[last] = 0xff; // pad count larger than the payload
        assert!(matches!(parse_rtp(&pkt), Err(Error::Transport(_))));
    }
}
