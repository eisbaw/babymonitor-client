//! PATH-A media-frame framing: the **imm wrapper** + a **fixed 12-byte
//! RTP-like header** that each reassembled KCP message carries on the cap3/cap4
//! AES media path (`re/media_decode_spec.md` §5, item **[G]** — the PATH-A video
//! depacketizer lives in `libThingCameraSDK` and is reconstructed empirically
//! here, validated byte-for-byte against the cap4 capture).
//!
//! This corrects the engine's first assumption that "one reassembled KCP message
//! is exactly one bare 12-byte RTP packet". The cap4 bytes show each KCP message
//! is instead:
//!
//! ```text
//! [ imm wrapper ] [ fixed 12-byte RTP-like header ] [ H.264 / audio payload ]
//!   28B base, or                byte0 = imm marker (0x80 keyframe-assoc /
//!   36B when flags@16 == 8        0xb8 inter), NOT a real RTP V/P/X/CC byte
//!   (8B metadata block @24)      byte1 = M-bit | PT  (video PT=96, audio PT=99)
//!   u32-LE @(wrapper_end-4) =    seq @2 (BE u16), ts @4 (BE u32, microseconds),
//!     RTP packet length          ssrc @8 (BE u32)
//! ```
//!
//! ## Why a fixed 12-byte header (not [`super::rtp::parse_rtp`])
//! `byte0` is a constant imm **marker**, not RTP's `version|P|X|CC` field.
//! Deriving the header length from `byte0 & 0x0f` (CSRC count) / `byte0 & 0x10`
//! (extension) — as a stock RFC-3550 parse does — corrupts the payload: for a
//! video inter-frame `byte0 == 0xb8`, `0xb8 & 0x0f == 8` would (wrongly) skip 32
//! CSRC bytes. cap4 proved a **fixed** 12-byte header is correct (a clean decode
//! of all 1231 frames is the proof). The stock [`super::rtp::parse_rtp`] is kept
//! for the in-lib `imm_p2p_rtp_decode_rtp2` PATH-B decoder (which *does* honor
//! CC/X) and the CLI's synthetic replay self-test — it is **not** the PATH-A
//! video path.
//!
//! The `byte0 & 0xc0 == 0x80` invariant still holds (the top two bits of both
//! `0x80` and `0xb8` are `10`), so it is reused as a cheap offset sanity gate,
//! exactly as the ground-truth extractor does.

use crate::stream::media::rtp::{RtpHeader, RtpPacket, RTP_VERSION};

/// imm wrapper length with no metadata block (the common case).
pub const IMM_WRAPPER_BASE: usize = 28;
/// imm wrapper length when `flags == 8` (an 8-byte metadata block at offset 24
/// carries the resolution/fps for video `[1, w, h, fps]` or audio `[2, 3, 0, 1]`).
pub const IMM_WRAPPER_WITH_META: usize = 36;
/// Offset of the `u32-LE flags` field inside the imm wrapper.
pub const IMM_FLAGS_OFFSET: usize = 16;
/// `flags` value that selects the 36-byte (metadata-bearing) wrapper.
pub const IMM_FLAGS_WITH_META: u32 = 8;
/// The fixed PATH-A RTP-like header length, in bytes.
pub const FIXED_RTP_HEADER_LEN: usize = 12;

/// Read a little-endian `u32` at `off`, or `None` if it overruns `buf`.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Locate the start of the fixed 12-byte RTP-like header inside a reassembled KCP
/// message `msg`, or `None` if `msg` is not a PATH-A media frame.
///
/// Mirrors the ground-truth extractor (`emulator_captures/cap4/stage6_extract.py`
/// `rtp_offset`): pick `28` or `36` from `flags@16`, require the RTP `byte0 &
/// 0xc0 == 0x80` sanity bit, and confirm via the wrapper's trailing length field
/// `u32-LE @ (off-4) == msg.len() - off`. If that exact check fails, fall back to
/// a short forward scan for the first offset whose length field self-describes
/// the tail. Returns `None` (skip, do not mis-decode) when nothing matches.
#[must_use]
pub fn rtp_offset(msg: &[u8]) -> Option<usize> {
    if msg.len() < IMM_WRAPPER_BASE {
        return None;
    }
    let flags = read_u32_le(msg, IMM_FLAGS_OFFSET)?;
    let off = if flags == IMM_FLAGS_WITH_META {
        IMM_WRAPPER_WITH_META
    } else {
        IMM_WRAPPER_BASE
    };
    if msg.len() >= off + FIXED_RTP_HEADER_LEN
        && (msg[off] & 0xc0) == 0x80
        && read_u32_le(msg, off - 4) == Some((msg.len() - off) as u32)
    {
        return Some(off);
    }
    // Fallback: scan for an offset whose preceding length field self-describes
    // the remaining tail (the wrapper layout can vary; the length field is the
    // reliable anchor). Bounded to the first 60 bytes, as the extractor does.
    let scan_end = 60.min(msg.len().saturating_sub(FIXED_RTP_HEADER_LEN));
    (4..scan_end).find(|&o| {
        (msg[o] & 0xc0) == 0x80 && read_u32_le(msg, o - 4) == Some((msg.len() - o) as u32)
    })
}

/// Parse a reassembled KCP message into a PATH-A [`RtpPacket`] (fixed 12-byte
/// header + payload), or `None` if `msg` is not a locatable media frame (a
/// control/setup record, or a truncated frame) — the caller skips it, mirroring
/// the native depacketizer which only emits located RTP frames.
///
/// The returned [`RtpHeader`] reports `marker`/`payload_type`/`sequence`/
/// `timestamp`/`ssrc`; `version` is reported as [`RTP_VERSION`] (the `0x80` top
/// bits) and `padding`/`extension`/`csrc_count` are forced to their inert values
/// because — unlike stock RTP — `byte0` here is an imm marker, not a real RTP
/// version/flags byte (see the module header).
#[must_use]
pub fn parse_media_frame(msg: &[u8]) -> Option<RtpPacket<'_>> {
    let off = rtp_offset(msg)?;
    let hdr = &msg[off..off + FIXED_RTP_HEADER_LEN];
    let b1 = hdr[1];
    let header = RtpHeader {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: b1 & 0x80 != 0,
        payload_type: b1 & 0x7f,
        sequence: u16::from_be_bytes([hdr[2], hdr[3]]),
        timestamp: u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
        ssrc: u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
    };
    Some(RtpPacket {
        header,
        payload: &msg[off + FIXED_RTP_HEADER_LEN..],
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Encode-side helper: wrap an RTP packet in a PATH-A imm wrapper, mirroring
    //! the cap4 send layout so the engine's synthetic e2e tests exercise the real
    //! framing (not the obsolete bare-RTP assumption).
    use super::*;

    /// Build a 28-byte (or 36-byte, with an 8-byte metadata block) imm wrapper in
    /// front of `rtp` (a fixed-12B-header RTP packet), setting the trailing length
    /// field so [`rtp_offset`] locates the RTP at the wrapper boundary.
    #[must_use]
    pub fn wrap_imm(stream_marker: u8, rtp: &[u8], meta: Option<[u8; 8]>) -> Vec<u8> {
        let wlen = if meta.is_some() {
            IMM_WRAPPER_WITH_META
        } else {
            IMM_WRAPPER_BASE
        };
        let mut m = vec![0u8; wlen];
        m[0] = stream_marker; // 0x03 video / 0x05 audio (informational byte0)
        let flags = if meta.is_some() {
            IMM_FLAGS_WITH_META
        } else {
            0
        };
        m[IMM_FLAGS_OFFSET..IMM_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
        if let Some(meta) = meta {
            m[24..32].copy_from_slice(&meta);
        }
        // Trailing length field at (wlen - 4) = RTP packet length.
        m[wlen - 4..wlen].copy_from_slice(&(rtp.len() as u32).to_le_bytes());
        m.extend_from_slice(rtp);
        m
    }

    /// Build a fixed-12-byte PATH-A RTP-like header + `payload`. `marker_byte0` is
    /// the imm marker (e.g. `0x80`/`0xb8`); `m_pt` packs the M-bit and 7-bit PT.
    #[must_use]
    pub fn build_fixed_rtp(
        marker_byte0: u8,
        marker: bool,
        pt: u8,
        seq: u16,
        ts: u32,
        ssrc: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(FIXED_RTP_HEADER_LEN + payload.len());
        p.push(marker_byte0);
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
    fn locates_and_parses_28b_wrapper_inter_frame() {
        // Video inter-frame: imm marker 0xb8 (the byte that broke the stock parse).
        let rtp = build_fixed_rtp(
            0xb8,
            false,
            96,
            0x0102,
            0x0a0b_0c0d,
            10,
            &[0x41, 0xAA, 0xBB],
        );
        let msg = wrap_imm(0x03, &rtp, None);
        let off = rtp_offset(&msg).expect("locatable");
        assert_eq!(off, IMM_WRAPPER_BASE);
        let pkt = parse_media_frame(&msg).expect("parses");
        assert_eq!(pkt.header.payload_type, 96);
        assert!(!pkt.header.marker);
        assert_eq!(pkt.header.sequence, 0x0102);
        assert_eq!(pkt.header.timestamp, 0x0a0b_0c0d);
        assert_eq!(pkt.header.ssrc, 10);
        assert_eq!(pkt.payload, &[0x41, 0xAA, 0xBB]);
    }

    #[test]
    fn locates_36b_wrapper_with_metadata_keyframe() {
        // Keyframe-assoc imm marker 0x80, M-bit set, with a resolution metadata
        // block → 36-byte wrapper.
        let rtp = build_fixed_rtp(0x80, true, 96, 1, 90_000, 10, &[0x67, 0x42]);
        let meta = [1, 0, 0, 0, 0, 0, 0, 0]; // shape-only stand-in for [1,w,h,fps]
        let msg = wrap_imm(0x03, &rtp, Some(meta));
        let off = rtp_offset(&msg).expect("locatable");
        assert_eq!(off, IMM_WRAPPER_WITH_META);
        let pkt = parse_media_frame(&msg).expect("parses");
        assert!(pkt.header.marker);
        assert_eq!(pkt.payload, &[0x67, 0x42]);
    }

    #[test]
    fn audio_pt99_round_trips() {
        let rtp = build_fixed_rtp(0x80, false, 99, 7, 1000, 10, &[0x11, 0x22, 0x33, 0x44]);
        let msg = wrap_imm(0x05, &rtp, None);
        let pkt = parse_media_frame(&msg).expect("parses");
        assert_eq!(pkt.header.payload_type, 99);
        assert_eq!(pkt.payload, &[0x11, 0x22, 0x33, 0x44]);
    }

    // NEGATIVE: a message too short for even the base wrapper is not a frame.
    #[test]
    fn too_short_is_not_a_frame() {
        assert!(rtp_offset(&[0u8; 20]).is_none());
        assert!(parse_media_frame(&[0u8; 20]).is_none());
    }

    // NEGATIVE: a wrapper whose length field does not self-describe the tail and
    // has no 0x80-marked alternative is skipped (None), never mis-located.
    #[test]
    fn garbage_without_length_anchor_is_skipped() {
        let mut msg = vec![0u8; 40];
        // No byte has high bits 0x80 at a self-describing offset → no match.
        for b in msg.iter_mut() {
            *b = 0x10;
        }
        assert!(rtp_offset(&msg).is_none());
    }

    // The fallback scan finds an RTP offset when the wrapper is an unexpected
    // length but the trailing length field still anchors it.
    #[test]
    fn fallback_scan_locates_shifted_offset() {
        let rtp = build_fixed_rtp(0x80, false, 96, 1, 1, 10, &[0x41, 0x00]);
        // 32-byte wrapper (neither 28 nor 36); flags!=8 so primary tries off=28
        // and fails the length check, then the scan finds off=32.
        let wlen = 32usize;
        let mut m = vec![0u8; wlen];
        m[wlen - 4..wlen].copy_from_slice(&(rtp.len() as u32).to_le_bytes());
        m.extend_from_slice(&rtp);
        // Ensure the (off=28) primary candidate does not accidentally validate.
        assert_eq!(rtp_offset(&m), Some(wlen));
        let pkt = parse_media_frame(&m).expect("parses via fallback");
        assert_eq!(pkt.payload, &[0x41, 0x00]);
    }
}
