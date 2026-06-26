//! H.264 RFC-6184 RTP depacketizer → Annex-B NAL stream
//! (`re/media_decode_spec.md` §4 Step D, §5).
//!
//! Derived by **inverting** the confirmed send packetizer
//! (`imm_p2p_h264_packetize` STAP-A@`15026c:42-46`, FU-A@`150100:53-56`,
//! threshold `0x4a7` = 1191) — so the layout is **[C]** and the RX inversion is
//! **[I]** (`re/media_decode_spec.md` §5):
//!
//! ```text
//! payload[0] & 0x1F:
//!   1..23  single NAL → emit 00 00 00 01 + payload
//!   24     STAP-A      → drop b0; loop { size=BE16; emit 00 00 00 01 + payload[size]; advance }
//!   28     FU-A        → nal_hdr = (b0 & 0xE0) | (b1 & 0x1F)
//!                        if b1 & 0x80 (S): start, emit nal_hdr + frag(byte+2)
//!                        else append frag(byte+2);  b1 & 0x40 (E) ends the NAL
//! ```
//!
//! Access-unit boundary = the RTP **M-bit**; a keyframe is NAL type 5 (IDR),
//! preceded by 7 (SPS) / 8 (PPS).

use crate::Error;

/// Annex-B 4-byte start code prefixed before every emitted NAL unit.
pub const ANNEXB_START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// NAL unit type for a single-time aggregation packet (STAP-A).
pub const NAL_STAP_A: u8 = 24;
/// NAL unit type for a fragmentation unit (FU-A).
pub const NAL_FU_A: u8 = 28;
/// NAL unit type for a coded slice of an IDR picture (keyframe).
pub const NAL_IDR: u8 = 5;
/// NAL unit type for a sequence parameter set.
pub const NAL_SPS: u8 = 7;
/// NAL unit type for a picture parameter set.
pub const NAL_PPS: u8 = 8;

/// Extract the 5-bit NAL unit type from a NAL header byte.
#[must_use]
pub fn nal_type(byte: u8) -> u8 {
    byte & 0x1f
}

/// Whether `nal` (a NAL header byte) is in the RFC-6184 range the decoder accepts
/// — `1..=23` (single), `24` (STAP-A), or `28` (FU-A). Used by the §4 structural
/// validation gate.
#[must_use]
pub fn is_supported_nal(byte: u8) -> bool {
    matches!(nal_type(byte), 1..=23 | NAL_STAP_A | NAL_FU_A)
}

/// Stateful H.264 RTP depacketizer (FU-A reassembly spans RTP packets).
#[derive(Debug, Default)]
pub struct H264Depacketizer {
    /// In-progress FU-A NAL (Annex-B start code + reconstructed NAL header +
    /// accumulated fragments) between the S and E fragments.
    fu_accum: Option<Vec<u8>>,
}

impl H264Depacketizer {
    /// A fresh depacketizer with no in-progress fragment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Depacketize one RTP H.264 payload into zero or more Annex-B NAL units
    /// (each prefixed with [`ANNEXB_START_CODE`]).
    ///
    /// A single NAL or a STAP-A yields its NAL(s) immediately; an FU-A yields a
    /// NAL only on its End fragment (the accumulated unit), `[]` otherwise.
    ///
    /// # Errors
    /// [`Error::Transport`] if the payload is empty, an unsupported NAL type, a
    /// malformed STAP-A (truncated size/NAL), or an FU-A continuation/end arrives
    /// without a preceding Start.
    pub fn push(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let &b0 = payload
            .first()
            .ok_or_else(|| Error::Transport("empty H.264 RTP payload".to_string()))?;
        match nal_type(b0) {
            1..=23 => {
                // Single NAL unit — emit verbatim with a start code.
                Ok(vec![with_start_code(payload)])
            }
            NAL_STAP_A => self.depacketize_stap_a(payload),
            NAL_FU_A => self.depacketize_fu_a(payload),
            other => Err(Error::Transport(format!(
                "unsupported H.264 NAL type {other} (expected 1..=23 single, 24 STAP-A, 28 FU-A)"
            ))),
        }
    }

    /// Whether an FU-A reassembly is currently in progress (no End seen yet).
    #[must_use]
    pub fn has_pending_fragment(&self) -> bool {
        self.fu_accum.is_some()
    }

    fn depacketize_stap_a(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        // STAP-A: drop the 1-byte STAP-A header, then repeated [u16 size | NAL].
        let mut out = Vec::new();
        let mut i = 1;
        while i < payload.len() {
            if i + 2 > payload.len() {
                return Err(Error::Transport(
                    "STAP-A truncated reading aggregation-unit size".to_string(),
                ));
            }
            let size = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
            i += 2;
            if size == 0 || i + size > payload.len() {
                return Err(Error::Transport(format!(
                    "STAP-A aggregation-unit size {size} overruns the payload"
                )));
            }
            out.push(with_start_code(&payload[i..i + size]));
            i += size;
        }
        if out.is_empty() {
            return Err(Error::Transport(
                "STAP-A carried no aggregation units".to_string(),
            ));
        }
        Ok(out)
    }

    fn depacketize_fu_a(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        // FU-A: byte0 = FU indicator, byte1 = FU header; fragment data from byte2.
        if payload.len() < 3 {
            return Err(Error::Transport(
                "FU-A payload shorter than the 2-byte FU header".to_string(),
            ));
        }
        let fu_indicator = payload[0];
        let fu_header = payload[1];
        let start = fu_header & 0x80 != 0;
        let end = fu_header & 0x40 != 0;
        let frag = &payload[2..];

        if start {
            // Reconstruct the original NAL header: F|NRI from the indicator,
            // type from the FU header.
            let nal_header = (fu_indicator & 0xe0) | (fu_header & 0x1f);
            let mut accum = Vec::with_capacity(ANNEXB_START_CODE.len() + 1 + frag.len());
            accum.extend_from_slice(&ANNEXB_START_CODE);
            accum.push(nal_header);
            accum.extend_from_slice(frag);
            self.fu_accum = Some(accum);
        } else {
            // Continuation/End must follow a Start.
            let accum = self.fu_accum.as_mut().ok_or_else(|| {
                Error::Transport(
                    "FU-A continuation/end fragment without a preceding start (packet loss?)"
                        .to_string(),
                )
            })?;
            accum.extend_from_slice(frag);
        }

        if end {
            let unit = self
                .fu_accum
                .take()
                .expect("end implies an in-progress FU-A accumulator");
            Ok(vec![unit])
        } else {
            Ok(Vec::new())
        }
    }
}

/// Prepend the Annex-B start code to a raw NAL unit.
fn with_start_code(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ANNEXB_START_CODE.len() + nal.len());
    out.extend_from_slice(&ANNEXB_START_CODE);
    out.extend_from_slice(nal);
    out
}

/// Whether an emitted Annex-B NAL unit (start code + NAL) is an IDR keyframe.
#[must_use]
pub fn is_keyframe_nal(annexb: &[u8]) -> bool {
    annexb
        .get(ANNEXB_START_CODE.len())
        .is_some_and(|&b| nal_type(b) == NAL_IDR)
}

/// One reassembled H.264 **access unit**: the concatenated Annex-B NAL stream
/// for one picture, plus whether it is a keyframe (`re/media_decode_spec.md` §5:
/// "access-unit boundary = RTP M-bit; keyframe = NAL type 5 (IDR), preceded by
/// 7 (SPS) / 8 (PPS)").
#[derive(Clone, PartialEq, Eq)]
pub struct AccessUnit {
    /// The access unit as a ready-to-decode Annex-B byte stream (each NAL already
    /// `00 00 00 01`-prefixed).
    pub annexb: Vec<u8>,
    /// Contains a coded IDR slice (NAL type 5) — a decodable keyframe.
    pub is_keyframe: bool,
    /// Carries a sequence parameter set (NAL type 7) in this AU.
    pub has_sps: bool,
    /// Carries a picture parameter set (NAL type 8) in this AU.
    pub has_pps: bool,
}

impl std::fmt::Debug for AccessUnit {
    /// Prints the AU's byte length + flags only — never the raw video bytes (the
    /// user's own feed on the live path).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessUnit")
            .field("annexb_len", &self.annexb.len())
            .field("is_keyframe", &self.is_keyframe)
            .field("has_sps", &self.has_sps)
            .field("has_pps", &self.has_pps)
            .finish()
    }
}

impl AccessUnit {
    /// Whether this AU is independently decodable from a cold start — it carries
    /// SPS + PPS + an IDR slice. A player should begin at the first such AU so the
    /// decoder has parameter sets before the keyframe.
    #[must_use]
    pub fn is_decodable_keyframe(&self) -> bool {
        self.is_keyframe && self.has_sps && self.has_pps
    }
}

/// Groups the Annex-B NAL units emitted by [`H264Depacketizer`] into
/// [`AccessUnit`]s, using the RTP **marker bit** as the access-unit boundary
/// (`re/media_decode_spec.md` §5). Feed it, per RTP packet, the depacketized
/// NAL(s) and that packet's marker bit; it yields a complete [`AccessUnit`] when
/// the marker closes the picture.
#[derive(Debug, Default)]
pub struct AccessUnitAssembler {
    annexb: Vec<u8>,
    is_keyframe: bool,
    has_sps: bool,
    has_pps: bool,
}

impl AccessUnitAssembler {
    /// A fresh assembler with no in-progress access unit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the Annex-B NAL units from one RTP packet (as produced by
    /// [`H264Depacketizer::push`]) and apply that packet's `marker` bit.
    ///
    /// Returns `Some(AccessUnit)` when `marker` is set (the access-unit boundary),
    /// otherwise `None` while the picture is still accumulating. An empty `marker`
    /// packet that nonetheless closes a non-empty AU still flushes it.
    pub fn push(&mut self, nals: &[Vec<u8>], marker: bool) -> Option<AccessUnit> {
        for nal in nals {
            match nal.get(ANNEXB_START_CODE.len()).map(|&b| nal_type(b)) {
                Some(NAL_IDR) => self.is_keyframe = true,
                Some(NAL_SPS) => self.has_sps = true,
                Some(NAL_PPS) => self.has_pps = true,
                _ => {}
            }
            self.annexb.extend_from_slice(nal);
        }
        if marker && !self.annexb.is_empty() {
            Some(self.flush())
        } else {
            None
        }
    }

    /// Whether a partial access unit is currently buffered (no marker seen yet).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.annexb.is_empty()
    }

    /// Force-emit any buffered access unit (e.g. at end-of-stream when no closing
    /// marker arrives). Returns `None` if nothing is buffered.
    pub fn finish(&mut self) -> Option<AccessUnit> {
        if self.annexb.is_empty() {
            None
        } else {
            Some(self.flush())
        }
    }

    fn flush(&mut self) -> AccessUnit {
        let au = AccessUnit {
            annexb: std::mem::take(&mut self.annexb),
            is_keyframe: self.is_keyframe,
            has_sps: self.has_sps,
            has_pps: self.has_pps,
        };
        self.is_keyframe = false;
        self.has_sps = false;
        self.has_pps = false;
        au
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_nal_emits_with_start_code() {
        let mut d = H264Depacketizer::new();
        // NAL type 1 (non-IDR slice).
        let out = d.push(&[0x41, 0xAA, 0xBB]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![0, 0, 0, 1, 0x41, 0xAA, 0xBB]);
    }

    #[test]
    fn stap_a_splits_aggregated_nals() {
        // STAP-A header 0x78, then [size=2|SPS bytes][size=3|PPS bytes].
        let mut payload = vec![0x78];
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&[0x67, 0x42]); // SPS (type 7)
        payload.extend_from_slice(&3u16.to_be_bytes());
        payload.extend_from_slice(&[0x68, 0xCE, 0x3C]); // PPS (type 8)
        let mut d = H264Depacketizer::new();
        let out = d.push(&payload).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], vec![0, 0, 0, 1, 0x67, 0x42]);
        assert_eq!(out[1], vec![0, 0, 0, 1, 0x68, 0xCE, 0x3C]);
        assert_eq!(nal_type(out[0][4]), NAL_SPS);
        assert_eq!(nal_type(out[1][4]), NAL_PPS);
    }

    #[test]
    fn fu_a_reassembles_idr_across_packets() {
        let mut d = H264Depacketizer::new();
        // FU indicator 0x7c = F0|NRI3|type28; FU header 0x85 = S=1,E=0,type5 (IDR).
        assert!(d.push(&[0x7c, 0x85, 0x11, 0x22]).unwrap().is_empty());
        assert!(d.has_pending_fragment());
        // Middle fragment (S=0,E=0).
        assert!(d.push(&[0x7c, 0x05, 0x33]).unwrap().is_empty());
        // End fragment (E=1).
        let out = d.push(&[0x7c, 0x45, 0x44]).unwrap();
        assert_eq!(out.len(), 1);
        // Reconstructed NAL header = (0x7c & 0xe0) | (0x85 & 0x1f) = 0x60 | 0x05 = 0x65.
        assert_eq!(out[0], vec![0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33, 0x44]);
        assert!(is_keyframe_nal(&out[0]), "type 5 = IDR keyframe");
        assert!(!d.has_pending_fragment());
    }

    // NEGATIVE: an FU-A continuation without a start fails loud (packet loss).
    #[test]
    fn fu_a_continuation_without_start_errors() {
        let mut d = H264Depacketizer::new();
        assert!(matches!(
            d.push(&[0x7c, 0x05, 0x33]),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: an empty payload is rejected.
    #[test]
    fn empty_payload_errors() {
        let mut d = H264Depacketizer::new();
        assert!(matches!(d.push(&[]), Err(Error::Transport(_))));
    }

    // NEGATIVE: a STAP-A whose size overruns the payload is rejected.
    #[test]
    fn stap_a_overrun_errors() {
        let mut payload = vec![0x78];
        payload.extend_from_slice(&99u16.to_be_bytes()); // claims 99 bytes
        payload.extend_from_slice(&[0x67, 0x42]);
        let mut d = H264Depacketizer::new();
        assert!(matches!(d.push(&payload), Err(Error::Transport(_))));
    }

    // NEGATIVE: an out-of-range NAL type (e.g. 0) is rejected.
    #[test]
    fn unsupported_nal_type_errors() {
        let mut d = H264Depacketizer::new();
        assert!(matches!(d.push(&[0x00, 0x11]), Err(Error::Transport(_))));
        assert!(!is_supported_nal(0x00));
        assert!(is_supported_nal(0x41)); // type 1
        assert!(is_supported_nal(0x78)); // STAP-A
        assert!(is_supported_nal(0x7c)); // FU-A
    }

    // ── AccessUnitAssembler ────────────────────────────────────────────────

    /// Helper: an Annex-B NAL with a given type byte (F/NRI = 0) + body.
    fn nal(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut v = ANNEXB_START_CODE.to_vec();
        v.push(ty & 0x1f);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn access_unit_flushes_on_marker_and_flags_keyframe() {
        let mut asm = AccessUnitAssembler::new();
        // SPS, PPS, IDR arrive across three marker-clear packets …
        assert!(asm.push(&[nal(NAL_SPS, &[0x42])], false).is_none());
        assert!(asm.has_pending());
        assert!(asm.push(&[nal(NAL_PPS, &[0xCE])], false).is_none());
        // … then the IDR with the marker bit closes the access unit.
        let au = asm
            .push(&[nal(NAL_IDR, &[0x11, 0x22])], true)
            .expect("marker closes the AU");
        assert!(au.is_keyframe);
        assert!(au.has_sps && au.has_pps);
        assert!(au.is_decodable_keyframe());
        // The AU is the concatenation of all three start-code-prefixed NALs.
        let mut expected = nal(NAL_SPS, &[0x42]);
        expected.extend(nal(NAL_PPS, &[0xCE]));
        expected.extend(nal(NAL_IDR, &[0x11, 0x22]));
        assert_eq!(au.annexb, expected);
        // State resets: the next AU starts clean.
        assert!(!asm.has_pending());
    }

    #[test]
    fn access_unit_non_idr_is_not_keyframe() {
        let mut asm = AccessUnitAssembler::new();
        let au = asm
            .push(&[nal(1, &[0xAA])], true) // type 1 = non-IDR slice
            .expect("marker closes the AU");
        assert!(!au.is_keyframe);
        assert!(!au.is_decodable_keyframe());
    }

    #[test]
    fn access_unit_finish_emits_trailing_partial() {
        let mut asm = AccessUnitAssembler::new();
        // No marker ever arrives; finish() must still drain the buffered AU.
        assert!(asm.push(&[nal(1, &[0x01])], false).is_none());
        let au = asm.finish().expect("finish drains the trailing AU");
        assert_eq!(au.annexb, nal(1, &[0x01]));
        // Idempotent: nothing left to flush.
        assert!(asm.finish().is_none());
    }

    #[test]
    fn access_unit_debug_redacts_video_bytes() {
        let au = AccessUnit {
            annexb: vec![0, 0, 0, 1, 0x65, 0xDE, 0xAD],
            is_keyframe: true,
            has_sps: false,
            has_pps: false,
        };
        let dbg = format!("{au:?}");
        assert!(dbg.contains("annexb_len"));
        assert!(!dbg.contains("DEAD") && !dbg.contains("dead"));
    }
}
