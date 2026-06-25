//! The `imm_p2p_rtc_frame_t` → typed [`Frame`] model + codec ids
//! (`re/webrtc_session.md` §4).
//!
//! The native frame plane (`imm_p2p_rtc_recv_frame` / `_send_frame`,
//! `re/ghidra/imm_p2p_rtc_recv_frame.c`) exchanges a `imm_p2p_rtc_frame_t`:
//!
//! ```c
//! typedef struct imm_p2p_rtc_frame_t {   // 0x28 bytes used
//!     /* 0x00 */ void*    payload;    // data pointer
//!     /* 0x08 */ uint32_t capacity;   // buffer capacity (recv IN)
//!     /* 0x0c */ uint32_t length;     // filled length (recv OUT / send IN)
//!     /* 0x10 */ uint64_t pts;        // presentation ts (RTP ts >>3 & 0x1fffffff)
//!     /* 0x18 */ uint64_t dts;        // == pts on recv
//!     /* 0x20 */ uint32_t type;       // 0=audio, 1=video, 2=video KEYFRAME
//!     /* 0x24 */ uint32_t _pad;
//! } imm_p2p_rtc_frame_t;
//! ```
//!
//! On the Rust/webrtc-rs side, the actual RTP de-paid payload arrives from the
//! SRTP tracks; this module is the typed shape that wraps a decoded-payload-ready
//! unit, mirroring the native `type`/`pts`/`dts`/`length` semantics so the
//! decode/render layer (a follow-up — TASK-0037) consumes a clean model.
//!
//! # Honesty (`re/webrtc_session.md` §4a caveat)
//! The native `type` field distinguishes only {audio=0, video=1, keyframe=2};
//! the exact CODEC-id enum (H.264 vs Opus vs PCMU) is NOT named in the two frame
//! functions — the codec is implied by which list (audio vs video) the frame
//! came from. We therefore model `kind` (the directly-recovered audio/video/
//! keyframe split) separately from `codec` (an OPTIONAL hint the caller supplies
//! from the negotiated SDP, NOT read from the frame struct). We do not invent a
//! codec id the struct does not carry.

use crate::Error;

/// The native `imm_p2p_rtc_frame_t.type` integer for an AUDIO frame.
pub const FRAME_TYPE_AUDIO: u32 = 0;
/// The native `type` integer for a non-keyframe VIDEO frame.
pub const FRAME_TYPE_VIDEO: u32 = 1;
/// The native `type` integer for a VIDEO KEYFRAME/IDR boundary.
pub const FRAME_TYPE_VIDEO_KEYFRAME: u32 = 2;

/// The directly-recovered frame kind (the audio/video/keyframe split from the
/// native `type` field — `re/webrtc_session.md` §4a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Audio frame (`type == 0`; the native audio frame list).
    Audio,
    /// Non-keyframe video (`type == 1`; the native video frame list).
    Video,
    /// Video keyframe / IDR boundary (`type == 2`).
    VideoKeyframe,
}

impl FrameKind {
    /// Decode a native `imm_p2p_rtc_frame_t.type` integer.
    ///
    /// # Errors
    /// [`Error::Frame`] for an unrecognized `type` value — we surface it rather
    /// than coercing to a default, so an unexpected wire value fails loud.
    pub fn from_native_type(t: u32) -> Result<Self, Error> {
        match t {
            FRAME_TYPE_AUDIO => Ok(Self::Audio),
            FRAME_TYPE_VIDEO => Ok(Self::Video),
            FRAME_TYPE_VIDEO_KEYFRAME => Ok(Self::VideoKeyframe),
            other => Err(Error::Frame(format!(
                "unrecognized imm_p2p_rtc_frame_t.type = {other} (expected 0/1/2)"
            ))),
        }
    }

    /// The native `type` integer this kind corresponds to.
    #[must_use]
    pub fn as_native_type(self) -> u32 {
        match self {
            Self::Audio => FRAME_TYPE_AUDIO,
            Self::Video => FRAME_TYPE_VIDEO,
            Self::VideoKeyframe => FRAME_TYPE_VIDEO_KEYFRAME,
        }
    }

    /// Whether this frame carries video (keyframe or not).
    #[must_use]
    pub fn is_video(self) -> bool {
        matches!(self, Self::Video | Self::VideoKeyframe)
    }

    /// Whether this is a keyframe boundary (the decoder may resync here).
    #[must_use]
    pub fn is_keyframe(self) -> bool {
        matches!(self, Self::VideoKeyframe)
    }
}

/// A media codec id — the codecs the Rust decode layer needs
/// (`re/webrtc_session.md` §4d). NOT read from the frame struct; supplied by the
/// caller from the negotiated SDP rtpmap. Kept as a closed enum of the codecs
/// the spec confirms for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264 video (OpenH264; packetization-mode 1) — the SCD921 video codec.
    H264,
    /// G.711 µ-law (PCMU/8000) — the SDP-negotiated audio codec.
    Pcmu,
    /// Opus — the higher-quality two-way-talk audio codec.
    Opus,
}

impl Codec {
    /// Map an SDP rtpmap codec name (case-insensitive) to a [`Codec`].
    ///
    /// # Errors
    /// [`Error::Frame`] for a codec name not in the confirmed set — we do not
    /// silently accept an unknown codec.
    pub fn from_rtpmap_name(name: &str) -> Result<Self, Error> {
        match name.to_ascii_uppercase().as_str() {
            "H264" => Ok(Self::H264),
            "PCMU" => Ok(Self::Pcmu),
            "OPUS" => Ok(Self::Opus),
            other => Err(Error::Frame(format!(
                "unsupported rtpmap codec `{other}` (expected H264/PCMU/OPUS)"
            ))),
        }
    }

    /// Whether this codec is audio.
    #[must_use]
    pub fn is_audio(self) -> bool {
        matches!(self, Self::Pcmu | Self::Opus)
    }
}

/// A typed media frame: the decoded-payload-ready unit the native `recv_frame`
/// hands out, in safe Rust (`re/webrtc_session.md` §4a/§4b).
///
/// `payload` is the RTP-de-paid media bytes (past the native 0x48-byte RTP
/// header on the device side; webrtc-rs de-pays on the Rust side). `pts`/`dts`
/// are the presentation/decode timestamps (the native side sets `dts == pts`).
/// `codec` is an OPTIONAL hint, since the native frame struct does not name the
/// codec (see module docs).
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// The de-paid media payload.
    pub payload: Vec<u8>,
    /// Presentation timestamp (native: `RTP ts >> 3 & 0x1fffffff`).
    pub pts: u64,
    /// Decode timestamp (native sets `dts == pts` on recv).
    pub dts: u64,
    /// Audio / video / keyframe (the directly-recovered `type` split).
    pub kind: FrameKind,
    /// Optional codec hint from the negotiated SDP (NOT from the frame struct).
    pub codec: Option<Codec>,
}

impl Frame {
    /// Build a [`Frame`] from the native field values, validating the `type`.
    ///
    /// This is the seam the (follow-up) recv loop calls once it has de-paid an
    /// RTP packet: pass the native `type` integer, the payload, and the pts; the
    /// dts mirrors the pts (native semantics).
    ///
    /// # Errors
    /// [`Error::Frame`] if `native_type` is not 0/1/2, or if `payload` is empty
    /// (the native recv path validates `payload != NULL && capacity != 0`; an
    /// empty payload is a malformed frame).
    pub fn from_native(
        native_type: u32,
        payload: Vec<u8>,
        pts: u64,
        codec: Option<Codec>,
    ) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::Frame(
                "frame payload is empty (native recv requires non-NULL payload)".into(),
            ));
        }
        let kind = FrameKind::from_native_type(native_type)?;
        Ok(Self {
            payload,
            pts,
            dts: pts,
            kind,
            codec,
        })
    }
}

impl std::fmt::Debug for Frame {
    /// Prints metadata + payload LENGTH only — never the raw media bytes (which
    /// are large and, on the live path, the user's own video).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("payload_len", &self.payload.len())
            .field("pts", &self.pts)
            .field("dts", &self.dts)
            .field("kind", &self.kind)
            .field("codec", &self.codec)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_kind_maps_native_types() {
        assert_eq!(FrameKind::from_native_type(0).unwrap(), FrameKind::Audio);
        assert_eq!(FrameKind::from_native_type(1).unwrap(), FrameKind::Video);
        assert_eq!(
            FrameKind::from_native_type(2).unwrap(),
            FrameKind::VideoKeyframe
        );
        assert!(FrameKind::Video.is_video());
        assert!(FrameKind::VideoKeyframe.is_keyframe());
        assert!(!FrameKind::Audio.is_video());
        // Round-trips back to the native integer.
        assert_eq!(FrameKind::Audio.as_native_type(), 0);
        assert_eq!(FrameKind::VideoKeyframe.as_native_type(), 2);
    }

    // NEGATIVE: an unrecognized type integer must error, not coerce to a default.
    #[test]
    fn frame_kind_rejects_unknown_type() {
        assert!(matches!(
            FrameKind::from_native_type(7),
            Err(Error::Frame(_))
        ));
        assert!(matches!(
            FrameKind::from_native_type(u32::MAX),
            Err(Error::Frame(_))
        ));
    }

    #[test]
    fn codec_maps_rtpmap_names_case_insensitively() {
        assert_eq!(Codec::from_rtpmap_name("H264").unwrap(), Codec::H264);
        assert_eq!(Codec::from_rtpmap_name("h264").unwrap(), Codec::H264);
        assert_eq!(Codec::from_rtpmap_name("PCMU").unwrap(), Codec::Pcmu);
        assert_eq!(Codec::from_rtpmap_name("opus").unwrap(), Codec::Opus);
        assert!(Codec::Pcmu.is_audio());
        assert!(Codec::Opus.is_audio());
        assert!(!Codec::H264.is_audio());
    }

    // NEGATIVE: an unsupported codec name is rejected, not silently accepted.
    #[test]
    fn codec_rejects_unknown_name() {
        assert!(matches!(
            Codec::from_rtpmap_name("VP9"),
            Err(Error::Frame(_))
        ));
    }

    #[test]
    fn frame_from_native_sets_dts_equal_pts() {
        let f =
            Frame::from_native(2, vec![0x00, 0x00, 0x01, 0x65], 12345, Some(Codec::H264)).unwrap();
        assert_eq!(f.kind, FrameKind::VideoKeyframe);
        assert_eq!(f.pts, 12345);
        assert_eq!(f.dts, 12345, "native recv sets dts == pts");
        assert!(f.kind.is_keyframe());
        assert_eq!(f.codec, Some(Codec::H264));
    }

    // NEGATIVE: an empty payload is a malformed frame (native requires non-NULL).
    #[test]
    fn frame_from_native_rejects_empty_payload() {
        assert!(matches!(
            Frame::from_native(0, Vec::new(), 0, None),
            Err(Error::Frame(_))
        ));
    }

    // NEGATIVE: an invalid native type propagates through from_native.
    #[test]
    fn frame_from_native_rejects_bad_type() {
        assert!(matches!(
            Frame::from_native(9, vec![1, 2, 3], 0, None),
            Err(Error::Frame(_))
        ));
    }

    // Debug must not dump raw payload bytes (only the length).
    #[test]
    fn debug_hides_payload_bytes() {
        let f = Frame::from_native(1, vec![0xDE, 0xAD, 0xBE, 0xEF], 1, None).unwrap();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("payload_len"));
        assert!(dbg.contains('4')); // the length
        assert!(!dbg.contains("DEAD") && !dbg.contains("dead"));
    }
}
