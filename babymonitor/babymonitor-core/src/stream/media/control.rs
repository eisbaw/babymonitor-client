//! The **conv=0 imm control channel**: the client-initiated KCP control PDUs that
//! make the SCD921 begin streaming after ICE validates (`re/media_start_handshake.md`,
//! TASK-0083).
//!
//! # Why this exists
//! After ICE validates (the camera answers our plain connectivity check), the
//! camera still does **not** stream until the *client* sends KCP control packets
//! first. cap4's working flow proves it: the app sends three conv=0 KCP PUSH
//! segments (capture frames 253–255), each carrying a 28-byte `imm` control PDU,
//! and the camera begins streaming ~37 ms later (frame 256, then conv=1 video at
//! 259). Our client did ICE then only *received* → camera-silent media. Replaying
//! these PDUs is the fix.
//!
//! # The 28-byte `imm` control PDU
//! Little-endian, decrypted from cap4 (key#0, HMAC-confirmed —
//! `re/media_start_handshake.md` §"The 28-byte imm control PDU"). Field layout:
//!
//! ```text
//! @0  magic = 0x12345678   (constant — the imm control marker)
//! @4  u32   per-message:  f253=0x00010004  f254=0x00010003  f255=0x00010005
//! @8  u32   = 0
//! @12 u32   per-message:  f253=9          f254=6           f255=0x00040006
//! @16 u32   = 8           (constant across the three)
//! @20 u32   = 0
//! @24 u32   per-message:  f253=4          f254=0           f255=4
//! ```
//!
//! These are **protocol constants / small codes — NO session tokens, no creds**
//! (`re/media_start_handshake.md` §"The 28-byte imm control PDU"), so they are
//! replayable verbatim in a fresh session (the AES/HMAC that seal them on the wire
//! use the new session's `a=aes-key`; the *plaintext* PDU is the same). They are
//! reproduced here as exact byte templates — the literals are the ground truth; the
//! [`build_media_start_pdu`] builder only documents the field structure and is
//! cross-checked against the literals in tests.

/// The conv (KCP channel id) the media-start control PDUs ride on (cap4: the app's
/// conv=0 send stream). Demuxed away from the video (`1`) / audio (`2`) media convs.
pub const MEDIA_START_CONV: u32 = 0;

/// The constant `imm` control marker at PDU offset 0 (little-endian `u32`).
pub const MEDIA_START_MAGIC: u32 = 0x1234_5678;

/// Length of one `imm` control PDU, in bytes.
pub const MEDIA_START_PDU_LEN: usize = 28;

/// PDU **A** — cap4 frame 253 (`78563412 04000100 00000000 09000000 08000000
/// 00000000 04000000`), the verbatim decrypted plaintext.
pub const PDU_F253: [u8; MEDIA_START_PDU_LEN] = [
    0x78, 0x56, 0x34, 0x12, // @0  magic 0x12345678
    0x04, 0x00, 0x01, 0x00, // @4  0x00010004
    0x00, 0x00, 0x00, 0x00, // @8  0
    0x09, 0x00, 0x00, 0x00, // @12 9
    0x08, 0x00, 0x00, 0x00, // @16 8
    0x00, 0x00, 0x00, 0x00, // @20 0
    0x04, 0x00, 0x00, 0x00, // @24 4
];

/// PDU **B** — cap4 frame 254 (`78563412 03000100 00000000 06000000 08000000
/// 00000000 00000000`), the verbatim decrypted plaintext.
pub const PDU_F254: [u8; MEDIA_START_PDU_LEN] = [
    0x78, 0x56, 0x34, 0x12, // @0  magic 0x12345678
    0x03, 0x00, 0x01, 0x00, // @4  0x00010003
    0x00, 0x00, 0x00, 0x00, // @8  0
    0x06, 0x00, 0x00, 0x00, // @12 6
    0x08, 0x00, 0x00, 0x00, // @16 8
    0x00, 0x00, 0x00, 0x00, // @20 0
    0x00, 0x00, 0x00, 0x00, // @24 0
];

/// PDU **C** — cap4 frame 255 (`78563412 05000100 00000000 06000400 08000000
/// 00000000 04000000`), the verbatim decrypted plaintext.
pub const PDU_F255: [u8; MEDIA_START_PDU_LEN] = [
    0x78, 0x56, 0x34, 0x12, // @0  magic 0x12345678
    0x05, 0x00, 0x01, 0x00, // @4  0x00010005
    0x00, 0x00, 0x00, 0x00, // @8  0
    0x06, 0x00, 0x04, 0x00, // @12 0x00040006
    0x08, 0x00, 0x00, 0x00, // @16 8
    0x00, 0x00, 0x00, 0x00, // @20 0
    0x04, 0x00, 0x00, 0x00, // @24 4
];

/// The three media-start control PDUs, in the exact send order the cap4 app used
/// (frames 253 → 254 → 255). Replayed verbatim as KCP PUSH payloads on
/// [`MEDIA_START_CONV`]. **Ground truth** (`re/media_start_handshake.md`).
pub const MEDIA_START_PDUS: [[u8; MEDIA_START_PDU_LEN]; 3] = [PDU_F253, PDU_F254, PDU_F255];

/// Build one `imm` control PDU from its three per-message fields (`@4`, `@12`,
/// `@24`), with the constant `@0` magic / `@16` = 8 / `@8` = `@20` = 0 (the field
/// layout documented in the module header). This only **documents** the structure
/// — [`MEDIA_START_PDUS`] is the on-wire ground truth; the builder is cross-checked
/// against the literals in tests.
#[must_use]
pub fn build_media_start_pdu(f4: u32, f12: u32, f24: u32) -> [u8; MEDIA_START_PDU_LEN] {
    let mut p = [0u8; MEDIA_START_PDU_LEN];
    p[0..4].copy_from_slice(&MEDIA_START_MAGIC.to_le_bytes());
    p[4..8].copy_from_slice(&f4.to_le_bytes());
    // @8 stays 0.
    p[12..16].copy_from_slice(&f12.to_le_bytes());
    p[16..20].copy_from_slice(&8u32.to_le_bytes());
    // @20 stays 0.
    p[24..28].copy_from_slice(&f24.to_le_bytes());
    p
}

/// Read the little-endian `u32` at offset 0 of a PDU (the `imm` magic marker).
#[must_use]
pub fn pdu_magic(pdu: &[u8; MEDIA_START_PDU_LEN]) -> u32 {
    u32::from_le_bytes([pdu[0], pdu[1], pdu[2], pdu[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    // The first PDU must be the verbatim f253 literal, 28 bytes, magic 0x12345678
    // (the task's required assertion). The literal is re-stated inline so the test
    // is a real cross-check, not a tautology against the same constant.
    #[test]
    fn pdu0_is_the_f253_literal_with_imm_magic() {
        let f253: [u8; 28] = [
            0x78, 0x56, 0x34, 0x12, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        ];
        assert_eq!(MEDIA_START_PDUS[0].len(), MEDIA_START_PDU_LEN);
        assert_eq!(MEDIA_START_PDU_LEN, 28);
        assert_eq!(
            MEDIA_START_PDUS[0], f253,
            "PDU[0] must equal the f253 literal"
        );
        assert_eq!(pdu_magic(&MEDIA_START_PDUS[0]), 0x1234_5678);
        assert_eq!(pdu_magic(&MEDIA_START_PDUS[0]), MEDIA_START_MAGIC);
    }

    // Every PDU is 28 bytes and carries the imm magic at @0.
    #[test]
    fn all_pdus_are_28b_with_magic() {
        for pdu in &MEDIA_START_PDUS {
            assert_eq!(pdu.len(), 28);
            assert_eq!(pdu_magic(pdu), MEDIA_START_MAGIC);
        }
    }

    // The builder reproduces each literal from its three per-message fields — this
    // documents the @4 / @12 / @24 field semantics AND guards a typo in the literals.
    #[test]
    fn builder_reproduces_the_literals() {
        assert_eq!(build_media_start_pdu(0x0001_0004, 9, 4), PDU_F253);
        assert_eq!(build_media_start_pdu(0x0001_0003, 6, 0), PDU_F254);
        assert_eq!(build_media_start_pdu(0x0001_0005, 0x0004_0006, 4), PDU_F255);
    }
}
