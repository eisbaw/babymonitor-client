//! G.711 µ-law (PCMU, RTP **PT 0**) decode — a 256-entry lookup table → 16-bit
//! signed PCM (`re/media_decode_spec.md` §4 Step D, §5).
//!
//! # ⚠ This is the TALK-BACK (app→camera) direction ONLY
//!
//! G.711 µ-law @ 8 kHz is the **upstream** "speak to the baby" audio, NOT the
//! camera's downstream audio. The **downstream** camera audio (camera→app, the
//! one you listen to) is raw **16 kHz mono S16LE PCM** on `conv = 2` — see
//! [`super::audio`], cap4-validated byte-exact. Do **not** run this µ-law decode
//! on the downstream payload: it would halve the rate and mangle every sample
//! (that conflation was the original "audio bug"). This module is retained for the
//! talk-back path and as the documented PCMU codec.
//!
//! µ-law has no sync word, so correctness is validated structurally (RTP `PT == 0`)
//! plus the decoded amplitude envelope — `re/media_decode_spec.md` §4 marks PT/ts
//! as **[C]** and the talk-back audio plausibility as **[I]**.
//!
//! The decode is the standard ITU-T G.711 µ-law expansion (the Sun `g711.c`
//! reference): bias `0x84`, 8-bit code → 14-bit magnitude → sign. It is a pure,
//! input-independent table, so we bake it at compile time as a `const` LUT and
//! pin its anchor values in tests.

/// Sample rate of a G.711 PCMU stream (8 kHz), in Hz. The RTP clock for PT 0.
pub const PCMU_SAMPLE_RATE_HZ: u32 = 8_000;

/// RTP payload type for G.711 µ-law (PCMU) — the static PT the cap3 audio
/// channel uses (`re/media_decode_spec.md` §4).
pub const PCMU_PAYLOAD_TYPE: u8 = 0;

/// The G.711 µ-law expansion bias (`0x84`) from the ITU-T reference algorithm.
const MULAW_BIAS: i32 = 0x84;

/// Decode one µ-law code byte to a 16-bit signed PCM sample (ITU-T G.711, the
/// Sun `g711.c` `ulaw2linear`). `const` so the whole [`MULAW_LUT`] is built at
/// compile time.
const fn mulaw_to_linear(code: u8) -> i16 {
    // The code is stored complemented on the wire; invert to recover the fields.
    let u = !code;
    let mantissa = (u & 0x0f) as i32;
    let exponent = ((u & 0x70) >> 4) as i32;
    // 4-bit mantissa → 14-bit magnitude, then apply the exponent shift.
    let magnitude = (((mantissa << 3) + MULAW_BIAS) << exponent) - MULAW_BIAS;
    if u & 0x80 != 0 {
        // Sign bit set → negative sample.
        (-magnitude) as i16
    } else {
        magnitude as i16
    }
}

/// Build the 256-entry µ-law → linear-PCM lookup table at compile time.
const fn build_mulaw_lut() -> [i16; 256] {
    let mut lut = [0i16; 256];
    let mut i = 0;
    while i < 256 {
        lut[i] = mulaw_to_linear(i as u8);
        i += 1;
    }
    lut
}

/// The 256-entry G.711 µ-law → 16-bit signed PCM decode table. Index by the raw
/// µ-law code byte.
pub static MULAW_LUT: [i16; 256] = build_mulaw_lut();

/// Decode a G.711 µ-law (PCMU) RTP payload to 16-bit signed PCM samples (one
/// `i16` per input byte; 8 kHz mono).
#[must_use]
pub fn mulaw_decode(payload: &[u8]) -> Vec<i16> {
    payload.iter().map(|&b| MULAW_LUT[b as usize]).collect()
}

/// Decode a G.711 µ-law (PCMU) payload directly to little-endian `s16le` bytes —
/// the raw-PCM layout a downstream player/muxer (e.g. `ffmpeg -f s16le -ar 8000
/// -ac 1`) consumes. Two bytes per input sample.
#[must_use]
pub fn mulaw_decode_s16le(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() * 2);
    for &b in payload {
        out.extend_from_slice(&MULAW_LUT[b as usize].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The four ITU-T G.711 µ-law anchor codes (Sun g711.c reference values).
    // These pin the LUT against the canonical expansion — a wrong bias/shift
    // moves them immediately.
    #[test]
    fn mulaw_anchor_values_match_itu_reference() {
        assert_eq!(MULAW_LUT[0x00], -32124, "code 0x00 = max-negative");
        assert_eq!(MULAW_LUT[0x80], 32124, "code 0x80 = max-positive");
        assert_eq!(MULAW_LUT[0xFF], 0, "code 0xFF = +zero (silence)");
        assert_eq!(MULAW_LUT[0x7F], 0, "code 0x7F = -zero (silence)");
    }

    // A handful of additional reference points across the range.
    #[test]
    fn mulaw_midrange_values_match_itu_reference() {
        // Computed from ulaw2linear(): independently re-derivable.
        assert_eq!(MULAW_LUT[0x01], -31100);
        assert_eq!(MULAW_LUT[0x40], -1884);
        assert_eq!(MULAW_LUT[0xC0], 1884);
    }

    // The decode is symmetric about the sign bit (|+code| == |−code|) for the
    // µ-law layout, a structural invariant of the table.
    #[test]
    fn mulaw_is_sign_symmetric() {
        for c in 0u16..128 {
            let neg = MULAW_LUT[c as usize]; // top bit clear after complement? check magnitude
            let pos = MULAW_LUT[(c + 128) as usize];
            assert_eq!(
                neg.unsigned_abs(),
                pos.unsigned_abs(),
                "magnitude mismatch for code pair {c}/{}",
                c + 128
            );
        }
    }

    #[test]
    fn mulaw_decode_maps_each_byte_to_one_sample() {
        let payload = [0x00u8, 0x80, 0xFF, 0x7F];
        let pcm = mulaw_decode(&payload);
        assert_eq!(pcm, vec![-32124, 32124, 0, 0]);
        // s16le is little-endian, two bytes per sample.
        let le = mulaw_decode_s16le(&payload);
        assert_eq!(le.len(), payload.len() * 2);
        assert_eq!(&le[0..2], &(-32124i16).to_le_bytes());
        assert_eq!(&le[2..4], &32124i16.to_le_bytes());
    }

    #[test]
    fn empty_payload_decodes_to_empty() {
        assert!(mulaw_decode(&[]).is_empty());
        assert!(mulaw_decode_s16le(&[]).is_empty());
    }

    // The full LUT stays within the documented G.711 µ-law magnitude bound
    // (±32124) — no entry overflows i16 / leaves the valid range.
    #[test]
    fn mulaw_lut_within_g711_magnitude_bound() {
        for (code, &v) in MULAW_LUT.iter().enumerate() {
            assert!(
                (-32124..=32124).contains(&(v as i32)),
                "code {code:#04x} decoded to out-of-range {v}"
            );
        }
    }
}
