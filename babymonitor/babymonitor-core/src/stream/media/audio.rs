//! **Downstream** camera audio (camera→app, the baby's room) — raw **16 kHz mono
//! S16LE PCM**, NOT G.711.
//!
//! # The correction this module pins (cap4 ground truth)
//!
//! The earlier assumption — that the audio channel is G.711 µ-law (PCMU, PT 0,
//! 8 kHz), the [`super::g711`] path — is **wrong for the downstream direction**.
//! The cap4 capture settles it: the camera's audio on the media `conv = 2`
//! ([`super::kcp::AUDIO_CONV`]) is **little-endian signed-16-bit PCM at 16 kHz,
//! mono**, carried verbatim as the RTP payload after the fixed-12B PATH-A header
//! (`emulator_captures/cap4/stage6_extract.py`: `extract_audio` concatenates the
//! post-header payloads and writes them as `wave` `nchannels=1 sampwidth=2
//! framerate=16000`; the result byte-matches `secrets/cap4_audio.s16le`,
//! 1 532 800 bytes — validated end-to-end in `tests/cap4_replay.rs` and
//! `tests/cap4_audio_downstream.rs`).
//!
//! So the downstream "decode" is the **identity** transform: the
//! [`MediaUnit`](super::MediaUnit) `payload` for the audio conv *is already* the
//! S16LE samples. This module exists to (a) make that explicit and named, (b) pin
//! the sample format the MPEG-TS muxer must be told (`-f s16le -ar 16000 -ac 1`),
//! and (c) keep the downstream path clearly separated from the talk-back G.711
//! path so the two are never conflated again.
//!
//! # Direction map (do not conflate)
//!
//! | direction | conv | format | module |
//! |---|---|---|---|
//! | **downstream** camera→app (listen to baby) | `2` | raw **S16LE @ 16 kHz mono** | **this module** |
//! | **talk-back** app→camera (speak to baby) | — | G.711 µ-law (PCMU, PT 0, 8 kHz) | [`super::g711`] |
//!
//! Confidence: **[C]** — byte-exact against the cap4 capture (the 16 kHz / mono /
//! S16LE container parameters are pinned by `stage6_extract.py` and the
//! byte-identical replay; an 8 kHz or µ-law mis-treatment would shift every sample
//! and fail the byte compare).

/// Downstream camera-audio sample rate (Hz) — 16 kHz (cap4 `AUDIO_RATE`).
pub const DOWNSTREAM_SAMPLE_RATE_HZ: u32 = 16_000;

/// Downstream camera-audio channel count — mono.
pub const DOWNSTREAM_CHANNELS: u16 = 1;

/// Bytes per S16LE sample (signed 16-bit = 2 bytes).
pub const BYTES_PER_SAMPLE: usize = 2;

/// The ffmpeg raw-PCM input format string for the downstream audio
/// (`-f s16le -ar 16000 -ac 1`). Pinned so the muxer is fed the correct
/// container parameters.
pub const FFMPEG_INPUT_FORMAT: &str = "s16le";

/// Treat a downstream-audio [`MediaUnit`](super::MediaUnit) payload as the raw
/// S16LE PCM it already is, returning it unchanged for muxing.
///
/// This is deliberately the identity transform: the camera sends 16 kHz mono
/// S16LE directly as the RTP payload (cap4), so there is nothing to decode — the
/// function names the contract and is the single call site the muxer feeds. (A
/// G.711 `mulaw_decode` here would be the very bug this module corrects.)
#[must_use]
pub fn downstream_pcm_s16le(payload: &[u8]) -> &[u8] {
    payload
}

/// The number of whole S16LE samples in a downstream-audio payload (`len / 2`).
/// A trailing odd byte (never expected on a well-formed frame) is not counted.
#[must_use]
pub fn sample_count(payload: &[u8]) -> usize {
    payload.len() / BYTES_PER_SAMPLE
}

/// Playback duration (whole milliseconds) of a downstream-audio byte run at the
/// pinned 16 kHz mono S16LE rate. Used only for human-facing diagnostics.
#[must_use]
pub fn duration_ms(total_bytes: usize) -> u64 {
    let samples = (total_bytes / BYTES_PER_SAMPLE) as u64;
    samples * 1000 / u64::from(DOWNSTREAM_SAMPLE_RATE_HZ)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_constants_match_cap4_ground_truth() {
        // cap4 stage6_extract.py: AUDIO_RATE=16000, wave nchannels=1 sampwidth=2.
        assert_eq!(DOWNSTREAM_SAMPLE_RATE_HZ, 16_000);
        assert_eq!(DOWNSTREAM_CHANNELS, 1);
        assert_eq!(BYTES_PER_SAMPLE, 2);
        assert_eq!(FFMPEG_INPUT_FORMAT, "s16le");
    }

    #[test]
    fn downstream_pcm_is_identity() {
        // The payload IS the S16LE samples — the "decode" must not alter a byte
        // (this is the explicit anti-regression vs the G.711 mistreatment).
        let payload = [0x00u8, 0x80, 0xFF, 0x7F, 0x34, 0x12];
        assert_eq!(downstream_pcm_s16le(&payload), &payload);
        assert!(downstream_pcm_s16le(&[]).is_empty());
    }

    #[test]
    fn sample_and_duration_math() {
        // 1 532 800 bytes (the cap4 truth) = 766 400 samples = 47 900 ms @ 16 kHz.
        assert_eq!(sample_count(&vec![0u8; 1_532_800]), 766_400);
        assert_eq!(duration_ms(1_532_800), 47_900);
        // An odd trailing byte is not a whole sample.
        assert_eq!(sample_count(&[0u8; 5]), 2);
    }
}
