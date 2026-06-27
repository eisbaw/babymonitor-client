//! cap4 **real-media** replay validation — LOCAL-ONLY, `#[ignore]`d.
//!
//! Drives the committed Rust media pipeline
//! ([`babymonitor_core::stream::media::MediaEngine`]) over the real cap4 capture
//! and asserts it reconstructs **byte-identical** output to the independently
//! pinned ground truth (the Decrypt phase). This is the end-to-end proof that the
//! Rust transport+decrypt matches the wire, not just synthetic vectors.
//!
//! ## Why `#[ignore]`d
//! cap4 is REAL baby-video ciphertext + live keys — HIGHLY SENSITIVE. The inputs
//! (`media.pcap`, `cap4_keys.txt`) and the ground-truth outputs
//! (`cap4_video.h264`, `cap4_audio.s16le`) live under gitignored
//! `emulator_captures/cap4/` and `secrets/`. This test **reads them at runtime**;
//! it never inlines key/frame/video bytes (the test source is tracked). It is
//! `#[ignore]`d so `just e2e` / CI never need the files, and `assert-offline` can
//! still enumerate it without them. Run it explicitly:
//!
//! ```text
//! cargo test -p babymonitor-core --test cap4_replay -- --ignored --nocapture
//! ```
//!
//! ## What is validated
//! The pipeline under test (the real one): UDP datagram → HMAC-SHA1 verify+strip
//! → conv demux → KCP RX + per-segment AES-128-CBC decrypt → frg reassembly →
//! imm-wrapper + fixed-12B RTP parse → `MediaUnit` → H.264 depacketize. The
//! per-session **key gate** is the engine's own HMAC-SHA1 check: the capture
//! carries several overlapping sessions on the same conv, and only datagrams that
//! validate under key index 0 are accepted (the rest surface as a loud HMAC error
//! and are skipped, mirroring the native receiver's drop).
//!
//! The pcap parse here is a minimal, test-only LINKTYPE_LINUX_SLL2 reader (the
//! transport seam is UDP datagrams; capturing them is out of scope for the lib).

use std::path::{Path, PathBuf};

use babymonitor_core::stream::media::h264::H264Depacketizer;
use babymonitor_core::stream::media::{MediaEngine, MediaUnit};

/// The camera's source IP in the cap4 capture.
const CAM_IP: &str = "192.0.2.184";
/// Video / audio conv (channel) ids (active_handle == 0 ⇒ conv == channel id).
const VIDEO_CONV: u32 = 0x0000_0001;
const AUDIO_CONV: u32 = 0x0000_0002;
/// KCP PUSH command byte.
const IKCP_CMD_PUSH: u8 = 0x51;

/// Repo root = `<crate>/../..` (`babymonitor/babymonitor-core` → repo root).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the repo root")
        .to_path_buf()
}

fn pcap_path() -> PathBuf {
    repo_root().join("emulator_captures/cap4/media.pcap")
}
fn keys_path() -> PathBuf {
    repo_root().join("secrets/cap4_keys.txt")
}
fn video_truth_path() -> PathBuf {
    repo_root().join("secrets/cap4_video.h264")
}
fn audio_truth_path() -> PathBuf {
    repo_root().join("secrets/cap4_audio.s16le")
}

/// Load media key index 0 (first whitespace token = 32 hex chars = 16 bytes).
/// Never logged.
fn load_key0() -> Vec<u8> {
    let text = std::fs::read_to_string(keys_path()).expect("read cap4 keys");
    let tok = text.split_whitespace().next().expect("a key token");
    let key = hex_decode(tok);
    assert_eq!(key.len(), 16, "media key 0 must be 16 bytes (AES-128)");
    key
}

fn hex_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "odd hex length");
    (0..b.len() / 2)
        .map(|i| {
            let hi = (b[2 * i] as char).to_digit(16).expect("hex");
            let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex");
            (hi * 16 + lo) as u8
        })
        .collect()
}

/// All `incl_len` packet records of a classic (non-pcapng) pcap, in order.
fn parse_pcap(data: &[u8]) -> Vec<&[u8]> {
    assert!(
        data.len() >= 24,
        "pcap shorter than its 24-byte global header"
    );
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Classic pcap, little- or big-endian. (cap4 is 0xa1b2c3d4 — LE.)
    let le = matches!(magic, 0xa1b2_c3d4 | 0xa1b2_3c4d);
    let be = matches!(magic.swap_bytes(), 0xa1b2_c3d4 | 0xa1b2_3c4d);
    assert!(
        le || be,
        "unrecognized pcap magic {magic:#010x} (pcapng unsupported)"
    );
    let rd_u32 = |b: &[u8], o: usize| {
        let v = [b[o], b[o + 1], b[o + 2], b[o + 3]];
        if le {
            u32::from_le_bytes(v)
        } else {
            u32::from_be_bytes(v)
        }
    };
    let mut out = Vec::new();
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let incl = rd_u32(data, off + 8) as usize;
        off += 16;
        if off + incl > data.len() {
            break;
        }
        out.push(&data[off..off + incl]);
        off += incl;
    }
    out
}

/// Decode one LINKTYPE_LINUX_SLL2 frame → (src IPv4 dotted, UDP payload), or None
/// if not IPv4/UDP. Mirrors `stage6_extract.py::sll2`.
fn sll2_udp(frame: &[u8]) -> Option<(String, &[u8])> {
    if frame.len() < 20 || u16::from_be_bytes([frame[0], frame[1]]) != 0x0800 {
        return None; // SLL2 protocol field must be IPv4 (0x0800)
    }
    let ip = &frame[20..];
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
        return None; // IPv4 + protocol 17 (UDP)
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    Some((src, &udp[8..]))
}

/// STUN: the magic cookie `2112a442` at offset 4 (skipped, like the extractor).
fn is_stun(p: &[u8]) -> bool {
    p.len() >= 8 && p[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

/// Collect, in capture order, all camera→host UDP datagrams that are KCP PUSH on
/// `conv` (non-STUN). Foreign-session datagrams are included here and filtered by
/// the engine's HMAC gate downstream.
fn camera_conv_datagrams<'a>(records: &'a [&'a [u8]], conv: u32) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    for &frame in records {
        let Some((src, pl)) = sll2_udp(frame) else {
            continue;
        };
        if src != CAM_IP || is_stun(pl) || pl.len() < 24 {
            continue;
        }
        let c = u32::from_le_bytes([pl[0], pl[1], pl[2], pl[3]]);
        if c != conv || pl[4] != IKCP_CMD_PUSH {
            continue;
        }
        out.push(pl);
    }
    out
}

/// Replay every `conv` datagram through the real [`MediaEngine`] (suite 3,
/// key0), returning the decoded [`MediaUnit`]s plus (accepted, hmac_dropped,
/// other_err) counts. HMAC failures are the per-session key gate → skipped.
fn replay(datagrams: &[&[u8]], key: &[u8]) -> (Vec<MediaUnit>, usize, usize, usize) {
    let mut engine = MediaEngine::from_security_level(3, key.to_vec()).expect("engine");
    let mut units = Vec::new();
    let (mut accepted, mut hmac_dropped, mut other_err) = (0, 0, 0);
    for &dg in datagrams {
        match engine.push_datagram(dg) {
            Ok(mut u) => {
                accepted += 1;
                units.append(&mut u);
            }
            Err(e) => {
                if e.to_string().contains("HMAC") {
                    hmac_dropped += 1;
                } else {
                    other_err += 1;
                }
            }
        }
    }
    (units, accepted, hmac_dropped, other_err)
}

/// Report the first differing offset (no byte VALUES — never leak video/audio
/// content) and the lengths, then assert equality.
fn assert_bytes_eq(got: &[u8], want: &[u8], label: &str) {
    if got != want {
        let first_diff = got
            .iter()
            .zip(want.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(want.len()));
        panic!(
            "{label}: MISMATCH — got {} bytes, want {} bytes, first diff at offset {first_diff}",
            got.len(),
            want.len()
        );
    }
}

/// Skip (with a clear note) when the local-only inputs are absent.
fn inputs_present() -> bool {
    for p in [pcap_path(), keys_path()] {
        if !p.exists() {
            eprintln!(
                "cap4_replay: SKIP — missing local-only input {} (gitignored; see CLAUDE.md)",
                p.display()
            );
            return false;
        }
    }
    true
}

#[test]
#[ignore = "local-only: needs the gitignored cap4 capture + keys under secrets/"]
fn cap4_video_matches_ground_truth() {
    if !inputs_present() || !video_truth_path().exists() {
        return;
    }
    let key = load_key0();
    let pcap = std::fs::read(pcap_path()).expect("read pcap");
    let records = parse_pcap(&pcap);
    let datagrams = camera_conv_datagrams(&records, VIDEO_CONV);

    let (units, accepted, hmac_dropped, other_err) = replay(&datagrams, &key);

    // Depacketize H.264 → Annex-B, concatenated in message order (no AU split —
    // exactly the ground-truth extractor's emission).
    let mut depay = H264Depacketizer::new();
    let mut out = Vec::new();
    let mut located = 0usize;
    for u in &units {
        located += 1;
        for nal in depay.push(&u.payload).expect("depacketize") {
            out.extend_from_slice(&nal);
        }
    }

    let truth = std::fs::read(video_truth_path()).expect("read video truth");
    eprintln!(
        "cap4 VIDEO: conv=1 datagrams={} accepted(key0)={} hmac_dropped(foreign)={} other_err={} \
         media_units={} h264_bytes={} truth_bytes={}",
        datagrams.len(),
        accepted,
        hmac_dropped,
        other_err,
        located,
        out.len(),
        truth.len()
    );
    assert_eq!(
        other_err, 0,
        "no non-HMAC errors expected on the key0 session"
    );
    assert_bytes_eq(&out, &truth, "cap4 video H.264");
}

#[test]
#[ignore = "local-only: needs the gitignored cap4 capture + keys under secrets/"]
fn cap4_audio_matches_ground_truth() {
    if !inputs_present() || !audio_truth_path().exists() {
        return;
    }
    let key = load_key0();
    let pcap = std::fs::read(pcap_path()).expect("read pcap");
    let records = parse_pcap(&pcap);
    let datagrams = camera_conv_datagrams(&records, AUDIO_CONV);

    let (units, accepted, hmac_dropped, other_err) = replay(&datagrams, &key);

    // Audio payload = the raw S16LE PCM after the fixed-12B header, concatenated.
    let mut out = Vec::new();
    for u in &units {
        out.extend_from_slice(&u.payload);
    }

    let truth = std::fs::read(audio_truth_path()).expect("read audio truth");
    eprintln!(
        "cap4 AUDIO: conv=2 datagrams={} accepted(key0)={} hmac_dropped(foreign)={} other_err={} \
         media_units={} pcm_bytes={} truth_bytes={}",
        datagrams.len(),
        accepted,
        hmac_dropped,
        other_err,
        units.len(),
        out.len(),
        truth.len()
    );
    assert_eq!(
        other_err, 0,
        "no non-HMAC errors expected on the key0 session"
    );
    assert_bytes_eq(&out, &truth, "cap4 audio S16LE");
}
