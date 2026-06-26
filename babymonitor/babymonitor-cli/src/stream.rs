//! `babymonitor-cli stream` — drive the live A/V pipeline (login → device
//! discovery → MQTT 302 signaling → media RX/decode) and re-mux the decoded
//! Annex-B H.264 into **MPEG-TS served over HTTP** so a standard player connects:
//!
//! ```text
//!   vlc  http://127.0.0.1:8554/stream.ts
//!   mpv  http://127.0.0.1:8554/stream.ts
//!   ffplay http://127.0.0.1:8554/stream.ts
//! ```
//!
//! # Two execution modes
//!
//! - **Live** (default, no `--replay-annexb`): wires stages 1→5 against the
//!   on-disk session. In this sandbox there is no authenticated session and no
//!   live Tuya broker/camera, so it stops at the first honest gate and explains
//!   what is missing (it NEVER fabricates a stream — the project's TOKEN-PENDING
//!   discipline). The owner runs this for real with an injected session.
//!
//! - **Replay** (`--replay-annexb <file.264>`): the OFFLINE-validatable path. It
//!   reads an Annex-B H.264 sample, RTP-packetizes it (single-NAL / FU-A), pushes
//!   it through the **real** [`rtp::parse_rtp`] + [`H264Depacketizer`] +
//!   [`AccessUnitAssembler`] (the same decode stage the live media engine feeds),
//!   and re-muxes the reconstructed Annex-B into the chosen output. This is what
//!   `just stream-validate` exercises end-to-end and `ffprobe` confirms is a valid
//!   `h264` stream — proving the depacketizer + mux/serve path with no camera.
//!
//! # The muxer
//!
//! The Rust side feeds **decrypted Annex-B** to `ffmpeg` on stdin; `ffmpeg` is the
//! downstream MPEG-TS muxer/HTTP server (a pure-Rust TS muxer is a possible future
//! follow-up). `--output stdout` instead writes raw Annex-B to stdout for
//! `mpv -` / `ffplay -f h264 -`.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};

use babymonitor_core::session::SessionStore;
use babymonitor_core::stream::media::h264::{AccessUnitAssembler, H264Depacketizer};
use babymonitor_core::stream::media::rtp;
use babymonitor_core::Error;
use clap::{Args, ValueEnum};

/// Default HTTP port the MPEG-TS stream is served on.
const DEFAULT_PORT: u16 = 8554;
/// Default RTP packetization budget (payload bytes) for the replay packetizer —
/// kept well under a 1400-byte MTU so larger NALs exercise the FU-A path.
const DEFAULT_MTU: usize = 1100;
/// Dynamic RTP payload type the replay packetizer stamps on H.264 packets (96 is
/// the conventional first dynamic PT).
const H264_PAYLOAD_TYPE: u8 = 96;
/// The raw-H.264 input framerate handed to ffmpeg (raw Annex-B carries no
/// timing; ffmpeg synthesizes PTS from this).
const FFMPEG_INPUT_FPS: &str = "15";

/// Where the re-muxed stream is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputMode {
    /// Serve MPEG-TS over HTTP at `http://127.0.0.1:<port>/stream.ts` (ffmpeg
    /// `-listen 1`; one client). The default — `vlc`/`mpv`/`ffplay` connect.
    Http,
    /// Write MPEG-TS to a file (`--ts-out`). Used by the offline `ffprobe`
    /// validation.
    Ts,
    /// Write raw Annex-B H.264 to stdout for `mpv -` / `ffplay -f h264 -`.
    Stdout,
}

/// Arguments for `babymonitor-cli stream`.
#[derive(Debug, Args)]
#[command(
    after_help = "PLAY IT WITH (default --output http, serving http://127.0.0.1:<port>/stream.ts):\n\
        \x20 vlc    http://127.0.0.1:8554/stream.ts\n\
        \x20 mpv    http://127.0.0.1:8554/stream.ts\n\
        \x20 ffplay http://127.0.0.1:8554/stream.ts\n\n\
        OFFLINE (no camera) — replay a synthetic/captured Annex-B sample through the real\n\
        RTP depacketizer + the mux/serve path, then validate with ffprobe:\n\
        \x20 babymonitor-cli stream --replay-annexb sample.264 --output ts --ts-out out.ts\n\
        \x20 ffprobe out.ts            # -> codec_name=h264\n\
        \x20 babymonitor-cli stream --replay-annexb sample.264   # serve over HTTP, then: vlc http://127.0.0.1:8554/stream.ts\n\n\
        STDOUT fallback (raw Annex-B):\n\
        \x20 babymonitor-cli stream --replay-annexb sample.264 --output stdout | mpv -"
)]
pub struct StreamArgs {
    /// HTTP port for `--output http` (serves `http://127.0.0.1:<port>/stream.ts`).
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// Where to send the re-muxed stream.
    #[arg(long, value_enum, default_value = "http")]
    pub output: OutputMode,

    /// Output file for `--output ts` (the MPEG-TS the offline ffprobe check
    /// validates).
    #[arg(long)]
    pub ts_out: Option<PathBuf>,

    /// OFFLINE replay: read this Annex-B H.264 file, RTP-packetize it, run it
    /// through the real depacketizer, and re-mux it (no network / no camera).
    /// Without this flag, `stream` attempts the gated LIVE pipeline.
    #[arg(long)]
    pub replay_annexb: Option<PathBuf>,

    /// RTP packetization budget (payload bytes) for the replay packetizer. NALs
    /// larger than this are FU-A fragmented.
    #[arg(long, default_value_t = DEFAULT_MTU)]
    pub mtu: usize,
}

/// Entry point for the `stream` subcommand.
///
/// # Errors
/// - Replay: [`Error::Transport`] if the Annex-B file has no NALs, an RTP/
///   depacketize step fails, or the ffmpeg muxer cannot be spawned / exits
///   non-zero.
/// - Live: an honest gated error (no session / no live broker) — never a faked
///   stream.
pub fn run_stream(args: &StreamArgs, _json: bool) -> Result<(), Error> {
    if let Some(path) = &args.replay_annexb {
        run_replay(args, path)
    } else {
        run_live(args)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LIVE path — wired, honestly gated
// ─────────────────────────────────────────────────────────────────────────────

/// Wire the live pipeline as far as the offline environment allows, then stop at
/// the first honest gate. All diagnostics go to stderr so `--output stdout` keeps
/// stdout clean.
fn run_live(args: &StreamArgs) -> Result<(), Error> {
    let store = SessionStore::default_path()?;
    let have_session = store.load()?.is_some();

    eprintln!("stream (live): login -> discovery -> signaling -> media -> output");
    eprintln!(
        "  stage 1  auth:       {}",
        if have_session {
            "session present (sid/uid redacted)"
        } else {
            "NO session — login is blocked (inject a captured session, README §6)"
        }
    );
    eprintln!(
        "  stage 2  discovery:  needs the session's DeviceList + per-camera CameraInfoBean (p2pId/p2pKey/ices)"
    );
    eprintln!(
        "  stage 3  signaling:  MQTT 302 offer/answer over the TLS broker (CONNECT password is native-derived, re/mqtt_signaling.md)"
    );
    eprintln!(
        "  stage 4  media:      MediaEngine — suite-3 AES-128-CBC + HMAC-SHA256 / KCP / RTP / H.264 -> Annex-B (re/media_decode_spec.md)"
    );
    eprintln!(
        "  stage 5  output:     ffmpeg -> MPEG-TS at http://127.0.0.1:{}/stream.ts",
        args.port
    );
    eprintln!();
    eprintln!(
        "blocked: the live broker/camera and an authenticated device session are not available in this static-analysis sandbox."
    );
    eprintln!("For an OFFLINE end-to-end demo of stages 4-5 (depacketize -> mux -> serve), run:");
    eprintln!("  babymonitor-cli stream --replay-annexb <sample.264>   then: vlc http://127.0.0.1:{}/stream.ts", args.port);

    Err(Error::StreamPending)
}

// ─────────────────────────────────────────────────────────────────────────────
// REPLAY path — offline-validatable (no network, no camera)
// ─────────────────────────────────────────────────────────────────────────────

/// Read an Annex-B H.264 file, RTP-packetize it, push it through the real
/// [`rtp::parse_rtp`] + [`H264Depacketizer`] + [`AccessUnitAssembler`], and re-mux
/// the reconstructed Annex-B into the chosen output.
fn run_replay(args: &StreamArgs, path: &PathBuf) -> Result<(), Error> {
    let data = std::fs::read(path).map_err(|e| {
        Error::Transport(format!("read Annex-B replay file {}: {e}", path.display()))
    })?;
    let nals = split_annexb_nals(&data);
    if nals.is_empty() {
        return Err(Error::Transport(format!(
            "no H.264 NAL units found in {} (expected an Annex-B 00 00 [00] 01 stream)",
            path.display()
        )));
    }

    let mut sink = OutputSink::spawn(args.output, args.port, args.ts_out.as_ref())?;
    announce(&sink, args);

    let mut depay = H264Depacketizer::new();
    let mut asm = AccessUnitAssembler::new();
    let mut seq: u16 = 0;
    let mut ts: u32 = 0;
    let ssrc: u32 = 0x1234_5678;
    let mut packets = 0usize;
    let mut emitted_nals = 0usize;
    let mut keyframes = 0usize;

    for nal in &nals {
        let payloads = packetize_nal(nal, args.mtu);
        let frags = payloads.len();
        let is_vcl = matches!(nal[0] & 0x1f, 1..=5);
        for (j, payload) in payloads.iter().enumerate() {
            // Mark the last fragment of a VCL NAL as the access-unit boundary
            // (testsrc is single-slice-per-picture; ffmpeg re-derives AU
            // boundaries from the byte stream regardless).
            let marker = is_vcl && j + 1 == frags;
            let rtp_packet = build_rtp_packet(H264_PAYLOAD_TYPE, marker, seq, ts, ssrc, payload);
            seq = seq.wrapping_add(1);
            packets += 1;

            let parsed = rtp::parse_rtp(&rtp_packet)
                .map_err(|e| Error::Transport(format!("replay RTP parse: {e}")))?;
            let out_nals = depay
                .push(parsed.payload)
                .map_err(|e| Error::Transport(format!("replay depacketize: {e}")))?;

            // Feed the decoded Annex-B straight to the muxer (a complete,
            // ordered NAL stream), and run the AU assembler for keyframe stats.
            for out_nal in &out_nals {
                sink.write_annexb(out_nal)?;
                emitted_nals += 1;
            }
            if let Some(au) = asm.push(&out_nals, parsed.header.marker) {
                if au.is_keyframe {
                    keyframes += 1;
                }
            }
        }
        if is_vcl {
            // Advance the RTP timestamp one frame (90 kHz clock / fps).
            ts = ts.wrapping_add(90_000 / 15);
        }
    }
    if let Some(au) = asm.finish() {
        if au.is_keyframe {
            keyframes += 1;
        }
    }

    eprintln!(
        "stream: replayed {} NAL(s) -> {packets} RTP packet(s) -> {emitted_nals} depacketized NAL(s), {keyframes} keyframe access-unit(s).",
        nals.len()
    );
    if keyframes == 0 {
        eprintln!(
            "stream: warning — no IDR keyframe in the sample; the decoder may not render a picture."
        );
    }
    sink.finish()
}

/// Print the connect/play instructions to stderr (so stdout can stay clean for
/// `--output stdout`).
fn announce(sink: &OutputSink, args: &StreamArgs) {
    match sink {
        OutputSink::Ffmpeg { target, .. } => match args.output {
            OutputMode::Http => {
                eprintln!("stream: serving MPEG-TS at {target}");
                eprintln!("stream: connect a player now —");
                eprintln!("    vlc    {target}");
                eprintln!("    mpv    {target}");
                eprintln!("    ffplay {target}");
            }
            OutputMode::Ts => eprintln!("stream: writing MPEG-TS to {target}"),
            OutputMode::Stdout => {}
        },
        OutputSink::Stdout(_) => {
            eprintln!("stream: writing raw Annex-B H.264 to stdout — pipe to `mpv -` or `ffplay -f h264 -`.");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output sink (ffmpeg muxer / stdout)
// ─────────────────────────────────────────────────────────────────────────────

/// The downstream byte sink for the decoded Annex-B stream.
enum OutputSink {
    /// ffmpeg child reading Annex-B on stdin, muxing MPEG-TS to `target`.
    Ffmpeg {
        child: Child,
        stdin: ChildStdin,
        target: String,
    },
    /// Raw Annex-B to this process's stdout.
    Stdout(io::Stdout),
}

impl OutputSink {
    /// Spawn the sink for `mode`. For ffmpeg modes the Rust side feeds Annex-B on
    /// the child's stdin (`-f h264 -i pipe:0 -c:v copy -f mpegts ...`).
    fn spawn(mode: OutputMode, port: u16, ts_out: Option<&PathBuf>) -> Result<Self, Error> {
        match mode {
            OutputMode::Stdout => Ok(Self::Stdout(io::stdout())),
            OutputMode::Http => {
                let target = format!("http://127.0.0.1:{port}/stream.ts");
                Self::spawn_ffmpeg(&["-listen", "1", &target], target.clone())
            }
            OutputMode::Ts => {
                let path = ts_out.ok_or_else(|| {
                    Error::Transport(
                        "--output ts requires --ts-out <FILE> (the MPEG-TS output path)"
                            .to_string(),
                    )
                })?;
                let target = path.display().to_string();
                Self::spawn_ffmpeg(&["-y", &target], target.clone())
            }
        }
    }

    /// Spawn ffmpeg with the shared raw-H.264-in / MPEG-TS-out args plus the
    /// mode-specific output args.
    fn spawn_ffmpeg(output_args: &[&str], target: String) -> Result<Self, Error> {
        let mut cmd = Command::new("ffmpeg");
        cmd.args([
            "-hide_banner",
            "-loglevel",
            "warning",
            // Raw Annex-B carries no timing; assume this input framerate …
            "-r",
            FFMPEG_INPUT_FPS,
            "-f",
            "h264",
            "-i",
            "pipe:0",
            "-c:v",
            "copy",
            // … and stamp each copied packet with a monotonic frame-index PTS so
            // the MPEG-TS muxer has well-formed timestamps (no "unset timestamps"
            // warning; players get a steady clock).
            "-bsf:v",
            "setts=ts=N",
            "-f",
            "mpegts",
        ])
        .args(output_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::Transport(
                    "ffmpeg not found in PATH — it is the downstream MPEG-TS muxer (add it to shell.nix / install ffmpeg)"
                        .to_string(),
                )
            } else {
                Error::Transport(format!("spawning ffmpeg muxer: {e}"))
            }
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Transport("ffmpeg stdin pipe was not captured".to_string()))?;
        Ok(Self::Ffmpeg {
            child,
            stdin,
            target,
        })
    }

    /// Write one Annex-B chunk (a start-code-prefixed NAL, or a whole access unit)
    /// to the sink.
    fn write_annexb(&mut self, buf: &[u8]) -> Result<(), Error> {
        let res = match self {
            Self::Ffmpeg { stdin, .. } => stdin.write_all(buf),
            Self::Stdout(out) => out.write_all(buf),
        };
        res.map_err(|e| {
            // A broken pipe means the player/ffmpeg went away — report it plainly.
            Error::Transport(format!("writing Annex-B to the output sink: {e}"))
        })
    }

    /// Close the input and wait for the muxer to finish.
    fn finish(self) -> Result<(), Error> {
        match self {
            Self::Stdout(mut out) => out
                .flush()
                .map_err(|e| Error::Transport(format!("flushing stdout: {e}"))),
            Self::Ffmpeg {
                stdin, mut child, ..
            } => {
                // Drop stdin to send EOF, then wait for ffmpeg to drain + exit.
                drop(stdin);
                let status = child
                    .wait()
                    .map_err(|e| Error::Transport(format!("waiting for ffmpeg: {e}")))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(Error::Transport(format!(
                        "ffmpeg muxer exited with {status} (see its stderr above)"
                    )))
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Annex-B parse + RTP packetize (replay-side helpers)
// ─────────────────────────────────────────────────────────────────────────────

/// Split an Annex-B byte stream into raw NAL units (NAL header byte first, NO
/// start code). Handles both 3-byte (`00 00 01`) and 4-byte (`00 00 00 01`)
/// start codes; the extra leading `00` of a 4-byte code is treated as the
/// trailing byte of the previous NAL and dropped.
fn split_annexb_nals(data: &[u8]) -> Vec<Vec<u8>> {
    // Find every 00 00 01 start-code position.
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i);
            i += 3;
        } else {
            i += 1;
        }
    }

    let mut nals = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let nal_start = s + 3;
        let mut nal_end = starts.get(k + 1).copied().unwrap_or(data.len());
        // Strip the trailing 0x00 that belongs to the next 4-byte start code.
        if k + 1 < starts.len() && nal_end > nal_start && data[nal_end - 1] == 0 {
            nal_end -= 1;
        }
        if nal_end > nal_start {
            nals.push(data[nal_start..nal_end].to_vec());
        }
    }
    nals
}

/// RTP-packetize one raw NAL unit into one or more H.264 RTP payloads
/// (RFC-6184). A NAL that fits in `max_payload` is sent as a single-NAL payload;
/// a larger NAL is FU-A fragmented. This is the inverse of [`H264Depacketizer`],
/// used only by the offline replay path to exercise the depacketizer.
fn packetize_nal(nal: &[u8], max_payload: usize) -> Vec<Vec<u8>> {
    if nal.is_empty() {
        return Vec::new();
    }
    if nal.len() <= max_payload.max(2) {
        return vec![nal.to_vec()];
    }
    // FU-A: indicator keeps F|NRI, swaps type to 28; header carries S/E + type.
    let nal_header = nal[0];
    let fu_indicator = (nal_header & 0xe0) | 28;
    let nal_type = nal_header & 0x1f;
    let body = &nal[1..];
    let chunk = max_payload.saturating_sub(2).max(1);

    let mut out = Vec::new();
    let mut off = 0;
    while off < body.len() {
        let end = (off + chunk).min(body.len());
        let start_bit = off == 0;
        let end_bit = end == body.len();
        let fu_header = (u8::from(start_bit) << 7) | (u8::from(end_bit) << 6) | nal_type;
        let mut p = Vec::with_capacity(2 + (end - off));
        p.push(fu_indicator);
        p.push(fu_header);
        p.extend_from_slice(&body[off..end]);
        out.push(p);
        off = end;
    }
    out
}

/// Build a minimal 12-byte-header RTP packet (no CSRC/ext/pad) + `payload`.
fn build_rtp_packet(pt: u8, marker: bool, seq: u16, ts: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(rtp::RTP_HEADER_LEN + payload.len());
    p.push(0x80); // V=2, P=0, X=0, CC=0
    p.push((u8::from(marker) << 7) | (pt & 0x7f));
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const SC: [u8; 4] = [0, 0, 0, 1];

    #[test]
    fn split_handles_3_and_4_byte_start_codes() {
        // 4-byte start | NAL A (2 bytes) | 3-byte start | NAL B (3 bytes)
        let mut data = vec![0, 0, 0, 1, 0x67, 0x42];
        data.extend_from_slice(&[0, 0, 1, 0x68, 0xCE, 0x3C]);
        let nals = split_annexb_nals(&data);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0], vec![0x67, 0x42]);
        assert_eq!(nals[1], vec![0x68, 0xCE, 0x3C]);
    }

    #[test]
    fn split_strips_4byte_code_leading_zero() {
        // NAL A then a 4-byte start code: the 00 before 00 00 01 must NOT leak
        // into NAL A.
        let mut data = vec![0, 0, 0, 1, 0xAA, 0xBB];
        data.extend_from_slice(&[0, 0, 0, 1, 0xCC]);
        let nals = split_annexb_nals(&data);
        assert_eq!(nals[0], vec![0xAA, 0xBB], "trailing 0x00 must be stripped");
        assert_eq!(nals[1], vec![0xCC]);
    }

    #[test]
    fn split_empty_or_no_startcode_yields_nothing() {
        assert!(split_annexb_nals(&[]).is_empty());
        assert!(split_annexb_nals(&[0xDE, 0xAD, 0xBE, 0xEF]).is_empty());
    }

    #[test]
    fn small_nal_is_single_packet() {
        let nal = [0x67u8, 0x42, 0x00, 0x1f];
        let pkts = packetize_nal(&nal, 1100);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], nal);
    }

    #[test]
    fn large_nal_fu_a_round_trips_through_depacketizer() {
        // A 300-byte IDR NAL (type 5) fragmented at a tiny MTU, then reassembled
        // by the REAL depacketizer must reproduce the original NAL exactly.
        let mut nal = vec![0x65u8]; // F=0,NRI=3,type=5 (IDR)
        nal.extend((0..299u32).map(|i| (i & 0xff) as u8));
        let pkts = packetize_nal(&nal, 100);
        assert!(pkts.len() > 1, "must fragment");
        // First fragment has S bit, last has E bit.
        assert_eq!(pkts[0][1] & 0x80, 0x80, "first fragment S");
        assert_eq!(pkts.last().unwrap()[1] & 0x40, 0x40, "last fragment E");

        let mut depay = H264Depacketizer::new();
        let mut reassembled = None;
        for p in &pkts {
            let out = depay.push(p).unwrap();
            if !out.is_empty() {
                assert!(reassembled.is_none(), "only the End fragment emits");
                reassembled = Some(out[0].clone());
            }
        }
        let got = reassembled.expect("FU-A reassembles on the End fragment");
        let mut expected = SC.to_vec();
        expected.extend_from_slice(&nal);
        assert_eq!(got, expected);
    }

    #[test]
    fn build_rtp_packet_round_trips_through_parser() {
        let payload = [0x41u8, 0xDE, 0xAD];
        let pkt = build_rtp_packet(96, true, 0x1234, 0x0001_0000, 0xAABB_CCDD, &payload);
        let parsed = rtp::parse_rtp(&pkt).unwrap();
        assert_eq!(parsed.header.payload_type, 96);
        assert!(parsed.header.marker);
        assert_eq!(parsed.header.sequence, 0x1234);
        assert_eq!(parsed.payload, payload);
    }

    // Full replay micro-pipeline (no ffmpeg): Annex-B in -> packetize ->
    // parse_rtp -> depacketize -> Annex-B out must equal the input NAL stream.
    #[test]
    fn replay_pipeline_reconstructs_annexb() {
        let mut input = Vec::new();
        // SPS (type 7), PPS (type 8), IDR (type 5, 250 bytes -> FU-A at mtu 100).
        for nal in [
            vec![0x67u8, 0x42, 0x00, 0x1f],
            vec![0x68u8, 0xCE, 0x3C, 0x80],
            {
                let mut idr = vec![0x65u8];
                idr.extend((0..249u32).map(|i| (i & 0xff) as u8));
                idr
            },
        ] {
            input.extend_from_slice(&SC);
            input.extend_from_slice(&nal);
        }

        let nals = split_annexb_nals(&input);
        assert_eq!(nals.len(), 3);

        let mut depay = H264Depacketizer::new();
        let mut asm = AccessUnitAssembler::new();
        let mut out = Vec::new();
        let mut seq = 0u16;
        for nal in &nals {
            let payloads = packetize_nal(nal, 100);
            let frags = payloads.len();
            let is_vcl = matches!(nal[0] & 0x1f, 1..=5);
            for (j, payload) in payloads.iter().enumerate() {
                let marker = is_vcl && j + 1 == frags;
                let pkt = build_rtp_packet(96, marker, seq, 0, 1, payload);
                seq += 1;
                let parsed = rtp::parse_rtp(&pkt).unwrap();
                let decoded = depay.push(parsed.payload).unwrap();
                for n in &decoded {
                    out.extend_from_slice(n);
                }
                asm.push(&decoded, parsed.header.marker);
            }
        }
        assert_eq!(out, input, "round-trip Annex-B must be byte-identical");
    }
}
