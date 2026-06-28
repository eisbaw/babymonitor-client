# Stream playback — `babymonitor-cli stream` (TASK-0070)

Operational doc for the `stream` subcommand: it consumes the decoded media from the
PATH-A engine (`re/media_decode_spec.md`) and re-muxes the H.264 into **MPEG-TS over
HTTP** so a standard player connects. This is the "view the baby" output stage.

## Play it (live or replay, `--output http` default)

The Rust side feeds **decrypted Annex-B H.264** to `ffmpeg`, which muxes MPEG-TS and
serves it at `http://127.0.0.1:<port>/stream.ts` (default port 8554). Connect with:

```sh
vlc    http://127.0.0.1:8554/stream.ts
mpv    http://127.0.0.1:8554/stream.ts
ffplay http://127.0.0.1:8554/stream.ts
```

`ffmpeg -listen 1` serves a single client; start the player after the subcommand
prints `serving MPEG-TS at …`.

> Note: the default http port **8554** collided with a local QEMU emulator during
> live runs — pick a free `--port` if 8554 is taken (free-port selection tracked in
> TASK-0087).

## Pipeline (what `stream` wires)

```
login → device discovery → MQTT 302 signaling → MediaEngine (suite-3 AES-128-CBC +
20B HMAC-SHA1 / KCP / fixed-12B RTP) → conv demux:
  conv 1 video → H264Depacketizer (STAP-A/FU-A → Annex-B) → AccessUnitAssembler
  conv 2 audio → raw 16 kHz mono S16LE PCM (downstream, NOT G.711)
→ ffmpeg → MPEG-TS (h264 + AAC) over HTTP
```

The assembled live driver is `babymonitor-cli/src/stream_live.rs` (gated under
`--features live`; see `re/live_stream_run.md` for the owner run steps).

### Audio — two directions, do NOT conflate

| direction | conv | format | module | confidence |
|---|---|---|---|---|
| **downstream** camera→app (listen to baby) | 2 | raw **S16LE @ 16 kHz mono** | `media::audio` | **[C]** cap4 byte-exact |
| **talk-back** app→camera (speak to baby) | — | G.711 µ-law (PCMU, PT 0, 8 kHz) | `media::g711` | [I] |

The earlier doc claimed the audio channel was G.711 µ-law @ 8 kHz — that is the
**talk-back** direction only. The **downstream** camera audio is raw 16 kHz mono
S16LE PCM, carried verbatim as the RTP payload after the fixed-12B header
(`emulator_captures/cap4/stage6_extract.py` `extract_audio`; `media::audio`). It is
muxed into the TS as an AAC track (`stream --replay-audio …` offline; the live pump
routes conv 2 to the audio FIFO). The crypto/auth is **HMAC-SHA1 (20-byte
trailer)**, not the spec's earlier SHA-256 guess — corrected by cap4
(`FUN_0016a004:100 mbedtls_md_info_from_type(5)=SHA1`; `media/crypto.rs`).

## Honest status

- **Live path** (no `--replay-annexb`): the self-contained Rust client now connects
  to the **real SCD921** and decodes the live **1080p H.264 keyframe end-to-end**
  (Superseded 2026-06-28, v0.1.0-live-stream, commit fa930f0; earlier this bullet
  said the path was gated and only returned `StreamPending`). Proven pipeline:
  MQTT-302 signaling → ICE (client binds the media UDP socket early, trickles its own
  host candidate, sends NO `USE-CANDIDATE`, tolerates ICMP `ECONNREFUSED`) → conv 0
  auth + media-start → conv 1 video → KCP + AES-128-CBC + 20-byte HMAC-SHA1 → H.264 →
  player. **[C] PROVEN**: live keyframe decodes + displays (VLC displayed it). If no
  session/camera is reachable the path still falls back to `StreamPending` (never a
  fabricated stream) — that is the fallback, not the steady-state outcome.
  - **Honest caveat — sustained/continuous live A/V is NOT yet verified.** Across
    live runs the camera's conv 1 video froze at **~12 segments** (its initial KCP
    send window). Root cause: the single-threaded media pump
    (`stream_live.rs` `pump_to_output`) does a **blocking** write into ffmpeg
    (`stream.rs` `write_annexb`/`OutputSink`), starving the KCP ACK loop
    (`mod.rs` `drain_media_acks`) so the camera's `snd_una` never advances. So
    "live keyframe decodes + displays" is **[C] PROVEN**; "smooth continuous live A/V"
    is **not** yet verified. Follow-ups: TASK-0085 (decouple the ACK loop from the
    blocking sink — the blocker), TASK-0086 (KCP WASK/WINS + flush cadence),
    TASK-0087 (A/V sink: drop `-shortest` / free-port check / clean disconnect),
    TASK-0088 (newtype the derived auth password), TASK-0089 (verify conv1/conv2 ACK
    byte-shape vs cap4 + sustained-A/V harness). TASK-0083 (live media transport) is
    **DONE**.
- **Replay path** (`--replay-annexb <file.264>` [`--replay-audio <file.s16le>`]):
  fully runnable **offline** — it exercises the real `rtp::parse_rtp` +
  `H264Depacketizer` + `AccessUnitAssembler` on a synthetic/captured Annex-B sample
  and re-muxes (with the optional downstream-audio track) through the ffmpeg sink.
- **`emulator_captures/cap4` now EXISTS and byte-validates the engine.**
  `tests/cap4_replay.rs` (`#[ignore]`d, local-only) replays the real cap4 capture
  through the committed `MediaEngine` and reconstructs **byte-identical** output to
  the independent ground truth: **4 090 176 B** H.264 video (conv 1) and
  **1 532 800 B** S16LE audio (conv 2). The `cap4_unified_pump_routes_av_to_truth`
  test proves the same conv-based A/V routing the live pump uses. Decode is no longer
  synthetic-only.

## Offline validation (no camera) — `just stream-validate`

Synthesizes a baseline Annex-B H.264 sample **and a 16 kHz mono S16LE audio
sample**, replays them through the depacketizer + A/V muxer, and asserts with
`ffprobe` that the produced MPEG-TS carries a decodable `h264` video AND an audio
track:

```sh
# what `just stream-validate` does, by hand:
ffmpeg -f lavfi -i testsrc=size=320x240:rate=15:duration=1 \
    -c:v libx264 -profile:v baseline -pix_fmt yuv420p -g 15 -bf 0 -f h264 sample.264
ffmpeg -f lavfi -i "sine=frequency=440:duration=1:sample_rate=16000" -ac 1 -f s16le audio.s16le
# video-only:
babymonitor-cli stream --replay-annexb sample.264 --output ts --ts-out out.ts
ffprobe -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 out.ts   # -> h264
# A/V (downstream audio muxed alongside video):
babymonitor-cli stream --replay-annexb sample.264 --replay-audio audio.s16le --output ts --ts-out av.ts
ffprobe -show_entries stream=codec_type -of csv=p=0 av.ts                          # -> video + audio
```

`just stream-validate` is part of `just e2e`. The byte-exact decode proof is the
local-only cap4 replay (above): `cargo test -p babymonitor-core --test cap4_replay
-- --ignored`.

## Output modes

| `--output` | Result | Player |
|---|---|---|
| `http` (default) | MPEG-TS over HTTP at `http://127.0.0.1:<port>/stream.ts` | `vlc`/`mpv`/`ffplay <url>` |
| `ts` (`--ts-out F`) | MPEG-TS written to file `F` | offline `ffprobe`/playback |
| `stdout` | raw Annex-B H.264 to stdout (video only — no audio mux) | `… --output stdout \| mpv -` (or `ffplay -f h264 -`) |

`--replay-audio <file.s16le>` (with `http`/`ts`) muxes the downstream 16 kHz mono
S16LE audio as an AAC track alongside the video. ffmpeg is the downstream
muxer/server (a pure-Rust MPEG-TS muxer is a possible future follow-up); the Rust
side feeds it the decrypted Annex-B video on `pipe:0` and the S16LE audio on a
second input (a file for replay; a FIFO for the live pump). Raw Annex-B has no
timing, so ffmpeg is given `-r 15` + `-bsf:v setts=ts=N` to stamp monotonic PTS.
