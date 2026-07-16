# PRD: Philips Avent Baby Monitor+ — Reverse Engineering to a Rust Client

## Goal

Reverse-engineer the Android app **`com.philips.ph.babymonitorplus`** (Philips Avent
"Baby Monitor+") deeply enough to **reimplement a full-feature-parity client in Rust** —
starting with the hardest and most valuable parts: the **live video/audio stream** and the
**pairing/authentication** between the app and the camera.

## Hardware in scope

- Camera/base: **Philips Avent SCD921 / SCD923** (WiFi "Baby Monitor+").
- The user owns the camera + one screen device. They want a software client (no second screen unit).

## Methodology constraint

- **Static analysis was the PRIMARY method** (Superseded 2026-06-28, v0.1.0-live-stream). The
  original constraint was "static analysis only — no rooted device, emulator, or live packet
  capture is available." That no longer holds: a live emulator capture pipeline later became
  available via the sibling **`android_emulator_re`** project (Frida/Magisk TLS-unpinning +
  mitmproxy), yielding decrypted app flows (`emulator_captures/` cap0–cap4). These genuine
  captures plus live runs against the **real SCD921** were used to *validate* the protocol: the
  conv=0 auth and the full H.264 keyframe path are now live-validated end-to-end (milestone
  v0.1.0-live-stream, commit fa930f0). *Note: the project `CLAUDE.md` still asserts "Static
  analysis only. No live capture is available." — that statement now conflicts with reality and
  should be reconciled separately; it is out of scope for this single-file edit.*
- Consequence: the live protocol was first reconstructed from decompiled Java/Kotlin **and**
  native libraries (`.so`). For a consumer WiFi cam the stream/pairing logic is almost always
  in native code (often a third-party P2P SDK). Native-lib analysis (Ghidra/radare2) is therefore
  first-class here, not optional. The streaming protocol was ultimately confirmed/validated using
  genuine captured app flows + live runs, not static analysis alone.
- **Honesty rule:** if the wire format cannot be determined from the available evidence, say so
  explicitly and document exactly what additional evidence would unblock it. Do not fabricate
  protocol details. (For the streaming path, captures now exist, so claims there are backed by
  real flows rather than blocked on a missing pcap; every claim still carries its confidence
  level and cites its evidence.)

## Key unknowns to resolve (in priority order)

> Status: these original research questions are now largely **resolved** (Superseded 2026-06-28,
> v0.1.0-live-stream) — streaming stack, pairing, auth/encryption, and cloud-vs-local are answered;
> see `re/review_gate_findings.md`, the streaming docs, and the "Streaming hypothesis" section below.
> Retained here as the original framing.

1. **Streaming stack** — what SDK/protocol carries audio+video?
   - Identify native libs and any third-party P2P/streaming SDK (TUTK/Kalay, PPCS, agora,
     WebRTC, RTSP, proprietary). Knowing the SDK lets us cross-reference public knowledge.
2. **Pairing / device discovery** — how does the app find and bind to the camera (local
   mDNS/SSDP/UDP broadcast? cloud relay? QR/AP-mode provisioning?).
3. **Authentication / encryption** — device credentials, session keys, TLS/DTLS, any
   pre-shared keys or per-device secrets, and where they are stored.
4. **Cloud vs local** — does streaming go peer-to-peer on the LAN, or via a vendor relay
   (NAT traversal)? Is there an account/cloud API at all?
5. **Control plane** — settings, two-way talk, lullabies, nightlight, sensors (temp/humidity),
   notifications/events.

## Milestones

- **M1 Setup** — project scaffolding, toolchain (nix), backlog, obtain APK.
- **M2 Extract & decompile** — APK/XAPK → jadx (DEX), apktool (manifest/resources),
  catalog native libs per ABI, identify framework & obfuscation.
- **M3 Static analysis** — map architecture; identify streaming SDK, pairing, auth, cloud API,
  data models; produce a protocol design document with confidence levels per claim.
- **M4 Native-lib analysis** — Ghidra/radare2 on the streaming/pairing `.so`; recover protocol
  structures, magic bytes, crypto. (Replaces the "live API validation" phase of the generic skill.)
- **M5 Rust core** — `babymonitor-core` crate: discovery, pairing, session/auth, stream transport.
- **M6 Rust media** — decode/display video+audio (and two-way audio).
- **M7 CLI/viewer** — `babymonitor-cli`: pair, stream, control. Human + `--json` output.
- **M8 Feature parity** — sensors, lullabies, nightlight, events/notifications.
- **M9 Security & cleanup** — PII/secret scan, README, LICENSE, consolidate artifacts under `re/`.

## Non-goals (for now)

- Defeating DRM or any paywall (there is none expected; this is local device access).
- Redistributing Philips firmware or copyrighted assets.
- **No public redistribution of Philips' recovered Tuya appKey/appSecret/sign-key** (their developer
  credentials; publishing them violates Tuya's developer ToS and is the highest-liability artifact).
- **No attacking Tuya cloud infrastructure**; live calls are rate-limited and single-shot.

## Authorized scope

This is authorized self-use: the user owns the SCD921/923 camera and the Tuya account, and wants a
software second-screen because the official app will not run on their phone. All live testing uses the
user's own account and device only.

## Streaming hypothesis (updated post-review)

**RESOLVED (v0.1.0-live-stream; LAN carrier live-proven by TASK-0126)** — the
transport is decided and proven end-to-end against the real SCD921. Signaling is
selectable: Tuya cloud MQTT or key-proven `IPC_LAN_302` on TCP 6668. Media is
direct P2P/ICE UDP in either case, with **KCP** framing rather than raw WebRTC media:

- **WebRTC-style "302" signaling over Tuya MQTT or local frame type 32** (sealed with the device localKey)
  → **ICE** (host-candidate trickle, no USE-CANDIDATE, tolerates ICMP ECONNREFUSED)
  → **conv=0** media-start/auth → **conv=1** video over **KCP**.
- LAN mode supplies a numeric RFC 5389 responder on the client LAN; a kernel
  allowlist denying all non-camera destinations still produced live A/V. This is
  cloud-free runtime for a paired/configured camera, not cloud-free pairing or
  localKey recovery after reset.
- Media is **per-segment AES-128-CBC (inline-IV, PKCS7)** + a **per-datagram 20-byte
  HMAC-SHA1(media_key16)** → **H.264**. Explicitly **NOT DTLS-SRTP**.
- conv ids: 0 = control, 1 = video, 2 = downstream audio (16 kHz mono S16LE, inferred).

Confidence / honest caveat: **"live keyframe decodes + displays" is PROVEN** (the Rust client
decoded the live 1080p H.264 keyframe and VLC displayed it). **"Smooth continuous live A/V" is now
verified** (TASK-0085 decoupled the media pump from the KCP ACK loop) — earlier, across live runs the
camera's conv=1 video froze at ~12 segments (its initial KCP
send window); root-caused to the single-threaded media pump starving the KCP ACK loop. Follow-ups:
TASK-0085 (decouple the ACK loop from the blocking sink — the blocker), TASK-0086 (KCP WASK/WINS +
flush cadence), TASK-0087 (A/V sink fixes), TASK-0088 (newtype the derived auth password),
TASK-0089 (verify conv1/conv2 ACK byte-shape + sustained-A/V harness). TASK-0083 (live media
transport) is DONE.

Original candidate list (pre-triage history, see `re/review_gate_findings.md`):
1. **WebRTC-over-MQTT** signaled via Tuya cloud (may bypass `libThingP2PSDK` entirely; cheaper if viable).
2. **Tuya P2P** (`libThingP2PSDK`, TUTK/IOTC lineage); AV framing likely static-recoverable, per-session
   key exchange likely needs one live pcap.

## Working agreements

- All RE artifacts live under `re/`. Large regenerable output (decompiled/, extracted/) is gitignored.
- Every discovery/tangent becomes a backlog task — no ad-hoc rabbit holes.
- Credentials, captures, per-device secrets, PII → `secrets/` (gitignored).
- Each protocol claim carries a confidence level and its evidence (file:line or lib + offset).
