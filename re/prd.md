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

- **Static analysis only.** No rooted device, emulator, or live packet capture is available.
- Consequence: the live protocol must be reconstructed from decompiled Java/Kotlin **and**
  native libraries (`.so`). For a consumer WiFi cam the stream/pairing logic is almost always
  in native code (often a third-party P2P SDK). Native-lib analysis (Ghidra/radare2) is therefore
  first-class here, not optional.
- **Honesty rule:** if the wire format cannot be determined from static analysis alone, say so
  explicitly and document exactly what additional evidence (e.g. a single pcap) would unblock it.
  Do not fabricate protocol details.

## Key unknowns to resolve (in priority order)

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

Two candidate transports — to be decided by triage before deep effort (see `re/review_gate_findings.md`):
1. **WebRTC-over-MQTT** signaled via Tuya cloud (may bypass `libThingP2PSDK` entirely; cheaper if viable).
2. **Tuya P2P** (`libThingP2PSDK`, TUTK/IOTC lineage); AV framing likely static-recoverable, per-session
   key exchange likely needs one live pcap.

## Working agreements

- All RE artifacts live under `re/`. Large regenerable output (decompiled/, extracted/) is gitignored.
- Every discovery/tangent becomes a backlog task — no ad-hoc rabbit holes.
- Credentials, captures, per-device secrets, PII → `secrets/` (gitignored).
- Each protocol claim carries a confidence level and its evidence (file:line or lib + offset).
