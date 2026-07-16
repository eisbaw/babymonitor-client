# Wave-1 Backlog Review Gate — Findings & Decisions

Four read-only reviewer subagents (mped-architect, qa-test-runner, security, protocol-realism)
attacked the proposed Wave-1 backlog. This logs what they found and how the backlog was revised.
**Every downstream subagent should read this** — it carries corrected technical hypotheses and
named public references that change the implementation targets.

## Plan-changing technical findings (highest value)

### F1 — The signing scheme is the Tuya *mobile-app SDK* sign, NOT OpenAPI HMAC (confidence: likely→confirm in task 7)
- tinytuya / `tuya-iot-python-sdk` implement **Tuya OpenAPI** signing (`openapi.tuya*.com`,
  `client_id`+`access_token`, `HMAC-SHA256(client_id+access_token+t+nonce+stringToSign, secret)`).
  Philips' white-labeled app does **not** use a developer cloud project — it uses the **mobile-app
  API gateway** (`a.tuya*/api.tuya*`, the `a.m.*` family).
- Per `nalajcie/tuya-sign-hacking`, the mobile sign key is **not** a plain appSecret. It is
  `HMAC-SHA256(data, key)` with `key = [app_cert_SHA256]_[token_decoded_from_an_embedded_BMP]_[appSecret]`.
  The BMP token is obfuscated (polynomial/linear-algebra decode).
- **Strong corroboration in this app:** `assets/t_s.bmp` was seen in the asset listing — exactly the
  embedded-BMP token mechanism from that writeup.
- Consequence: tasks 7/12 retargeted to the mobile sign; the differential test reference is
  `nalajcie/tuya-sign-hacking` (or a live-captured vector), NOT tinytuya. Recovering the key
  derivation (cert pin + BMP token + routine, likely in `libthing_security.so`/`libthingnetsec.so`)
  is part of task 5 and is the expected hard blocker, not an edge case.
- Ref: https://github.com/nalajcie/tuya-sign-hacking ; https://developer.tuya.com/en/docs/iot/new-singnature

### F2 — Streaming may be WebRTC-over-MQTT, bypassing libThingP2PSDK (confidence: speculative, triage first)
- **Update — RESOLVED as of v0.1.0-live-stream (commit fa930f0):** confidence is now **confirmed**.
  The transport IS WebRTC-style 302 signaling over Tuya MQTT, decoding a live SCD921 1080p H.264
  keyframe end-to-end. Important correction to the `webrtc-rs` implication below: only the
  signaling/ICE shape is WebRTC-like — the **media plane is NOT DTLS-SRTP**. It is custom **KCP +
  AES-128-CBC (inline-IV, PKCS7) per segment + a per-datagram 20-byte HMAC-SHA1(media_key16)**, so
  `webrtc-rs` does not cover the media path and proprietary AV framing still had to be reconstructed.
- `seydx/tuya-ipc-terminal` streams modern Tuya cameras via **WebRTC**, signaled over **MQTT + Tuya
  cloud API**, then bridges to RTSP — explicitly NOT using Tuya's native P2P SDK. Newer Tuya IPC
  firmware commonly supports WebRTC.
- The app still bundles `libThingP2PSDK`, so the SCD921 may be P2P-only, WebRTC-capable, or both.
  A Rust client over `webrtc-rs` + an MQTT signaling client could be far cheaper than statically
  reconstructing the proprietary P2P AV framing.
- Consequence: NEW task — triage the streaming-mode decision (JS-first: `assets/mini_app_js`,
  `thing_uni_plugins`, MQTT/`webrtc`/`sdp`/`ice`/`stun` strings) BEFORE committing deep P2P effort.
  Task 10's verdict must choose which transport Wave 2 pursues.
  (Resolved 2026-06-28, v0.1.0-live-stream: WebRTC-over-MQTT selected and shipped — no longer an open decision.)
- Ref: https://github.com/seydx/tuya-ipc-terminal

### F3 — P2P static feasibility: framing likely recoverable, session key exchange likely the blocker (confidence: likely)
- Public lineage is rich: TUTK/IOTC-PPCS is documented (WyzeCam `tutk.py`/`tutk_ioctl_mux.py` are
  full Python reimplementations of IOTC session + AV framing; `videoP2Proxy`), and Tuya publishes an
  official `tuya-iotos-android-iot-p2p-demo` showing the P2P channel API surface.
- What is typically NOT statically recoverable: the per-session key exchange / handshake secret —
  exactly what one pcap unblocks. Expected task-10 verdict: **`partially`**.
- Refs: https://github.com/tuya/tuya-iotos-android-iot-p2p-demo ;
  https://kroo.github.io/wyzecam/reference/tutk/tutk/ ; https://github.com/miguelangel-nubla/videoP2Proxy
- Note (2026-06-28, v0.1.0-live-stream): this TUTK/IOTC-PPCS P2P route is the road-not-taken — the
  transport verdict (F2) selected the MQTT/KCP path. F3's substantive feasibility claims are unaffected.

### F4 — Superseded: TCP 6668 carries both datapoints and local P2P signaling, not A/V media (confidence: confirmed)
- The original review correctly observed that ordinary tinytuya/localtuya commands carry DPs,
  but incorrectly generalized that to every command on the port. The SCD921 also accepts
  `IPC_LAN_302` command/frame type 32 on TCP 6668, carrying the same offer/answer/candidate
  signaling envelope as cloud MQTT. TASK-0126 live-proved that carrier with all non-camera egress
  denied. Video and audio still do **not** travel on TCP 6668: after signaling, they use direct
  ICE/KCP UDP. Tuya 3.3 uses `localKey` AES-ECB plus CRC32; the endpoint is key-proven by a fresh,
  correlated decrypted answer rather than by treating an open port or CRC as authentication.

### F5 — Datacenter is selected at runtime from the login response, not static from assets (confidence: likely)
- `assets/thing_domains_v1` gives candidate domains; the actual datacenter is chosen by country/region
  and returned at login. Task 7 must model datacenter selection as runtime-from-login-response.

## Grounding / security defects fixed in the backlog (confidence: confirmed — process record, not a protocol claim)

**Confidence: confirmed (process/decision record).** This section is NOT a
protocol/wire-format claim — it logs backlog decisions taken at the Wave-1 review
gate. The label is `confirmed` because each item is a verifiable fact about the
backlog/scripts, not a hypothesis about the device. Evidence is the tracked
artifacts themselves: `re/scripts/check_evidence.py:1` (the grounding lint),
`re/scripts/secret_scan.sh:1` (the secret/PII gate), and `re/scripts/stub_grep.sh:1`
(the stub tripwire), all wired into the `Justfile` gate recipes.

- **APK source bug:** native libs live in `config.arm64_v8a.apk`, not the base APK. Tasks 4/5 corrected.
- **Scaffold-first:** task 11 (workspace + Justfile + `check-evidence` + `secret-scan` + stub-grep)
  moved to no-deps so its gates exist before analysis docs and before the review gate.
- **`check-evidence` must ship with a fixtures test** (a planted bad fragment it must flag + a good one
  it must pass) and a concrete claim lexicon; it also asserts task-10's verdict is exactly one of
  `{recoverable-statically|partially|needs-live-capture}`. A self-certifying lint is not grounding.
- **Device-list parser (task 13) must have a negative test** (rejects malformed/missing camera P2P
  handle) and required-field invariants — a permissive serde sponge with only a happy-path test is a
  green-but-meaningless suite.
- **Differential signing must use an independent reference** (F1), not a self-derived vector (circular).
- **appKey/sign-key recovery (task 5) is a SPIKE** with a verdict and an explicit contingency edge into
  the re-plan: if not statically recoverable, the live-capture path (gold oracle) produces the vector.
- **Secret/PII scan is a Wave-1 gate** (`just secret-scan`, bites on planted secret/PII; covers tracked
  files, `git diff`, and `backlog/tasks/*.md`), not deferred to M9. Device-list fixtures anonymized
  before any value enters a committed file/note/summary; `localKey` and P2P creds are secrets.
- **Subagent leak channel closed:** never write a recovered secret/token/real account ID into a task
  field, `re/*.md`, or a returned summary — reference its `secrets/` location only (added to CLAUDE.md
  + task onboarding).
- **Legal scope:** no public redistribution of Philips' Tuya appKey/appSecret; no attacking Tuya infra;
  rate-limit live calls; authorized scope = the user's own account + device only (added to PRD).
- **Review gates given teeth:** tasks 6/15 must triage/close (or consciously defer) the fix-tasks they
  file and run `just secret-scan`; the wave doesn't silently advance past open P0/P1 findings.
- **Re-ranking:** the value spine (11→1/3/4→5→7→12→13→14) stays HIGH; P2P triage/spike and pairing
  become parallel risk-probes at lower priority; the WebRTC streaming-mode triage is HIGH.
