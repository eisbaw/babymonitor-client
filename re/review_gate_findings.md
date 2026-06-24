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
- `seydx/tuya-ipc-terminal` streams modern Tuya cameras via **WebRTC**, signaled over **MQTT + Tuya
  cloud API**, then bridges to RTSP — explicitly NOT using Tuya's native P2P SDK. Newer Tuya IPC
  firmware commonly supports WebRTC.
- The app still bundles `libThingP2PSDK`, so the SCD921 may be P2P-only, WebRTC-capable, or both.
  A Rust client over `webrtc-rs` + an MQTT signaling client could be far cheaper than statically
  reconstructing the proprietary P2P AV framing.
- Consequence: NEW task — triage the streaming-mode decision (JS-first: `assets/mini_app_js`,
  `thing_uni_plugins`, MQTT/`webrtc`/`sdp`/`ice`/`stun` strings) BEFORE committing deep P2P effort.
  Task 10's verdict must choose which transport Wave 2 pursues.
- Ref: https://github.com/seydx/tuya-ipc-terminal

### F3 — P2P static feasibility: framing likely recoverable, session key exchange likely the blocker (confidence: likely)
- Public lineage is rich: TUTK/IOTC-PPCS is documented (WyzeCam `tutk.py`/`tutk_ioctl_mux.py` are
  full Python reimplementations of IOTC session + AV framing; `videoP2Proxy`), and Tuya publishes an
  official `tuya-iotos-android-iot-p2p-demo` showing the P2P channel API surface.
- What is typically NOT statically recoverable: the per-session key exchange / handshake secret —
  exactly what one pcap unblocks. Expected task-10 verdict: **`partially`**.
- Refs: https://github.com/tuya/tuya-iotos-android-iot-p2p-demo ;
  https://kroo.github.io/wyzecam/reference/tutk/tutk/ ; https://github.com/miguelangel-nubla/videoP2Proxy

### F4 — LAN port-6668 local protocol is datapoint-only (control/sensors), NOT AV (confidence: confirmed)
- tinytuya/localtuya LAN protocol (TCP 6668, AES with per-device local key) carries **DPs** — on/off,
  settings, sensor values — not video. Not a shortcut for streaming, but may simplify the **M8
  control plane** (nightlight, lullaby, temp/humidity) without cloud. The local key comes from the
  cloud device-list (task 13). Triage in Wave 2, not Wave 1.

### F5 — Datacenter is selected at runtime from the login response, not static from assets (confidence: likely)
- `assets/thing_domains_v1` gives candidate domains; the actual datacenter is chosen by country/region
  and returned at login. Task 7 must model datacenter selection as runtime-from-login-response.

## Grounding / security defects fixed in the backlog

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
