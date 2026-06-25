---
id: TASK-0016
title: 'RE-PLAN: plan Wave 2 from Wave-1 knowledge (not feature code)'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 05:15'
labels:
  - phase-gate
  - replan
  - wave1
dependencies:
  - TASK-0015
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

Re-plan task - NOT feature code. Re-invoke Skill phase2-backlog-snowball with: re/prd.md, TESTING.md, and the Wave-1 lessons/notes - ESPECIALLY the task-10 P2P feasibility verdict {recoverable-statically | partially | needs-live-capture} and the cloud-auth/pairing docs. Plan Wave 2 to the depth the new knowledge now supports (e.g. Rust P2P transport + media decode/display + two-way audio if P2P is feasible; otherwise a narrowed scope + the exact evidence needed). Write no implementation in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wave-2 tasks exist in the tracker, dependency-ordered and test-grounded
- [ ] #2 Wave 2 again ends with its own re-plan task UNLESS the project is now firm enough for a full breakdown
- [ ] #3 TESTING.md updated with what Wave 1 taught (especially the real P2P verdict and any new oracles)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD from TASK-0009 (re/p2p_triage.md) for the Wave-2 WebRTC Rust client: the native WebRTC signaling/session surface in libThingP2PSDK.so is now mapped with DEMANGLED C++ argument types (richest for porting):
- Session-init: thing_p2p_rtc_connect_v2(remote_id, dev_id, skill, token, trace_id, timeout_ms, lan_mode) emits the {cmd:connect_v2} JSON over MQTT 302.
- Signaling I/O: set_signaling (inbound sdp/candidate), SendMessageThroughMQTT (outbound), 302 envelope {header,msg,token}. Maps to rumqttc + the Tuya MQTT 302 codec (localKey-AES).
- Media: imm_p2p_rtc_sdp_* (encode/decode/negotiate) + imm_p2p_ice_* + DTLS-SRTP via bundled mbedTLS -> maps onto webrtc-rs. AV frames via imm_p2p_rtc_frame_t / recv_frame; H264 RTP via imm_p2p_h264_packetize_*.
- Codec: video is OpenH264 fork tagged '1.5.0-Philips620.3' (use an openh264-backed decode crate); audio = WebRTC audio_processing + Opus.
OPEN RISK to flow into Wave-2 scope: the SDP-carried AES key (imm_p2p_rtc_sdp_get_aes_key) + session-key derivation is the likely hard blocker (review-gate F3) - TASK-0010 must verify static-recoverability; if not, Wave-2 needs a live pcap. The PPCS path stays a contingency branch gated behind a live p2pType==2.

FEED-FORWARD from TASK-0014 (CLI + e2e harness) — client state for Wave-2 planning:

WORKS OFFLINE TODAY (babymonitor-cli):
- `auth status` / `auth logout` against the SessionStore (~/.local/share/babymonitor/session.json).
- `devices list` / `devices show <id>` parse a device-list body from --fixture (default synthetic fixture); human + --json output; secrets redacted by default (--show-secrets to reveal, with stderr warning).
- `info`; all read-only commands wired into `just showcase` (green).
- Core layer: sign (5/6 ingredients), session store, device/camera models + CameraView accessor — all unit/fixture tested.

TOKEN-PENDING (the single blocker, everything funnels through it):
- `auth login` and any LIVE cloud fetch (`devices list --live`, core::list_devices) return Error::BmpTokenPending. Blocked on TASK-0030 (port the bmp_token decoded from assets/t_s.bmp via the native white-box table cipher). No fake success anywhere.
- The #[ignore]d gold-oracle test (babymonitor-cli/tests/live_e2e.rs) currently asserts the honest token-pending state; it becomes the real login->list->find-SCD921 once TASK-0030 lands.

WHAT WAVE-2 NEEDS (dependency order):
1. TASK-0030 (bmp_token port) — UNBLOCKS sign + login + live device-list. Critical path. Needs the gold sign vector (nalajcie tooling or one live capture) to also pin the two `likely` sign ambiguities (key-part order; KeyOnly vs KeyAndCanonical fold).
2. Wire the real HTTP fetch in core::list_devices (currently returns NotImplemented even WITH a token) — request decoration (envelope params + sign) + POST + parse. Rate-limited/single-shot (structure already assumes single-shot, no retry loop).
3. The login flow itself (2-step ticket: thing.m.user.username.token.get -> thing.m.user.email.password.login; RSA-encrypt passwd; datacenter from User.domain) producing a real Session to persist.
4. THEN the WebRTC-over-MQTT stream (p2pType=4 / ThingWebRtc on the SCD921): per-camera CameraInfoBean fetch + P2pConfig (ices/relay/session) -> WebRTC negotiation -> decode >=1 video frame + audio. This is the ultimate gold-oracle.

UNCONFIRMED / needs-live to resolve in Wave-2: CameraInfoBean.id vs DeviceBean.dev_id equivalence; which of category/categoryCode the wire populates; the `ipc` category literal (only `sp` grounded).
<!-- SECTION:NOTES:END -->
