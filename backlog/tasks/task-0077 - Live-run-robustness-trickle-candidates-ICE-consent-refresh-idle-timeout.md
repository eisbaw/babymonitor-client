---
id: TASK-0077
title: 'Live-run robustness: trickle candidates, ICE consent refresh, idle timeout'
status: In Progress
assignee:
  - '@claude'
created_date: '2026-06-27 20:05'
updated_date: '2026-06-28 07:14'
labels:
  - stream
  - ice
  - live
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Real-run blockers found in the live-path review (offline code is fine; these bite a live session): (R3) the driver requires the camera host candidate in the ANSWER SDP, but normal ICE TRICKLES candidates separately via 302 candidate messages — connect_and_negotiate must collect trickled candidates, else it errors no-ICE-candidate even on LAN. (R4) no ICE consent refresh: the pump sends one USE-CANDIDATE check then only receives; RFC 7675 needs a ~5s keepalive or the camera cuts the stream. (R7) MAX_IDLE_POLLS ~20s ends the session if first-keyframe latency exceeds it. Handle all three when wiring the live run.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Trickled 302 candidate messages are collected and added to the ICE candidate set (not only answer-SDP candidates)
- [ ] #2 Periodic ICE connectivity-check/consent refresh keeps the media path alive for a sustained stream
- [ ] #3 Idle/first-keyframe timeout is generous enough for real camera startup
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented (offline-validated; the live network run is the lead's).

Root cause proven from captures: the camera ANSWER SDP carries 0 a=candidate lines (cap3 AND cap4). The old open_media_transport errored on candidates.is_empty() => a guaranteed live failure even on LAN. The host candidate only arrives as trickled 302 candidate messages.

(a) TRICKLE: new MqttSignalingSession::negotiate_with_trickle (session.rs) collects remote candidates interleaved before the answer AND in a post-answer window; dedupes mqtt+lan duplicates; filters the empty sentinel. negotiate() now delegates to it (back-compat). connect_and_negotiate returns NegotiationOutcome{answer, remote_candidates}; LiveSignalingParams gained trickle_polls + poll_interval (sleep-free offline via Duration::ZERO; ~20ms live to stop the busy-spin). stream_live merges trickled + SDP candidates and only errors if BOTH are empty.

(b) CONSENT: the pump now demuxes STUN from media on the shared 5-tuple (cap4 had ~559 STUN pkts on the media path) -- feeding a STUN pkt to suite-3 would fail HMAC and abort. PathKeepalive sends an RFC7675 consent-refresh check ~every 5s AND answers the camera's inbound checks with a new stun::encode_binding_success (keyed by our local pwd) so the camera keeps streaming. A foreign/corrupt media datagram is now a logged drop, not stream-fatal.

(c) IDLE: PumpTimers -- generous 60s FIRST-media window (camera startup can exceed 20s), 20s steady-idle once media is flowing.

OFFLINE TESTS (all pass): tests/trickle_candidates_cap.rs parses the REAL cap3+cap4 candidate messages into IceCandidates (read at runtime, skip-if-absent, no values printed); session trickle-collection test; stun binding-success KAT; CLI keepalive/consent_reply/refresh_check/is_stun/PumpTimers tests.

GATES: just e2e GREEN; cargo clippy -p babymonitor-cli --features live --all-targets -D warnings CLEAN.

HONEST gaps: the captures show NO inbound (camera->app) candidate messages -- all captured candidate msgs are app-outbound -- so the camera-trickles-inbound premise is asserted by the task and validated only via a synthetic inbound feed + the real wire-format parse; the end-to-end keepalive/trickle over a live socket is unverified (no camera in sandbox). The answer-wait/trickle/consent timings are first-cut; the lead may tune them on the live run.

LIVE TEST #1 (2026-06-28, this machine is on the camera LAN 192.0.2.233; camera 192.0.2.184 reachable; broker reachable; valid session). Got FAR: session auth OK -> rtc.config.get fetched LIVE OK -> discovery p2pType=4 -> MQTT creds derived -> CONNECTED m1.tuyaeu.com:8883 TLS + PUBLISHED 302 offer (so MQTT CONNECT AUTH IS CORRECT — broker accepted; risk #4 RESOLVED) -> then: no answer in 500 polls (camera silent). Stuck at the unproven 302 topic / offer-fidelity gate.
<!-- SECTION:NOTES:END -->
