---
id: TASK-0016
title: 'RE-PLAN: plan Wave 2 from Wave-1 knowledge (not feature code)'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 01:04'
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
Forward-carried from TASK-0017 (streaming-mode triage) for the Wave-2 re-plan: VERDICT = implement WebRTC-over-MQTT FIRST (cheaper than PPCS AV-framing). Transport is data-driven per device (p2pType 2=PPCS/4=WebRTC + skill.webrtc bitmask), MQTT msg code 302, envelope {header:{type:offer|answer|candidate,from,to,sessionid,trace_id},msg,token}, 302 payload AES-localKey at proto ver pv. Suggested Wave-2 tasks: (1) Tuya MQTT client + 302 message crypto (depends on localKey from device-list TASK-0013 + sign TASK-0007); (2) WebRTC session over webrtc-rs (SDP/trickle-ICE/DTLS-SRTP); (3) H264/Opus decode. DEPENDENCY/RISK EDGE: a live obtainCameraConfig call on the real SCD921 must confirm p2pType=4 BEFORE committing - the only finding that can flip the transport choice. De-prioritize the PPCS spikes (TASK-0009/0010) unless that live check returns p2pType=2. Full evidence: re/streaming_mode.md.
<!-- SECTION:NOTES:END -->
