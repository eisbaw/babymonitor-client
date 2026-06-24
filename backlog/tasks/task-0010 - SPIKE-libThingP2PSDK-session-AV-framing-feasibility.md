---
id: TASK-0010
title: 'SPIKE: libThingP2PSDK session + AV framing feasibility'
status: To Do
assignee: []
created_date: '2026-06-24 22:36'
updated_date: '2026-06-24 22:46'
labels:
  - phase4
  - re
  - wave1
  - p2p
  - spike
  - risk
dependencies:
  - TASK-0009
  - TASK-0017
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

RISK SPIKE (skill phase 4). Deepest static dive: reconstruct P2P session establishment (signaling, NAT-traversal/broker vs LAN), the AV stream framing (headers, codec markers for H.264/H.265 + Opus/SBC), and any per-session crypto. Ghidra decompilation of libThingP2PSDK + cross-ref public work. Delegate to general-purpose subagent. Time-box; depth over breadth on the session+framing path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 re/p2p_protocol.md documents session setup + AV framing to the depth statically achievable, every claim with confidence+evidence (lib@offset)
- [ ] #2 MANDATORY verdict, exactly one of {recoverable-statically | partially | needs-live-capture}, with the precise evidence that a single pcap (if ever available) would unblock — this verdict drives Wave-2 planning
- [ ] #3 TIME-BOXED probe (depth on session+framing path only). The verdict must also CHOOSE which transport Wave 2 pursues (P2P vs the WebRTC path from task 17), and name SPECIFICALLY which bytes a single pcap would unblock (e.g. handshake nonce / key-agreement)
<!-- AC:END -->
