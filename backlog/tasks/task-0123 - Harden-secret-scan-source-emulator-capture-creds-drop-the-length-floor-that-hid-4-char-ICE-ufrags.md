---
id: TASK-0123
title: >-
  Harden secret-scan: source emulator-capture creds + drop the length floor that
  hid 4-char ICE ufrags
status: To Do
assignee: []
created_date: '2026-06-30 19:27'
labels:
  - security
  - secret-scan
  - tech-debt
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A public-repo leak (real cap3 ICE ufrags/pwds in tracked sdp.rs/session.rs/signaling.rs + signaling_cap3_redacted.jsonl, scrubbed via filter-repo) slipped past both just secret-scan AND the manual pre-push pickaxe. Root cause: the scanner's secret dictionary sourced account/device/session secrets only and applied a >=14-char length floor, so 4-char ICE ufrags (and capture-only creds) were structurally invisible. Also: a fixture named *_redacted.jsonl + 'synthetic' code comments carried genuine capture bytes (false labels).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 secret-scan sources candidate creds from emulator_captures/cap*/ (ICE ufrag/pwd, sessionid, trace_id, media keys) in addition to secrets/, so capture-only values are scanned
- [ ] #2 no minimum-length floor that hides short tokens like 4-char ICE ufrags; or a dedicated ice-ufrag/ice-pwd rule
- [ ] #3 audit every *_redacted/synthetic-labelled fixture + comment for genuine capture bytes; relabel or truly synthesize so the label is honest
<!-- AC:END -->
