---
id: TASK-0035
title: >-
  Wave-2 DECISION: unblock auth — runtime SDK-config byte[] OR one live sign
  vector (relaxes static-only)
status: To Do
assignee: []
created_date: '2026-06-25 07:14'
labels:
  - phase3
  - wave2
  - auth
  - decision
  - blocked-human
dependencies:
  - TASK-0012
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
REVIEWER-CONFIRMED TERMINAL FINDING (TASK-0033): the bmp_token decode keys off a RUNTIME JNI byte[] SDK-config (doCommandNative param_6), so the Tuya signer is NOT computable under pure static analysis — the imath+matrix is fully ported (re/scripts/bmp_token_ghidra.py) but the production token needs the runtime config blob. A working login (and therefore the whole client + stream) is BLOCKED until the user relaxes the no-dynamic constraint. OPTIONS (human decision): (a) capture ONE live accepted sign request on the user device (Frida/proxy) -> pins bmp_token + SignBody + postData-fold simultaneously (TASK-0012 AC#3, cheapest); (b) dump the runtime SDK-config byte[] once via a single hook -> feeds the ported matrix to compute the token offline thereafter; (c) accept the analysis-complete-but-non-functional endpoint (client stays token-injectable). This is the single decision gating a working client.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 User decides (a)/(b)/(c); if (a) or (b), capture the artifact to secrets/ and wire it through the BmpTokenProvider; the differential then validates the signer
<!-- AC:END -->
