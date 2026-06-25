---
id: TASK-0049
title: >-
  ILLEGAL_CLIENT_ID is an app-attestation/provisioning gate, not a
  host/sign/ttid problem — decide on-device capture vs accept block
status: To Do
assignee: []
created_date: '2026-06-25 15:01'
labels:
  - auth
  - identity
  - live
  - blocked
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0048 GENUINELY EXHAUSTED the static host avenue: every reachable EU regionConfig gateway (legacy a1.tuyaeu.com/a1.tuyaus.com AND the newer iotbing apigw-eu.iotbing.com + a1-us.iotbing.com) returns ILLEGAL_CLIENT_ID with the fully app-faithful envelope (wire ttid=sdk_international@appKey, channel=oem, appRnVersion, full initUrlParams shape, chKey, correct appKey). px.tuyaeu.com does not resolve publicly and a3.tuyaeu.com is HTTPS-PSK (not an atop API host). The real appKey is confirmed (TASK-0046). So the rejection is upstream of signature verification: an identity/provisioning gate (likely app-attestation / SafetyNet-Play-Integrity / a server-side appKey<->package-signature binding) that a from-scratch standalone client cannot reproduce from static material alone. The sign oracle stays unreachable; bmp_token candidate + MD5 fold remain un-validated. DECISION NEEDED from owner: (a) authorize a single on-device capture (Frida hook on the outgoing token.get / app-attestation header, or one mitmproxy request, TASK-0022) to read the missing provisioning field/header; or (b) accept that the cloud-login avenue is blocked for a pure-static client and pivot to the LAN/local pairing + stream path (which may not need cloud token.get at all). No further host sweeps — that avenue is closed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Owner decides between on-device capture (a) and local-pairing pivot (b); decision recorded
- [ ] #2 If (a): the exact missing provisioning surface (header/param/attestation) is identified from ONE capture and the static client updated; if (b): a backlog task for the LAN pairing/stream avenue is created
- [ ] #3 re/live_login.md verdict promoted from likely to confirmed once a second source (capture or a definitive provisioning-doc) corroborates the app-attestation-gate conclusion
<!-- AC:END -->
