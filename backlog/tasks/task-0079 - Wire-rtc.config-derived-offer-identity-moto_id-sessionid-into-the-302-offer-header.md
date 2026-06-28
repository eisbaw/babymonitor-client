---
id: TASK-0079
title: >-
  Wire rtc.config-derived offer identity (moto_id + sessionid) into the 302
  offer header
status: To Do
assignee: []
created_date: '2026-06-28 07:00'
labels:
  - live
  - stream
  - signaling
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0078 auto-builds the runtime and correctly sets from/cname=uid, but the 302 OFFER header still omits moto_id and synthesizes sessionid (dev_id+trace_id) instead of using rtc.config session.sessionId. cap3 ground truth: the offer header carries moto_id (=rtc.config motoId) and sessionid (=rtc.config session.sessionId). The current OfferEnvelopeArgs/SignalingFlow have no moto_id field and take a synthesized sessionid. Wire the rtc.config-derived moto_id + sessionId through StreamRuntime.camera -> SignalingFlow/OfferEnvelopeArgs -> the offer header, faithful to cap3, without breaking the signaling_cap3 byte-repro tests. Scoped out of TASK-0078 to avoid touching the byte-validated signaling layer.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Offer header carries moto_id == rtc.config motoId (cap3-faithful); answer/candidate parsing unaffected
- [ ] #2 Offer header.sessionid + SDP WMS use rtc.config session.sessionId (not the synthesized dev_id+trace_id)
- [ ] #3 tests/signaling_cap3.rs still passes; offline test asserts the offer header round-trips moto_id+sessionid
<!-- AC:END -->
