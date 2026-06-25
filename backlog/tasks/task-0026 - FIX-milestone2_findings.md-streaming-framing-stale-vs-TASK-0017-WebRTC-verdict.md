---
id: TASK-0026
title: >-
  FIX: milestone2_findings.md streaming framing stale vs TASK-0017 WebRTC
  verdict
status: To Do
assignee: []
created_date: '2026-06-25 02:39'
updated_date: '2026-06-25 02:46'
labels:
  - review-followup
  - wave1
  - docs
dependencies:
  - TASK-0017
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AUDIT FINDING F3 (TASK-0006), severity P1/deferrable. re/milestone2_findings.md ~:78,88,98 frames streaming as 'P2P streaming most likely brokered through Tuya servers', calls libThingP2PSDK 'the audio/video session channel' and 'the riskiest piece', with NO pointer to the later WebRTC-over-MQTT verdict. The symbol ThingCameraConstants.P2PType P2P_TYPE_THING(4) (decompiled/jadx/sources/com/thingclips/smart/camera/api/ThingCameraConstants.java ~:1613) shows WebRTC is the preferred per-device transport. The milestone2 claims are labelled likely/speculative so this is NOT a grounding violation - but milestone2 is the project ENTRY doc and a reader hitting it first gets a P2P-first steer the set later reverses (streaming_mode.md). FIX: add a one-line forward-pointer in milestone2 to the streaming_mode.md verdict (WebRTC-over-MQTT preferred, PPCS fallback). Low risk, high navigational value. Do before re-plan (TASK-0016). VERIFY: just check-evidence GREEN. Do NOT change the confidence labels or the substance.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 milestone2_findings.md gains a one-line forward-pointer to streaming_mode.md WebRTC-over-MQTT-preferred/PPCS-fallback verdict at the stale P2P-first framing (~:78,88,98); confidence labels and substance unchanged
- [ ] #2 just check-evidence GREEN over re/*.md (incl. edited milestone2); just secret-scan GREEN; no new contradiction introduced
<!-- AC:END -->
