---
id: TASK-0026
title: >-
  FIX: milestone2_findings.md streaming framing stale vs TASK-0017 WebRTC
  verdict
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 02:39'
updated_date: '2026-06-25 03:00'
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
- [x] #1 milestone2_findings.md gains a one-line forward-pointer to streaming_mode.md WebRTC-over-MQTT-preferred/PPCS-fallback verdict at the stale P2P-first framing (~:78,88,98); confidence labels and substance unchanged
- [x] #2 just check-evidence GREEN over re/*.md (incl. edited milestone2); just secret-scan GREEN; no new contradiction introduced
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add one-line forward-pointer to streaming_mode.md WebRTC-over-MQTT verdict at milestone2 streaming framing (points 1 + 4). Keep likely labels + substance.
2. check-evidence GREEN.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Added a one-line forward-pointer at milestone2 point #4 (the libThingP2PSDK "hard core / riskiest piece" framing) covering points 1+4, pointing to re/streaming_mode.md WebRTC-over-MQTT-preferred / PPCS-fallback / chosen-by-p2pType verdict.
GOTCHA: kept the surrounding `confidence: likely` label and substance untouched (the pointer is explicitly marked navigation-only). check-evidence still GREEN because the section already carries likely + a real citation; the pointer adds no new confirmed claim.

Cycle-10 review: both GO. Corrections true, greps re-verified zero WebRTC primitives in JS, no new contradiction. P2 citation nits -> TASK-0028.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added a one-line forward-pointer in re/milestone2_findings.md (the project entry doc) from its stale "cloud-brokered P2P" streaming framing (points 1+4) to the re/streaming_mode.md verdict: WebRTC-over-MQTT (code 302) preferred per-device, legacy PPCS fallback, chosen at runtime from cloud p2pType.

No confidence labels or substance changed (navigation pointer only). check-evidence + secret-scan + e2e GREEN; no new cross-doc contradiction.
<!-- SECTION:FINAL_SUMMARY:END -->
