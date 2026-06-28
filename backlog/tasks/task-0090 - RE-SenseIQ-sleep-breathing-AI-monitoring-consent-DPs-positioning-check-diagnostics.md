---
id: TASK-0090
title: >-
  RE SenseIQ sleep & breathing AI monitoring (consent DPs, positioning check,
  diagnostics)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:57'
labels:
  - re
  - ai-detection
  - philips-differentiator
  - senseiq
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the Philips-proprietary SenseIQ feature: real-time sleep-stage (awake/light/deep), sleep-duration and breathing-rate detection with 30-day history, plus the SenseIQ positioning check and the optional improvement/diagnostics consent path. Static-RE only: identify the control/consent DPs, the consent + enable flow, where video frames are analysed (on-device vs Philips cloud), and what diagnostics metrics (signal/AI confidence, box location/size, 7-day retention) get uploaded when consent=true. Produce an re/ writeup of the protocol surface; do NOT implement the AI. This is the headline non-Tuya differentiator and likely the highest-value unknown.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The SenseIQ enable/consent DP(s) (e.g. bm_senseIQ_consents) and any positioning-check control are identified with file:line evidence and their semantics documented
- [x] #2 The data path is characterized: which frames/metrics leave the device, to Tuya vs Philips endpoints, and the diagnostics fields + retention, with confidence levels and explicit unknowns
- [x] #3 re/senseiq.md writeup exists covering enable flow, positioning check, diagnostics consent, and what evidence would unblock unresolved parts; no secrets/PII committed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static-RE only. Mapped SenseIQ DP surface from DeviceDpUtil.DpCode enum (DeviceDpUtil.java:54-81): sleepiq_switch(id1) enable, sleepiq_status(id3) device->app results, sleepiq_consent(id5) primary consent, senseiq_diagnostics(id6) declared-but-app-unused, sensiq_diag_consent(id7) diagnostics consent, sleepiq_area(id10) positioning box, no_senseiq_switch(id13) no-signal alert.

Consents written via Tuya cloud API thing.m.device.dp.publish v2.0 (ConsentBusiness.java:115-121), keyed by DP id. Enable via local/MQTT publishDps (DeviceDpUtil.java:2213). Positioning box = CameraMotionDesignatedScreenBean num/region0 x,y,xlen,ylen over MQTT (SleepIQZoneSettingModel.java:298-303).

Data path: consent/control = Tuya endpoints (high conf). Diagnostics metrics (signal conf/strength, AI detection conf, AI box loc/size; every minute; 7-day retention) = Philips servers per consent string strings.xml:1450, but firmware-driven (no app-side upload code) = medium conf, flagged unknown. AI inference runs on Baby Unit firmware (results return as DPs). Raw video-frame egress to Philips = UNKNOWN.

Wrote re/senseiq.md. just secret-scan PASSES (verified with file staged, in-scope).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the Philips SenseIQ protocol surface in re/senseiq.md (static RE only; AI not implemented).

DPs (DeviceDpUtil.DpCode, DeviceDpUtil.java:54-81): sleepiq_switch(id1)=enable, sleepiq_consent(id5)=primary privacy consent, sensiq_diag_consent(id7)=optional diagnostics consent, sleepiq_area(id10)=positioning/mattress box, sleepiq_status(id3)=device->app results, senseiq_diagnostics(id6)=declared-but-app-unused, no_senseiq_switch(id13)=no-signal alert.

Enable flow: consent first (cloud), then enable switch (local/MQTT). Consents are Tuya DPs written via thing.m.device.dp.publish v2.0 keyed by DP id (ConsentBusiness.java:115-121); enable via publishDps (DeviceDpUtil.java:2213). Positioning check writes sleepiq_area as CameraMotionDesignatedScreenBean over MQTT (SleepIQZoneSettingModel.java:298-303).

Data path: control+consent = Tuya (high conf). Diagnostics (signal/AI confidence, AI box loc/size, every minute, 7-day retention) = Philips servers per consent string (strings.xml:1450) but firmware-driven, no app upload code (medium). AI inference on-device; raw video-frame egress to Philips = key UNKNOWN. Residual-unknowns section lists unblock evidence (firmware dump / live capture of sleepiq_status + diagnostics POST). No secrets/PII committed; just secret-scan passes.
<!-- SECTION:FINAL_SUMMARY:END -->
