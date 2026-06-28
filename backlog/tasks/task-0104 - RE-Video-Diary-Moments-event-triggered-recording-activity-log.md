---
id: TASK-0104
title: RE Video Diary / Moments event-triggered recording & activity log
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:06'
labels:
  - re
  - media-playback
  - automation
  - philips-differentiator
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the Philips 'Moments'/Video Diary feature: automatic event-triggered clip recording driven by motion/sound/cry/baby-awake events with per-event-type toggles and time settings, plus the activity diary/log (cry/motion/sleep/awake, manual entries). Static-RE: map VideoDiarySettingActivity, the diary event-type constants/DPs and how recorded segments are indexed by event type, and where the diary persists (local DB vs Tuya cloud). Produce an re/ writeup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The Video Diary event-type triggers and their enable settings are documented with file:line evidence (VideoDiarySettingActivity + bm_diary_* events)
- [x] #2 The diary persistence/sync path (local vs cloud) is identified with confidence
- [x] #3 re/video_diary.md writeup exists covering event-triggered recording + activity logging
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read VideoDiarySettingActivity + VideoDiaryViewModel
2. Decode ExtFunctionUtils bitmask + DeviceDpUtil ext_functions DP read/write
3. Map switches->bits->view ids; support gates B/C/D
4. Identify persistence (cloud DP vs local) + clip storage
5. Write re/video_diary.md; run secret-scan
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the Philips "Moments" (internal: Video Diary) event-triggered recording feature in re/video_diary.md (static RE, confidence-annotated, file:line evidence).

Key findings:
- The five per-event-type recording toggles (sound/motion/cry/baby-awake/baby-asleep) are NOT one-DP-each: they are packed into the bits of a single Tuya integer DP `ext_functions` (DpCode EXT_FUNCTIONS, dpId 21). Bit map proven from ExtFunctionUtils (bit0=sound, bit1=motion, bit2=cry, bit3=awake, bit4=asleep) and cross-checked against VideoDiaryViewModel.J() decode, onCheckedChanged() encode, and the layout switch ids.
- The two sensitivity sliders reuse the shared detection DPs (motion_sensitivity / decibel_sensitivity) via NightowlMQTTCameraModel, not ext_functions.
- "Baby awake" is gated on SenseIQ being active (DeviceDpUtil.B), cry/sleepIQ rows gated by support predicates C/D.
- Persistence: settings persist as the cloud DP ext_functions via IThingIPCDpHelper.publishDps (Tuya cloud/MQTT, no local DB). Recorded clips are subscription-backed Tuya Cloud Storage (cloud panel route bm_camera_cloud_panel / BmCameraCloudActivity), indexed by the same event taxonomy.
- Honest correction: there is NO user-authored journal/manual-entry feature; the only "diary" is the automatic Moments clips.

AC1/2/3 met. secret-scan passes (no secrets/PII inlined).
<!-- SECTION:FINAL_SUMMARY:END -->
