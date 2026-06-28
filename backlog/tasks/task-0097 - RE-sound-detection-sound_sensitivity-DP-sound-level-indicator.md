---
id: TASK-0097
title: 'RE sound detection: sound_sensitivity DP + sound level indicator'
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:55'
labels:
  - re
  - ai-detection
  - sensors
  - dp
  - baby-monitor
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the audio-event detection used by the baby monitor: the sound detection on/off switch and SoundSensitivityMode (high/mid/low) DP, plus the real-time 'sound level indicator' that visualizes nursery audio even when muted. Static-RE: map the DP codes/value semantics and where the live audio-level metric is sourced from (audio spectrum manager vs DP) into an re/ writeup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The sound_detect_switch and sound_sensitivity DP codes + value mapping are documented with file:line evidence
- [x] #2 The sound-level-indicator data source is identified (e.g. trctaudiospectrumanager / stream audio) with confidence noted
- [x] #3 re/sound_detection.md writeup exists
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static-RE complete. DP codes: decibel_switch (bool, dpId 139) = sound-detect on/off; decibel_sensitivity (string-enum, dpId 140) = sensitivity. Evidence in DpSoundCheck.java:41/46, DpSoundSensitivity.java:51/56, FuncBaseSoundCheck.java:24/29/285/321, FuncBaseSoundSensitivity.java:112-113, DeviceDpUtil.java:55-56/1575-1580.

Value-mapping caveat: TWO SoundSensitivityMode enums disagree - legacy devicecontrol.mode = LOW(0)/HIGH(1) (2 levels); newer ka.panel nightowl-camera-setting = LOW(0)/MID(1)/HIGH(2) (3 levels, matches task high/mid/low). Which mounts for SCD921 is not statically decidable.

Sound-level indicator: trctaudiospectrumanager RULED OUT (local mic+local-music FFT, RECORD_AUDIO perm, audioPlay(filePath), onSpectruData emit). Most plausible live source = stream PCM via IRegistorIOTCListener.receivePCMData (mute=setMute gates only local speaker, consistent with "see sound activity while muted"). Exact bm_sound_level_indicator wiring is in a runtime-downloaded RN bundle absent from static tree (string only in localized res). secret-scan: OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the SCD921 audio-event detection in re/sound_detection.md (static analysis only).

Findings:
- Sound-detection on/off = DP `decibel_switch` (boolean, dpId 139); sensitivity = DP `decibel_sensitivity` (string-enum, dpId 140). Each claim cites file:line in DpSoundCheck/DpSoundSensitivity, FuncBaseSoundCheck/FuncBaseSoundSensitivity, and DeviceDpUtil DpCode table + N() publisher (high confidence).
- Honest ambiguity flagged: two SoundSensitivityMode enums map levels differently - legacy LOW(0)/HIGH(1) vs newer baby-monitor LOW(0)/MID(1)/HIGH(2). The 3-level enum is the high/mid/low path; which mounts for SCD921 needs a DP-schema/live read (medium).
- Sound-level indicator: ruled OUT trctaudiospectrumanager (it is a local mic + local-music-file FFT visualizer; high). Identified the most plausible live source as decoded stream PCM via IRegistorIOTCListener.receivePCMData, since mute (setMute) gates only local speaker rendering, matching the UI tip "See sound activity while muted" (medium). The exact bm_sound_level_indicator wiring lives in a runtime-downloaded RN panel bundle absent from the static tree - documented as a residual unknown with what would unblock it.

Gate: `just secret-scan` passes (no secrets/PII inlined; DP codes and string names only). AC 1-3 met.
<!-- SECTION:FINAL_SUMMARY:END -->
