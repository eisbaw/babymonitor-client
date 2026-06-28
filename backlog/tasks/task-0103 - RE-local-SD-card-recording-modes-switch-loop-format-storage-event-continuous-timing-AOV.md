---
id: TASK-0103
title: >-
  RE local SD-card recording modes (switch/loop/format/storage +
  event/continuous/timing/AOV)
status: Done
assignee:
  - '@myself'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:14'
labels:
  - re
  - device-settings
  - dp
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document SD-card recording if present on SCD921/923. Map DpSDCardRecordSwitch, DpSDCardRecordLoopSwitch, DpSDFormat, DpSDStorage (status/capacity), RecordMode EVENT(1)/CONTINUOUS_RECORD(2), and the AOV/time-lapse low-frame mode (record 1 frame / 5s) plus scheduled/timed recording. Static-RE each DP code + value mapping into one re/ writeup. Note confidence that these may be generic Tuya capabilities not wired on the baby unit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The SD record switch/loop/format/storage DPs and the record-mode enum are documented with file:line evidence
- [x] #2 Whether SCD921/923 actually exposes SD recording (vs generic Tuya SDK presence) is assessed and stated with confidence
- [x] #3 re/sdcard_recording.md writeup exists covering modes (event/continuous/timing/AOV)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Static-RE per ACs: grep decompiled/jadx + decompiled/apktool; write re/sdcard_recording.md with per-claim confidence + file:line evidence; verify just secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Pure static-RE doc task; no code implemented. Grepped jadx tree under decompiled/jadx/sources for the four start-from DP operators + RecordMode + Func rows, then expanded to DpRecordModel/DpAovModel/DpAovCustomizeFrameModel/FuncChangeRecordModel/FuncAOVRecordModel and the timing-setting model. Resolved jadx-synthetic R.string ids (F6/E6/O5/P5/B6/z6/y6/C6/w6/A6/D6/Xa/H6) via integer ids in ipc/camera/ui/R.java -> apktool public.xml (string 0x7f13xxxx) -> strings.xml for exact label text. For AC2 reused the same captured SCD921 schema environment_sensors.md cites; grepped it for all 14 SD/record DP codes (all 0) and extracted the 43 codes it DOES advertise (schema names only, no values). Gotchas captured: (1) Tuya schema typo sd_storge; (2) record_mode value 3=TIMING exposed via raw-string publish but absent from the RecordMode enum; (3) DpAovModel.j() casts to RecordMode so cannot represent AOV value 3, but the real publish uses raw substring; (4) AOV resource-name vs displayed-pairing crossed (B6,z6/y6,C6) so trust the literal subtitle interval. secret-scan via nix-shell: OK; confirmed it scans untracked files (secret_scan.sh:151) so the new doc was genuinely covered. Did not modify backlog status (left to orchestrator).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the local SD-card recording / record-mode control plane for the Philips Avent Baby Monitor+ (Tuya-reskin SCD921/923) in a new static-RE writeup at re/sdcard_recording.md. What changed: new doc mapping every SD/record DP (record_switch master, record_loop overwrite-when-full, ipc_mute_record mute audio, record_mode enum EVENT/CONTINUOUS/TIMING + record_timing_set schedule, the AOV time-lapse trio record_mode_aov_switch / record_aov_mode 1frame-per-5s|2s|custom / record_aov_mode_customize seconds-interval default 5, plus sd_format, sd_format_state, sd_storge pipe-delimited total|video|free, sd_status, sd_umount, sd_encryption), each with a confidence level and symbol + File.java:NN evidence, and ACTION/SUB_ACTION + DpCamera.java registrations cited. UI value->label mappings resolved by chaining jadx R.java integer ids -> apktool public.xml -> strings.xml. Key finding (AC2): the SCD921 does NOT expose SD recording — the captured live device schema (43 DP codes) advertises none of the 14 SD/record codes, so the whole feature group is dormant generic Tuya camera-SDK code gated off by querySupportByDPCode(), the same pattern as the documented humidity gap; stated high-confidence for the captured device with an honest medium-confidence caveat for other firmware/variants since support is server-delivered. Honesty notes surfaced: schema typo sd_storge, record_mode/AOV value 3 handled by raw-string publish despite the enum omitting it, and the crossed AOV resource-name vs subtitle pairing. Validation: nix-shell 'just secret-scan' = OK and confirmed to cover untracked files; no secrets/PII inlined (schema referenced by path:line only); no code implemented.
<!-- SECTION:FINAL_SUMMARY:END -->
