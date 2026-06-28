---
id: TASK-0108
title: >-
  RE device settings & diagnostics DPs (privacy mode, volume, mic sensitivity,
  status light, restart, battery, wifi signal, time/zone, privacy zones)
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
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the remaining device control/diagnostics DP family as one consolidated reference. Cover privacy mode (camera/mic off, blue-LED indicator), device speaker volume + microphone sensitivity, status/indicator-light toggle, remote restart, battery level (battery_percentage), wifi signal RSSI, system time-format/timezone (getSystemTimeFormat/getIpcTimeZoneId), and privacy-zone polygon masking. Static-RE: tabulate DP code -> value semantics for each into one re/ writeup. Privacy mode is the notable baby-monitor item — call it out.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each listed control/diagnostics DP code and its value semantics are tabulated with file:line evidence
- [x] #2 Privacy mode and privacy-zone masking entrypoints are explicitly documented with confidence
- [x] #3 re/device_settings_dps.md writeup exists with a DP reference table; rows that are generic-Tuya-but-maybe-unwired are flagged
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Static-RE per ACs: grep decompiled/jadx + decompiled/apktool; write re/device_settings_dps.md with per-claim confidence + file:line evidence; verify just secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static grep-only analysis of decompiled/jadx/sources and decompiled/apktool. Key findings: (1) volume=basic_device_volume, mic=mic_sensitivity, status-light=basic_indicator, restart=device_restart (shared by camera DpRestartDevice and station DpRestartStationDevice with different notify ACTIONs), privacy=basic_private (boolean, provably so), battery=wireless_electricity (NOT battery_percentage — that DP only appears in an unrelated audio module, flagged). (2) Two start-from operators are placeholders: DpWifiSignal is @Deprecated returning literal 'DpWifiSignal'; real wifi RSSI is a pull via requestWifiSignal() over the MQTT/transfer channel (TransferWifiSignal.f() returns ''). (3) Privacy-zone polygon transport uses multi_privacy_area (JSONArray of CameraMotionRegionBean: ispoly int, points Integer[], pointList AnchorPoint float x/y) published via L3(); ipc_privacy_polygon gates single-polygon mode; ipc_privacy_zone is the master switch. (4) Time: getSystemTimeFormat returns int 0/1/2 via locale date heuristic (TRCTIpcMonitorManager.java:799-804); getIpcTimeZoneId returns IANA tz id (TimeZoneUtils.b().getID()). No secrets/PII written — only generic Tuya DP-code identifiers and English UI labels. just secret-scan passes. Did not modify backlog status (left to orchestrator). One citation corrected after verification (time if/else 799-804). Per-DP value TYPES are schema-carried and marked MEDIUM where not provable from Java; honest unblock notes given (runtime SchemaBean dump / live DP capture / Philips RN panel JS not in extracted bundle).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the remaining device control/diagnostics DP family for the SCD921 (Tuya-reskin) as one consolidated static-RE reference at re/device_settings_dps.md. Covered speaker volume (basic_device_volume), mic sensitivity (mic_sensitivity), status/indicator light (basic_indicator), remote restart (device_restart, camera + station variants), battery level/reporting/power-mode/low-power (wireless_electricity, battery_report_cap, wireless_powermode, wireless_lowpower), wifi RSSI (request/response channel, not a settable DP), system time-format + 24h flag + IANA timezone id (RN bridge methods), the baby-monitor-notable Privacy mode (basic_private boolean lens/mic-off, with Philips bm_privacy_mode/blue-LED copy), and privacy-zone polygon masking (ipc_privacy_zone master switch, ipc_privacy_polygon, multi_privacy_area JSON payload of CameraMotionRegionBean polygons). Every claim carries HIGH/MEDIUM/LOW confidence and a decompiled file:line citation; value-type inferences and the unproven Philips-UI->DP binding are flagged honestly, and a Residual-Unknowns section lists what evidence (runtime schema dump, live DP/WIFI_SIGNAL/multi_privacy_area capture, Philips RN panel JS) would unblock each gap. Generic-Tuya rows that may be present-in-code-but-unwired on this hardware (battery/power family, station variants, deprecated DpWifiSignal placeholder) are explicitly called out. No secrets or PII were written; `just secret-scan` passes.
<!-- SECTION:FINAL_SUMMARY:END -->
