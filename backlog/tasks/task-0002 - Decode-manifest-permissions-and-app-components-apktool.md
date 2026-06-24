---
id: TASK-0002
title: 'Decode manifest, permissions, and app components (apktool)'
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:35'
updated_date: '2026-06-24 23:24'
labels:
  - phase2
  - re
  - wave1
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 2): AndroidManifest + resources reveal services/activities/receivers, the permission set (camera/mic/location/local-network), exported components, deep links and any custom URI schemes used for pairing/login. Delegate to Explore subagent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 decompiled/apktool produced from base APK; re/manifest_analysis.md lists permissions, all services/activities/receivers, intent-filters, deep-link schemes, and flags anything network/pairing-relevant
- [x] #2 Tuya/RN service entry points (push, P2P, camera foreground service) identified with class names
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. apktool d base apk -> decompiled/apktool (decode manifest+resources).
2. Parse AndroidManifest.xml: permissions, services/activities/receivers, intent-filters, deep-link schemes.
3. Identify Tuya/RN service entry points (push, P2P, camera foreground service) by class name.
4. Write re/manifest_analysis.md with AndroidManifest.xml line citations.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
apktool d -f exit 0; decompiled/apktool gitignored. re/manifest_analysis.md written with AndroidManifest.xml line cites.
Key: MqttService:252 (cloud/WebRTC-signaling candidate), GwBroadcastMonitorService:872 (LAN UDP discovery), nightowl watchdog FGS:431, DoorBellCallService:657 (camera push), ThingRCTSmartCameraPanelActivity:117 (live-view RN panel host). Custom scheme philipsclnightowl:// (strings.xml:9199).
GOTCHA: app element is com.smart.app.SmartApplication (Tuya bootstrap), NOT a Philips Application. networkSecurityConfig=@xml/b926312 worth a later look for pinning/cleartext (not chased).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Decoded the base APK manifest+resources with apktool 2.12.1 and documented the full component surface in re/manifest_analysis.md, every claim cited to AndroidManifest.xml line numbers.

What: permission set (CAMERA/RECORD_AUDIO/FINE+COARSE_LOCATION/WIFI/MULTICAST/FOREGROUND_SERVICE(+MEDIA_PLAYBACK)/POST_NOTIFICATIONS/BLUETOOTH/INTERNET), tallies (574 activities, 34 services, 19 receivers, 8 providers), 3 deep-link schemes (philipsclnightowl://, module.entrance://netdiagnosis), and Tuya/RN entry points by class.

Entry points pinned: MqttService:252, GwBroadcastMonitorService UDP:872, nightowl watchdog FGS:431, DoorBellCallService:657, ThingRCTSmartCameraPanelActivity:117, TUNIModuleProvider:279. check-evidence + secret-scan green.
<!-- SECTION:FINAL_SUMMARY:END -->
