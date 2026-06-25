---
id: TASK-0001
title: Decompile all DEX with jadx into searchable Java
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:34'
updated_date: '2026-06-25 00:22'
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

WHY: 14 multidex files (~190MB) hold the Java/Kotlin half of this Tuya-reskin app. A clean jadx decompile under decompiled/jadx is the substrate every later static-analysis task searches. Delegate to an Explore/general-purpose subagent (large output).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All classes*.dex from extracted/xapk base APK decompiled to decompiled/jadx (jadx -Xmx4g), with a short re/decompile_dex.md noting jadx failures/obfuscation coverage
- [x] #2 Package-level map produced: com.tuya/com.thingclips namespaces, Philips packages, React Native bridge packages — counts + where the Tuya camera/P2P/auth code lives
- [x] #3 decompiled/ stays gitignored; only the summary md is committed
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. jadx -Xmx4g decompile all classes*.dex from base apk into decompiled/jadx; capture stdout/stderr to a log for failure accounting.
2. Tally package-level counts (com.tuya/com.thingclips, com.philips, RN bridge) via find/rg over decompiled/jadx.
3. Locate camera/P2P/auth code packages with evidence paths.
4. Write re/decompile_dex.md with command, coverage, package map, citations.
5. Verify check-evidence + secret-scan green; commit re doc only.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
jadx 1.5.0 decompile running; ~41.7k .java written (36,686 classes). re/decompile_dex.md has command + package map + obfuscation/coverage honesty.
GOTCHA: -Xmx4g is NOT a jadx CLI flag (errors Unknown option); heap goes via JADX_OPTS env (set in nix shell).
KEY LOCATIONS (forward-carried):
- TASK 7 cloud-auth: com/thingclips/sdk/network/ThingApiSignManager.java:69 generateSignature, :524 swapSignString (MD5-base64 byte-permute); sign KEY likely native (t_s.bmp, task 5). com/thingclips/sdk/user = login SDK.
- TASK 9/17 streaming: com/thingclips/smart/p2p/api/IThingP2P.java (connect/recvData/resendOffer) + utils/IMqttServiceUtils.java (send302MessageThroughMqtt, registerMqtt302) = WebRTC-over-MQTT Java side. camera/ipccamerasdk + camera/middleware/p2p = AV glue.
- Pairing: com/thingclips/smart/activator (381 files).
GOTCHA: partial R8 obfuscation (impl classes pqdbppq-style; 44 obfuscated top pkgs); public interfaces are the reliable read.
GOTCHA: jadx tail is VERY slow on classes5/8.dex (heaviest obfuscated) - stuck ~80% CPU-bound for a long time. Package STRUCTURE is complete+stable; only heavy-class bodies still flushing. AC#1 will be checked once jadx exits (process still running at notes time).

RESOLVED: 4g heap OOMd (exit 1, ~41.7k files, truncated 80%). Re-ran at -Xmx12g -> clean exit 0, 99% (36685/36686), 51,008 .java files, zero OOM. AC#1 now genuinely met.
Residual: 1,806 Method-not-decompiled stubs across 1,397 files (R8 obfuscation, flagged inline; no whole-class drops). 18 GB RAM available, 12g heap is the fix.
GOTCHA for future runs: shell.nix JADX_OPTS=-Xmx4g is too small for this dex set; prefix JADX_OPTS="-Xmx12g" (last -Xmx wins in HotSpot).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Decompiled all 14 classes*.dex from the base APK with jadx 1.5.0 into decompiled/jadx (gitignored) and produced re/decompile_dex.md (command, coverage, package map, code locations).

Key result: the shell-default -Xmx4g heap OOMs on this Tuya-SDK+RN dex set (exit 1, truncated ~80%/41.7k files); the documented fix is -Xmx12g, which decompiles cleanly (exit 0, 99%, 51,008 .java, zero OOM). Residual is 1,806 Method-not-decompiled stubs across 1,397 files (R8 obfuscation, flagged inline by jadx; no whole class dropped) — recorded honestly, not hidden.

Package map (counts cited): com.thingclips 22,377 files = the whole engine; com.philips just 1 (pure Tuya reskin); React Native at com.facebook.react 588. Located and cited the high-value code: cloud-auth sign (com/thingclips/sdk/network/ThingApiSignManager.java:69/:524), P2P/streaming (com/thingclips/smart/p2p IThingP2P + IMqttServiceUtils = WebRTC-over-MQTT Java side), camera/ipc/activator/mqtt packages. check-evidence + secret-scan green; cited line numbers verified stable on the final tree.
<!-- SECTION:FINAL_SUMMARY:END -->
