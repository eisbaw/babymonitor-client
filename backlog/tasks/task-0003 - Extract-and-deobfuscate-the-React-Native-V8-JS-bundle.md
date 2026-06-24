---
id: TASK-0003
title: Extract and deobfuscate the React Native / V8 JS bundle
status: In Progress
assignee:
  - '@reverser'
created_date: '2026-06-24 22:35'
updated_date: '2026-06-24 23:33'
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

WHY: app runs React Native on V8; assets (kit_js, mini_app_js, thing_uni_plugins=101 plugins, mini_app_js) hold much of the auth/pairing orchestration in far-more-readable JS than native/Java. Delegate to Explore subagent (large output).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All JS bundles located under assets/ extracted to decompiled/js (beautified); re/js_bundle_map.md indexes the bundles, the Tuya RN bridge module names, and where login/pairing/streaming flows live
- [ ] #2 Notes whether bundle is plain JS, Hermes bytecode, or V8 cache; if bytecode, records the tool needed to decompile and files a follow-up task
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. unzip assets/{kit_js,mini_app_js,thing_uni_plugins} -> decompiled/js.
2. Determine format: head bytes (plain JS vs Hermes HBC magic 0x1F1903C1 vs V8 cache). file/xxd.
3. Beautify plain-JS kit_js bundles (js-beautify if available, else note minified).
4. Index bundles + Tuya RN bridge module names (TUNI* managers) + locate login/pairing/streaming flows via rg over IPCKit/P2PKit/PlayNetKit/Activation.
5. Write re/js_bundle_map.md; secret-scan must stay green (do NOT commit raw bundle content with secrets).
<!-- SECTION:PLAN:END -->
