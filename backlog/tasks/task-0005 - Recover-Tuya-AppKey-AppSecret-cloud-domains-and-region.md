---
id: TASK-0005
title: 'Recover Tuya AppKey/AppSecret, cloud domains and region'
status: To Do
assignee: []
created_date: '2026-06-24 22:35'
updated_date: '2026-06-24 22:46'
labels:
  - phase3
  - re
  - wave1
  - auth
  - security
dependencies:
  - TASK-0001
  - TASK-0003
  - TASK-0004
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md, re/review_gate_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology. Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) + confidence. NEVER write a recovered secret/token/real account ID into a task field, re/*.md, or your returned summary — reference its secrets/ location only. File new backlog tasks for tangents.

SPIKE (verdict required). Recover the material needed to sign Tuya mobile-app API requests. Per re/review_gate_findings.md F1 the signing key is NOT a plain appSecret: key = [app_cert_SHA256]_[token decoded from an embedded BMP (assets/t_s.bmp)]_[appSecret], HMAC-SHA256 (ref nalajcie/tuya-sign-hacking). Search BOTH APKs: DEX+assets+t_s.bmp in the base APK, native string tables in config.arm64_v8a.apk (libthing_security.so / libthingnetsec.so likely hold the white-box derivation). Delegate to general-purpose subagent. SECRETS: recovered values go ONLY to secrets/; committed md records location+method, never the value.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 secrets/tuya_appkey.json holds appKey/appSecret (if found) + their source location; re/tuya_cloud_config.md documents region/datacenter domains from thing_domains_v1 and the api base URLs, with evidence citations and confidence
- [ ] #2 If key/secret are not statically recoverable (e.g. white-box crypto in libthing_security), that is stated honestly with what would be needed, and a follow-up task is filed
- [ ] #3 VERDICT (exactly one): {recoverable-statically | needs-runtime-hook | needs-live-capture} for the full sign-key derivation (cert pin + BMP token + routine), with the precise evidence a runtime hook or pcap would unblock
- [ ] #4 re/tuya_cloud_config.md contains ONLY non-secret config (domains/region/base URLs); appKey/appSecret/sign-key values appear in NO committed file
- [ ] #5 If this repo is ever published, appKey/appSecret are scrubbed; README will state they are not redistributed (Philips' Tuya developer credentials)
<!-- AC:END -->
