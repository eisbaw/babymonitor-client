---
id: TASK-0005
title: 'Recover Tuya AppKey/AppSecret, cloud domains and region'
status: To Do
assignee: []
created_date: '2026-06-24 22:35'
updated_date: '2026-06-24 22:36'
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
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY: Tuya cloud signs every API request (HMAC) with the app developer key/secret Philips embedded. Without them, reimplementing cloud auth is far harder. Search DEX, JS bundle, native string tables, assets/thing_domains_v1 and *config*.json. Delegate to general-purpose subagent. SECRETS: write any recovered key/secret ONLY to secrets/ (gitignored); the committed md records location+method, NOT the secret value.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 secrets/tuya_appkey.json holds appKey/appSecret (if found) + their source location; re/tuya_cloud_config.md documents region/datacenter domains from thing_domains_v1 and the api base URLs, with evidence citations and confidence
- [ ] #2 If key/secret are not statically recoverable (e.g. white-box crypto in libthing_security), that is stated honestly with what would be needed, and a follow-up task is filed
<!-- AC:END -->
