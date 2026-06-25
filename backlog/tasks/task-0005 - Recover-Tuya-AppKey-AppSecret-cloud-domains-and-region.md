---
id: TASK-0005
title: 'Recover Tuya AppKey/AppSecret, cloud domains and region'
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:35'
updated_date: '2026-06-25 01:33'
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
  - TASK-0019
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md, re/review_gate_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology. Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) + confidence. NEVER write a recovered secret/token/real account ID into a task field, re/*.md, or your returned summary — reference its secrets/ location only. File new backlog tasks for tangents.

SPIKE (verdict required). Recover the material needed to sign Tuya mobile-app API requests. Per re/review_gate_findings.md F1 the signing key is NOT a plain appSecret: key = [app_cert_SHA256]_[token decoded from an embedded BMP (assets/t_s.bmp)]_[appSecret], HMAC-SHA256 (ref nalajcie/tuya-sign-hacking). Search BOTH APKs: DEX+assets+t_s.bmp in the base APK, native string tables in config.arm64_v8a.apk (libthing_security.so / libthingnetsec.so likely hold the white-box derivation). Delegate to general-purpose subagent. SECRETS: recovered values go ONLY to secrets/; committed md records location+method, never the value.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 secrets/tuya_appkey.json holds appKey/appSecret (if found) + their source location; re/tuya_cloud_config.md documents region/datacenter domains from thing_domains_v1 and the api base URLs, with evidence citations and confidence
- [x] #2 If key/secret are not statically recoverable (e.g. white-box crypto in libthing_security), that is stated honestly with what would be needed, and a follow-up task is filed
- [x] #3 VERDICT (exactly one): {recoverable-statically | needs-runtime-hook | needs-live-capture} for the full sign-key derivation (cert pin + BMP token + routine), with the precise evidence a runtime hook or pcap would unblock
- [x] #4 re/tuya_cloud_config.md contains ONLY non-secret config (domains/region/base URLs); appKey/appSecret/sign-key values appear in NO committed file
- [ ] #5 If this repo is ever published, appKey/appSecret are scrubbed; README will state they are not redistributed (Philips' Tuya developer credentials)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FINAL SUMMARY: SPIKE complete. VERDICT=needs-runtime-hook for the full sign-key derivation. Tuya mobile-app sign algorithm characterized end-to-end (sorted-whitelist params joined by '||', postData folded as swapSignString(md5AsBase64), keyed sign via native doCommandNative cmd=1). appKey/appSecret/TTID recovered statically (secrets/tuya_appkey.json). F1 CONFIRMED: key=[app_cert_SHA256]_[t_s.bmp token]_[appSecret] in libthing_security.so (decode via imath/matrix in libthing_security_algorithm.so). Datacenter domains encrypted in thing_domains_v1/regions, runtime-decrypted, region-selected post-login (F5). Docs: re/tuya_sign.md (+Verdict), re/tuya_cloud_config.md (non-secret). Gates: check-evidence/secret-scan/e2e all GREEN. Follow-ups: TASK-0022 (Frida), TASK-0023 (Ghidra). Fed forward to TASK-0007/0012.

Cycle-5 review: both GO. Secret-hygiene P0 PASSED (appKey/appSecret in zero tracked files, full history scan clean; secrets/ gitignored). Verdict needs-runtime-hook honest+correctly scoped. Orchestrator fixed 2 P2 prose-precision nits (tuya_sign.md:154 symbol-export wording; tuya_cloud_config.md regions-envelope description).
<!-- SECTION:NOTES:END -->
