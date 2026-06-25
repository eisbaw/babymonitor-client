---
id: TASK-0027
title: >-
  FIX: milestone2_findings.md sign-key staleness - appSecret-alone is NOT
  sufficient to sign Tuya requests
status: To Do
assignee: []
created_date: '2026-06-25 02:46'
updated_date: '2026-06-25 02:52'
labels:
  - review-followup
  - wave1
  - docs
  - auth
dependencies:
  - TASK-0005
  - TASK-0007
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AUDIT FINDING F5 (TASK-0006 meta-review NO-GO), severity P1/deferrable. re/milestone2_findings.md 'What this means for the reimplementation' point #3 (~:83-86) frames the embedded Tuya appKey/appSecret as SUFFICIENT to sign cloud requests: 'Tuya cloud signs every API request (HMAC) with these; they are required to reimplement cloud auth.' This is STALE/refuted by the later TASK-0005 spike: re/tuya_sign.md verdict is needs-runtime-hook - appKey/appSecret ALONE are INSUFFICIENT. The mobile sign KEY is key=[app_cert_SHA256]_[token_decoded_from_t_s.bmp]_[appSecret] (review_gate_findings.md F1 ~:16), and two of three ingredients (cert SHA-256 = runtime input; decoded t_s.bmp token) plus the keyed-hash routine are NOT statically reproducible (tuya_sign.md 'What is and isnt statically reproducible' table; native evidence pbddddb.bdpdqbp -> doCommandNative cmd=1 in decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java, key material in libthing_security.so). Same staleness class as the streaming one (F3/TASK-0026): milestone2 is the stale ENTRY doc. FIX: correct/forward-point milestone2 point #3 to the tuya_sign.md needs-runtime-hook verdict, stating appSecret alone is insufficient (also needs cert_sha256 + decoded BMP token, neither statically reproducible). Do NOT change confidence labels elsewhere or restate secret values. VERIFY: just check-evidence GREEN; no new contradiction introduced.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 milestone2 point #3 (~:84) corrected/forward-pointed to re/tuya_sign.md verdict, explicitly stating appKey/appSecret ALONE are insufficient to sign (also requires app-cert SHA-256 + decoded t_s.bmp token per review_gate_findings.md F1), neither statically reproducible -> needs-runtime-hook
- [ ] #2 just check-evidence GREEN over re/*.md (incl. edited milestone2); just secret-scan GREEN; no new cross-doc contradiction introduced
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Minor: the matrix in re/review_wave1_analysis.md already uses 'F5' for an unrelated datacenter row; when you touch the doc, disambiguate the label (one-char cleanup).
<!-- SECTION:NOTES:END -->
