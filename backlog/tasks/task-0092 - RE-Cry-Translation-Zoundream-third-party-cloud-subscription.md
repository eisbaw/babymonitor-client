---
id: TASK-0092
title: RE Cry Translation (Zoundream third-party cloud subscription)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:55'
labels:
  - re
  - ai-detection
  - cloud
  - subscription
  - third-party
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the Zoundream-powered cry-translation service: a paid cloud feature that interprets baby cries (hungry/sleepy/uncomfortable). Static-RE the integration: how cry audio is captured and forwarded (via Tuya servers vs direct Zoundream API), the classify keys/result schema, and the subscription/account management surface (trial, monthly subs, manage account). Produce an re/ writeup of the API/result contract; do NOT capture or commit any account identifiers or tokens — reference secrets/ only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The Zoundream audio-forwarding path and result/classify schema are documented with file:line evidence (CryTranslationClassifyKeys) and confidence levels
- [x] #2 The subscription/account-management entrypoints are identified; any recovered identifiers are referenced by secrets/ location only, never inlined
- [x] #3 re/cry_translation.md writeup exists distinguishing detection (on-device DP) from translation (cloud), with explicit unknowns
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep cry/zoundream sources under decompiled/jadx\n2. Map detection DP vs translation DP + token/subscr DPs\n3. Recover classify keys + result delivery channel\n4. Recover subscription JSON schema + JS-bridge + web/auth entrypoints\n5. Write re/cry_translation.md; run just secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- App forwards NO cry audio: zero audio/record/upload/mic code in the cry package; app only writes token DP cry_trans_token(id17) + subscription JSON DP cry_trans_subscr(id14) to the baby unit. Audio leaves the BABY UNIT -> Zoundream cloud (consent string bm_cry_trans_about_service_text2).
- Result/classify schema = CryTranslationClassifyKeys (10 keys) mapped to reused ipc_* message-type strings; delivered as Tuya message-center "212" notifications; MessageCenterApp routes to CryReasonsType.
- Detection (cry_det_switch id12, Philips/on-device) is distinct from Translation (cry_trans_switch id2, Zoundream).
- Subscription web = *.zoundream.app URLs, env(zdEnv)+region selected; WebView injects Authorization=ZoundreamSecretProvider.a() (remote Tangram nightowl:zdSecret; testing placeholder NOT inlined).
- No secrets/PII inlined; just secret-scan = OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the Zoundream-powered Cry Translation integration in re/cry_translation.md (static analysis only).

Key findings:
- Detection vs Translation separated: cry_det_switch (DP id 12, Philips on-device) vs cry_trans_switch (DP id 2, Zoundream). The app forwards NO cry audio — verified there is zero audio/record/upload/microphone code in the cry package. Activation is token-over-DP: the Zoundream subscription web page hands a token to the native bridge, the app writes it to DP cry_trans_token (id 17) and mirrors subscription JSON to DP cry_trans_subscr (id 14). The baby unit then streams sound to Zoundream cloud directly (consent string bm_cry_trans_about_service_text2).
- Result/classify schema: CryTranslationClassifyKeys maps 10 categories (no_cry, sleep, hungry, uncomfortable, burp, pain, 3x license_expired*, Crying_is_translating) onto reused ipc_* Tuya message-type strings; results arrive as message-center "212" push notifications and are routed via MessageCenterApp -> CryReasonsType -> NCryTransReasonsActivity. Subscription JSON contract captured (ZounDreamQueryStatusBean / CryTranslationStatusBean: token,type,status,start,days_left,days_total,logged_in,next_billing).
- Subscription/account entrypoints: *.zoundream.app web URLs selected by zdEnv + region; WebView injects Authorization = ZoundreamSecretProvider.a() (remote Tangram nightowl:zdSecret; the testing placeholder is intentionally NOT inlined). JS bridge namespace cryTranslation with identifyDevice/subscriptionStatus/querySubscription. CallingReason lifecycle signals documented.

Every claim carries a confidence level and file:line evidence. Residual unknowns (camera<->Zoundream wire protocol, where classification runs, web-page POST body, zdSecret semantics, type/status vocabulary) are listed with what would unblock them. No secrets/PII inlined; just secret-scan passes.
<!-- SECTION:FINAL_SUMMARY:END -->
