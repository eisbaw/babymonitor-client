---
id: TASK-0024
title: >-
  Re-anchor re/*.md citations to symbol names (line numbers drift across jadx
  runs)
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 01:50'
updated_date: '2026-06-25 02:28'
labels:
  - phase3
  - re
  - review-followup
  - citation-hygiene
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-7 review of TASK-0007 (both reviewers, P1). The analysis docs cite decompiled paths as path:LINE, but jadx line numbers shift between runs/configs (e.g. -Xmx12g --no-debug-info vs default), so several load-bearing cites in re/tuya_cloud_auth.md (checkAPIName cited :185-191 but actually :236-239; User.java :34-57 vs :241-259; CameraInfoBean P2pConfig :140-175 vs :1459-1465) point into obfuscation noise. Symbolic anchors (class/field/method/string-constant names) are ALL correct. Fix: adopt a citation convention of SYMBOL-anchored cites (e.g. ThingApiParams.checkAPIName / User.sid) with line as an optional hint, and sweep existing re/*.md to match. Relates to TASK-0021 (check-evidence validates shape not content). Consider pinning the jadx invocation in just decompile so lines are reproducible. Affects all analysis docs, not just tuya_cloud_auth.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A symbol-anchored citation convention is documented (TESTING.md / check_evidence header) and the existing re/*.md load-bearing cites are swept to it (or verified symbol+line accurate against the current just decompile tree)
- [x] #2 check-evidence still green; ideally a spot-check that a sampled cited symbol resolves in the current decompile
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1) Document symbol-anchored citation convention (path::Symbol / Symbol (path ~:NN); symbol authoritative, line = approximate hint) in TESTING.md Part 1 + check_evidence.py header. 2) Widen CITATION_RE minimally to accept a bare source path and a ~:NN / :NN hint; normalise line hints in distinct_citations so a file cited bare+hinted is ONE source (do not game the >=2-source confirmed rule). 3) Add self-test: hinted+bare cites accepted; no-citation claim still FAILS; confirmed-one-file-twice still flags. 4) Sweep load-bearing cites in re/*.md to symbol-anchored form, verifying each symbol resolves in the current jadx tree and fixing line hints; prioritise reviewer-flagged drifts (checkAPIName, User.sid, CameraInfoBean.P2pConfig). 5) Note 'decompile' recipe already pins -Xmx12g --no-debug-info. 6) Gates: check-evidence, gates-selftest, secret-scan, e2e all green.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
GOTCHAS / decisions:
- check_evidence widening: added a SOURCE_EXT alternative to CITATION_RE that accepts a bare decompiled source path (.java/.kt/.so/.xml/.json/.js/.ts/.md/...) plus an optional ~:NN or :NN hint. Legacy 'path:NN' alt kept verbatim so nothing already-green regressed. NOT weakened: a claim section still needs a confidence label AND >=1 distinct citation, and the >=2-source 'confirmed' rule still holds.
- Subtle correctness fix: distinct_citations() now strips the line hint (LINE_HINT_RE) before de-duping, so the SAME file cited bare + hinted is ONE source. Without this, the symbol-anchored convention could game rule 4b (confirmed needs 2 sources) by re-citing one file with/without a line. Self-test case (d) proves it still flags.
- Had to add 'md' to SOURCE_EXT: my sweep dropped ':NN' from sibling re/*.md cross-doc references, which then stopped matching any citation token (they were previously matched only via path:NN). Adding .md keeps cross-doc refs as valid citation tokens (consistent with line-optional principle; not a weakening since .md:NN already matched before).
- Reviewer-flagged drifts verified+fixed against current jadx tree: checkAPIName ~:192 (was :185-191), User.sid ~:255 / domain ~:241 / uid ~:259 / ecode ~:242 (was :34-57), CameraInfoBean.P2pConfig ~:1459 with p2pKey ~:1462 / initStr ~:1461 (was :140-175).
- Symbols verified to resolve in current tree (rg): ThingApiParams.checkAPIName/initUrlParams/KEY_*; pqdbppq action constants (:42/43/46/66/88/102); LoginBusiness.y/s/r; TUNIAPIRequestManager.apiRequestByAtop + TUNILoginManager.onTicketSuccess; User/Domain/qdddbpp; HomeBean/DeviceBean/CameraInfoBean; ThingApiSignManager.generateSignature(Sdk)/swapSignString/postDataMD5Hex/getUrlWithQueryString/bdpdqbp; pbddddb.bdpdqbp; ThingNetworkSecurity.initJNI; BuildConfig.THING_SMART_* (values stay in secrets/); P2PMQTTServiceManager.send302MessageThroughMqtt/handleMqttAnswer/isP2PMqttAnswer/registerMqtt302; IThingP2P.resendOffer/setSignaling/connect; ThingCameraConstants.P2PType; qpppdqb demo bean; SecureNativeApi.getConfig; manifest permission/activity names + thing_jump_scheme.
- 'just decompile' ALREADY pins JADX_OPTS=-Xmx12g + --no-debug-info; no change needed.
- LIMITATIONS: (1) apktool XML line hints (manifest/strings) are more stable than jadx but still re-decode-dependent; left as approximate hints anchored on android:name / resource name. (2) Cross-doc 're/foo.md' references: I removed their stale ':NN' line numbers (they pointed at sibling-doc lines that also drift) but did not re-verify each sibling line; they now resolve as whole-doc references, which is correct for a cross-doc pointer. (3) I did NOT touch every trivial cite; focus was every CLAIM section's citation resolving to a real symbol. (4) Committed on branch task-0024-symbol-anchored-citations (was on master); NOT pushed.

Review NO-GO follow-up (post-commit bcc5d00): the TASK-0024 change added 'md' to SOURCE_EXT in re/scripts/check_evidence.py, which let a cross-doc .md reference count as an independent source for the confidence:confirmed >=2-source rule. A .md sibling doc is derived from the same decompile and is NOT independent evidence; re/tuya_cloud_auth.md section '5b. DeviceBean core fields' exploited this (its 'second source' was re/review_gate_findings.md). FIX: (1) removed 'md' from SOURCE_EXT so a bare .md path is no longer a citation token; only 5b broke (other docs' .md cross-refs sit alongside real decompiled cites). (2) downgraded 5b from confirmed to likely and reworded it to state honestly: single decompiled source = DeviceBean field declarations; localKey/secKey secrecy is NOTED (not independently grounded) in review_gate_findings.md. (3) added check_evidence.py selftest case (e): a confirmed section whose only 'sources' are two .md files FLAGS as <2 sources, and a claim whose ONLY citation is a .md FLAGS as missing citation; proved RED when md is re-added. (4) TESTING.md now states a cross-doc .md reference is a navigation pointer, not an independent evidence source. Gates: check-evidence GREEN (0 waived), gates-selftest GREEN, secret-scan GREEN, e2e GREEN.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Adopted a SYMBOL-ANCHORED citation convention for re/*.md: cite the class/method/field/string-constant symbol; the line number is an OPTIONAL approximate hint written ~:NN (jadx line numbers drift between decompile runs). Documented in TESTING.md Part 1 and the check_evidence.py header. Minimally widened check_evidence CITATION_RE to accept a bare source path and a ~:NN/:NN hint (legacy path:NN kept); normalised line hints in distinct_citations so a file cited bare+hinted is one source (>=2-source 'confirmed' rule un-gameable). Extended the self-test to prove the new forms are accepted while a no-citation claim still FAILS (and confirmed-one-file-twice still flags). Swept load-bearing cites across tuya_cloud_auth/tuya_sign/tuya_cloud_config/streaming_mode/decompile_dex/manifest_analysis/native_libs/js_bundle_map, verifying each symbol resolves in the current jadx tree and fixing line hints; the three reviewer-flagged drifts (checkAPIName, User.sid, CameraInfoBean.P2pConfig) are corrected. 'just decompile' already pins -Xmx12g --no-debug-info. Gates green: check-evidence (0 waived), gates-selftest, secret-scan, e2e. Commit edc0a40 on branch task-0024-symbol-anchored-citations (not pushed).
<!-- SECTION:FINAL_SUMMARY:END -->
