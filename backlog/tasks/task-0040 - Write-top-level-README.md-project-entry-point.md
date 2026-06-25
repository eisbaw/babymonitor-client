---
id: TASK-0040
title: Write top-level README.md (project entry point)
status: Done
assignee:
  - '@architect'
created_date: '2026-06-25 09:39'
updated_date: '2026-06-25 09:43'
labels:
  - phase9
  - docs
  - wave2
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Final pure-static deliverable: a top-level README.md consolidating the project, with citations into the re/ docs. No overclaims, no secrets.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 README covers: (1) device/app = reskinned Tuya SCD921/923; (2) the two core findings (WebRTC-over-MQTT video; MD5 sign with 5/6 ingredients recovered); (3) the Ghidra-confirmed runtime-bmp_token blocker + what one live artifact unblocks; (4) the Rust client status + how to run; (5) static-only methodology (jadx + Ghidra-primary/r2-cross-check)
- [x] #2 Every load-bearing claim cites a re/ doc; no secrets; check-evidence + secret-scan + e2e green
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Consolidate the project into a top-level README.md (repo root, OUT of check-evidence's re/*.md scope). Cover the 5 required points, each citing re/*.md docs inline: (1) device/app = reskinned Tuya IPC SCD921/923 [milestone2_findings.md]; (2) two findings -- WebRTC-over-MQTT video [streaming_mode/webrtc_session/p2p_triage] + MD5 sign with 5/6 ingredients [tuya_sign_static, review_gate_findings F1]; (3) Ghidra-confirmed runtime-bmp_token blocker + the one live artifact that unblocks [bmp_token_whitebox §9, tuya_sign_static]; (4) Rust client status (complete, token-injectable, CANNOT login/stream) + build/run [babymonitor/README.md]; (5) static-only methodology jadx + Ghidra-primary/r2-cross-check + grounding gates [prd.md, TESTING.md]. Status line, scope/authorized-use note, repo-layout map, LICENSE pointer (MIT in Cargo, no root LICENSE file yet). NO secret values -- reference by location/doc only. Verify check-evidence + secret-scan + e2e GREEN, then one commit (no AI-credit trailer).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wrote top-level README.md (repo root). Covers all 5 points, each with re/*.md citations: (1) reskinned Tuya IPC SCD921/923 [milestone2_findings.md]; (2) WebRTC-over-MQTT video [streaming_mode.md/webrtc_session.md/p2p_triage.md] + MD5 mobile sign 5/6 ingredients [tuya_sign_static.md, review_gate_findings.md F1]; (3) runtime bmp_token blocker -- Ghidra-confirmed runtime JNI byte[] SDK-config (doCommandNative param_6), unblocked by ONE accepted live sign vector OR a one-time runtime-config dump (both excluded by static-only) [bmp_token_whitebox.md §9, tuya_sign_static.md]; (4) Rust client complete+token-injectable but CANNOT login/stream, with build/run [babymonitor/README.md]; (5) static-only methodology jadx + Ghidra-primary/r2-cross-check + grounding gates [prd.md, TESTING.md]. Includes Status line, Scope/authorized-use, repo-layout map, LICENSE pointer (MIT in Cargo, no root LICENSE file yet). NO secret values -- creds referenced by secrets/ location only. Gates GREEN: check-evidence (17 docs; README is OUT of its re/*.md scope -- re_dir=re/, non-recursive *.md glob), secret-scan (tracked+diff+backlog), e2e (build/test 97+ pass/clippy/fmt/stub-grep/assert-offline/bmp-decode).
<!-- SECTION:NOTES:END -->
