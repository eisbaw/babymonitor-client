---
id: TASK-0054
title: >-
  Reframe core stream/device doc-comments that frame TASK-0032/bmp_token as the
  auth/stream-credential blocker
status: Done
assignee:
  - '@claude'
created_date: '2026-06-25 17:56'
updated_date: '2026-06-25 18:02'
labels:
  - phase3
  - docs
  - cleanup
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-0053 corrected the user-facing LOGIN-wall messaging (CLI + babymonitor/README) to the proven sign-insensitive server-side identity gate (ILLEGAL_CLIENT_ID, TASK-0050/0051). Residual internal doc-comments in the core stream/device layer still frame TASK-0032/bmp_token as the auth blocker for STREAM credentials (e.g. babymonitor-core/src/stream/session.rs ~:15,:233; src/stream/mod.rs ~:38; src/device.rs auth-gate comments; live_e2e.rs stream test ~:113,:134). These are not the user-facing login reason (so out of TASK-0053 scope) but conflate the same disproven cause: the real reason stream creds are unfetchable is the absent authenticated session (identity gate), with bmp_token only the signer's un-validated 6th ingredient. Reframe these internal comments consistently; keep control flow + the BmpTokenPending/StreamPending variant names unchanged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Core stream/device doc-comments + the live_e2e stream test reframe TASK-0032/bmp_token from 'the auth/stream blocker' to 'the absent authenticated session (server-side identity gate, TASK-0050/0051); bmp_token is only the signer un-validated 6th ingredient'; no control-flow or type-name change
- [x] #2 just e2e + just secret-scan + just check-evidence all green
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Reframe StreamPending *why* in stream/mod.rs (~37-38), stream/session.rs (~14-15, ~225-235), lib.rs StreamPending variant doc (~155-163, sibling with same conflation): the live media path is blocked by the absent authenticated session (server-side identity gate, ILLEGAL_CLIENT_ID, TASK-0050/0051); the device creds it needs ride that session; bmp_token noted only as the signer's un-validated 6th ingredient (TASK-0032), not the blocker. Keep StreamPending/MqttEnvelopePending names + logic exact.
2. Reframe device.rs list_devices framing (module doc ~53-59, fn doc ~527-533, ~547-552 inline, test comment ~624): list_devices needs an authenticated session, unobtainable because token.get is rejected by the server-side identity gate (TASK-0050/0051); it additionally cannot sign without the un-validated bmp_token (TASK-0032). Either way it honestly reports pending. Keep BmpTokenPending/PendingBmpToken/token_provider.bmp_token()? logic exact.
3. Reframe live_e2e.rs stream test doc (~113-119) + #[ignore] reason (~133-138) to identity-gate framing; bmp_token as un-validated ingredient.
4. Leave the genuine bmp_token-decode framing (lib.rs BmpTokenPending variant + module TOKEN-PENDING note, all of sign.rs) untouched — TASK-0032 legitimately owns the decode; not a conflation.
5. Run just e2e + secret-scan + check-evidence; fix any asserted-string/doc-test breakage honestly.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Reframed internal core doc-comments so the codebase tells one true story about the blocker, matching the user-facing correction from TASK-0052/0053.

What changed (comments + #[ignore] strings ONLY — no control flow, no type/variant names, no logic):
- stream/mod.rs: webrtc-rs honest-scope note + the StreamPending status block.
- stream/session.rs: LiveSessionDriver gating doc + run() honest-gating doc.
- lib.rs: the Error::StreamPending variant doc (sibling carrying the same conflation).
- device.rs: list_devices module doc, fn doc, the token_provider.bmp_token()? probe comment, and the list_devices_is_token_pending test comment.
- live_e2e.rs: the stream test doc + its #[ignore] reason string.

New framing: the device-list / stream creds are unfetchable because there is no authenticated session — token.get is rejected by a server-side identity gate (ILLEGAL_CLIENT_ID), proven sign-insensitive (TASK-0050/0051). bmp_token is now noted only as the signer's un-validated 6th sign ingredient (TASK-0032), explicitly NOT the blocker. list_devices honestly reports pending either way and never fabricates.

Left untouched on purpose (genuine, not a conflation): the BmpTokenPending variant doc + TOKEN-PENDING module note in lib.rs, and all of sign.rs — TASK-0032 legitimately owns the bmp_token decode itself. The PendingBmpToken/BmpTokenPending/StreamPending/MqttEnvelopePending names and the token_provider.bmp_token()? probe are unchanged.

User impact: none functional; the internal narrative now matches the proven blocker.

Gates (all green): just e2e exit 0 (103 core tests pass, 3 ignored; 10 + 6 in sibling crates; clippy -D warnings clean; fmt-check clean), just secret-scan OK, just check-evidence OK (22 docs, 0 waived).
<!-- SECTION:FINAL_SUMMARY:END -->
