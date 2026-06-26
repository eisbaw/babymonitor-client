---
id: TASK-0065
title: >-
  Complete full live login: password.login (RSA+MFA) -> session sid/uid ->
  device.list
status: To Do
assignee: []
created_date: '2026-06-26 10:31'
labels:
  - auth
  - login
  - stream-unblock
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
token.get now succeeds (returns the RSA pubkey + ticket). Complete the login flow: RSA-encrypt the password under the token.get pubkey (PKCS#1 v1.5), submit user.email.password.login (handle the graphic/captcha + MFA code steps seen in emulator_captures/cap1), capture the session (sid/uid/home DC domain), then drive device.list against a1.tuyaeu.com. Validate each step against cap1/flows.json. Interactive MFA is owner-gated.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 password.login succeeds and yields a session (sid/uid + home-DC domain)
- [ ] #2 MFA/captcha steps handled per cap1 sequence (token.get refresh + mfa.code.get)
- [ ] #3 device.list returns the account home + baby-monitor device record (post-AES-decrypt)
- [ ] #4 Each request validated against emulator_captures/cap1/flows.json; secrets stay in secrets/
<!-- AC:END -->
