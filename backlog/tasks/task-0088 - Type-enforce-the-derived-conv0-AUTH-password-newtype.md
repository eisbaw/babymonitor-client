---
id: TASK-0088
title: Type-enforce the derived conv=0 AUTH password (newtype)
status: To Do
assignee: []
created_date: '2026-06-28 20:45'
labels:
  - stream
  - media
  - refactor
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
set_media_auth takes a plain String and cannot enforce that the caller passes the DERIVED md5 (md5_hex_lower(password||localKey)) rather than the raw rtc.config password — the bug that made the camera go silent. Wrap it in a newtype constructible only via derive_media_auth_password so the precondition is unforgeable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A DerivedAuthPassword newtype is the only type set_media_auth accepts; it is constructed only by derive_media_auth_password
- [ ] #2 Passing a raw password to the auth path is a compile error
<!-- AC:END -->
