---
id: TASK-0105
title: RE family sharing & role permissions (admin/guest)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:08'
labels:
  - re
  - account
  - sharing
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document multi-user sharing: the Tuya home/member/share API (IThingHomeDeviceShare, IThingHomeMember, MemberBean) and the Philips role model (Admin full control vs Guest view-only), including how per-role permissions map to feature gating in the panel (bm_*_admin_* vs bm_*_guest_* strings). Static-RE the share/invite API surface and the role->capability matrix into an re/ writeup. Do not commit any real uid/homeId/email — reference secrets/ only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The device-share/invite + member-management API entrypoints are documented with file:line evidence
- [x] #2 The admin-vs-guest capability matrix is captured from the role-gated strings/funcs with confidence
- [x] #3 re/family_sharing.md writeup exists; no account identifiers inlined
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep IThingHomeDeviceShare/IThingHomeMember/MemberBean + role beans
2. Capture admin/guest capability matrix from bm_*_admin/guest strings
3. Resolve SDK factory + concrete camera-share caller
4. Write re/family_sharing.md (confidence-annotated, file:line, residual unknowns)
5. Run just secret-scan; keep doc clean (no uid/homeId/email/PID inlined)
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- Mapped two sharing mechanisms: home-membership (IThingHomeMember + MemberBean role/admin/customRole) vs device-share (IThingHomeDeviceShare + SharedUserInfoBean, flat/no-role).
- Role enum MemberRole (OWNER=2/ADMIN=1/MEMBER=0/CUSTOM=-1/INVALID=-999) + MemberStatus (WAITING/ACCEPT/REJECT/INVALID).
- API entrypoints with file:line incl. updateMemberRole (member :69), transferOwner :57, addShare/addShareWithHomeId/inviteShare; SDK factories ThingHomeSdk.getDeviceShareInstance :677 / getMemberInstance :1162; camera-panel caller DefaultDeviceShareUseCase :2315/2864/3051.
- Captured full Admin/Guest capability matrix for all 4 model variants (family/ecoowl/no1_owl/no2) from bm_*_admin/guest_*_content strings; invariant: account-management + alerts config are Admin-only across every variant.
- HONEST gaps: Philips capability table is rendered by a runtime-downloaded RN panel (grep proves bm_*_content strings unreferenced outside R.java); server-vs-client enforcement of guest limits not statically determinable.
- No uid/homeId/email/PID values inlined; just secret-scan PASSES.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added re/family_sharing.md: static RE of multi-user sharing for the Tuya-reskin SCD921/923.

What: documents the two independent Tuya sharing mechanisms (role-graded home membership via IThingHomeMember/MemberBean vs flat view-oriented device share via IThingHomeDeviceShare/SharedUserInfoBean), the MemberRole/MemberStatus enums, the CustomRoleBean resource-ACL model, the full member + device-share/invite API surface with file:line evidence and SDK factory + camera-panel call sites, and the verbatim Admin-vs-Guest capability matrix for all four device-model variants (family/ecoowl/no1_owl/no2) from the bm_*_admin/guest_*_content strings.

Key findings: account-management and alerts-config are Admin-only in every variant (the hard privilege boundary); recording-type features (snapshot/video/voice recording) are the clearest Admin-gated capabilities; a device share carries no role field (Guest = flat grant), so role gradation lives entirely on the home-member side via updateMemberRole(isAdmin).

Honesty: the Philips capability table is consumed by a runtime-downloaded RN panel (grep-proven absent from the static APK outside R.java), so the exact SCD921/923 prefix and the server-vs-client enforcement of guest limits are NOT statically resolvable; documented in Residual unknowns with what would unblock each. No account identifiers/PII/PID values inlined; just secret-scan passes.
<!-- SECTION:FINAL_SUMMARY:END -->
