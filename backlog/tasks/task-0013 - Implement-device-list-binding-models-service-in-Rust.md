---
id: TASK-0013
title: Implement device list/binding models + service in Rust
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 01:44'
labels:
  - phase5
  - rust
  - wave1
  - device
dependencies:
  - TASK-0012
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

WHY: lets the client discover the SCD921 under the Tuya account - prerequisite for any streaming. Implement typed models + service from re/tuya_cloud_auth.md, serde camelCase, liberal Option/default. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 core::device lists devices and exposes the camera entry (id, p2p creds handles, online state); fixture test deserializes a real/representative device-list JSON (stored in secrets/) without error
- [ ] #2 Model mismatches found vs real shape are fixed; honest notes on any field whose meaning is still unknown
- [ ] #3 PROVE THE CHECK BITES: a negative test asserts the parser REJECTS/surfaces an error on a malformed device entry (missing camera P2P-credential handle / wrong type); the camera entry asserts required (non-Option) invariants (device id, p2p creds handle) so it is not a permissive serde sponge
- [ ] #4 ANONYMIZE: any device-list JSON quoted in re/*.md, notes, or summaries has uid/homeId/localKey/gwId/email/GPS/IP replaced with synthetic placeholders; a sanitized committable fixture is produced and tests run against it; localKey + P2P creds treated as secrets
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
[from TASK-0007: re/tuya_cloud_auth.md sections 5a-5c]
DEVICE-LIST CONTAINER: HomeBean{homeId, deviceList: List<DeviceBean>, sharedDeviceList: List<DeviceBean>}. Populated via home-detail atop call (action obfuscated to 'n' in DEX -> exact a= needs live capture).
DeviceBean record fields (src com/thingclips/smart/sdk/bean/DeviceBean.java:29-157):
  devId(String), name(String, may be PII), localKey(String) SECRET, secKey(String) SECRET, uuid(String, anonymize), pv(String), productId(String), productVer(String), schema/schemaMap, skills(Map), category/categoryCode (camera=sp/ipc family), dps/dpCodes/dpName(Map, may be sensitive), mac/ip/lat/lon (lat/lon = PII), iconUrl/uiType/ui/bv/gwType.
  -> SECRET fields: localKey, secKey. Anonymize devId/uuid/name/lat/lon in any fixture.
CAMERA P2P/WebRTC record - CameraInfoBean (per-devId config, separate fetch; src camera/ipccamerasdk/bean/CameraInfoBean.java:9-26,140-175):
  id(String), p2pId(String, sensitive handle), p2pType(int), p2pSpecifiedType(int), p2pPolicy(int), password(String) SECRET, sessionTid(String) SECRET, skill(String JSON: videos[]/audios[]/p2p/cloudGW/localStorage/sdk_version/video_num), mediaConsumerSkill(String), vedioClarity(int)/vedioClaritys(int[]), audioAttributes{hardwareCapability[],callMode[]}, p2pConfig(nested), panoramicInfo(String).
  Nested P2pConfig: p2pKey(String) SECRET, initStr(String) SECRET, ices(List, WebRTC ICE servers), session(Object) SECRET, tcpRelay/udpRelay(Object, relay descriptors).
  -> SECRET fields: password, sessionTid, p2pKey, initStr, session.
IMPORTANT: moto_id does NOT exist in this app. The P2P credential handles are p2pId + P2pConfig.p2pKey + initStr/session/ices/relays (WebRTC-shaped, corroborates F2 WebRTC-over-MQTT).
NEGATIVE TEST (per review gate): parser must REJECT a camera record missing the P2P handle (p2pId / p2pKey) and assert required-field invariants. Anonymize all real values before any committed fixture; localKey/p2pKey/password/sessionTid/initStr/session are secrets -> secrets/ only.
<!-- SECTION:NOTES:END -->
