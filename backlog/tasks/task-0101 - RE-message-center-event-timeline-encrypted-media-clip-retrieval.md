---
id: TASK-0101
title: RE message center / event timeline & encrypted media-clip retrieval
status: Done
assignee:
  - '@myself'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:57'
labels:
  - re
  - notifications
  - cloud-storage
  - media-playback
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the cloud event timeline and how event-attached media is fetched and decrypted. Map obtainMessageList/obtainMessageDaysFor/obtainMessageSchemes, the AIEventBean/AIDetectConfigBean event types and CameraMessageType (ipc_ai/ipc_motion/ipc_doorbell/ipc_passby/ipc_linger/ipc_leave_msg), and the encrypted media playback (playMediaVideoWithPath(url,key)/playMediaAudioWithPath, AES-128-CBC clips, YUV/PCM callback), plus video download (startDownloadVideoMessageAttachmentWithUrl) and deleteMessage/shareMedia. Produce an re/ writeup of the event schema + media-key/decrypt contract; reference any keys by secrets/ only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The message-list/event-schema API and the AI event type enumeration are documented with file:line evidence
- [x] #2 The encrypted clip retrieval contract (URL + media key + AES-128-CBC + decode callback) is characterized with confidence; no key material inlined
- [x] #3 re/message_center.md writeup exists covering event timeline + encrypted media retrieval + share/delete/download
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep messagecenter sources for message-list API + AI beans\n2. Map TRCT RN bridge methods to IThingCloudVideo + CameraMessageBusiness endpoints\n3. Characterize encrypted-clip contract (url/encryptKey/AES-128-CBC/YUV-PCM callback)\n4. Write re/message_center.md with confidence + file:line\n5. Run just secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static RE only. Endpoints read literally from CameraMessageBusiness.java: thing.m.msg.list.by.json (v1.0 RN / v2.0 dddbppd), thing.m.msg.days.by.json v2.0, thing.m.ipc.msg.sort.tag.get v1.0, thing.m.msg.remove v1.0. Media key = thing.m.ipc.storage.secret.get v1.0 (per-devId, cached) gated by CameraMessageBean.isNeedPullEncKey. Clip contract = playMediaVideoWithPath(url,encryptKey,i)->IThingCloudVideo.playVideo; decode emits raw YUV (onReceiveFrameYUVData->playMediaVideoInfo) + PCM (onReceiveAudioBufferData->playMediaAudioInfo). AES-128-CBC family confirmed in Java AES helper (AES/CBC/PKCS5Padding, 16B key, 16B IV) but actual clip decrypt is native -> marked [M], native-unconfirmed. No key/PII values written; secret-scan OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the Tuya message-center event timeline + encrypted media-clip retrieval for the SCD921 reskin in re/message_center.md.\n\nWhat:\n- Event-list API: 4 mobile-gateway endpoints (thing.m.msg.list.by.json / .days.by.json / .ipc.msg.sort.tag.get / .msg.remove) with request keys and the CameraMessageBean response schema (incl. attachVideos/attachAudios + isNeedPullEncKey).\n- Event taxonomy: CameraMessageType (ipc_ai/motion/doorbell/passby/linger/leave_msg/...), AIEventBean/AIDetectConfigBean/AIDetectEventBean/CameraMessageClassifyBean, and the baby-monitor classify-key enums -> msgCode mapping (Motion->ipc_motion, Cry->ipc_baby_cry, etc., with honest caveat on reused generic codes).\n- Encrypted clip contract: (url, encryptKey, flag) -> IThingCloudVideo.playVideo/playAudio/startVideoMessageDownload; key provenance via thing.m.ipc.storage.secret.get (per-devId, cached); cipher = AES-128-CBC family (Java helper proven; native clip-decrypt marked medium); decode callbacks deliver raw YUV/PCM to the RN panel.\n- Share/delete/download paths (ShareMessageUtil, startVideoMessageDownload, thing.m.msg.remove) and a Rust parity contract.\n\nEvidence: file:line cites across decompiled/jadx/sources (TRCTCameraMessageManager, CameraMessageBusiness, dddbppd, CameraMessageBean, AI*Bean, *ClassifyKeys, AES.java) + JS bundle confirmation.\n\nSecrets: no key/PII values inlined; storage secret + encryptKey referenced as secrets/ only. just secret-scan: OK.\n\nConfidence: endpoints/schema/taxonomy HIGH; encryptKey<->storage-secret identity and exact clip cipher params MEDIUM (native-unconfirmed); reskin msgCode reality and play int arg LOW/open (need one captured msg.list response or Ghidra on the camera native lib).
<!-- SECTION:FINAL_SUMMARY:END -->
