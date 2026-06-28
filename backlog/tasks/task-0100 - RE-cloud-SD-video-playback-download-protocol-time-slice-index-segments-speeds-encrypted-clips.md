---
id: TASK-0100
title: >-
  RE cloud/SD video playback & download protocol (time-slice index, segments,
  speeds, encrypted clips)
status: Done
assignee:
  - '@myself'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:14'
labels:
  - re
  - media-playback
  - cloud-storage
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the recorded-video playback path, which is distinct from the already-RE'd live stream. Map the native record-index API (getRecordDaysByMonth, getRecordFragmentsByDay, startPlayBack, startPlayBackDownload, setPlayBackSpeed), the RN playback control (playbackStart/Seek/Pause/Resume/Stop, requestPlaybackTimeSliceDataByDay), cloud playback config strings (configCloudData/V2), variable speeds (0.5x-32x), and the encrypted-clip download/decrypt format. Produce an re/ writeup of the index/segment/seek/decrypt contract.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The day/fragment index API and start/seek/speed playback entrypoints are documented with file:line evidence
- [x] #2 The encrypted clip download + decryption scheme (key source, cipher) is characterized with confidence and explicit unknowns, no secrets committed
- [x] #3 re/playback_protocol.md writeup exists distinguishing local-SD vs cloud playback paths
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Static-RE per ACs: grep decompiled/jadx + decompiled/apktool; write re/playback_protocol.md with per-claim confidence + file:line evidence; verify just secret-scan.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static-only RE via grep of decompiled/jadx/sources. Findings: (1) RN bridge trctcameramanager/TRCTCameraManager.java is a pass-through to ICameraManager impl ipc/camera/rnpanel/cameramanager/TRCTCameraManager.java; Tz.a()/Tz.b(0) are obfuscation no-ops. (2) Two parallel recorded paths share one key source: LOCAL-SD via IThingSmartCameraP2P (device/SD), CLOUD via IThingCloudCamera + Tuya mobile-API REST topics. (3) Seek has no dedicated native call: playbackSeek delegates verbatim to playbackStart (seek = restart at new playTime). (4) Time-slice index format = RecordInfoBean{count, items:[TimePieceBean]}; TimePieceBean carries uuid/encrypt(flag)/encryptMD5/startTime/endTime(epoch s)/segmentSize/prefix/playTime. (5) Encrypted-clip decrypt fully chained in Java up to the JNI boundary: per-uuid secretKey -> integrity check Base64(SHA256(sk)[:32])==encryptMD5 -> setEncryptionInfo. File-download cipher is AES/CBC/PKCS5 with in-band IV + 64-byte header (EncryptUtils). Honest corrections noted in-doc: task said strings are ipc_playback_speed_* but actual keys are camera_playback_speed_* (8 entries, 0.5x-32x); ipc_playback_speed_* count=0. Residual unknowns documented with unblock evidence: in-.so streaming cipher, JNI startPlayBack 4th int, speed int-code table (RN JS), cloudPlaybackStart s3/s4 + config-tags JSON schema, cloud m3u8-vs-segment container. No backlog CLI mutation performed (orchestrator owns task state); no secrets written; just secret-scan OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wrote re/playback_protocol.md (TASK-0100): a static-RE writeup of the recorded-video playback/download protocol, distinct from the already-RE'd live stream. It maps (a) the native record-index + playback JNI API (ThingCameraNative getRecordDaysByMonth/getRecordFragmentsByDay/startPlayBack/startPlayBackDownload/setPlayBackSpeed/setEncryptionInfo, with epoch-second start/stop/playTime semantics from the IThingSmartCameraP2P/ICameraP2P middleware), (b) the RN control surface (playbackStart/Seek/Pause/Resume/Stop, requestPlaybackTimeSliceDataByDay, cloudPlaybackStart/Stop, configCloudData/V2) with their delegating call bodies, (c) the time-slice index format (RecordInfoBean -> List<TimePieceBean> with uuid/encrypt/encryptMD5/startTime/endTime/segmentSize/prefix), (d) the cloud REST backend (thing.m.ipc.storage.secret.get[.list], prefixs.get, read.authority.get, getCloudTimeLine/getCloudUrls), and (e) the encrypted-clip key/cipher contract.

Key results: seek = re-issued startPlayBack at a new playTime (no dedicated native seek). The decrypt key is a per-uuid secretKey fetched from the cloud (thing.m.ipc.storage.secret.get.list) and integrity-bound to the index by Base64(SHA256(secretKey)[:32]) == encryptMD5; it is installed to the native decoder via setEncryptionInfo. The download-to-file cipher is AES/CBC/PKCS5Padding with a raw-string key and an in-band 16-byte IV behind a 64-byte container header (4 || IV16 || 4 || 40), confirmed in EncryptUtils. Variable speed (0.5x-32x) is an int code via setPlayBackSpeed/setPlayCloudDataSpeed; UI labels are camera_playback_speed_* (the task's ipc_playback_speed_* prefix does not exist - corrected in-doc).

Every claim carries a high/medium/low confidence tag and a decompiled/jadx file:line citation; the streaming in-.so cipher, the JNI startPlayBack 4th int, the speed int-code table, and cloudPlaybackStart's trailing strings are listed as explicit residual unknowns with the evidence (Ghidra of the camera .so / JS-bundle dump / one owner-account cloud GET) that would unblock each. No secret or PII value is written anywhere; `nix-shell --run 'just secret-scan'` returns OK with the new (untracked) doc in scope.
<!-- SECTION:FINAL_SUMMARY:END -->
