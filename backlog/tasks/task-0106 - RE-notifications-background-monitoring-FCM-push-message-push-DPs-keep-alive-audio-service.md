---
id: TASK-0106
title: >-
  RE notifications & background monitoring (FCM push, message-push DPs,
  keep-alive audio service)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:05'
labels:
  - re
  - notifications
  - monitoring
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document how alerts reach the phone and how background monitoring stays alive. Map the FCM listener service (ThingFcmListenerService, SENDER_ID), per-event message-push DPs (FuncMsgPushSwitch/FuncBaseMessagePush), notification settings categories (sound/motion/temperature/cry/SenseIQ), and the continuous background-audio monitoring foreground/keep-alive service that keeps listening when the app is backgrounded/locked. Static-RE into one re/ writeup; do not commit the FCM sender id if it is a Philips secret — reference secrets/ location.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The FCM push entrypoint and the per-event message-push DP(s) are documented with file:line evidence
- [x] #2 The background-audio keep-alive service and its monitoring loop are identified with confidence; the push payload->event mapping is sketched
- [x] #3 re/notifications.md writeup exists covering push + notification settings + background monitoring; no secrets inlined
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep manifest+jadx for FCM listener, KeepAliver, FuncMsgPush, watchdog
2. Trace FCM entrypoint -> MainProcessService -> FcmManager -> PushCenter; recover payload keys
3. Enumerate per-event message-push DPs (CameraMsgPushModel)
4. Map Night Owl BackgroundGroundService + PanelWatchDogManager 20s loop + LocalNotificationManager lifecycle + RN bridge
5. Resolve obfuscated R.string aliases via public.xml
6. Write re/notifications.md; run just secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static RE complete; re/notifications.md written.

- FCM entrypoint: ThingFcmListenerService.q() (fcmpush/service) -> MainProcessService.b() -> FcmManager.d() -> PushCenterService.onPostData. Payload keys from ConstantStrings/PushBean (type/devId/link/msgId/ct/p).
- Per-event message-push DPs (CameraMsgPushModel.l7): ipc_doorbell_message (master), ipc_doorbell_push, doorbell_pir_switch, doorbell_sensitivity; FuncBaseMessagePush gates ipc_message_set; plus ipc_power_push.
- Keep-alive: com.thingclips.nightowl.watchdog.BackgroundGroundService (FGS mediaPlayback, notif id 1, channel thing_camera). Monitoring loop = PanelWatchDogManager.startRxjava Observable.interval(0,20,SECONDS)->SessionStatus. LocalNotificationManager lifecycle starts/stops FGS on background/foreground; RN bridge TRCTIpcMonitorManager.showWatchDogLocalNotification arms it.
- Resolved obfuscated R.string aliases via public.xml: title=app_name, content=bmp_background_audio_notification_content, channel=push_channel_common.
- SENDER_ID value NOT inlined (gcm_sender_id resource referenced only). just secret-scan: OK.
- Honest gaps: FCM `type` enum values server-side (no captured payload); sound/cry/temp/SenseIQ push toggles live in runtime RN bundle + cloud, not DP-bound in this APK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the notification + background-monitoring stack for the Tuya-reskin SCD921 into re/notifications.md (static RE only).

What changed:
- New writeup re/notifications.md covering (1) inbound FCM push, (2) per-event message-push DPs/settings, (3) Night Owl background-audio keep-alive FGS + its heartbeat loop, with file:line evidence and confidence levels.

Key findings:
- FCM entrypoint ThingFcmListenerService.q() forwards the FCM data map cross-process to FcmManager.d(), which parses the `link` field via PushUtil.parseMessage into a PushBean and routes to PushCenterService.onPostData. Payload field dictionary recovered from ConstantStrings + PushBean (type/devId/link/msgId/ct/c/cc/ts/p).
- Per-event message-push DPs enumerated from CameraMsgPushModel.l7(): ipc_doorbell_message (master), ipc_doorbell_push, doorbell_pir_switch, doorbell_sensitivity; device entry FuncBaseMessagePush gates ipc_message_set; low-battery ipc_power_push.
- Background keep-alive identified with high confidence: com.thingclips.nightowl.watchdog.BackgroundGroundService (foregroundServiceType=mediaPlayback). Monitoring loop = PanelWatchDogManager.startRxjava() RxJava Observable.interval(0,20s) posting SessionStatus; LocalNotificationManager starts the FGS on app-background and tears it down on foreground/session-loss; RN module TRCTIpcMonitorManager arms/disarms it. Obfuscated R.string aliases resolved via public.xml (title=app_name, content="Background Audio is active.", channel=push_channel_common).
- Disambiguated the two mediaPlayback FGS: generic Tuya KeepAliverService (push pipeline) vs Philips BackgroundGroundService (baby audio).

Secret hygiene: FCM sender id value not inlined (gcm_sender_id resource referenced by location only); no devId/token/PII in the doc. `just secret-scan` passes.

Honest gaps (Residual unknowns in doc): server-side FCM `type` enum values (no captured payload), and the sound/cry/temperature/SenseIQ per-category push toggles which live in the runtime-downloaded RN panel + cloud API, not as DPs in this APK.
<!-- SECTION:FINAL_SUMMARY:END -->
