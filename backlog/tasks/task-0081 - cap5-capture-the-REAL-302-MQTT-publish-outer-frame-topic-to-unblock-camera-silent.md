---
id: TASK-0081
title: >-
  cap5: capture the REAL 302 MQTT publish (outer frame + topic) to unblock
  camera-silent
status: Done
assignee:
  - '@myself'
created_date: '2026-06-28 08:57'
updated_date: '2026-06-28 12:03'
labels:
  - stream
  - signaling
  - capture
  - live
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Live tests reach MQTT-connect + offer-publish but the camera never answers. The published 302 frame the camera parses is unobserved (cap3 captured only the DECRYPTED 302 content, not the MQTT publish). Capture it with the deep Frida agent (Java hooks, no native): (1) send302MessageThroughMqtt(devId,pv,localKey,json,302) args -> exact pv + decrypted content; (2) the MQTT publish (qqpddqd.publish / MqttAsyncClient.publish) -> topic + outer {data,gwId,protocol,pv,t}; (3) the subscribe topic. Plan + hook spec in re/cap5_publish_capture.md. Then diff vs our build_302_frame/build_offer/topics and fix to byte-match.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cap5/publish.jsonl captures the real MQTT publish topic + outer {data,gwId,protocol,pv,t} frame for a live 302 offer
- [x] #2 send302 args (pv, localKey, json) + the subscribe topic captured
- [x] #3 our build_302_frame/topics/offer fixed to byte-match the real publish; live re-test gets a camera answer
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. RE the real frame from cap5/offer_302_frame.bin + decompiled encode/parse (DONE - see notes).\n2. mqtt_crypto.rs: add build_mqtt22_frame (binary 2.2+crc+s+o+AES(envelope)) + parse_mqtt22_frame; keep legacy Frame302 only for the old tests, mark deprecated.\n3. envelope = {data:<302json-object>,protocol:302,t:sec}; AES-128-ECB-PKCS7(localKey) RAW (not base64); crc32(be(s)+be(o)+ct) big-endian prefix at [3:7].\n4. transport.rs publish_302: emit binary frame; add per-session s/o counters (5s-window dedup, monotonic is safe).\n5. inbound try_recv_302: parse_mqtt22_frame (symmetric) for the camera ANSWER.\n6. KAT test: reproduce secrets/cap5 offer_302_frame.bin byte-for-byte from captured s/o/t/localKey/inner-json (ignore-gated, secrets local).\n7. just e2e + qa-test-runner + mped-architect; then live re-test for a camera answer.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## cap5 RE — the camera-silent root cause (verified on offer_302_frame.bin)

The published 302 frame is **Tuya binary MQTT-2.2**, NOT the JSON {data,gwId,protocol,pv,t} our build_302_frame emits. Decompiled ground truth: encode pbbppqb.java:493 + qpbpqpq.java:63; parse qbpppdb.java:290-378; dedup qdddqdp.java:725-728.

Wire layout (big-endian; verified crc32(frame[7:])==frame[3:7] on the real frame):
- [0:3]   pv ascii ("2.2")
- [3:7]   CRC32(frame[7:])           standard zlib crc32, big-endian
- [7:11]  s = sequence (int, BE)
- [11:15] o = order    (int, BE)
- [15:]   AES-128-ECB(localKey, envelope) PKCS7, RAW bytes (no base64)

AES plaintext = the PublishBean2_2 ENVELOPE (not the 302 json directly):
  {"data":<302-json>,"protocol":302,"t":<unix_seconds>}
302-json = {"header":{from,is_pre,moto_id,p2p_skill,path,security_level,sessionid,to,trace_id,type:offer}, "msg":{log,preconnect:true,sdp,tcp_token,token}}

Camera acceptance gates (so byte-matching the APP is NOT required):
1. crc32(frame[7:])==frame[3:7] — self-consistent, we compute it.
2. (devId,s,o) not seen in last 5000ms (qdddqdp 5s-window dedup) — monotonic s per publish is always safe; NO cross-session persistence.
3. AES-ECB decrypts to valid JSON w/ protocol:302 + header/msg.

Old cap5_publish_capture.md hypothesis (outer JSON, body@offset 11) was WRONG: body starts @15; [11:15] is the 4-byte order field, not part of AES. topics confirmed: pub smart/mb/out/<devId>, sub smart/mb/in/<devId>.

## Fix implemented + byte-validated (mped-architect + qa-test-runner reviewed)\n\nRewrote the 302 frame codec in babymonitor-core/src/stream/mqtt_crypto.rs to the binary message-2.2 format (was the wrong JSON {data,gwId,protocol,pv,t}): added crc32(), wrap/unwrap_publish_envelope(), build_302_frame(inner,key,pv,s,o,t)/parse_302_frame(frame,key,pv). session.rs threads per-publish s/o counters seeded from OS entropy (avoids the camera 5s-dedup collision on fast retry). KAT tests/mqtt_frame_cap5.rs reproduces the REAL cap5/offer_302_frame.bin BYTE-FOR-BYTE (parse + AES re-encrypt + full rebuild all match). re/mqtt_2_2_frame.md documents the format + confidence.\n\nGates: cargo build, clippy -D warnings, all 267 core tests, full just e2e GREEN; cap5 KAT passes byte-for-byte.\n\nReview fixes applied: OS-entropy s/o seeding (was now_unix collision); removed dead Error::MqttEnvelopePending + its wrong error string; corrected 6 stale docs that still described the old base64 {data,gwId,protocol,pv,t} frame; labeled inbound-parse confidence (outbound byte-pinned, inbound symmetric-not-byte-validated); noted serde_json key-order dependency of the byte-match. Follow-up TASK-0082 filed for inbound trace_id/sessionid filtering.\n\nREMAINING (the AC3 live half): a live re-test against the real camera to confirm it now ANSWERS — environmental (needs camera on LAN + valid session/MFA + --features live-tls).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed the camera-silent live-streaming blocker end-to-end. Two root causes, both required:

1) The published 302 signaling frame used the wrong wire format. Reverse-engineered the real format from cap5 plus the decompiled Tuya SDK and reimplemented it as the binary Tuya message-2.2 frame: pv ++ be32(crc32(s++o++ct)) ++ be32(s) ++ be32(o) ++ AES-128-ECB(localKey, envelope) where envelope = data/protocol:302/t. Byte-validated: build_302_frame reproduces the real captured publish frame byte-for-byte in tests/mqtt_frame_cap5.rs.

2) The rumqttc sync eventloop was never driven. The transport used Connection::try_recv = poll().now_or_never(), which polls the connect/publish future once and drops it, so TLS+CONNECT+SUBSCRIBE+PUBLISH never completed and the offer was never actually transmitted. Switched to blocking recv_timeout() plus an establish-to-CONNACK step in connect(). This was the decisive fix.

Also: per-publish s/o counters seeded from OS entropy for the camera 5s dedup; poll_inbound now skips the protocol:23 frames the camera multiplexes onto the 302 topic instead of aborting; removed the dead Error::MqttEnvelopePending and its wrong error string; corrected stale docs across mqtt_crypto/session/transport/mod/lib. mped-architect and qa-test-runner reviewed; just e2e, clippy -D warnings, and the cap5 KAT are all green.

Verified LIVE against the real SCD921: session, rtc.config.get, discovery, MQTT CONNECT (CONNACK), offer published (PUBACK), then camera ANSWER plus 4 trickled ICE candidates received and the per-session media key extracted. Remaining work is a separate media-transport layer: host-direct UDP to the camera candidate returns ICMP Connection refused, tracked as a new task.
<!-- SECTION:FINAL_SUMMARY:END -->
