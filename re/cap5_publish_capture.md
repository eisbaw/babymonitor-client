# cap5 — capture the REAL 302 MQTT publish (unblock "camera silent")

## Why
Live tests #1/#2 (this machine on the camera LAN, valid session) got all the way to:
session → `rtc.config.get` → discovery (p2pType=4) → **MQTT CONNECT auth ACCEPTED by the broker** →
302 offer published → **then the camera never answers** (no inbound on `smart/mb/in/<devId>` or the
wildcard). pv="2.2", gwId=devId, the offer is byte-faithful to cap3's *decrypted* content, the camera is
`cloudOnline:True`. So the failure is in the **published frame the camera actually parses**, and we have
**no wire ground truth** for it: cap3 hooked the *decrypted* 302 content (`send302MessageThroughMqtt` arg),
NOT the MQTT publish (the outer `{data,gwId,protocol,pv,t}` frame, the exact topic, or `gwId`). Any subtle
mismatch (gwId, outer-frame shape, topic, the localKey-AES of `data`, or a missing offer field) → the
camera silently drops it. One capture of the real publish resolves all of them.

## What to capture (Java hooks — same rig/agent as cap3; all plaintext, no native needed)
Add these to the deep Frida agent and drive a live-view in the app for ~20 s:

1. **The 302 builder args** — `com/thingclips/.../P2PMQTTServiceManager.send302MessageThroughMqtt(String devId, String pv, String localKey, String json, int protocol, cb)` (also `homeCamera.publish(devId,pv,localKey,json,302,cb)`):
   log `{devId, pv, localKey, protocol, json}` — gives the exact `pv` and the decrypted 302 content the app builds.
2. **The actual MQTT publish** (the outer frame + topic — THE prize): hook the publish that carries it —
   `com.thingclips.sdk.mqtt` publish path (`qqpddqd.publish` / `MqttServerManager.publishDevice` →
   `bqbppdq.java:3660-3678`) and/or the low-level `org.eclipse.paho...MqttAsyncClient.publish(String topic, MqttMessage)`.
   Log `{topic, payloadUtf8}` where payload is the outer JSON `{data, gwId, protocol, pv, t}` (data = base64 AES-ECB(localKey)).
3. **The subscribe** — hook the subscribe call (`...subscribe(String topic ...)`); log the topic(s) the app subscribes to for the 302 channel (confirm `smart/mb/in/<devId>` vs anything else).

## Output → `emulator_captures/cap5/`
`publish.jsonl` lines, e.g. `{"tag":"302-builder","devId":"…","pv":"…","localKey":"…","json":"{header…}"}`,
`{"tag":"mqtt-publish","topic":"smart/mb/out/…","payload":"{\"data\":\"…\",\"gwId\":\"…\",\"protocol\":302,\"pv\":\"…\",\"t\":…}"}`,
`{"tag":"mqtt-subscribe","topic":"smart/mb/in/…"}`. Gitignored (real localKey/PII); local only.

## Then (mine)
Diff the real publish vs our `build_302_frame`/`build_offer`/topics: pin `gwId`, the outer-frame shape, the
publish/subscribe topics, `pv`, and the localKey-AES of `data`. Fix `mqtt_crypto.rs`/`stream_live.rs`/`topics.rs`
to byte-match, then re-run the live test — the camera should answer → ICE host-direct → media → a live frame.
