---
id: TASK-0080
title: >-
  Live no-answer debug: pin the real 302 subscribe topic + byte-faithful offer
  (camera silent)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 07:14'
updated_date: '2026-06-28 08:57'
labels:
  - stream
  - signaling
  - live
  - debug
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Live test #1: MQTT connect+auth works, offer published, but the camera never answers. Suspects: (1) wrong SUBSCRIBE topic — Java smart/mb/in/<id> id-identity is ambiguous (devId vs uid); cap3 answer is addressed to the APP user-id (from=camera,to=app), so the app likely subscribes on its own id, not devId. (2) offer not byte-faithful to cap3 (sessionid format = <devId><unix_s><8rand>, moto_id empty, exact header fields/SDP/token). Add a wildcard-subscribe diagnostic (smart/mb/in/#) to observe IF/WHERE the camera answers, make the offer byte-match cap3, then re-test.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Wildcard-subscribe diagnostic logs any inbound 302 message + its exact topic during a live offer
- [x] #2 Offer byte-matches cap3 (header fields, sessionid=<devId><unix><rand>, moto_id empty, SDP, ices from rtc.config)
- [ ] #3 The real subscribe-topic id is pinned (devId vs uid) and the camera answer is received
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## 302 identity + topic — pinned from Java + cap3 (TASK-0080)

Ground-truth answers (Java file:line + cap3). No real uid/devId literals below — see secrets/ + cap3.

**1. APP p2p-id (offer `from`, region-prefix+13ms+5rand) = the account UID.**
- It is `p2pConfig.session.uid` from rtc.config.get (region prefix e.g. `eu`, len matches cap3 `from`). NOT the top-level `p2pId` (which is "" for p2pType=4 WebRTC).
- Java: the offer JSON is built natively; the routing `from` is the account uid. cap3 offer `header.from == SDP a=ssrc cname == uid`.
- Runtime mapping: rtc.config `result.p2pConfig.session.uid`, falling back to the on-disk Session `uid`. Already wired: stream_live.rs assemble_runtime (`from_id = rtc.uid else session.uid`).

**2. `to` = camera devId (NOT rtc.config.p2pId).** cap3 `to == devId`; rtc.config top-level `p2pId` is "". Code uses `creds.dev_id`. Confirmed.

**3. sessionid = `<devId><unix_seconds><8-rand>`** (cap3: devId + 10-digit unix secs + 8-char base62). The SDP `o=- <unix_seconds> 1 IN IP4 127.0.0.1` uses the SAME secs, and `a=msid-semantic: WMS <sessionid>` repeats the full id. trace_id = `<uuidv4>_<devId>_<unix_millis>`.

**4. SUBSCRIBE TOPIC = `smart/mb/in/<devId>` (devId, NOT uid).**
- Decisive: MqttServerManager.publishDevice auto-subscribes the device inbound topic BEFORE publishing: `String i = mqttControlBuilder.i(); if(!isSubscribe("smart/mb/in/"+i)) subscribe("smart/mb/in/"+i)` then publishes `smart/mb/out/"+i` — `com/thingclips/sdk/mqtt/bqbppdq.java:3660-3678`.
- `i = mqttControlBuilder.i()` returns field `g`, set by `.r(str)` where `str` = the publish first-arg = devId — MqttControlBuilder.java r()@861 (this.g=str), i()@258 (return this.g); set in qqpddqd.java publish()@1201 `.r(str)`; P2PMQTTServiceManager.send302MessageThroughMqtt@1550 calls `homeCamera.publish(devId,pv,localKey,json,302,cb)`.
- The answer `header.to=<uid>` is an APP-LAYER field, NOT the MQTT topic. The camera publishes the answer UP on the device inbound topic `smart/mb/in/<devId>`; the app receives it there because publishDevice subscribed it. So the project hypothesis "app subscribes on its own uid not devId" is DISPROVEN — devId is correct, and the Rust code already uses `smart/mb/in/<devId>` (topics.rs + stream_live assemble).
- Side note: qqpqqpq.java:345 getTopicSuffix() = `["smart/mb/in/", "m/dg/", "smart/mb/"+uid]` is the dp-router prefix set (user personal topic `smart/mb/<uid>` is for user-level pushes), NOT the 302 channel.

## Implementation (offline-validated; live receive is the lead's run)

**AC#1 wildcard-subscribe diagnostic** — babymonitor-core/src/stream/transport.rs:
- New env `BM_302_WILDCARD_DIAG` (const WILDCARD_DIAG_ENV). When set, RumqttcTransport::connect ALSO subscribes to the inbound wildcard `inbound_wildcard(subscribe_topic)` (= `smart/mb/in/#`), and try_recv_302 eprintln-logs EVERY inbound publish `topic + payload_len + accepted` (payload encrypted -> length only, never bytes). In diag mode an answer on ANY sibling `smart/mb/in/*` is still delivered (accepts_topic widens by inbound prefix) so negotiation completes AND we learn the real topic. Unset => byte-identical to before (strict `== subscribe_topic`).
- Pure helpers inbound_wildcard/inbound_prefix/accepts_topic are offline-unit-tested (no socket).

**AC#2 byte-faithful offer** — babymonitor-cli/src/stream_live.rs:
- SessionHandles::mint(dev_id) now samples one wall-clock instant: o_session = unix_seconds (was random u64), session_rand = 8-char base62, trace_id = `<uuidv4>_<devId>_<unix_millis>` (was a 16-char base62). Added local RFC-4122 v4 UUID minter (no new crate).
- build_offer: sessionid = `<devId><o_session><session_rand>` (was `<devId><trace_id>`); used as header.sessionid AND SDP WMS; o-line uses the SAME unix_seconds. moto_id already "" ; from=uid, to=devId ; SDP already cap3-byte-exact (sdp.rs) ; msg.token ices already parsed from rtc.config (negotiate parse_ice_servers(creds.ices)).
- Added SignalingFlow::from/to/sessionid/trace_id read accessors (session.rs) for the new assertion test.
- New test build_offer_sessionid_and_traceid_match_cap3_shape asserts the full cap3 shape.

**AC#3** subscribe-topic id PINNED = devId (see findings #4). "camera answer is received" is the lead's LIVE run — left unchecked.

## Honest gaps / caveats
- Offer msg OMITS `tcp_token` + `log` (negotiate passes make_offer_args(.., None, None)). cap3 offer carried both. NOT in AC#2's enumerated list, and rtc.config tcpRelay/log are not yet surfaced by RtcConfig -> follow-up if the camera needs them.
- The `smart/mb/in/<devId>` topic is Java-derived, NOT wire-confirmed (broker is TLS:8883; no MQTT frame in any capture). The wildcard diag exists precisely to confirm it on the live run.
- 302 frame crypto/framing IS real (mqtt_crypto::build_302_frame: localKey-AES + {data,gwId,protocol:302,pv,t}).

## Validation (ACTUAL)
- nix-shell just e2e: GREEN (build, test, lint, fmt-check, stub-grep, assert-offline, bmp/regions, stream-validate OK).
- clippy -p babymonitor-cli --features live --all-targets -D warnings: clean.
- New/edited files produce ZERO secret-scan hits.

## Pre-existing secret-scan FAILURE (NOT mine)
- just secret-scan fails on committed `emulator_captures/cap*/flows.full.txt` (real JWTs/localKey; committed in 5603d96) + binary @-byte false-positives. emulator_captures/ is NOT in secret_scan EXCLUDE_GLOBS and the cap*/flows.full.txt are TRACKED. This predates this task; recommend a separate backlog task to scrub/gitignore those captures.

## Session 2 — offer tcp_token+log, IceServer byte-order, --diag-topics flag (topic+type log)

Closed the req#1 gap the prior session flagged and reworked the diagnostic to the spec.

**Offer fidelity (AC#2, now complete):**
- rtc.config p2pConfig.tcpRelay + log are SURFACED by RtcConfig (tcp_relay_json/log_json) and threaded StreamCredentials.tcp_relay/log -> build_offer.
- Offer now carries msg.tcp_token (rtc.config tcpRelay with sessionId RE-MINTED to <devId><o_session><8-rand> — cap3 shape; same o_session secs as the header sessionid, distinct rand) and msg.log (verbatim passthrough). Absent rtc.config descriptors => omitted (graceful).
- IceServer field order reordered to credential,ttl,urls,username so the token TURN entry is byte-identical to cap3.
- NEW offline test signaling_cap3::assert_offer_builder_reproduces: rebuilds the offer via the SAME SignalingEnvelope::offer path build_offer uses, asserts (a) Value-equality vs the captured offer and (b) cap3 header/msg key ORDER + moto_id:"" + is_pre:0. Runs against the redacted fixture ALWAYS and the REAL cap3 (mqtt+lan) here -> PASS.

**Subscribe topic (AC#3 / req#2):** KEPT strict = smart/mb/in/<devId> per the Java RE (the app-p2p-id hypothesis is DISPROVEN in session-1 notes). Did NOT switch to uid — that would contradict the cited evidence and break the publishDevice auto-subscribe. The diagnostic probes uid/personal LIVE instead.

**Diagnostic (AC#3):** added hidden CLI flag stream --diag-topics (sets BM_302_WILDCARD_DIAG). When armed it ALSO subscribes smart/mb/in/<uid>, smart/mb/<uid> (personal) + the in/# wildcard, and poll_inbound logs the EXACT topic + header.type of every ACCEPTED 302 (bodies withheld); non-302 on a sibling/personal topic is logged+skipped (no abort). try_recv_302 now returns Inbound302{topic,payload} so the topic reaches the decrypt layer. topics::personal_topic + diag_extra_topics added with unit tests.

**Validation (ACTUAL):** nix-shell just e2e = GREEN (exit 0). cargo clippy -p babymonitor-cli --features live --all-targets -D warnings = clean (exit 0). New tests pass: core surfaces_tcp_relay_and_log, topics diag_extra_topics/personal_topic, transport accepts_topic_strict_vs_diag, cli build_offer_includes_tcp_token_and_log_from_rtc_config, signaling_cap3 real+redacted offer-builder reproduction.

**Honest caveats:** tcp_token.sessionId re-mint is cap3-INFERRED (not decompiled). security_level=3 + p2p_skill=1635 are cap3-pinned CONSTANTS (no rtc.config integer field maps). smart/mb/in/<devId> remains Java-derived, NOT wire-confirmed (TLS:8883). My .rs changes add ZERO secret literals; just secret-scan still fails on the PRE-EXISTING committed emulator_captures/cap*/flows.full.txt + binary @-byte false positives (not mine). No git commit made.

LIVE TEST #2 (corrected byte-faithful offer + --diag-topics + wildcard): STILL camera-silent — ZERO inbound on smart/mb/in/<devId>, the wildcard, or the uid candidates. Subscribe-topic id confirmed = devId (Java publishDevice auto-subscribes smart/mb/in/<devId>; the answer header.to=uid is APP-LAYER not the MQTT topic). pv=2.2 (code default; device record has NO pv), gwId=devId, localKey 16-char, camera cloudOnline=TRUE. So auth+connect+offer-content are validated, but the PUBLISHED 302 FRAME (outer {data,gwId,protocol,pv,t}, the exact topic, gwId, the localKey-AES of data) has NO wire ground truth (cap3 only captured the DECRYPTED 302 content). -> need cap5 (TASK-0081).
<!-- SECTION:NOTES:END -->
