---
id: TASK-0083
title: 'Live media transport: ICE host-direct UDP gets Connection refused after answer'
status: In Progress
assignee:
  - '@myself'
created_date: '2026-06-28 12:03'
updated_date: '2026-06-28 17:09'
labels:
  - stream
  - media
  - ice
  - live
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Live signaling now fully works (camera returns Answer + 4 trickled ICE candidates + media key). The media transport then sends a host-direct STUN/nomination UDP to the camera host candidate (e.g. 192.0.2.184:<port>) and the recv surfaces ICMP Connection refused (os error 111) = the camera port is not accepting our packet. Establish the working ICE/KCP media path (cap4 reached the camera via a LAN host candidate, STUN KAT-validated, so the format is right; this is a live connectivity/sequence/candidate-selection issue). May need a cap6 capture of the real app-camera ICE/media UDP handshake.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 media UDP path to the camera is established (no Connection refused) and KCP segments are received
- [ ] #2 at least one H.264 keyframe is decoded from the live camera and rendered/written to the TS
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Workflow: map media-transport + STUN + candidate-publish path + cap5/cap4 ground truth in parallel; synthesize a file-level plan.\n2. Implement: bind media UDP socket EARLY (learn our host candidate ip:port); trickle our local host candidate(s) to the camera as 302 candidate messages (session.publish_candidate), app-format.\n3. Bidirectional ICE: respond to camera inbound checks, RETRANSMIT our checks (RTO backoff), TOLERATE transient ICMP Connection refused; early-exit the trickle phase once a host candidate is in hand (architect #3).\n4. Live re-test: camera opens the media path -> KCP/AES -> H.264 keyframe decoded (decode already proven on cap4).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Diagnosis (live + cap5)

We are on the camera LAN: us 192.0.2.233/24, camera 192.0.2.184, pingable. Signaling fully works; the camera answers with its host candidate + media key. Then our single nominating STUN check to the camera host port returns ICMP Connection refused.

ROOT CAUSE from cap5: the real app TRICKLES ITS OWN host candidates to the camera. cap5 has 429 app-to-camera candidate 302 messages, e.g. `a=candidate:... UDP ... <ip> <port> typ host` for IPv4 plus an IPv6 link-local. Our client sends local_candidates = EMPTY by design [stream_live negotiate, comment "host-direct: rely on the camera host candidate"]. So the camera never learns OUR address, never checks/opens a path to us, and our checks hit an unready port -> ICMP refused.

FIX = the real bidirectional ICE handshake, mirroring the app:
1. Bind the media UDP socket EARLY so we know our host candidate ip:port.
2. Trickle our local host candidate(s) to the camera as 302 candidate messages [session.publish_candidate], like the app.
3. Keep responding to the camera inbound checks [PathKeepalive.consent_reply already does], RETRANSMIT our checks with RTO backoff, and TOLERATE transient ICMP Connection refused instead of aborting, until the pair validates.
4. Then KCP/AES media flows. Decode already proven on cap4.

Needs a small restructure so the socket is bound before signaling and our candidate can be trickled. A cap6 capture of the real app-camera ICE/media UDP handshake would confirm the exact check sequence and the winning candidate pair.

WORKFLOW PLAN (TASK-0083 ICE trickle + bidirectional). 8 steps:
S1: Split bind from connect + tolerate ICMP ECONNREFUSED in the media transport [transport.rs]
S2: Add an early-exit predicate to the trickle negotiation [session.rs]
S3: Thread the host-candidate early-exit through the live wiring [transport.rs]
S4: Bind early, gather + trickle our local host candidate(s) (std-only egress-IP, no new dep) [stream_live.rs]
S5: Connect the pre-bound socket to the selected host (no re-bind, no premature check) [stream_live.rs]
S6: Bidirectional ICE in the pump: RTO-backoff nomination retransmit + keep answering inbound checks + tolerate ECONNREFUSED until validated [stream_live.rs]
S7: Rewire run_live_stream end-to-end [stream_live.rs]
S8: Offline tests for every newly-added pure seam [transport.rs, session.rs, stream_live.rs]

Tests: transport.rs: classify_recv maps Err(ConnectionRefused) -> Ok(None), Err(WouldBlock) -> Ok(None), Ok(n) -> Ok(Some(n)), and a generic Err(BrokenPipe) -> Err(Transport) — pure, synthesize io::Error via std::io::Error::from(ErrorKind::*); transport.rs: try_send error-classification reuses classify-style mapping (ConnectionRefused/WouldBlock -> Ok(None)); assert via the same pure helper so no socket is opened in the offline gate; stream_live.rs: format_host_candidate(ip, port) round-trips through mtransport::parse_candidate -> kind==Host, component==1, transport=="UDP", priority==2130706431, ip/port preserved, and the produced string starts with "a=candidate:" and ends with "\r\n" (matches re/mqtt_signaling.md:144); stream_live.rs: PathKeepalive RTO schedule — nominate_due true at seed; after mark_nominate_sent the interval doubles 250ms->500ms->1s->...->capped at NOMINATE_RTO_MAX; after mark_validated, nominate_due stays false (no further retransmit). Drive with injected Instants/durations, no sleeps

LIVE-ONLY: That trickling our host candidate actually causes the camera to open and check a path back to us and start sending media — the core hypothesis; there is no camera in the static sandbox so the cause->effect is unprovable offline; That the tolerated ICMP ECONNREFUSED genuinely clears once the camera's media port becomes ready and the pair then validates (cap5 proved the symptom; the recovery is live-only); The real RTO/retransmit cadence the camera expects/uses (we use RFC 5389 defaults 250ms->x2->3s cap as a principled stand-in)

RISKS(top): Offline-gate hard constraint: `just assert-offline` runs `cargo test --offline`, so adding an interface-enumeration crate (if-addrs/local-ip-address/get_if_addrs) would FAIL the gate (not in the cargo cache). This is why the plan uses the std-only egress-IP trick. True multi-interface enumeration (to match the app's many host candidates) must be a separate task that first vendors such a crate into the offline cache — flag, do not silently add the dep; Egress-IP trick yields ONE interface IP (the default-route egress). On a multi-homed host (active VPN, docker/bridge as default route, multiple NICs) it can return an address the camera cannot reach. Mitigation: also probe toward the camera's host-candidate IP once known (most-correct egress) and/or filter to RFC1918/LAN ranges; at minimum log the chosen ip:port so a wrong pick is visible; Connected-UDP semantics: after connect_peer the socket only receives from the camera's host-candidate base ip:port. If the camera sends checks/media from a different source port (symmetric NAT, srflx/relay path), connected recv silently drops them — fine for cap4 LAN host-direct, still broken for remote/NAT (srflx/TURN remain documented stubs, out of scope here)

## PROGRESS (live, today): ICE handshake now WORKS — new blocker is client-initiated KCP media-start

Implemented the workflow plan (steps 1-8): bind socket early, gather+trickle OUR local host candidate (192.0.2.233:<port>), early-exit trickle on host candidate, split bind/connect, tolerate ICMP ECONNREFUSED, RTO-backoff nomination, bidirectional ICE in the pump.

Then mined cap4/media.pcap (the real working app<->camera UDP flow, tshark) and found the decisive ICE fix: the app sends 141 connectivity checks to the camera with ZERO USE-CANDIDATE (attr 0x0025 count=0). Our nominating check set USE-CANDIDATE=true -> camera ignored it. Dropped it.

LIVE RESULT after the fix: camera ANSWERS our check (inbound STUN 0x0101) -> "nomination VALIDATED", and the camera sends its OWN binding requests (0x0001) which we answer (camera_checks_answered=15). Full bidirectional ICE established. BUT media_ok=0 -> camera still does not stream.

NEW ROOT CAUSE (cap4): after ICE, the APP SENDS KCP PACKETS FIRST (media.pcap frames 217, 253-255 app->camera: KCP cmd 0x52/0x51, conv=0) and ONLY THEN does the camera start streaming (frame 256+ camera->app, 1260-byte media). We do ICE then just wait/recv -> the camera never gets the KCP/imm media-start -> never streams. We must INITIATE the KCP/imm media channel (send the initial KCP packets) after ICE validates.

NEXT (workflow): RE the cap4 KCP/imm media-start handshake (what the app sends in 217/253-255, KCP layer, imm session-open, encrypted?) and the Rust TX/KCP send path, then implement client-initiated media-start. (cap6 = the user's earlier pre-fix re-run; superseded.)

## BREAKTHROUGH: decrypted the media-start trigger (cap4 frame 253)

Decrypted cap4's conv=0 control PDU with media key#0 (HMAC-SHA1 confirmed). The 28-byte imm control PDU that triggers streaming (re/media_start_handshake.md):
  f253: magic 0x12345678 | @4=0x00010004 | @8=0 | @12=9 | @16=8 | @20=0 | @24=4
  f254/f255 = sibling PUSHes (sn 4,5) with varying @4/@12/@24. ALL protocol constants/codes - NO session tokens/creds -> replayable in a fresh session.
Cipher corrected: suite-3 AES-128-CBC + inline IV + 20B HMAC-SHA1 (NOT ECB). Datagram = KCP 24B hdr (LE) + [IV16 + CBC32] + HMAC20 = 92B.

Sequence: after ICE validates, send 3x KCP PUSH (the f253/254/255 PDUs sealed) -> camera streams 37ms later (conv=0 ack, then conv=1 video which our PROVEN RX decodes).

RESIDUAL UNKNOWN: the app's conv=0 send stream starts at sn=3 (all 132 conv=0 PUSH in cap4 have sn>=3; sn 0,1,2 never sent as PUSH). Either imm-KCP inits snd/rcv_nxt at 3, or sn 0,1,2 were on an earlier path outside cap4's window. Two live-testable hypotheses: start our conv=0 snd_nxt at 3 (mirror app) vs at 0.

NEXT: implement the TX path (KCP sender + AES-CBC encrypt/HMAC + imm control PDU + MediaEngine TX + pump wiring), KAT vs cap4 f253-255, live-test. Workflow plan recorded.

## MEDIA-START WORKS — camera streams! New blocker: KCP ACKs (flow control)

Implemented the client-initiated KCP/imm media-start (workflow: control.rs PDUs, MediaEngine::open_media_start, pump wiring; S1/S2 crypto+kcp TX). LIVE config A (MEDIA_START_SN=3, MEDIA_START_UNA=2, mirroring cap4):
  nomination VALIDATED -> "media-start: sent 3 KCP control segments (conv=0, sn>=3)" -> ICE summary media_ok=6 (!), stop reason changed from "no media within 60s" to "media idle for 20s" = THE CAMERA STREAMED.
So sn=3/una=2 was correct; the media-start trigger works.

NEW BLOCKER: the camera sent ~6 media datagrams (its initial send window) then STALLED -> we never ACK its segments, so the camera's KCP send window fills and it stops (cap4: the app sends ~785 packets back, mostly KCP ACKs, and the camera streams 16000+). 6 datagrams < a keyframe, so no decodable frame yet.
FIX: on each received camera PUSH (conv=1 video, conv=2 audio, conv=0 control), send a KCP ACK (cmd=0x52, sn=acked, una=rcv_nxt, len=0, +HMAC) back so the camera's window advances and it keeps streaming.

Also noted: machine moved networks (egress now 198.51.100.105, camera 192.0.2.184 different subnet) but ICE+media still traversed (NAT reverse path) — media_ok=6 proves it.

## TX mechanism WORKS — camera accepts our control; missing = the INITIAL conv=0 handshake content

Added KCP ACK emission (KcpReceiver.drain_acks + MediaEngine.drain_media_acks; pump ACKs every received segment) so the camera's send window advances. Added inbound-KCP-header diag (conv/cmd/sn/una).

LIVE A/B (the MEDIA_START_SN/UNA flip), with the inbound diag:
- Config A (sn=3, una=2, cap4-mirror): camera replies conv=0 cmd=0x52 sn=3 UNA=0 (x6). una=0 => the camera's rcv_nxt for OUR stream is 0; our sn=3,4,5 are out-of-order, buffered, never delivered -> stall.
- Config B (sn=0, una=0, fresh start): camera replies conv=0 cmd=0x52 sn=2 UNA=3. una=3 => the camera RECEIVED our sn=0,1,2 and acknowledged them. Sequencing is CORRECT. But the camera ACKs and stops (media_ok=1, no conv=1 video).

CONCLUSION: the TX/KCP mechanism is correct (camera accepts our conv=0 PUSHes, una advances 0->3). The remaining gap is the CONTENT of the initial sn=0,1,2 PDUs. cap4's captured 28-byte PDUs (f253/254/255) are the sn=3,4,5 CONTINUATION; the true initial handshake (sn 0,1,2) is outside cap4's window and likely includes the imm auth step (SendAuthorizationInfo @ decompiled/ghidra_p2p/.../00147608: 104-byte, magic 0x12345678, code@4, username@8, password@0x28). We send the wrong (continuation) content as sn=0,1,2.

NEXT (decision): (a) cap7 = capture a FRESH live-view from connection #1 (gets conv=0 sn=0,1,2 + the auth), or (b) RE the imm conv=0 control sender from the decompile to synthesize sn=0,1,2 (auth creds source = ?). Baseline set to config B (sn=0 = the live-correct sequencing).

## Ghidra+smali RE: the auth PDU (sn=0) is FULLY GROUNDED — password source pinned

decompile RE workflow (Ghidra over libThingP2PSDK, 4643 funcs) + smali of the jadx-undecompiled binder:
- SendAuthorizationInfo @ ghidra_p2p/funcs/00147608: 104-byte PDU = magic 0x12345678 @0 | code(i32) @4 | username[31] @8 | password[63] @0x28; sealed suite-3 (AES-128-CBC + inline IV + 20B HMAC-SHA1) over conv=0 KCP, same path as the 28-byte PDUs (imm_p2p_rtc_send_data @00162da0 -> FUN_0016304c).
- Java call site: com/thingclips/smart/p2p/pbbppqb.i():815 = sendAuthorizationInfo(handle, 0, 0, "admin", str, timeout). username="admin", code=0 CONFIRMED.
- The password binder pbbppqb.j() FAILED jadx decompile; SMALI (smali_classes14/.../p2p/pbbppqb.smali:7212) reveals it does JSONObject.getString("password") on the camera-info bean (also reads "p2pConfig","skill"), then connectV3.
- => auth password = camera-info "password" field = OUR rtc.config result.password (CONFIRMED present in secrets/tuya_rtc_config.json alongside p2pId/auth/skill). We HAVE every value.

So sn=0 auth PDU is implementable with HIGH confidence: magic 0x12345678 | code=0 | "admin" | rtc.config.result.password.

REMAINING GAP: conv=0 sn=1,2 (the 2 setup PDUs between auth and the cap4 28-byte PDUs at sn=3,4,5) - content still not pinned (native connectV3 internals / not in cap4). Next live experiment: send auth(sn=0) + the 3 known 28-byte PDUs at sn=1,2,3 (contiguous, no KCP gap) and see if the camera opens video; if it stalls, sn=1,2 needs the connectV3 conv=0 RE or cap7.

## Live test WITH auth PDU: camera goes SILENT (auth value/sn=1,2 still needs cap7)

open_media_start now emits 4 segments: auth(sn=0, 104B, magic 0x12345678 + "admin" + rtc.config.result.password) + the 3 28-byte PDUs(sn=1,2,3). All gates green (374 tests).

LIVE RESULT: "media-start: sent 4 KCP control segments" -> ICE summary media_ok=0, NO inbound conv=0 from the camera at all (vs config B without auth = camera ACK'd una=3). So adding the sn=0 auth made the camera STOP responding entirely. Since the only change is sn=0 (28-byte PDU -> 104-byte auth), the camera rejected our auth and dropped the conv=0 channel.

Most likely: the auth PASSWORD VALUE is wrong. The smali pinned the FIELD name (getString("password") on the camera-info bean) and we used rtc.config result.password, but the camera-info bean in the app comes from requestCameraInfo (a possibly-different API than rtc.config.get); the password may differ. Secondary: the real sequence needs the sn=1,2 SETUP PDUs (inside native connectV3, not in cap4), and our compressed auth+PDUs is malformed.

STATIC RE IS EXHAUSTED for the final piece. We have (grounded): full signaling, ICE, the media-start KCP mechanism (camera accepts our sequencing), the auth PDU LAYOUT + username="admin" + the password FIELD name. NOT statically resolvable: the exact auth password VALUE binding (which JSON object) + the sn=1,2 setup content (native connectV3 internals).

=> cap7 is now the surest unblock: capture a FRESH live-view from connection #1; decrypt conv=0 sn=0 (auth) with the session media key -> read the EXACT password value (compare to rtc.config.password to confirm/correct the source) AND read sn=1,2 setup. Then the replay is exact.
<!-- SECTION:NOTES:END -->
