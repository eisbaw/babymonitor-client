---
id: TASK-0083
title: 'Live media transport: ICE host-direct UDP gets Connection refused after answer'
status: To Do
assignee: []
created_date: '2026-06-28 12:03'
updated_date: '2026-06-28 12:07'
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
<!-- SECTION:NOTES:END -->
