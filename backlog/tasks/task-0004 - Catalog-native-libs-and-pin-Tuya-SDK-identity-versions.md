---
id: TASK-0004
title: Catalog native libs and pin Tuya SDK identity/versions
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-24 22:35'
updated_date: '2026-06-24 23:31'
labels:
  - phase3
  - re
  - wave1
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Static analysis only. Cite evidence (file:line / lib@offset) with confidence levels. File new backlog tasks for tangents; do not chase inline.

WHY (skill phase 2/3): the .so set is the ground truth of the stack. Need each Tuya lib version, exported symbols, and embedded strings to cross-reference public Tuya RE. Delegate to Explore subagent; use nm/readelf/strings/radare2.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 re/native_libs.md tables every lib/arm64-v8a/*.so with size, SONAME, detected version strings, and role; Tuya libThingP2PSDK/CameraSDK/VideoCodec/AudioEngine/SmartLink versions pinned where present
- [x] #2 Exported-symbol dumps saved to analysis/ for the P2P/camera/codec libs; obvious crypto (OpenSSL 1.1, libthing_security) and their algorithms noted
- [x] #3 CORRECTION: native libs are in extracted/xapk/config.arm64_v8a.apk (NOT the base APK). Analyze that split. Cross-check at least one lib (e.g. libThingP2PSDK) SONAME/version against a public Tuya SDK release, or record the mismatch
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. unzip config.arm64_v8a.apk lib/arm64-v8a/*.so to decompiled/nativelibs.
2. For each .so: size, SONAME (readelf -d), version strings (strings|grep), role.
3. Pin Tuya P2P/Camera/VideoCodec/AudioEngine/SmartLink versions; note crypto libs.
4. nm -D / readelf dumps for P2P/camera/codec libs -> re/symbols/.
5. Cross-check libThingP2PSDK SONAME/version vs public Tuya release.
6. Write re/native_libs.md.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Analyzed config.arm64_v8a.apk (58 .so). re/native_libs.md has full table; re/symbols/ has dynsym+dynamic dumps for P2P/camera/codec/audio/smartlink.
KEY: libThingP2PSDK = WebRTC-over-MQTT (SDP/ICE/DTLS-SRTP via bundled mbedTLS + MQTT signaling, connect_v2 cmd with skill/token/lan_mode) AND legacy PPCS. Confirms review-gate F2. Stack = Tuya ipc-tymedia-sdk (build-path leak in AudioEngine).
Versions: OpenSSL 1.1.1w; P2P 3.10.0; Camera 1.2.x; VideoCodec=OpenH264; AudioEngine=WebRTC audio_processing(AEC/AGC/NS/VAD); MP3=LAME.
GOTCHA: SDK version literals are mostly printf %s-substituted at runtime, so pinned tokens are labelled likely. Crypto: P2P bundles its OWN mbedTLS (not app OpenSSL); sign/whitebox key-derivation likely in libthing_security_algorithm.so/libthingnetsec.so (task 5, not chased).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Inventoried all 58 arm64-v8a native libs from config.arm64_v8a.apk into re/native_libs.md (size/SONAME/version/role table) with committed exported-symbol + dynamic-section dumps under re/symbols/ for the P2P/camera/codec/audio/smartlink libs.

Key finding (high-value): libThingP2PSDK.so carries a full WebRTC stack (SDP a=ice-ufrag/rtcp-mux, STUN/TURN, DTLS-SRTP via statically-bundled mbedTLS) signaled over Tuya MQTT (create signaling mqtt worker thread, SendMessageThroughMqtt, connect_v2 command) AND a legacy PPCS (TUTK/IOTC) path. This confirms review-gate F2: streaming is WebRTC-over-MQTT, making webrtc-rs + MQTT signaling the likely cheaper Rust path over PPCS AV-framing reconstruction.

Identity cross-checked against public tuya/tuya-rtc-camera-sdk-android (WebRTC+MQTT) and the leaked build path /Users/xucs/.../ipc-tymedia-sdk. Versions pinned: OpenSSL 1.1.1w; ThingP2PSDK 3.10.0; CameraSDK 1.2.x; codecs OpenH264/LAME/Opus/WebRTC-audio. check-evidence + secret-scan green; re/symbols not gitignored and scanned clean.
<!-- SECTION:FINAL_SUMMARY:END -->
