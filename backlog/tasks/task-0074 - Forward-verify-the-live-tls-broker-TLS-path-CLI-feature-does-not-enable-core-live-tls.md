---
id: TASK-0074
title: >-
  Forward + verify the live-tls broker-TLS path (CLI feature does not enable
  core live-tls)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-26 22:20'
updated_date: '2026-06-27 18:09'
labels:
  - stream
  - mqtt
  - build
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Reviewer found the TLS:8883 connect line (transport.rs, rumqttc tls_with_default_config, behind core feature live-tls) is NOT forward-enabled by the CLI live feature, so cargo build/clippy --features live never compiles it; tokio-rustls 0.25 is also absent from this sandbox cache. Add feature forwarding (cli live -> core live-tls) and verify the TLS broker connect builds on a networked machine.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 babymonitor-cli live feature forward-enables babymonitor-core/live-tls
- [x] #2 cargo build/clippy --features live compiles the TLS:8883 transport line (on a networked machine)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-0074 implemented + offline-validated.

Change (single source edit): babymonitor/babymonitor-cli/Cargo.toml `live` feature now lists `babymonitor-core/live-tls` (plus a comment explaining why). babymonitor-core is a non-optional dep, so the `crate/feature` forward-edge is valid.

Feature-graph verification (definitive, via `cargo metadata` resolve nodes):
- cli `--features live`  => babymonitor-core features = ["live-tls"]; rumqttc features = ["use-rustls"].
- default (no live)      => babymonitor-core features = []; rumqttc features = []. (offline/default gate unchanged.)
`cargo tree -e features -p babymonitor-cli --features live` shows the rumqttc rustls stack (rustls-native-certs, rustls-webpki, ring, tokio-rustls 0.25).

Correction to the task premise (honest): tokio-rustls 0.25.0 IS now present in this sandbox cargo cache (~/.cargo/registry/{cache,src}/.../tokio-rustls-0.25.0). So contrary to the task note, `--features live` COMPILES HERE offline. Verified both:
  - `cargo check  --offline -p babymonitor-cli --features live` => Finished (compiles tokio-rustls 0.25, rumqttc use-rustls, babymonitor-core with live-tls => the `#[cfg(feature = "live-tls")]` `opts.set_transport(rumqttc::Transport::tls_with_default_config())` line at stream/transport.rs:149 is now type-checked).
  - `cargo clippy --offline -p babymonitor-cli --features live` => Finished, no warnings.
No live network calls were made (offline build only; no broker/camera/TLS contacted).

just e2e: RED, but NOT from this change. Failing recipe is `stream-validate` (the last e2e step), which builds the DEFAULT bin (no features) and flakes ~50% on its `ffprobe ... | grep -qx h264` codec probe (exit 1 "produced TS is not h264" / exit 141 SIGPIPE). Proven pre-existing + flaky: 5 identical back-to-back runs = 1:fail 2:ok 3:fail 4:ok 5:fail, with my one-file default-OFF Cargo.toml change as the only working-tree source edit. All other e2e gates (build/test/lint/fmt-check/stub-grep/assert-offline/test-bmp-decode/test-regions) passed. Filed as TASK-0076.

Did NOT git commit (per task).

DONE: babymonitor-cli live feature now forward-enables babymonitor-core/live-tls (Cargo.toml +9). Confirmed: cargo build --offline -p babymonitor-cli --features live FINISHED 38.86s, no errors — tokio-rustls 0.25 IS cached on this machine; the TLS:8883 transport line (transport.rs:145-150) now compiles + links. Caveat: only type-checks/links; no TLS handshake exercised (needs a live broker).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Forward-enable the live broker-TLS path: cli `live` -> core `live-tls`.

What changed:
- babymonitor/babymonitor-cli/Cargo.toml: added `babymonitor-core/live-tls` to the `live` feature array (+ explanatory comment). Previously `cargo build --features live` never enabled core `live-tls`, so the TLS:8883 CONNECT line (stream/transport.rs:149, `Transport::tls_with_default_config()`, under `#[cfg(feature="live-tls")]`) was dead-stripped and the live MQTT signaling silently fell back to plain TCP.

Why: the live MQTT signaling broker is TLS/8883; the cli is the only consumer that turns on the live stack, so it must forward the core feature.

Verification (offline only, no network):
- cargo metadata resolve: `--features live` => core=[live-tls], rumqttc=[use-rustls]; default => both empty (offline gate untouched).
- cargo check/clippy --offline -p babymonitor-cli --features live both Finished cleanly (tokio-rustls 0.25 happens to be in this cache now, so the TLS line actually type-checks here, not just on a networked machine).

User impact: a real `--features live` build now actually compiles+links the rustls broker transport; the live owner-run path can negotiate over TLS instead of plain TCP.

Risks/follow-ups: live broker/camera path remains owner-run (no creds/sockets exercised here). just e2e is currently RED due to a PRE-EXISTING flaky `stream-validate` (ffprobe codec probe race; default-build, unrelated to this change) — filed TASK-0076. Not committed (per task).
<!-- SECTION:FINAL_SUMMARY:END -->
