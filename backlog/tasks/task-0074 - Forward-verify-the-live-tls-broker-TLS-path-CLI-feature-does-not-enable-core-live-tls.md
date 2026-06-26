---
id: TASK-0074
title: >-
  Forward + verify the live-tls broker-TLS path (CLI feature does not enable
  core live-tls)
status: To Do
assignee: []
created_date: '2026-06-26 22:20'
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
- [ ] #1 babymonitor-cli live feature forward-enables babymonitor-core/live-tls
- [ ] #2 cargo build/clippy --features live compiles the TLS:8883 transport line (on a networked machine)
<!-- AC:END -->
