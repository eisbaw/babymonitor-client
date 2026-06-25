---
id: TASK-0014
title: 'End-to-end acceptance harness: gated live login+device-list'
status: To Do
assignee: []
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 05:01'
labels:
  - phase7
  - test
  - wave1
  - e2e
dependencies:
  - TASK-0013
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ONBOARDING (do first): read CLAUDE.md, re/prd.md, TESTING.md, re/milestone2_findings.md; invoke Skill tool to load android-app-reverser and follow its 9-phase methodology (do not improvise). Use nix-shell --run for all tools. Cite evidence with confidence. File new backlog tasks for tangents; do not chase inline.

UX/E2E TASK (skill phase 7). Wire the gold-oracle acceptance signal from TESTING.md: a #[ignore] live test + a CLI path (babymonitor-cli auth login; devices list) that runs against the user real Tuya account/SCD921. Document the manual auth setup. mped-architect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 babymonitor-cli supports auth login + devices list with human and --json output; showcase includes the read-only commands
- [ ] #2 An #[ignore]d live e2e test exists with documented setup (creds from secrets/); README snippet explains how the user runs it against the real camera
- [ ] #3 Live calls rate-limited/single-shot; just e2e (offline) excludes the live test; README documents authorized scope = user's own account + device only
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FEED-FORWARD from TASK-0013 (device models + accessor, babymonitor-core::device) — the API shape the CLI 'devices list' / 'devices show' should surface:

PARSE (offline, no network needed for the model layer):
- device::parse_device_list(&[u8]) -> Result<DeviceList, Error::DeviceParse>
- device::parse_camera_info(&[u8]) -> Result<CameraInfoBean, Error::DeviceParse>
- DeviceList{ device_list: Vec<DeviceBean>, shared_device_list: Vec<DeviceBean> }; DeviceList::all_devices() iterates owned+shared; DeviceList::find_camera_device() -> Option<&DeviceBean> (sp/ipc family).

DEVICES LIST (per DeviceBean): dev_id (REQUIRED), name, category, online() (bool, cloud||LAN), is_camera(), product_id, pv, uuid. CAMERA SHOW (CameraView::pair(&DeviceBean,&CameraInfoBean) -> Result, errors DeviceMismatch on non-camera): dev_id(), online(), transport() -> device::P2pTransport{Ppcs|ThingWebRtc|Other(i32)} (.is_webrtc()), p2p_id(), p2p_config() -> Option<&P2pConfig>.

LIVE FETCH IS TOKEN-PENDING: device::list_devices(&SigningKeyMaterial,&impl BmpTokenProvider, sid, home_id) returns Err(BmpTokenPending) until TASK-0030 ports the bmp_token (same gate as TASK-0012's Signer::sign). So the CLI 'devices list' real-network path must be #[ignore]/token-pending behind that — the OFFLINE showcase path should run against the synthetic fixture (babymonitor/babymonitor-core/tests/fixtures/{device_list.json,camera_info.json}) or print a clear 'login required / signing pending (TASK-0030)' message, never panic.

SECRET / PII FIELDS — MUST NOT PRINT BY DEFAULT (only behind an explicit --show-secrets/--reveal flag, and even then warn): DeviceBean.local_key, DeviceBean.sec_key, CameraInfoBean.password, CameraInfoBean.session_tid, P2pConfig.p2p_key, P2pConfig.init_str (+ session/ices/tcpRelay/udpRelay descriptors). dev_id/uuid/p2p_id are account-linked PII — safe to show in an authorized local CLI but keep OUT of --json that could be pasted into a bug report by default; the models' Debug already redacts the crypto secrets, so prefer {:?} or the accessor methods over hand-formatting raw fields. secret-scan will catch a real value leaking into any tracked file/snapshot.
<!-- SECTION:NOTES:END -->
