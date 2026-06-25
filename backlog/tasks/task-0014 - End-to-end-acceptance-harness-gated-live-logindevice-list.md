---
id: TASK-0014
title: 'End-to-end acceptance harness: gated live login+device-list'
status: Done
assignee:
  - '@architect'
created_date: '2026-06-24 22:37'
updated_date: '2026-06-25 05:17'
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
- [x] #1 babymonitor-cli supports auth login + devices list with human and --json output; showcase includes the read-only commands
- [x] #2 An #[ignore]d live e2e test exists with documented setup (creds from secrets/); README snippet explains how the user runs it against the real camera
- [x] #3 Live calls rate-limited/single-shot; just e2e (offline) excludes the live test; README documents authorized scope = user's own account + device only
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
PART A device.rs review fixes (first, minimal):
1. P1: fix CameraView::pair rustdoc — delete false id-mismatch clause; state camera-category-only + info.id/dev_id equivalence unconfirmed (needs-live).
2. P2: add #[serde(alias="categoryCode")] to category field (grounded §5b: category/categoryCode siblings) + a test asserting categoryCode populates is_camera.
3. P2: hedge the "ipc" literal as (inferred) in is_camera comment (only sp grounded).
4. P2: narrow .gitignore negation from tests/fixtures/** to the 2 known files.
Re-run e2e.

PART B CLI + harness:
5. Add deps to babymonitor-cli (serde_json for --json; babymonitor-core already dep).
6. Rewrite main.rs: clap subcommands auth {login,status,logout}, devices {list,show <id>}, plus keep info. login -> BmpTokenPending honest report (not fake). status/logout work offline vs SessionStore. devices list/show parse fixture body offline; live fetch token-pending message. --json mode + human. Secrets redacted by default; --show-secrets gated (still warns, never prints real crypto secret — fixtures are synthetic so safe but gate stays).
7. Wire showcase: auth status, devices list (fixture), devices show, etc.
8. #[ignore]d live e2e integration test (tests/live_e2e.rs) documenting auth login -> devices list -> find SCD921, honestly blocked on TASK-0030.
9. README.md (babymonitor/) snippet: build, token-pending status, authorized scope, how live test runs once unblocked.
10. Gate: just e2e, showcase, check-evidence, secret-scan all GREEN.
11. Feed-forward TASK-0016. Commit (no AI trailer).
<!-- SECTION:PLAN:END -->

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

GOTCHAS / honest limitations (TASK-0014):
- The client CANNOT log in: `auth login` honestly returns the token-pending state (Error::BmpTokenPending), blocked on bmp_token (TASK-0030). No fake success. Verified via showcase output.
- Exit-code policy nuance: `auth login` token-pending exits 0 (it is a complete, honest answer to "what is my login state"); `devices list --live` token-pending exits 1 (it was asked to FETCH and could not). This asymmetry is deliberate and documented in code comments; `--live` is therefore OMITTED from `just showcase` (which requires all-zero exits) while the read-only offline commands are included.
- `devices list/show` OFFLINE path reads a response body from `--fixture` (default: the committed synthetic fixture). No network. `--live` surfaces token-pending without touching the network (probes the PendingBmpToken signer gate first).
- Secrets: localKey/secKey redacted by default in both human and --json; `--show-secrets` reveals (only synthetic values exist) and prints a stderr warning. device_json verified to never leak a secret with show_secrets=off (unit test).
- Live gold-oracle test (tests/live_e2e.rs) is #[ignore]d (excluded from just e2e); run with `--ignored --test-threads=1`. Today it asserts the honest token-pending state (panics if someone makes it fake-succeed without TASK-0030). README documents the manual setup + authorized scope.
- PART A device.rs fixes landed: P1 doc (deleted false id-mismatch clause; camera-category-only + id/dev_id equivalence is needs-live); P2 serde alias categoryCode (+2 tests); P2 ipc-literal hedged "(inferred)"; P2 .gitignore narrowed to the 2 named fixtures (verified: stray file under tests/fixtures/ is now ignore-by-default, known fixtures still tracked).
- AC#4 (rate-limit/single-shot): no live calls this task; structure supports it (single-shot probe, no retry loop) and README/live-test mandate --test-threads=1 for the future live pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
CLI surface + gated live e2e harness (TASK-0014), plus 4 TASK-0013 review fixes.

What changed:
- babymonitor-cli: clap subcommands `auth {login,status,logout}`, `devices {list,show <id>}`, plus `info`. Human + `--json` output on every command. `auth status`/`logout` work offline against the SessionStore; `auth login` honestly reports token-pending (Error::BmpTokenPending), never a fake login. `devices list/show` parse a device-list body from `--fixture` (default: committed synthetic fixture); `--live` surfaces token-pending without touching the network.
- Secrets: localKey/secKey redacted by default (human + json); `--show-secrets` reveals (only synthetic values exist) with a stderr warning. Unit test proves device_json never leaks a secret by default.
- `just showcase` wired with all read-only commands (green). `--live` deliberately omitted (token-pending exits non-zero by design).
- Gold-oracle live test babymonitor-cli/tests/live_e2e.rs is #[ignore]d (excluded from just e2e); asserts the honest token-pending state today, becomes the real login->list->find-SCD921 once TASK-0030 lands. Run with `--ignored --test-threads=1` (single-shot, rate-limit-safe).
- babymonitor/README.md: build, the token-pending login status, authorized-scope note (user own account+device only), and how to run the live test once unblocked.

Part A (device.rs review fixes): corrected CameraView::pair rustdoc (camera-category-only; id/dev_id equivalence is needs-live); added #[serde(alias="categoryCode")] (+2 tests); hedged the inferred `ipc` category literal; narrowed .gitignore to the 2 named fixtures so stray files under tests/fixtures/ are ignore-by-default.

Gates: just e2e GREEN (build+test+clippy -D+fmt+stub-grep+offline+bmp-decode); just showcase GREEN; check-evidence GREEN; secret-scan GREEN.

Honest limitation: the client CANNOT log in — that is token-pending on the bmp_token (TASK-0030). The offline CLI + harness are complete; the live path is gated, not faked.
<!-- SECTION:FINAL_SUMMARY:END -->
