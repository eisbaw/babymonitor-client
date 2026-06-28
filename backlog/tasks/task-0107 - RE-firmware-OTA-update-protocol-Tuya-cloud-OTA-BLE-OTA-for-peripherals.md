---
id: TASK-0107
title: RE firmware OTA update protocol (Tuya cloud OTA + BLE OTA for peripherals)
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 22:06'
labels:
  - re
  - ota
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the firmware update path for the baby unit. Map the Tuya OTA notification/flow (camera_dp_update_titile, upgrade process states, status-LED semantics) and, if applicable, the BLE OTA for paired sensors/peripherals (BleOTABean/OnBleUpgradeListener via libBleLib.so, BleOtaParam type/version/firmwareData). Static-RE: identify the OTA check/trigger entrypoint, version reporting DP, and update state machine into an re/ writeup. Read-only documentation — do not attempt to push firmware.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The OTA check/notify/trigger entrypoint and firmware-version reporting are documented with file:line evidence
- [x] #2 The cloud-OTA vs BLE-OTA boundary is characterized with confidence; BLE OTA marked applicable-or-not for SCD921/923
- [x] #3 re/firmware_ota.md writeup exists
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Grep Tuya OTA interfaces/business + BLE OTA start-from files\n2. Map cloud OTA API surface + version reporting + state machine\n3. Check SCD921 BLE applicability via manifest + captured schema\n4. Write re/firmware_ota.md\n5. Run secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Cloud OTA is the SCD921 path: IThingOta.getOtaInfo()/startOta() (ddppdbq.java:2838/3266) over thing.m.device.upgrade.* APIs (bqqbpqb.java/DeviceOTABusiness.java); version reporting via thing.m.device.version.update v4.2 (bqqbpqb.java:266); state machine = DevUpgradeStatusEnum (0..14,100,-101). Notify via MQTT (ThingDevUpgradeStatusBean/ProductUpgradeEvent) + camera_dp_update_titile (RN panel, not in smali). Provisioning-time forced upgrade = orange-LED flow (firmware_upgrade_process_* strings, config_activity_update_device). BLE OTA (BleOTABean/OnBleUpgradeListener/BleOtaParam, dqqdbqp.java:3591, bbbdqpb.java:3429, libBleLib.so) is NOT applicable: live device category=sp, capability=1 (Wi-Fi only, BLE bit unset), no BLE sub-devices. secret-scan OK.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the SCD921/923 firmware OTA path in re/firmware_ota.md.\n\nWhat: Mapped the Tuya cloud OTA surface (IThingOta entrypoints getOtaInfo/startOta/setOtaListener -> ddppdbq.java; thing.m.device.upgrade.info/confirm/cancel/progress.report/status.update/process.info/auto.switch + version reporting via thing.m.device.version.update v4.2 -> bqqbpqb.java/DeviceOTABusiness.java), the full state machine (DevUpgradeStatusEnum + UpgradeInfoBean constants + UpgradeModeEnum OTA/PID), the notify path (MQTT ThingDevUpgradeStatusBean/ProductUpgradeEvent + the camera_dp_update_titile UI string), and the Philips provisioning-time forced-upgrade orange-LED semantics (firmware_upgrade_process_* strings + config_activity_update_device layout).\n\nBLE-OTA boundary: characterized BleOTABean/OnBleUpgradeListener/BleOtaParam + startBleOta (dqqdbqp.java:3591) + otaDevice (bbbdqpb.java:3429) + libBleLib.so as generic Tuya BLE/mesh SDK, and marked it NOT applicable to SCD921/923 (live device category=sp, capability bitmask=1 -> Wi-Fi only/no BLE bit; manifest BLE required=false; no paired BLE sensors). High confidence overall; camera.hardware.upgrade.get usage and the RN-panel notify DP are low/medium (runtime-only).\n\nEvidence: file:line citations throughout; no secrets/PII inlined (device id/meshId referenced by secrets/ location only). just secret-scan passes.
<!-- SECTION:FINAL_SUMMARY:END -->
