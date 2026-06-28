---
id: TASK-0098
title: 'RE environmental sensors: temperature & humidity DPs + alert thresholds'
status: Done
assignee:
  - '@claude'
created_date: '2026-06-28 21:46'
updated_date: '2026-06-28 21:56'
labels:
  - re
  - sensors
  - dp
  - baby-monitor
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the room temperature and humidity monitoring. Map DpTemperature (sensor_temperature, ACTION.TEMPERATURE_SIGNAL) and DpHumidity (sensor_humidity, ACTION.HUMIDITY_SIGNAL): DP codes, value scaling/units, the C/F unit setting (getTempUnit), humidity comfort banding (Dry/Comfortable/Moist), and configurable alert thresholds. Static-RE into one re/ writeup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The sensor_temperature and sensor_humidity DP codes, value scaling and units are documented with file:line evidence
- [x] #2 The temperature unit (C/F) setting and the alert-threshold mechanism are identified with confidence
- [x] #3 re/environment_sensors.md writeup exists covering both sensors and their alert path
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read DpTemperature/DpHumidity + BaseDpOperator/ValueDpOperateBean for codes+scale source\n2. Find getTempUnit (RN bridge q0 + account User encoding)\n3. Cross-ref live captured device schema for real scale/units/threshold DPs\n4. Map scene_humidity_tip banding + temperature_alarm/detection strings\n5. Write re/environment_sensors.md; run secret-scan
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Static RE complete. Key finding: SCD921 live schema has sensor_temperature (dpId 207, scale 2, unit C) but NO sensor_humidity DP -> DpHumidity is dead generic-SDK capability on this hardware. Temp alert uses dedicated device DPs (temp_max/min_switch 231/232 + temp_max/min_cvalue 233/234 [0-40C step 1C, scale 2] + F string twins 235/236), not a cloud scene. Two unit encodings: RN getTempUnit/q0 = 0=C/1=F; account User.getTempUnit = 1=C/2=F. Humidity comfort banding from scene_humidity_tip string = Dry 0-40%, Comfortable 40-70%, Moist 70-100% (generic Tuya, not wired here). secret-scan passes.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the SCD921 environmental-sensor data model in re/environment_sensors.md (static RE of the Tuya camera SDK + the live decrypted device schema under secrets/).

Findings:
- DP operators: DpTemperature -> sensor_temperature / TEMPERATURE_SIGNAL; DpHumidity -> sensor_humidity / HUMIDITY_SIGNAL (DpTemperature.java:15,49; DpHumidity.java:148,153). Codes resolve to dpId/value-type via the device SchemaBean (BaseDpOperator.java:31-61).
- Scaling is schema-driven (ValueDpOperateBean copies scale/min/max/unit); raw transported, display = raw/10^scale. Live schema: sensor_temperature dpId 207, unit C, min 0, max 5000, scale 2 -> raw/100 = 0.00-50.00 C.
- HEADLINE: the live SCD921 schema has NO humidity DP; DpHumidity is dead generic-SDK capability on this hardware (isSupport()==false). The Dry/Comfortable/Moist banding (0-40/40-70/70-100%) is the generic Tuya scene_humidity_tip string (strings.xml:7460), not wired to this device.
- Alert path = dedicated device DPs: temp_max_switch/temp_min_switch (231/232 bool) + temp_max_cvalue/temp_min_cvalue (233/234 value, 0-4000 scale 2 step 100 => 0-40 C in 1 C steps) + temp_max_fvalue/temp_min_fvalue (235/236 string twins). Not a cloud scene; temperature_alarm/temperature_detection strings are scene/RN-panel labels (medium confidence wiring).
- Unit setting: TWO encodings documented. RN bridge getTempUnit -> q0() returns 0=Celsius/1=Fahrenheit (default C; small F-default country list) (ka.../TRCTCameraManager.java:5500-5611,10800-10806). Account User.getTempUnit = 1=Celsius/2=Fahrenheit (TemperatureProxy.java:86-94).

All claims carry confidence + file:line/secrets-path evidence; no PII/secret values inlined. just secret-scan passes.
<!-- SECTION:FINAL_SUMMARY:END -->
