# SenseIQ — sleep-stage / breathing-rate AI monitoring, consent DPs, positioning check, diagnostics (TASK-0090)

Static RE of the Philips-proprietary **SenseIQ** feature (the headline non-Tuya
differentiator): real-time sleep stage (active-awake / light / deep), sleep duration,
breathing rate with 30-day history, plus the **positioning check** and the optional
**SenseIQ improvement / diagnostics** consent path. This documents the *protocol surface*
(DPs, consent flow, data path) only — **the AI itself is not reimplemented here**.

> Citation convention: `decompiled/jadx/sources/<pkg>/<File>.java:NN` is jadx-decompiled
> Java/Kotlin from the base APK; `decompiled/apktool/res/values/strings.xml:NN` is the
> apktool resource table. Jadx renames `R.string.*` to short obfuscated aliases (e.g.
> `R.string.t6`); the human-readable string `name=` cited from `strings.xml` is the
> ground truth for UI semantics. No secret/PII value appears in this doc — device ids,
> localKey, tokens, account ids are referenced by their `secrets/` location only.
> Owning module: `nightowl-camera-setting` (the camera-panel feature library; the panel
> UI carrying SenseIQ is native Kotlin, **not** the JS/miniapp bundle — confirmed by a
> zero-hit grep for `senseiq|sleepiq` across `decompiled/js/`).

---

## Verdict (confidence: high for the DP/consent surface; medium for the off-device data path)

SenseIQ is driven by a small set of **Tuya datapoints (DPs)** on the SCD921 camera. The
app does **not** run the AI and does **not** upload video frames itself: it (a) writes
**consent** and **enable** DPs, (b) writes the **mattress region box** DP, and (c) reads a
**status** DP that the *camera firmware* produces. The sleep/breathing inference therefore
runs **on the Baby Unit (camera) firmware**, and the results return to the app as DPs.

- Two consent DPs gate the feature: `sleepiq_consent` (primary, "process baby's video
  image") and `sensiq_diag_consent` (optional improvement/diagnostics). Both are written
  through the **Tuya mobile cloud API** `thing.m.device.dp.publish` (v2.0), not a Philips
  endpoint.
- The **positioning check** is the `sleepiq_area` DP — a normalized mattress bounding box
  pushed to the camera over MQTT.
- The **diagnostics upload** (signal confidence/strength, AI detection confidence, AI box
  location/size, every minute, 7-day retention to Philips) is described only in consent
  UI strings and is carried by a declared-but-app-unused DP `senseiq_diagnostics` → the
  upload is **firmware→Philips**, not visible in app code. This is the main residual unknown.

---

## 1. The SenseIQ DP table (confidence: high)

All SenseIQ DPs are defined in one enum, `DeviceDpUtil.DpCode`
(`decompiled/jadx/sources/com/thingclips/smart/ka/panel/camera/details/camera/utils/DeviceDpUtil.java:54-81`).
Each entry is `new DpCode(name, ordinal, dpCode, dpId)` where `dpCode` is the Tuya DP
**code** (string, used by the IPC DP helper / local + MQTT path) and `dpId` is the numeric
**DP id** (used by the cloud `dp.publish` API). SenseIQ-relevant rows:

| DP code (string)       | DP id | enum const                | role |
|------------------------|-------|---------------------------|------|
| `sleepiq_switch`       | 1     | `DP_SLEEPIQ_SWITCH`       | enable/disable SenseIQ (bool) — DeviceDpUtil.java:63 |
| `sleepiq_status`       | 3     | `SLEEPIQ_STATUS`          | result channel device→app (JSON string) — :64 |
| `sleepiq_consent`      | 5     | `DP_SLEEPIQ_CONSENT`      | **primary privacy consent** (bool) — :65 |
| `senseiq_diagnostics`  | 6     | `SENSEIQ_DIAGNOSTICS`     | diagnostics payload DP (declared; **no app-side use**) — :74 |
| `sensiq_diag_consent`  | 7     | `DP_SENSIQ_DIAG_CONSENT` / `SENSIQ_DIAG_CONSENT` | **diagnostics/improvement consent** (bool) — :66, :75 |
| `awake_delay`          | 8     | `DP_AWAKE_DELAY`          | Baby-awake alert delay (string/enum) — :70 |
| `sleepiq_area`         | 10    | `DP_SLEEPIQ_AREA`         | **positioning/mattress region box** (JSON string) — :67 |
| `awake_switch`         | 11    | `DP_AWAKE_SWITCH`         | Baby-awake alert enable (bool) — :71 |
| `no_senseiq_switch`    | 13    | `NO_SENSEIQ_SWITCH`       | **No-signal alert** enable (bool) — :68 |
| `no_senseiq_signal`    | 15    | `NO_SENSEIQ_SIGNAL`       | no-signal indicator — :69 |

Notes / honesty:
- `sensiq_diag_consent` (id 7) appears **twice** in the enum (`DP_SENSIQ_DIAG_CONSENT`
  and `SENSIQ_DIAG_CONSENT`) — two aliases, same wire DP. (`DeviceDpUtil.java:66,75`)
- DP **value types** are inferred from how the app reads/writes them
  (`Boolean.TYPE` / `String.class` calls), not from a DP schema dump. The device's
  authoritative DP schema (datatype, enum ranges) would come from
  `thing.m.product.info.get` / the device schema — not captured here. Confidence on the
  bool/JSON typing: high (matches every read/write site); on exact enum ranges: low.
- The Baby-awake notification's message-center classify key is `"ipc_car"`
  (`SenseIQClassifyKeys.BABY_AWAKE`,
  `decompiled/jadx/sources/com/thingclips/smart/ka/ipc/messagecenter/consts/SenseIQClassifyKeys.java:11`).
  (The `Tz.a()/Tz.b(0)` noise interleaved through these classes is anti-decompilation
  control-flow padding; it has no runtime effect on the constants.)

---

## 2. Consent DPs and the enable flow (confidence: high)

### 2a. How consent is written — Tuya cloud `dp.publish`, keyed by DP **id**

Consent is **not** a normal local DP set; it goes through the Tuya **mobile cloud** API.
`ConsentBusiness.l(devId, dpsJson, listener)` builds:

```
ApiParams("thing.m.device.dp.publish", "2.0")
  postData: devId = <camera devId>          # secrets/ — real id never inlined here
  postData: dps   = {"<dpId>": <bool>}      # JSON, keyed by numeric DP id, not code
  postData: reason = "offline_device"        # allows setting even if device offline
```
(`decompiled/jadx/sources/com/thingclips/smart/ka/panel/camera/details/business/ConsentBusiness.java:115-121`)

The two consent writes therefore are:
- **Primary consent ON:** `{"5": true}` → `SleepIQSettingModel.H()` /
  `SleepIQRevokeConsentModel` use `DP_SLEEPIQ_CONSENT.getDpId()` (=5)
  (`SleepIQSettingModel.java:181`; `SleepIQRevokeConsentModel.java:678,1858`).
- **Diagnostics consent ON:** `{"7": true}` → `SleepIQSettingModel.G()` /
  `SleepIQRevokeConsentModel` use `DP_SENSIQ_DIAG_CONSENT.getDpId()` (=7)
  (`SleepIQSettingModel.java:142`; `SleepIQRevokeConsentModel.java:1586`).

So both consents are persisted as **Tuya device DPs** (ids 5 and 7), via a **Tuya**
endpoint — confidence: high. Current state is read back with the IPC DP helper:
`isSleepIQConsentEnable` reads `sleepiq_consent` (`DeviceDpUtil.java:3305`); the diagnostics
consent reads `sensiq_diag_consent` (`DeviceDpUtil.java:551`).

### 2b. Enable / disable SenseIQ — local/MQTT DP

The feature *enable* itself is a separate DP, written over the IPC DP helper (local + MQTT
fast path), **not** the cloud consent API:
`createIPCDpHelper.publishDps(DP_SLEEPIQ_SWITCH /* "sleepiq_switch" */, enable, cb)`
(`DeviceDpUtil.java:2213`). `sleepIQEnable` state is read from the same DP
(`DeviceDpUtil.java:640`). The settings UI tracks both flags together —
`SleepDataBean(sleepIQEnable, isSleepIQConsentEnable)` (`SleepIQSettingModel.java:243-252`).

### 2c. Flow ordering and revoke semantics (confidence: high)

- **Order:** consent must exist before the feature is usable. The consents list toggle
  handler `SleepIQConsentsListModel.L(...)`
  (`SleepIQConsentsListModel.java:650-685`) maps the **primary** consent switch
  (`R.string.t6`, = `bm_senseIQ_consents`, `strings.xml:1445`) to enable/revoke, and the
  **diagnostics** switch (`R.string.R0`) to `sensiq_diag_consent`. Turning the diagnostics
  switch ON for the first time routes through `SleepIQRevokeDiagConsentTipsActivity`
  (a confirmation gate) before the DP write (`SleepIQConsentsListModel.java:672-683`).
- **Revoke cascade:** revoking the **primary** consent disables SenseIQ entirely, and the
  UI text states the diagnostics consent is *automatically revoked* with it
  (`bm_disable_sleepIQ_alert_tip` `strings.xml:1242`; `bm_senseIQ_improvement_content1`
  `strings.xml:1449`; `bm_enable_sleepIQ_diag_content` `strings.xml:1258-1262`). Whether the
  cascade is enforced server-side or only client-side is not proven statically (the app
  writes `{"5": false}`; firmware/cloud may auto-clear id 7) — confidence: medium.
- A **non-medical-device warning** consent gate is part of the enable wizard
  (`bm_sleepIQ_warning_no_medical*` `strings.xml:1463-1472`;
  `WelcomeToSenseIqActivity`, `SleepIQWarningMedicalActivity`).

---

## 3. Positioning check (confidence: high for the DP; medium for the validation logic)

The "Positioning check" (UI: `mty_senseIQ_set_mattress` = "Positioning check"
`strings.xml:6489`; `mty_set_mattress_area_senseiq` = "Set mattress area for SenseIQ"
`strings.xml:6511`; rationale `bm_positioning_check_content` `strings.xml:1416`) writes the
**`sleepiq_area`** DP. It is the user-drawn orange box matching the mattress edges
(`mty_senseiq_region_settings_tips` `strings.xml:6500`).

Wire payload is a `CameraMotionDesignatedScreenBean` serialized to JSON and published over
the MQTT camera channel
(`SleepIQZoneSettingModel.java:298-303` → `mMQTTCamera.L3("sleepiq_area", json, cb)`):

```jsonc
// CameraMotionDesignatedScreenBean  (fields from
// decompiled/jadx/sources/com/thingclips/smart/ipc/panelmore/bean/CameraMotionDesignatedScreenBean.java:6-15)
{ "num": 1,
  "region0": { "x": <f>, "y": <f>, "xlen": <f>, "ylen": <f> } }
// x,y = normalized top-left; xlen,ylen = normalized width/height (floats, 0..1 inferred)
```
The same DP is read back and parsed to drive the overlay
(`SleepIQZoneSettingModel.java:503-510`; read helper `DeviceDpUtil.java:3070-3074`).

The positioning check also drives **distance/orientation guidance** ("reposition Baby
Unit", "adjust mattress height", `mty_senseiq_zone_region_*` `strings.xml:6501-6503`) and
ties to the **No-signal alert** (`no_senseiq_switch`, written at `DeviceDpUtil.java:1442`;
subtitle `bm_senseiq_subtitle` = "Baby awake alert, No signal alert & Positioning check"
`strings.xml:1453`). Whether the box is merely a crop hint or a hard analysis gate (and
how the firmware scores "good position") is **not statically determinable** — the scoring
runs in firmware. Confidence: medium.

---

## 4. Status / results channel and 30-day history (confidence: medium)

The live SenseIQ state returns as the **`sleepiq_status`** DP (device→app), a JSON string.
The only statically-located parse reads field **`"r"`** and compares it to `"network"`
(`DeviceDpUtil.java:3186-3195`, used to detect the no-signal/out-of-crib condition). The
documented status set is enumerated in the privacy string
(`bm_sleepIQ_pricacy_explain_content` `strings.xml:1460-1462`): SenseIQ Status =
`moving / breathing / no-signal / out-of-crib / analyzing`, plus the **current breathing
rate** when breathing, and **Sleep Session Data** (start/end time, duration, sleep stage =
active-awake / light sleep / deep sleep).

Honest gaps:
- The **full `sleepiq_status` JSON schema** (the breathing-rate field name, the stage
  encoding) is **not present in the decompiled Java** — only the `"r"` key was found. The
  live sleep-stage/breathing display and the **30-day history** charts were **not** located
  statically (no `sleepiq_status` consumer beyond `DeviceDpUtil`, no sleep-history REST API
  among the enumerated `ApiParams`, and no JS-bundle hit). Most likely a native panel
  sub-module and/or a Tuya cloud DP-report/statistics service. Confidence: medium that
  `sleepiq_status` is the live channel; low on its exact schema. **Unblock:** one live DP
  report/MQTT capture of `sleepiq_status` (sibling `android_emulator_re` pipeline), or
  Ghidra on the panel `.so` that renders the SenseIQ monitor view.

---

## 5. Data path — what leaves the device, and to whom (confidence: mixed; key unknown flagged)

| Item | Carrier (evidence) | Destination | Confidence |
|------|--------------------|-------------|-----------|
| Primary consent (`sleepiq_consent`, id 5) | Tuya API `thing.m.device.dp.publish` v2.0 (ConsentBusiness.java:115) | **Tuya** cloud → device DP | high |
| Diagnostics consent (`sensiq_diag_consent`, id 7) | same Tuya API (SleepIQSettingModel.java:142) | **Tuya** cloud → device DP | high |
| Enable (`sleepiq_switch`, id 1) | IPC DP publish, local + MQTT (DeviceDpUtil.java:2213) | device (LAN/Tuya MQTT) | high |
| Mattress box (`sleepiq_area`, id 10) | MQTT camera DP (SleepIQZoneSettingModel.java:303) | device firmware | high |
| Live status (`sleepiq_status`, id 3) | device-reported DP (DeviceDpUtil.java:3186) | device → app | medium |
| **AI inference (frames → sleep/breathing)** | n/a (no frame upload in app) | **on Baby Unit firmware** | medium-high |
| **Diagnostics metrics** (signal conf./strength, AI detection conf., AI box loc/size) | `senseiq_diagnostics` DP **declared but app-unused** (DeviceDpUtil.java:74); described only in consent UI string (`bm_senseIQ_improvement_content2` `strings.xml:1450`) | **Philips servers** ("our servers"), **every minute**, **7-day** retention, then anonymized + aggregated to a separate store | medium (text-only) |
| Raw baby **video image** egress | consent text says Philips "collect and analyse your baby's video image" (`strings.xml:1460`) — **no frame-upload code found in app** | **UNKNOWN** (likely on-device; possibly firmware→Philips) | low |

Reasoning for "AI runs on the Baby Unit": the app pushes the analysis region *to* the
device (`sleepiq_area`) and reads results *from* the device (`sleepiq_status`), and there
is no video-frame upload path in the decompiled app. So the inference is firmware-side and
results come back as DPs. The diagnostics metrics named in `strings.xml:1450` (signal
confidence/strength, AI detection confidence, AI box location/size) are exactly per-frame
inference internals — consistent with the **firmware** computing them and uploading to
**Philips** (not Tuya) when both consents are true; the app's role is only to set the
consent DPs. Because the `senseiq_diagnostics` DP has **no app-side reader/writer**, the
diagnostics transport and the Philips endpoint are **not proven statically**.

Philips-side endpoints that *do* appear in the app are the **MyPhilips account / OAuth**
service (`https://www.eu-west-1.api.philips.com/authorizationService/oauth2/token` and
`.../myphilips`, present in `strings.xml`) — these are account/marketing auth, not a
SenseIQ diagnostics ingest URL. No SenseIQ-diagnostics ingest URL was found in app
resources or code. Confidence: high that no such URL is in the *app*; the firmware holds it.

---

## 6. Residual unknowns and what would unblock them

1. **Diagnostics upload transport + Philips endpoint.** The "every minute / 7 days /
   anonymize+aggregate" behaviour is **UI-string-only** (`strings.xml:1450`); the
   `senseiq_diagnostics` DP is declared but unused by the app. *Unblock:* firmware dump of
   the SCD921 + strings/Ghidra for the ingest URL, **or** a live capture while both consents
   are ON (watch for a periodic POST to a Philips host and/or a `senseiq_diagnostics` DP
   report). Until then, treat the data-path row as text-derived, not wire-proven.
2. **Whether raw video frames ever leave the device to Philips.** Not determinable from the
   app (no frame upload). *Unblock:* same firmware/live-capture path; inspect for any image
   POST distinct from the Tuya media stream.
3. **`sleepiq_status` JSON schema** (breathing-rate field, stage encoding) and the **30-day
   history** source (Tuya statistics service vs Philips vs on-device). Only the `"r"` key is
   known. *Unblock:* live `sleepiq_status` DP-report capture + locate the SenseIQ monitor
   panel `.so`/sub-module.
4. **`sleepiq_area` region semantics** (normalization basis, whether `num`>1 / multiple
   regions are supported, firmware position-scoring). *Unblock:* device DP schema
   (`thing.m.product.info.get`) + a positioning-check capture.
5. **Consent revoke cascade enforcement** (client-only vs server-enforced auto-revoke of
   id 7 when id 5 is cleared). *Unblock:* capture the `dp.publish` calls during a revoke.
6. **Exact DP datatypes / enum ranges.** Inferred from read/write call sites, not from a
   schema dump. *Unblock:* the device DP schema JSON.

---

## Appendix — primary evidence index

- DP enum: `decompiled/jadx/sources/com/thingclips/smart/ka/panel/camera/details/camera/utils/DeviceDpUtil.java:54-81`
- Consent cloud API: `.../details/business/ConsentBusiness.java:115-121`
- Enable-flow / consent writes: `.../details/model/SleepIQSettingModel.java:142,181,243-252`
- Consent toggles + revoke routing: `.../details/model/SleepIQConsentsListModel.java:650-685`; `.../model/SleepIQRevokeConsentModel.java:678,1586,1858`
- Enable / no-signal / status / area read sites: `DeviceDpUtil.java:640,1442,2213,3070-3074,3186-3195,3305,551`
- Positioning box DP: `.../details/model/SleepIQZoneSettingModel.java:298-303,503-510`; bean `.../ipc/panelmore/bean/CameraMotionDesignatedScreenBean.java:6-15`
- Classify key: `.../ka/ipc/messagecenter/consts/SenseIQClassifyKeys.java:11`
- Semantics strings: `decompiled/apktool/res/values/strings.xml:1101,1242,1258-1262,1327,1416,1445-1453,1460-1472,6489,6500-6503,6511`
