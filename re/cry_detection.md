# Cry Detection — `cry_detection_switch` DP + `CRY_SOUND` event (TASK-0091)

Static-RE map of the **on/off AI cry-detection** feature of the Philips Avent Baby
Monitor+ (Tuya-reskin SCD921). This is the *binary* "is there an infant cry, yes/no"
feature — **distinct from Cry Translation** (Zoundream, "why is the baby crying", 5
reasons). The boundary between the two is stated explicitly in §5.

Scope: identify the Tuya DP code + value semantics, the `CameraNotifyModel.ACTION.CRY_SOUND`
event surface, the func/UI wiring, and how a *detected-cry* event reaches the app
(MQTT DP report vs message-center event).

**No secret values appear in this file.** Only DP codes, message-classify keys, string
resource names and (public, build-local) Android resource IDs are recorded — none of
these are credentials or PII. All cites are `path:line` under
`decompiled/jadx/sources/...` (jadx) or `decompiled/apktool/...` (apktool), relative to
the repo root.

> Confidence convention (per project rules): every claim is tagged **high / medium /
> low**. jadx method bodies are peppered with `com.ai.ct.Tz.a()/Tz.b(0)` no-op
> anti-tamper calls — ignore them; the `return`/assignment lines are the real logic.

---

## 1. The DP: `cry_detection_switch` (boolean on/off)

**Confidence: high.** The cry-detection control DP code is the string literal
**`cry_detection_switch`**, returned by the camera-SDK DP operator
`DpCrySoundSwitch`:

- `decompiled/jadx/sources/com/thingclips/smart/camera/devicecontrol/operate/dp/DpCrySoundSwitch.java:68`
  — `f()` returns `"cry_detection_switch"` (the DP code).
- same file `:107` — `g()` returns `CameraNotifyModel.ACTION.CRY_SOUND` (the in-app
  notify action this DP maps to; see §3).
- The class extends `BaseDpOperator`
  (`.../operate/dp/DpCrySoundSwitch.java:8`).

**Value type = bool. Confidence: high.** `BaseDpOperator`'s constructor looks the DP
code up in the device `schemaMap`, reads its `schemaType`, and for `"bool"` wraps it
as a `BoolDpOperateBean`:

- `.../operate/dp/BaseDpOperator.java:31` `String f = f();` (= `cry_detection_switch`)
  → `:37` `schemaMap.get(f)` → `:82-87` `case "bool"` → `:105-106`
  `new BoolDpOperateBean(...)`.
- Corroborated at the func layer: `FuncCrySoundSwitch` reads the DP strictly as a
  `Boolean` — `.../ipc/panelmore/func/FuncCrySoundSwitch.java:96`
  `this.a.x3("cry_detection_switch", Boolean.class) == Boolean.TRUE`.

**Value semantics. Confidence: high.** `TRUE` = cry detection enabled, `FALSE` =
disabled. Evidence: the UI renders a single switch item seeded from the boolean DP
value (`FuncCrySoundSwitch.java:96-98`, `generateSwitchItem(..., z)`), and writes the
boolean straight back on toggle (`FuncCrySoundSwitch.java:285`
`this.a.L3("cry_detection_switch", Boolean.valueOf(z), a(handler))`). There is no
enum/range — it is a plain bool toggle.

### 1b. Second DP code on the product panel: `cry_det_switch` (dpId 12)

**Confidence: high (existence); medium (which one the SCD921 firmware actually uses).**
The Philips/Nightowl *custom* camera panel (`...ka.panel...`, the branded UI) carries a
product-curated `DpCode` enum whose cry entry uses a **different** code string and a
concrete numeric dpId:

- `decompiled/jadx/sources/com/thingclips/smart/ka/panel/camera/details/camera/utils/DeviceDpUtil.java:72`
  — `DP_CRY_DET_SWITCH = new DpCode("DP_CRY_DET_SWITCH", 18, "cry_det_switch", 12)`
  → DP code **`cry_det_switch`**, **dpId 12**.

So the app contains **two** cry-detection DP code strings:
`cry_detection_switch` (generic Tuya camera-SDK operator/func, no dpId baked in) and
`cry_det_switch` dpId 12 (the branded product DpCode table, alongside the real SCD921
DPs `decibel_switch` dpId 139, `motion_switch`, `sleepiq_switch`, etc. at
`DeviceDpUtil.java:60-86`). Which one is present in the live SCD921 device schema cannot
be settled from static code alone — the curated product table strongly suggests
`cry_det_switch`/12 is the real firmware DP, while the Tuya-stock func keys on
`cry_detection_switch`. See §6 (residual unknowns) for how to confirm. `cry_det_switch`
has **no** dedicated `Dp*` operator class (grep finds it only in `DeviceDpUtil`), so its
bool type is inferred from the `*_switch` naming (medium confidence), not from a schema
read.

---

## 2. UI / func wiring (panel "more settings")

**Confidence: high.** The toggle is surfaced by `FuncCrySoundSwitch` (a `DpFunc`) in the
camera "panel more" settings:

- `decompiled/jadx/sources/com/thingclips/smart/ipc/panelmore/func/FuncCrySoundSwitch.java:16`
  — `class FuncCrySoundSwitch extends DpFunc`.
- `:103/:143` — `getId()` returns `"FuncCrySoundSwitch"`.
- `:147-161` — `getNameResId()` returns `R.string.G2` (an obfuscated jadx alias).
  Resolved: `decompiled/jadx/sources/com/thingclips/smart/ipc/camera/ui/R.java:2478`
  `public static int G2 = 0x7f130fbb`, and
  `decompiled/apktool/res/values/public.xml:21024`
  `name="ipc_cry_sound_detected_switch_settings" id="0x7f130fbb"` →
  `decompiled/apktool/res/values/strings.xml:4276`
  `ipc_cry_sound_detected_switch_settings = "Detect Baby Crying"`. So the row label is
  **"Detect Baby Crying"** (confidence: high — alias resolved end-to-end through R.java +
  public.xml).
- `:164-227` — `isSupport()` gating: if the device does **not** support
  `ipc_alarm_ind` but **does** support `decibel_switch` (and `decibel_switch == TRUE`),
  support also requires `querySupportByDPCode("cry_detection_switch")` (`:166-167`);
  otherwise support is purely `querySupportByDPCode("cry_detection_switch")` (`:187`).
  So the cry-detection row only shows when the schema actually carries the DP.
- `:229-289` — `onOperate(...)` writes the new boolean via
  `this.a.L3("cry_detection_switch", Boolean.valueOf(z), a(handler))` (`:285`).

**Operator registration. Confidence: high.** `DpCrySoundSwitch` is registered in the
camera operator manager:
`.../camera/devicecontrol/operate/DpCamOperatorManager.java:788`
`this.b.add(new DpCrySoundSwitch(cameraDeviceBean))`. A convenience boolean getter
exists at `.../operate/DpCamera.java:13398`
`dpCamOperatorManager.t("cry_detection_switch")`.

**Intro/onboarding screen. Confidence: high.**
`decompiled/apktool/res/layout/activity_cry_detection_intro.xml` binds
`@string/mty_cry_alert_title`, `@string/bm_cry_detection_intro` and
`@string/bm_cry_detection_enable`. The intro copy
(`strings.xml:1163`, `bm_cry_detection_intro`) reads: *"Cry Detection is an AI enabled
software that analyses audio streams picked up by your baby unit and identifies whether
they contain an infant cry sound or not. If a cry is detected, you will be notified in
the App."* — confirming the feature is binary detect/no-detect and that detection
results in an **in-App notification** (see §4). `bm_cry_detection_enable` =
"Enable Cry detection" (`strings.xml:1162`).

---

## 3. Event surface: `CameraNotifyModel.ACTION.CRY_SOUND` = the switch STATE, not the alert

**Confidence: high.** `CRY_SOUND` is one member of the camera-SDK notify enum:

- `.../camera/utils/event/model/CameraNotifyModel.java:89` — `CRY_SOUND,` (in `enum ACTION`).

**It carries the switch on/off STATE, via `SUB_ACTION.SET_STATUS`. Confidence: high.**
`BaseDpOperator.d(int)` emits the notify when the DP's value is reported/changed:

- `.../operate/dp/BaseDpOperator.java:256-258`
  `CameraEventSender.g(getDevId(), g(), h(), b(), i)` where
  `g()` = `ACTION.CRY_SOUND` (for this operator), `h()` = `SUB_ACTION.SET_STATUS`
  (`BaseDpOperator.java:830-831`), and `b()` = the current DP value
  (`BaseDpOperator.java:200` `getCurDpValue()`).

**`CRY_SOUND` has exactly one producer and no event-style consumer. Confidence: high.**
A full-tree grep for `CRY_SOUND` returns only two hits: the enum declaration
(`CameraNotifyModel.java:89`) and the producer `DpCrySoundSwitch.g()`
(`DpCrySoundSwitch.java:107`). I.e. nothing in the app treats `ACTION.CRY_SOUND` as a
"a cry just happened" signal — it is purely the **DP-report → UI-state** plumbing that
keeps the toggle in sync with the device. The actual per-event alert goes through the
message center (§4).

So: **MQTT DP report of `cry_detection_switch` → camera SDK → `CameraEventSender` →
`CameraNotifyModel(ACTION.CRY_SOUND, SUB_ACTION.SET_STATUS, value)`** is a *state-sync*
path (toggle reflects firmware state), **not** the cry-alert delivery path.

---

## 4. How a *detected-cry event* reaches the app — message center (`ipc_baby_cry`)

**Confidence: high (the classify key + path); medium (the "type 212" envelope label).**
A real cry-detected alert is delivered as a **Tuya camera message-center message**, not
as a DP report. Its sound-classify key (msgCode) is **`ipc_baby_cry`**:

- `.../ka/ipc/messagecenter/consts/SoundClassifyKeys.java:11-12` —
  `enum SoundClassifyKeys { Sound_detected("ipc_bang"), Cry_detected("ipc_baby_cry") }`.
- `.../ka/ipc/messagecenter/utils/Message212TypeFilterUtils.java:59` —
  `soundKeys = { SoundClassifyKeys.Sound_detected.getKey(), SoundClassifyKeys.Cry_detected.getKey() }`
  (i.e. `{"ipc_bang","ipc_baby_cry"}`). These are matched against
  `CameraMessageClassifyBean.getMsgCode()` (`Message212TypeFilterUtils.java:115` shows the
  `getMsgCode()[0]` comparison pattern).
- `Message212TypeFilterUtils.java:221` — the cry message renders with icon
  `R.drawable.cry_detected_icon` (`Intrinsics.areEqual(classifyKey, SoundClassifyKeys.Cry_detected.getKey()) ? R.drawable.cry_detected_icon ...`).

**Consumers / surface. Confidence: high.** `SoundClassifyKeys` is referenced by the
message-center UI + presenters:
`.../ka/ipc/messagecenter/activity/NIPCCameraMessageCenterActivity.java`,
`.../ka/ipc/messagecenter/presenter/CameraMoreMotionPresenter.java`,
`.../ka/ipc/messagecenter/utils/Message212TypeFilterUtils.java` (grep `SoundClassifyKeys`).

**"212" caveat. Confidence: medium.** The filter class is named
`Message212TypeFilterUtils` — "212" is Tuya's standard message-center *message type* for
device alarm/notification messages, and this util classifies type-212 messages by their
`msgCode`. I did **not** extract a numeric `212` literal from `MessageConstant.java`
(it lists the *string* sub-type codes such as `ipc_motion`, `ipc_doorbell`, etc. at
`.../ipc/messagecenter/MessageConstant.java:14-23`); the "212" is the well-known Tuya
convention encoded in the class name, not a constant I read. Treat "type 212" as the
likely transport category, with the *classify key* `ipc_baby_cry` being the high-confidence
identifier of a cry alert.

**Net answer to "DP report vs message-center event":**
- **Switch STATE** (enabled/disabled) → **MQTT DP report** of `cry_detection_switch`
  (or `cry_det_switch`/12), surfaced in-app as `ACTION.CRY_SOUND` / `SUB_ACTION.SET_STATUS`.
- **Detection EVENT** ("a cry was heard, notify me") → **message-center message**
  with sound-classify key `ipc_baby_cry` (Tuya type-212 alarm), shown in the message
  center / as a push notification. This matches the intro copy "you will be notified in
  the App" (§2).

---

## 5. Boundary with Cry Translation (Zoundream) — explicit

**Confidence: high.** Cry *Detection* and Cry *Translation* are two separate features:

| | Cry **Detection** (this doc) | Cry **Translation** (Zoundream) |
|---|---|---|
| Question | "is this an infant cry? yes/no" | "*why* is the baby crying?" (5 reasons) |
| DP code(s) | `cry_detection_switch` (SDK func); `cry_det_switch` dpId 12 (product table) | `cry_trans_switch` dpId 2; `cry_trans_token` dpId 17; `cry_trans_subscr` dpId 14 |
| DP refs | `DpCrySoundSwitch.java:68`; `DeviceDpUtil.java:72` | `DeviceDpUtil.java:73,76,77` |
| In-app notify | `ACTION.CRY_SOUND` (state only) | (separate cry-translation flow) |
| Message keys | `SoundClassifyKeys.Cry_detected = "ipc_baby_cry"` (`SoundClassifyKeys.java:12`) | `CryTranslationClassifyKeys`: `sleep`→`ipc_passby`, `hungry`→`ipc_linger`, `uncomfortable`→`ipc_antibreak`, `burp`→`ipc_custom`, `pain`→`ipc_io_alarm`, plus `no_cry`→`ipc_dev_link`, `license_expired*` (`CryTranslationClassifyKeys.java:49-56`) |
| Subscription | none (free, on-device) | license/subscription: `cry_trans_subscr` DP + `license_expired*` message keys |
| Strings | `bm_cry_detection_intro/enable`, `ipc_cry_sound_detected_switch_settings` ("Detect Baby Crying") | `mty_cry_*` family, e.g. `mty_cry_trans_cry_definitions` = "The 5 types of identifiable cries" (`strings.xml:6077`) |
| Layout | `res/layout/activity_cry_detection_intro.xml` | `res/layout/fragment_cry_definition.xml` (uses `@string/mty_cry_sleepy` etc.), `activity_cry_trans_*.xml` |

Note on the start-from layout `fragment_cry_definition.xml`: despite the "cry" name it
binds `mty_cry_*` strings (`@string/mty_cry_sleepy`, `@string/mty_cry_possible_res`,
`@string/mty_keep_in_mind`) — it is part of the **Cry Translation** UI (the "5 types of
identifiable cries" explainer), **not** cry detection. The cry-detection intro is
`activity_cry_detection_intro.xml`. The two features share the `mty_cry_alert_title`
string and a similar visual style, which is the likely source of confusion.

---

## 6. Residual unknowns (and what would unblock them)

1. **Which DP string is the live SCD921 firmware DP — `cry_detection_switch` vs
   `cry_det_switch` (dpId 12)?** Confidence the product uses `cry_det_switch`/12:
   *medium* (it is in the curated product `DpCode` table next to the known real DPs).
   *Unblock:* the device schema JSON (`cameraDeviceBean.getSchemaMap()` /
   `dpName/dpId` map) or a captured DP-report frame for this product. Anonymized
   schema/DP samples would live under `secrets/` — do not inline values.
2. **`cry_det_switch` value type.** Assumed bool from naming only; no schema/operator
   read confirms it. *Unblock:* same device schema as (1).
3. **Exact wire envelope of the `ipc_baby_cry` message-center alarm.** The classify key
   is solid (`ipc_baby_cry`), but the JSON payload shape (timestamp, attach/snapshot,
   `msgType` numeric, link fields) was not captured statically; the "212" is inferred
   from the class name. *Unblock:* a captured type-212 camera message (message-center
   list API or the MQTT alarm push) from the live/emulator capture pipeline — anonymize
   devId/uid before committing.
4. **Whether the firmware ever pulses `cry_detection_switch` as a momentary event vs
   only as a persistent toggle.** The only notify wiring observed is `SET_STATUS`
   (state), which argues that detection events travel via the message center, not the
   DP — but a DP-report capture during an actual cry would settle it definitively.
   *Unblock:* live DP-report trace.
