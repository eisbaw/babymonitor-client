# Cry Translation — Zoundream third-party cloud subscription (TASK-0092)

How the Philips Avent Baby Monitor+ exposes the paid **Cry Translation** feature, which
is powered by the third-party vendor **Zoundream**. This is a *static-analysis* writeup of
the app's integration surface: what the app forwards, the result/classify schema, and the
subscription/account-management entrypoints. Method: grep of `decompiled/jadx/sources` (DEX
→ jadx) and `decompiled/jadx/resources` (apktool/jadx resources). No live capture was used
for this task.

> Citation note: cites name a **symbol** (class / method / enum / DP code / string name).
> Any `File.java:NN` line is an **approximate hint** for the current `just decompile` tree —
> jadx line numbers drift, so grep the symbol. `decompiled/...` paths resolve only after a
> local `just decompile` (gitignored; never committed). The Kotlin source is obfuscated with
> `com.ai.ct.Tz.a()/b(0)` no-op control-flow noise — ignore those lines.

> Secret rule: the production Zoundream API secret is **not** an inlined value below. It is
> fetched at runtime from remote Tangram config (`nightowl:zdSecret`) and is not present in
> the APK. The hardcoded *testing-environment* placeholder at `ZoundreamSecretProvider.java:11`
> is deliberately **not reproduced** here. Any secret/token/account-id recovered at runtime
> must live under `secrets/` only and be referenced by path — never inlined into this file.

---

## VERDICT

**Two distinct features share the word "cry" and must not be conflated:**

1. **Cry *Detection*** — on-device (baby-unit) AI that decides *cry vs no-cry* and notifies
   the app. Processed by **Philips/Tuya**, gated by DP `cry_det_switch`. No Zoundream, no
   subscription. (confidence: high)
2. **Cry *Translation*** — the paid **Zoundream** feature that interprets *why* the baby is
   crying (sleep / hungry / uncomfortable / burp / pain). Gated by DP `cry_trans_switch`,
   unlocked by a subscription token written to the baby unit. (confidence: high)

**The app itself never captures or forwards cry audio.** There is **zero** audio / record /
microphone / upload code anywhere in the cry package (verified: a grep for
`audio|record|\.pcm|upload|microphone|\.wav` across
`…/details/activity/cry/` returns nothing). Audio forwarding happens **baby-unit → Zoundream
cloud directly**, authorised by the app writing a subscription *token* DP to the device. The
app's role is purely (a) a WebView that hosts Zoundream's subscription/account web pages and
(b) a DP courier that mirrors subscription state + token onto the camera. (confidence: high
for "app does not forward audio"; medium for the exact camera↔Zoundream transport, which is
firmware-side and not statically visible — see Residual unknowns.)

The user-facing consent string states this plainly
(`strings.xml` → `bm_cry_trans_about_service_text2`): *"when you use this feature you direct
Philips to connect your Baby Unit to Zoundream's cloud in order to enable you to share your
baby's sound data with Zoundream."*

---

## 1. Detection (on-device DP) vs Translation (cloud) — the DP map

`DeviceDpUtil$DpCode` enumerates the cry DPs (`DeviceDpUtil.java:72-79`). DP **code** is the
Tuya DP identifier string; DP **id** is the numeric Tuya datapoint id:

| DP code (string)   | DP id | Symbol                | Role | Feature |
|--------------------|:-----:|-----------------------|------|---------|
| `cry_det_switch`   | 12    | `DP_CRY_DET_SWITCH`   | enable on-device cry detection | Detection (Philips) |
| `cry_trans_switch` | 2     | `DP_CRY_TRANS_SWITCH` | enable cry translation / data-to-Zoundream | Translation (Zoundream) |
| `cry_trans_token`  | 17    | `CRY_TRANS_TOKEN`     | subscription/auth token written **to** the baby unit | Translation |
| `cry_trans_subscr` | 14    | `CRY_TRANS_SUBSCR`    | JSON subscription-status mirrored **to** the baby unit | Translation |

(confidence: high — these are literal enum entries, `DeviceDpUtil.java:72,73,78,79`.)

- Detection framing (Philips, baby-unit AI, 30-day retention) is the `bm_cry_detection_intro`
  string; the toggle is `DeviceDpUtil.M(...)` → `publishDps(DP_CRY_DET_SWITCH …)`
  (`DeviceDpUtil.java:1983`).
- Translation toggle writes `DP_CRY_TRANS_SWITCH` (`DeviceDpUtil.java:2024`). The
  notifications-off copy confirms the data destination: *"When you turn this toggle off, we
  will stop sending data to Zoundream™"* (`bm_cry_translation_notifications_content`).

---

## 2. Audio-forwarding / activation path (AC #1)

The activation handshake is **token-over-DP**, not audio-over-app:

1. The app opens a Tuya WebView (`CryTranslationActivity`) pointed at a Zoundream subscription
   URL (§5). The exposed JS bridge object is named **`cryTranslation`**
   (`CryTranslationJSComponent.getName()` → `"cryTranslation"`, `CryTranslationJSComponent.java:2793`).
2. The Zoundream web page calls back into the native bridge `@JavascriptInterface`
   `subscriptionStatus(data, handler)` (`CryTranslationJSComponent.java:3271-3303`) with a JSON
   blob. On a `token` field present, the app calls `sendToken(...)`
   (`CryTranslationJSComponent.java:2213-2378`), which does
   `publishDps(CRY_TRANS_TOKEN.getDpCode(), token, …)` — i.e. writes the Zoundream token to DP
   id 17 on the camera.
3. In parallel it writes subscription state via `sendSubscriptionStatus(...)` →
   `DeviceDpUtil.G(...)` → `publishDps(CRY_TRANS_SUBSCR …)` (`DeviceDpUtil.java:1066`).
4. After writing the token the app registers a device listener and waits for the camera to
   echo back DP id 17 (`registerDevListener` checks `DpCode.CRY_TRANS_TOKEN.getDpId()` == 17 in
   the incoming `onDpUpdate` payload, `CryTranslationJSComponent.java:1602-1606`), then shows
   the "activate success" page. The log line *"querySubscription publish 17 success"*
   (`QueryZdHandler.java:295`) corroborates dp-id 17 == token.

**Conclusion (AC #1, audio path):** the *baby unit* — once it holds the Zoundream token — is
what streams the baby's sound to Zoundream's cloud. The phone app forwards **no audio**; it
forwards a *token* + *subscription JSON* via Tuya DPs and renders results that come back as
push notifications (§4). The exact camera↔Zoundream wire protocol is firmware-side and out of
this APK's view. (confidence: high for the DP courier role; medium for "camera streams audio
directly", which rests on the consent string + the absence of any app-side audio code.)

---

## 3. Result / classify schema (AC #1)

### 3.1 `CryTranslationClassifyKeys` — result categories on the wire

`CryTranslationClassifyKeys` (an obfuscated Kotlin enum,
`…/ka/ipc/messagecenter/consts/CryTranslationClassifyKeys.java:49-58`) maps each result
*category* to a **reused generic Tuya IPC message-type string** (`getKey()`). Philips
overloaded the camera message-center taxonomy to carry Zoundream results:

| Enum constant               | `getKey()` wire string | Meaning |
|-----------------------------|------------------------|---------|
| `no_cry`                    | `ipc_dev_link`         | no cry / negative result |
| `sleep`                     | `ipc_passby`           | baby is sleepy |
| `hungry`                    | `ipc_linger`           | baby is hungry |
| `uncomfortable`             | `ipc_antibreak`        | baby is uncomfortable |
| `burp`                      | `ipc_custom`           | baby needs to burp |
| `pain`                      | `ipc_io_alarm`         | baby is in pain / irritated |
| `license_expired`          | `ipc_low_battery`      | subscription expired |
| `license_expired_in_7_days`| `ipc_full_battery`     | subscription expiring < 7 days |
| `license_expired_in_1_day` | `ipc_io_alarm_2`       | subscription expiring < 1 day |
| `Crying_is_translating`     | `ipc_connected`        | transient "analysing…" state |

The three `ipc_*` literals resolve via `MessageConstant.CameraMessageType`
(`MessageConstant.java:15,19,21`: `CONNECTED="ipc_connected"`, `LINGER="ipc_linger"`,
`PASSBY="ipc_passby"`). (confidence: high — literal enum + constant values.)

### 3.2 Result delivery channel — message-center "212" family

Results are delivered as **Tuya camera message-center push notifications**, not via a direct
Zoundream API call from the phone. `Message212TypeFilterUtils.cryTranslationKeys`
(`Message212TypeFilterUtils.java:46-58`) is exactly the 10 keys above, grouping them into the
"212" classify message family for the message list. `MessageCenterApp`
(`MessageCenterApp.java:23-42`) translates an incoming classify-key string into a
`CryReasonsType` and routes it to `NCryTransReasonsActivity` (`intent.putExtra("cryType", …)`):

- `ipc_passby`→`sleepy`, `ipc_linger`→`hungry`, `ipc_io_alarm`(pain)→`irritated`,
  `ipc_antibreak`→`uncomfortable`, `ipc_custom`→`burp`
  (`CryReasonsType` enum: `uncomfortable, irritated, burp, hungry, sleepy`,
  `CryReasonsType.java:9-14`).
- The three `license_expired*` keys branch to a subscription-expiry path
  (`MessageCenterApp.java:42`).

Note: `CryReasonsType` (5 display buckets) collapses `pain`→`irritated` and omits `no_cry`;
`CryTranslationClassifyKeys` (10) is the richer wire vocabulary. (confidence: high.)

### 3.3 Subscription-status JSON schema (web → app → device)

Two beans define the JSON contract. The **web→app** payload is `ZounDreamQueryStatusBean`
(`ZounDreamQueryStatusBean.java:556-565`):

```
{ token, type, status, start(Long), days_left(Int), days_total(Int),
  logged_in(Bool), next_billing(Long) }
```

The reduced **app→device** payload (written to DP `cry_trans_subscr`) is
`CryTranslationStatusBean` (`CryTranslationStatusBean.java:342-348`):

```
{ type, status, start(Long), days_left(Int), days_total(Int) }
```

Built in `DeviceDpUtil.G(...)` from the inbound JSON keys `status`/`type`/`start`/`days_left`/
`days_total` (`DeviceDpUtil.java:1054-1066`). The reverse — the app probing the web page for
status — is `QueryZdHandler.b(...)` calling JS method `cryTranslation.querySubscription`
(`QueryZdHandler.java:415-423`), seeded with `ZoundreamUtils.a(devId)` which sends
`{uuid, BUName, refurbishCount}` (`ZoundreamUtils.java:84-98`; same shape as the JS-bridge
`identifyDevice` reply, `CryTranslationJSComponent.java:2919-2924`). (confidence: high — literal
constructors and `JSONObject.getString("…")` calls.)

---

## 4. JS-bridge contract (`cryTranslation` namespace)

The native↔web contract (`CryTranslationJSComponent`, an `addJavascriptInterface` object whose
name is `cryTranslation`, registered at `ContainerInstance.java:3671`):

- **web → app (`@JavascriptInterface`):**
  - `identifyDevice(msg, handler)` → returns `{uuid, BUName, refurbishCount}`
    (`CryTranslationJSComponent.java:2885-2924`).
  - `subscriptionStatus(data, handler)` → consumes `{reason, status, token, type,
    associated_devices[]}` (`CryTranslationJSComponent.java:3271-3303`). `reason` is matched
    against `CallingReason` (§6); `token` triggers the DP-17 write; `account_deleted` routes to
    `sendEndSubscriptionStatus` which reads `associated_devices` (an array of camera uuids) and
    fans the clear-out via `UuidConvertUtils` (`CryTranslationJSComponent.java:1789-1799`).
- **app → web (`webView.u(...)` / dsbridge call):**
  - `cryTranslation.querySubscription` — invoked on page-finish for any `*zoundream*` URL
    (`CryTranslationJSComponent$urlActiveListener$1.java:417,435-438`) and by `QueryZdHandler`.

(confidence: high.)

---

## 5. Subscription / account-management entrypoints (AC #2)

### 5.1 Web endpoints (public URLs, environment + region selected)

`ZoundreamUriProvider` (`ZoundreamUriProvider.java`) picks the subscription web URL by an MMKV
int `zdEnv` (0=prod, 1/2/3=stage/test variants) and by the user's region
(`g()` → `user.getDomain().getRegionCode()`; `AZ`=US, `IN`=India, else EU). These are the
string-resource URLs (public Zoundream web app, **not secrets**), e.g.
`bm_cry_translation_dev_link*`, `bm_cry_translation_test_link*`,
`bm_cry_translation_stage_us_link*` → hosts under `*.zoundream.app`
(`subscription-eu.zoundream.app`, `subscription.us.zoundream.app`, etc.). The "manage account"
and "about service" deep-links are `ZoundreamUriProvider.c/e` and `bm_cry_trans_link_*` /
`bm_cry_trans_privacy_notice_link_*`. (confidence: high.)

The app-side UI entrypoints (the activities/fragments) are:
`CryTranslationActivity` (WebView host), `CryTransIntroActivity` /
`activity_cry_trans_intro.xml`, `CryDetectionIntroActivity`, `CryTransExplanationActivity`,
`CryTransActivateSuccessActivity` / `activity_cry_trans_activate_success.xml`,
`CryAboutServiceActivity`, `ZDIntroActivity`, and the state fragments
`CryTranslation{NotActive,Active,Cancel,Ended}Fragment` (+ `fragment_cry_translation_first_use.xml`).
The account-management labels are `bm_cry_trans_manage` ("Manage Zoundream account"),
`bm_cry_trans_zd_account` ("Zoundream account"), `bm_cry_trans_monthly_subs` ("Subscription"),
`bm_cry_trans_end_again_subs` ("Reactivate subscription"), `bm_cry_trans_next_payment`,
`bm_cry_trans_welcome_tip1` ("3 month free period") and `bm_cry_trans_tip_no_pay`
("no payment or credit card information"). (confidence: high — literal string names.)

### 5.2 Auth surface (how the WebView authenticates to Zoundream)

When the loaded URL contains `zoundream`, `ContainerInstance` injects an HTTP **`Authorization`**
header equal to `ZoundreamSecretProvider.a()` plus Tuya context (`Referer`, `thing-extra-info`,
and `thing-area-code`/`countryCode` cookies) before `loadUrl`
(`ContainerInstance.java:2672-2687`). `ZoundreamSecretProvider.a()`
(`ZoundreamSecretProvider.java:11`) returns the production secret from remote Tangram config
path **`nightowl:zdSecret`**, except in the testing env (`zdEnv==2`) where it returns a
hardcoded non-production placeholder string (value intentionally **not reproduced here** per
the secret rule). The `*zoundream*` host is allow-listed for bridge/cookie injection in
`WhiteListDataManageUtils` (`.*zoundream.*`, `WhiteListDataManageUtils.java:112`).

**Identifier handling:** the only device identifiers crossing the bridge are the camera `uuid`
(Tuya device uuid) and `BUName`/`refurbishCount`, plus the Tuya user `regionCode`/`phoneCode`
in cookies, and the Zoundream `token`. None are inlined in this doc; if any are recovered from
a live run they belong under `secrets/` only. (confidence: high.)

### 5.3 `CallingReason` — lifecycle signals from the web page

`subscriptionStatus.reason` is one of `CallingReason` (`CallingReason.java:11-16`):
`account_created`, `account_deleted`, `subscription_activated`, `subscription_canceled`,
`logged_in`, `logged_out`. App behaviour: `logged_out` → exit the translation page;
`account_deleted` → clear device subscription DPs; `account_created` → no-op
(`CryTranslationJSComponent.java:3284-3298`). (confidence: high.)

---

## 6. Residual unknowns (what static analysis cannot settle)

- **Camera↔Zoundream wire protocol.** The transport/format the baby unit uses to send audio to
  Zoundream's cloud, and how it presents the token, are firmware-side and **not in this APK**.
  Unblock: a packet capture from the baby unit's uplink, or baby-unit firmware. (confidence of
  the gap: high.)
- **Where the classify results originate.** We see results arrive as message-center "212"
  notifications keyed by `ipc_*` strings, but whether the classification is computed in
  Zoundream's cloud and pushed back via Tuya's notification pipeline (most likely) vs computed
  on the baby unit is not provable from the app alone. Unblock: a live MQTT/notification capture
  while a subscription is active. (confidence of the gap: high.)
- **Exact JSON the Zoundream web page POSTs to its own backend.** That lives in the remote web
  bundle loaded into the WebView, not in the APK; only the native-bridge surface (§4) is
  recoverable statically. Unblock: capture the WebView's network traffic.
- **`nightowl:zdSecret` production value & its semantics.** Whether the `Authorization` value is
  a static shared secret, a signing key, or a bearer token is not determinable statically (it is
  a remote-config string consumed only as an opaque header). Unblock: read the live Tangram
  config value (→ `secrets/`) and observe the header on the wire.
- **`type` field vocabulary.** `subscriptionStatus.type` / `status` strings (e.g. trial vs
  monthly) are passed through opaquely; their enumerated values are defined by Zoundream's web
  app, not the APK. Unblock: live capture of a real `subscriptionStatus` payload (anonymise
  before committing).
</content>
</invoke>
