# Family sharing & role permissions — Admin vs Guest (TASK-0105)

Static RE of multi-user sharing in the Philips Avent Baby Monitor+ app. The app is a
white-labeled **Tuya Smart** camera client, so sharing is implemented entirely by the Tuya
home/member/share SDK; Philips contributes only the **panel copy** (the human-readable
Admin-vs-Guest capability table in `res/values/strings.xml`) and the device-model branding.

All paths below are under `decompiled/jadx/sources/` (Java/Kotlin from jadx) or
`decompiled/apktool/` (resources from apktool) unless noted. jadx output is control-flow
obfuscated with `com.ai.ct.Tz` no-op calls (`Tz.a()` / `Tz.b(0)`); these are dead
instrumentation — ignore them. Class/field/method names in the `com.thingclips.smart.home.sdk`
interfaces are **not** obfuscated; they are public SDK API and match Tuya's published symbols.

**Secret hygiene:** no `uid` / `homeId` / `memberId` / `account` / email / device `productId`
(PID) value is inlined here. PID strings exist in `strings.xml` but are referenced by resource
**name + line** only; real per-account identifiers live under `secrets/` and are never quoted.

---

## 0. TL;DR — two distinct sharing mechanisms — **HIGH**

The Tuya SDK exposes **two separate, independent** ways to give another account access. The
Philips "Admin / Guest" UI is a skin over both:

| Mechanism | SDK entry | Data model | Granularity | Maps to Philips term |
|-----------|-----------|------------|-------------|----------------------|
| **Home membership** | `IThingHomeMember` | `MemberBean` (`role`/`admin`/`customRole`) | role-graded (owner/admin/member/custom) | **Admin** = `ROLE_ADMIN`; **Guest** ≈ `ROLE_MEMBER` |
| **Device share** | `IThingHomeDeviceShare` | `SharedUserInfoBean` / `DeviceShareBean` | flat, per-device, view-oriented (no role field) | **Guest** = a device-share recipient |

Key structural finding: a **device share carries no role/permission field** (see §5) — it is a
flat "this account may view this device" grant. Role gradation (Admin vs Guest capability
differences) lives on the **home-member** side via the integer `role` / boolean `admin` /
`CustomRoleBean`. So "Guest" is realized either as a low-privilege *home member* or as a
*device-share recipient*; "Admin" is always a home member with `ROLE_ADMIN`. The exact runtime
binding of the Philips "Guest" button to one-or-the-other is **not** statically resolvable (the
panel that drives it is a runtime-downloaded RN bundle; see §7 / Residual unknowns).

---

## 1. The role model — `MemberRole` + `MemberStatus` — **HIGH**

`com/thingclips/smart/home/sdk/anntation/MemberRole.java:11-17` (an `@IntDef`-style constant
holder, `RetentionPolicy.SOURCE`):

| Constant | Value | Meaning |
|----------|-------|---------|
| `ROLE_OWNER` | `2` | home creator / full owner (can `transferOwner`) |
| `ROLE_ADMIN` | `1` | **Admin** — full control |
| `ROLE_MEMBER` | `0` | ordinary member ≈ **Guest** baseline |
| `ROLE_CUSTOM` | `-1` | custom role; capabilities come from a `CustomRoleBean` |
| `INVALID_ROLE` | `-999` | sentinel "no role chosen" (builder default) |

Invitation lifecycle `com/thingclips/smart/home/sdk/anntation/MemberStatus.java:4-8`:
`WAITING=1`, `ACCEPT=2`, `REJECT=3`, `INVALID=4`. `MemberBean.memberStatus` is annotated
`@MemberStatus`, so a member row tracks pending/accepted/rejected/expired invite state.

> Confidence: HIGH — these are literal constants in unobfuscated SDK annotation classes.

---

## 2. Member data model — `MemberBean` / `MemberWrapperBean` / `CustomRoleBean` — **HIGH**

`com/thingclips/smart/home/sdk/bean/MemberBean.java` (fields at lines 8-19):

- `boolean admin` — `isAdmin()` at line 561 (the simple Admin/not-Admin flag the UI gates on).
- `int role` — `getRole()` at line 489 (the `MemberRole` value).
- `CustomRoleBean customRole` — `getCustomRole()` line 89 (present only when `role == ROLE_CUSTOM`).
- `int memberStatus` (`@MemberStatus`), plus identity fields `uid`, `account`, `homeId`,
  `memberId`, `nickName`, `headPic`. (Identity values are PII — not reproduced.)

`com/thingclips/smart/home/sdk/bean/MemberWrapperBean.java` — the **write** model (builder) used
by `addMember(MemberWrapperBean, …)` / `updateMember(MemberWrapperBean, …)`. Builder fields
(lines 26-37): `admin`, `role` (default `MemberRole.INVALID_ROLE`, line 36), `customRoleId`
(`@Nullable Long`, line 30), `autoAccept` (line 29 — auto-accept invite), `invitationCode`,
`countryCode`, `account`, `uid`, `homeId`, `memberId`, `nickName`, `headPic`. Constructed at
lines 975-988.

Fine-grained custom roles `com/thingclips/smart/home/sdk/bean/CustomRoleBean.java:7-13`:

- `long roleId`, `String roleName`, `List<RoleResourceBean> resourceList`.
- inner `RoleResourceBean` (lines 13-14): `String resId`, `int resType` — a
  resource-id + resource-type pair. This is Tuya's **resource-based ACL**: a custom role is a
  list of `(resType, resId)` grants. The integer meaning of `resType` is **not** defined in any
  decompiled bean (see Residual unknowns).

`com/thingclips/smart/family/bean/HomeRoleInfoBean.java:8-10` describes a home's available roles:
`int roleCreateLimit` (max custom roles), `List<CustomRoleBean> roleList`.

> Confidence: HIGH for the field shapes (plain POJOs). The semantics of `resType` is LOW.

---

## 3. Member-management API surface — `IThingHomeMember` — **HIGH**

`com/thingclips/smart/home/sdk/api/IThingHomeMember.java`. Obtained at runtime via the SDK
factory `ThingHomeSdk.getMemberInstance()` (`com/thingclips/smart/home/sdk/ThingHomeSdk.java:1162`).
Selected entrypoints (line numbers in the interface file):

| Method | Line | Purpose |
|--------|------|---------|
| `addMember(MemberWrapperBean, IThingDataCallback<MemberBean>)` | 21 | invite/add a home member with a role |
| `addMember(long homeId, String, String, String, boolean admin, …)` | 19 | legacy add-member with `admin` flag |
| `addMemberAccount(long homeId, String account, String, int role, …)` | 23-27 | add by account (3 overloads; one takes `role:int`) |
| `updateMember(MemberWrapperBean, IResultCallback)` | 65 | update a member (role/name/admin) |
| `updateMemberRole(long memberId, boolean isAdmin, …)` | **69** | **flip a member between Admin and not-Admin** |
| `updateMemberName(long memberId, String, …)` | 67 | rename member |
| `removeMember(long memberId, IResultCallback)` | 51 | revoke membership |
| `transferOwner(long homeId, long memberId, …)` | 57 | hand over `ROLE_OWNER` |
| `queryMemberList(long homeId, IThingGetMemberListCallback)` | 47 | list members (for the "Admin/Guest" roster) |
| `processInvitation(long, boolean accept, …)` | 45 | accept/decline an invite |
| `getInvitationMessage(long homeId, …)` / `getInvitationList(long, …)` | 37-41 | issue/list invitation codes |
| `cancelMemberInvitationCode(long, …)` / `reInviteMember(long, …)` | 29 / 49 | revoke / re-send invite |
| `updateInvitedMember(long, String, int role, …)` | 59-61 | change a pending invitee's role |
| `getAuthRoomList` / `saveAuthRoomList` (lines 31 / 53) | | per-member **room** scoping |
| `getAuthSceneList` / `saveAuthSceneList` (lines 33 / 55) | | per-member **scene** scoping |
| `getMemberDeviceList(long, …)` | 43 | devices visible to a member |
| `uploadMemberAvatar(String, File, …)` | 71 | member avatar |

The **role-change choke point** is `updateMemberRole(memberId, isAdmin, cb)` (line 69): the
boolean directly toggles Admin. Room/scene `saveAuth*` calls show membership can be scoped to a
subset of rooms/scenes — a finer mechanism than the binary Admin/Guest the Philips UI exposes.

> Confidence: HIGH — these are declared methods in the unobfuscated public interface.

---

## 4. Device-share / invite API surface — `IThingHomeDeviceShare` — **HIGH**

`com/thingclips/smart/home/sdk/api/IThingHomeDeviceShare.java`. Obtained via
`ThingHomeSdk.getDeviceShareInstance()` (`ThingHomeSdk.java:677`), which resolves an
`IThingDeviceSharePlugin` through `PluginManager` (line 678).

| Method | Line | Purpose |
|--------|------|---------|
| `addShare(long homeId, String countryCode, String account, ShareIdBean, boolean, IThingResultCallback<SharedUserInfoBean>)` | 13 | share device(s) to an account (by `ShareIdBean`) |
| `addShareWithHomeId(long, String countryCode, String account, List<String> devIds, …)` | 17 | share a device list to an account |
| `addShareWithMemberId(long, List<String> devIds, IResultCallback)` | 19 | share devices to an existing member |
| `addShareUserForGroup(long, String, String, long, …)` | 15 | share a group |
| `inviteShare(String countryCode, String account, String, IThingResultCallback<Integer>)` | 32 | create an invite; callback returns an invite id (Integer) |
| `confirmShareInviteShare(int, IResultCallback)` | 21 | accept an invite by id |
| `queryDevShareUserList(String devId, IThingResultCallback<List<SharedUserInfoBean>>)` | 36 | list who a device is shared with |
| `queryUserShareList(long, …)` / `queryShareReceivedUserList(…)` | 44 / 42 | shares I sent / shares I received |
| `queryShareDevFromInfo(String devId, …)` / `getReceivedShareInfo(long, …)` / `getUserShareInfo(long, …)` | 40 / 28 / 30 | share detail lookups |
| `removeUserShare(long, …)` / `removeReceivedUserShare(long, …)` / `removeReceivedDevShare(String, …)` | 52 / 50 / 48 | revoke shares (sender / receiver / by device) |
| `removeGroupShare(long, long, …)` | 46 | revoke group share |
| `renameShareNickname(long, String, …)` / `renameReceivedShareNickname(long, String, …)` | 56 / 54 | rename a share |
| `disableDevShare(String, long, …)` | 23 | disable a device share |
| `enableDevShare(String, long, …)` `@Deprecated` | 26 | (deprecated) enable |

**Concrete caller in the camera panel** —
`com/thingclips/smart/camera/sharedevice/biz/DefaultDeviceShareUseCase.java` holds the share
instance (`IThingHomeDeviceShare c;` line 24) and invokes:
- `addShareWithHomeId(...)` at **line 2315** and **line 3051**,
- `addShare(homeId, countryCode, account, shareIdBean, z, cb)` at **line 2864**.

This is the device-share flow the SCD921/923 camera panel actually drives (share the camera to
another account → that account becomes a view-oriented "Guest").

> Confidence: HIGH for the declared API and the camera-panel call sites. The semantics of the
> trailing `boolean` in `addShare` and the 3rd `String` of `inviteShare` are **not** annotated in
> the interface (LOW; impl is in a not-fully-decompiled plugin dex).

---

## 5. Share record model — `SharedUserInfoBean` / `DeviceShareBean` — **HIGH**

`com/thingclips/smart/home/sdk/bean/SharedUserInfoBean.java` (fields lines 7-14): `headPic`,
`homeId`, `iconUrl`, `memeberId` [sic], `mobile`, `remarkName`, `userAccount`, `userName`.
**There is no `role`, `admin`, or `permission` field** — confirming a device share is a flat
grant, not a graded one (see §0).

`com/thingclips/smart/home/sdk/bean/DeviceShareBean.java` (fields lines 7-13): `devId`,
`deviceName`, `homeName`, `iconUrl`, `room`, `boolean share`, `boolean tempShare`. The
`tempShare` flag marks a **temporary** share — a time-boxed Guest grant distinct from a
permanent one.

> Confidence: HIGH (plain POJOs). The duration/expiry tied to `tempShare` is not in the bean.

---

## 6. Admin-vs-Guest capability matrix (Philips panel copy) — **HIGH (text) / MEDIUM (binding)**

Philips ships the user-facing capability comparison as **localized strings** in
`decompiled/apktool/res/values/strings.xml`. The string-name grammar is
`bm_<model>_<role>_<category>_content`, where:

- `<model>` ∈ { `family`, `ecoowl`, `no1_owl`, `no2` } (four device-family variants present),
- `<role>` ∈ { `admin`, `guest` },
- `<category>` ∈ { `account_management`, `alerts_notifications`, `monitor`, `soothing_features` }.

Category headers and labels: `bm_account_management` = "Account management" (line 1049),
`bm_alerts_notifications` = "Alerts notifications" (1106), `bm_monitoring` = "Monitoring" (1328),
`bm_soothing_features` = "Soothing features" (1511), `bm_up_admin` = "Admin" (1535),
`bm_up_guest` = "Guest" (1536), `bm_add_admin_user` = "Add an admin user" (1099),
`bm_give_full_access` = "Looking to give full access?" (1276),
`bm_learn_more_user_limits_tips` = "about the differences between guest and admin" (~1290).

### 6a. `bm_family_*` variant (SenseIQ-capable; strings.xml:1265-1272)

| Category | **Admin** | **Guest** |
|----------|-----------|-----------|
| Account management | Admin user invitation, guest user invitation | **NA** |
| Alerts & notifications | Sound, motion, temperature and cry detection, SenseIQ, Cry translation | **NA** |
| Monitor | Video, audio, SenseIQ, Cry translation, temperature, background monitoring, snapshot and video recording | Video, audio, background monitoring, *other features differ based on device model* |
| Soothing features | Nightlight, soothing sounds, lullabies, true talk-back, voice recording | *Differs based on device model* |

### 6b. `bm_no2_*` variant (SenseIQ-capable; strings.xml:1389-1396)

| Category | **Admin** | **Guest** |
|----------|-----------|-----------|
| Account management | Admin user invitation, guest user invitation | **NA** |
| Alerts & notifications | Sound, motion, temperature and cry detection, SenseIQ, Cry translation | **NA** |
| Monitor | Video, audio, SenseIQ, Cry translation, temperature, background monitoring, snapshot and video recording | Video, audio, background monitoring |
| Soothing features | Nightlight, soothing sounds, lullabies, true talk-back, voice recording | **NA** |

### 6c. `bm_ecoowl_*` variant (no SenseIQ; strings.xml:1249-1256)

| Category | **Admin** | **Guest** |
|----------|-----------|-----------|
| Account management | Admin user invitation, guest user invitation | **NA** |
| Alerts & notifications | Sound, motion, temperature | **NA** |
| Monitor | Video, audio, temperature, background monitoring, snapshot and video recording | Video, audio, background monitoring |
| Soothing features | Nightlight, soothing sounds, lullabies, true talk-back, voice recording | **NA** |

### 6d. `bm_no1_owl_*` variant (guest is unusually permissive; strings.xml:1380-1387)

| Category | **Admin** | **Guest** |
|----------|-----------|-----------|
| Account management | Admin user invitation, Guest user invitation | **NA** |
| Alerts & notifications | Sound, motion, temperature | **NA** |
| Monitor | Video, audio, temperature, background monitoring, snapshot and video recording | Video, audio, temperature, background monitoring, snapshot and video recording (**same as Admin**) |
| Soothing features | Nightlight, soothing sounds, lullabies, true talk-back, voice recording | Nightlight, soothing sounds, lullabies, true talk-back (**no voice recording**) |

### 6e. Invariants across all variants — the actual role boundary

1. **Account management is Admin-only** in every variant (Guest = NA). Guests can never invite
   users or manage accounts. This is the hard privilege boundary.
2. **Alerts & notifications config is Admin-only** (Guest = NA) in all four variants.
3. **Monitor**: both roles always get the core *video + audio + background monitoring*; Admin
   additionally gets *snapshot & video recording* (and SenseIQ/Cry-translation on SenseIQ models).
   Exception: `no1_owl` grants Guest the full monitor set.
4. **Soothing features**: Admin always gets *voice recording*; Guest gets either NA, "differs",
   or (on `no1_owl`) the full set minus voice recording.
5. "Voice recording" and "snapshot & video recording" are **never** in a Guest column except
   `no1_owl` (recording yes, voice recording no) — recording-type features are the clearest
   Admin-gated capabilities.

### 6f. Which variant applies to the in-scope SCD921/923 — **MEDIUM**

The in-scope hardware label is `thing_nightOwl_deviceOne` = "SCD921/SCD923"
(`strings.xml:9717`). The SCD921/923 is the premium **SenseIQ + Cry-translation** model, and only
the `bm_family_*` and `bm_no2_*` variants list SenseIQ + Cry translation — so the SCD921/923
Admin/Guest table is one of those two (MEDIUM confidence). The model→variant resolver itself was
**not** found statically: `bm_no1_pid` (strings.xml:1388) and `bm_ecoOwl_pid` (1247),
`bm_owl_pid` (1411) hold productId (PID) lists, but no decompiled code maps a `<model>` matrix
prefix (`family`/`ecoowl`/`no1_owl`/`no2`) to a PID/model. (PID values intentionally omitted; see
those resource lines.) Resolving the exact SCD921/923 prefix needs the runtime panel (see §7).

> Confidence: HIGH that these strings are the verbatim Admin/Guest capability copy and that the
> invariants hold across variants. MEDIUM that SCD921/923 uses the `family`/`no2` table. LOW on
> the precise prefix→model mapping (no static resolver found).

---

## 7. How the role gates the panel — what is and isn't statically visible — **MEDIUM**

The generic Tuya role **selector** is statically present:
`com/thingclips/smart/family/base/share/InviteMemberRoleViewModel.java` (method `M()`) maps the
selected role to a label — `selectRoleData == 1` → `R.string.n2` (the Admin label),
`== 0` → `R.string.i0` (the Member label), `== -1` → `customRole.getRoleName()` — and the
view-model's `editorRole` defaults to `MemberRole.INVALID_ROLE`. This confirms the UI drives the
same `ROLE_ADMIN=1 / ROLE_MEMBER=0 / ROLE_CUSTOM=-1` values from §1.

The Philips **capability table** (the `bm_*_admin/guest_*_content` strings) is, however, **not
referenced by any decompiled Java/Kotlin/smali/JS** — a repo-wide grep for those string names
hits only `com/philips/ph/babymonitorplus/R.java` (the generated id table). The
`com.philips.ph.babymonitorplus` package itself contains essentially only `R.java`; there is no
Philips role-gating logic in the static APK. The strings are therefore consumed by a
**runtime-downloaded React Native / Tuya miniapp panel** (the app bundles Tuya RN kits under
`decompiled/js/assets/kit_js/` but the Philips device panel bundle is fetched at runtime and is
not in the APK). The actual per-feature gating decision (show/hide talk-back, recording, etc.
based on `MemberBean.isAdmin()`) executes there, not in recoverable static code.

`TRCTShareManager` (`com/thingclips/smart/rnplugin/trctsharemanager/TRCTShareManager.java`) is the
RN bridge for **system** sharing (WeChat/Email/Message/More via `getConstants()`, lines 50-65) —
i.e. sharing an invite *link* out of the app — **not** the device-permission grant; do not
confuse the two.

> Confidence: MEDIUM — the selector logic is HIGH; the conclusion that the capability table is
> rendered by an out-of-APK runtime bundle is HIGH (grep-proven absence), but the exact gating
> code is unrecoverable statically.

---

## 8. Implications for a Rust client — **HIGH (API), LOW (enforcement)**

To reach feature parity the Rust client must speak the Tuya cloud member/share endpoints behind
these SDK methods (the SDK is a thin wrapper over Tuya's `m.*` mobile-API actions, signed with
the mobile-app SDK sign — see `re/tuya_sign.md`):

- **As the owner/Admin** (the user owns the account): list members
  (`IThingHomeMember.queryMemberList`), invite (`addMemberAccount`/`addMember`), set role
  (`updateMemberRole`), revoke (`removeMember`); and on the device side, share the camera
  (`IThingHomeDeviceShare.addShareWithHomeId`/`addShare`) and list/revoke shares.
- **As a Guest** (read-only): the client must tolerate the cloud rejecting Admin-only DP writes.
- The exact cloud action names + request bodies are not in this writeup; they are the
  implementation behind the plugin (`IThingDeviceSharePlugin` / member plugin) and would be
  recovered from a live capture of the share/member screens (the static interface gives the shape,
  not the wire bytes).

**Honest caveat:** whether Guest restrictions are enforced **server-side** (cloud refuses a
guest's talk-back/recording DP write) or only **client-side** (the panel hides the control) is
**not determinable statically**. The capability strings in §6 are descriptive UI copy, not an
enforcement manifest. A guest account could, in principle, attempt a restricted DP directly; only
a live test (or the cloud's response) settles whether it is blocked.

---

## Residual unknowns / what would unblock them

1. **SCD921/923 matrix prefix** (MEDIUM): which of `family`/`no2` (or another) the SCD921/923
   actually renders. *Unblock:* capture the runtime-downloaded device-panel RN/miniapp bundle, or
   a live run of the family/share screen on the device; inspect which `bm_<model>_…_content`
   strings it requests (likely via `Resources.getIdentifier`).
2. **Guest enforcement boundary** (open): server-side vs client-side gating of restricted
   features. *Unblock:* live capture of a Guest account attempting an Admin-only DP write
   (e.g. two-way talk, recording) and observing the cloud/device response.
3. **`CustomRoleBean.RoleResourceBean.resType` semantics** (LOW): the integer→capability-class
   mapping for custom roles. *Unblock:* the role-resource catalog endpoint response (live), or the
   not-fully-decompiled member plugin impl.
4. **`addShare` trailing `boolean` and `inviteShare` 3rd `String`** (LOW): unannotated params.
   *Unblock:* decompile the `IThingDeviceSharePlugin` implementation dex, or a live call capture.
5. **`tempShare` duration model** (LOW): how a temporary Guest share's expiry is set/encoded — not
   in `DeviceShareBean`. *Unblock:* the share-create request body (live), or the plugin impl.
6. **`m.*` cloud action names + request/response bodies** for member/share (needed to actually
   implement, not just describe): *Unblock:* live mitm of the share/member flows
   (sibling `android_emulator_re` pipeline), then anonymize before committing.

---

## Evidence index (file:line)

- Role constants: `com/thingclips/smart/home/sdk/anntation/MemberRole.java:11-17`
- Invite status: `com/thingclips/smart/home/sdk/anntation/MemberStatus.java:4-8`
- Member read model: `com/thingclips/smart/home/sdk/bean/MemberBean.java:8-19,489,561`
- Member write model: `com/thingclips/smart/home/sdk/bean/MemberWrapperBean.java:26-37,975-988`
- Custom role: `com/thingclips/smart/home/sdk/bean/CustomRoleBean.java:7-13`
- Home roles: `com/thingclips/smart/family/bean/HomeRoleInfoBean.java:8-10`
- Member API: `com/thingclips/smart/home/sdk/api/IThingHomeMember.java` (esp. `updateMemberRole` :69, `transferOwner` :57, `removeMember` :51, `queryMemberList` :47)
- Share API: `com/thingclips/smart/home/sdk/api/IThingHomeDeviceShare.java` (esp. `addShare` :13, `addShareWithHomeId` :17, `inviteShare` :32, `queryDevShareUserList` :36, `disableDevShare` :23)
- Share/member factories: `com/thingclips/smart/home/sdk/ThingHomeSdk.java:677` (`getDeviceShareInstance`), `:1162` (`getMemberInstance`)
- Camera-panel share caller: `com/thingclips/smart/camera/sharedevice/biz/DefaultDeviceShareUseCase.java:24,2315,2864,3051`
- Share record beans: `com/thingclips/smart/home/sdk/bean/SharedUserInfoBean.java:7-14`, `DeviceShareBean.java:7-13`
- Role selector: `com/thingclips/smart/family/base/share/InviteMemberRoleViewModel.java` (`M()`)
- RN system-share bridge (NOT permission grant): `com/thingclips/smart/rnplugin/trctsharemanager/TRCTShareManager.java:50-65`
- Capability matrix copy: `decompiled/apktool/res/values/strings.xml:1249-1256,1265-1272,1380-1387,1389-1396,1535-1536`
- In-scope model label: `decompiled/apktool/res/values/strings.xml:9717` (`thing_nightOwl_deviceOne` = SCD921/SCD923)
