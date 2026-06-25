# Device pairing + Wi-Fi provisioning (EZ / AP / QR / bind) map (TASK-0008)

Static model of the **Tuya device-pairing + Wi-Fi-provisioning** path that
`com.philips.ph.babymonitorplus` uses to add a new camera: the cloud
**pairing-token** issue, the **EZ / SmartConfig** (SmartLink broadcast/multicast)
packet-length encoding in `libThingSmartLink.so`, the **AP (soft-AP)** config
payload, the **QR** payload format, and the cloud **bind-confirm** polling.

This builds ON the cloud-auth + device-list map in
[`re/tuya_cloud_auth.md`](tuya_cloud_auth.md) (the atop envelope §1, login §2,
session §3, datacenter §4, device-list/`DeviceBean` §5) and the native-lib
inventory [`re/native_libs.md`](native_libs.md) (`libThingSmartLink.so` is the
EZ/AP SmartLink encoder). Read those first — this doc does NOT re-derive the
signing scheme (`re/tuya_sign.md`) or the device-list bean shape.

> **THE KEY CONCLUSION for THIS user (already-paired camera):** see §6. For a
> camera **already bound** to the user's account, **NO pairing/provisioning is
> needed at all** — the device simply appears in the cloud device-list. Pairing
> (this whole document) is **NOT on the critical path** for the Rust client's
> stated goal (view the already-paired camera). It is here for completeness /
> future "add a new camera" support only.

> Citation note (symbol-anchored — TASK-0024): cites name a **symbol**
> (JNI/native function, Java class/method/field, or string-constant). Native
> cites use the lib SONAME + the Ghidra C committed under `re/ghidra/` + the file
> vaddr (image base **0x100000**, matching `re/symbols/libThingSmartLink.dynsym.txt`).
> Java `decompiled/jadx/.../*.java` paths are gitignored (regenerate via `just
> decompile`) and `~:NN` line hints are approximate — grep the symbol. The DEX is
> R8-obfuscated: method/class names like `pqdppqd`/`ppqdbbq` are mangled but the
> `thing.m.*` **action string-constants are NOT obfuscated** and are the authority.

> **No secret values appear in this file.** A real router SSID/password, a real
> pairing token, the per-account `sid`, or any `localKey`/`p2pKey` are secrets and
> are never written here — only the protocol shape and field names.

---

## 0. TL;DR pairing contract (confidence: confirmed)

Two independent sources ground the overall shape: the **native** `libThingSmartLink.so`
encoder (Ghidra C committed under `re/ghidra/smartlink_*.c`, cross-checked with
radare2 — §3) AND the **Java** activator/cloud layer (the `thing.m.device.*`
action-constant table in `com/thingclips/sdk/hardware/pqdppqd.java` + the camera
activator `com/thingclips/sdk/hardware/ppqdbbq.java` + `ThingSmartLink.smartLink`
JNI in `com/thingclips/smart/android/device/ThingSmartLink.java`). They describe
the same flow, so it is `confirmed`.

First-time pairing is a **four-step** flow:

1. **Get pairing token** from cloud: action `thing.m.device.token.create` v`2.0`
   → returns an `ActiveTokenBean` carrying the `token` (+ `secret`, `region/key`).
   The token is short-lived and scoped to the user's home/region.
2. **Provision Wi-Fi** to the unconfigured camera, embedding `(ssid, password,
   token)` via ONE of three transports:
   - **EZ / SmartConfig (SmartLink):** `ThingSmartLink.smartLink(ssid, pwd, token,
     5,2,1000,1,1)` → native `libThingSmartLink.so` encodes the bytes into UDP
     **packet lengths** broadcast to 255.255.255.255 + multicast group addresses.
   - **AP (soft-AP):** phone joins the camera's AP, sends an `APConfigBeanUDP`
     JSON `{ssid,passwd,token,ccode}` to the device over UDP/TCP.
   - **QR:** app renders a QR whose payload is the JSON `{"p":pwd,"s":ssid,"t":token}`;
     the camera scans it.
3. **Bind-confirm poll:** while the camera boots, joins Wi-Fi, and registers
   itself to cloud with that token, the app polls `thing.m.device.list.token`
   v`5.0` (postData `token`, bizDM `device_config_add`) until the device appears.
4. **Active/bind:** the device is activated/bound to the account
   (`thing.m.device.local.device.active` / `m.thing.device.local.device.active` /
   `thing.m.dm.device.active`); thereafter it is a normal `DeviceBean` in the
   home device-list (`re/tuya_cloud_auth.md` §5).

---

## 1. PAIRING TOKEN — cloud issue (confidence: confirmed)

Two independent sources: the action-constant + request-builder in the device
manager class `pqdppqd`
(`decompiled/jadx/sources/com/thingclips/sdk/hardware/pqdppqd.java`: constant
`pqdbppq = "thing.m.device.token.create"` ~:61, built into `new
ApiParams("thing.m.device.token.create","2.0"); setSessionRequire(true);
asyncRequest(apiParams, ActiveTokenBean.class, …)` ~:616) AND the response bean
`ActiveTokenBean`
(`decompiled/jadx/sources/com/thingclips/smart/sdk/bean/ActiveTokenBean.java`:
fields `token`, `secret`, `key` ~:7-9; ctor `ActiveTokenBean(String s){ token =
s.substring(2,10); secret = s.substring(10); }` ~:14). They agree on
action+shape, so this is `confirmed`.

- **Action:** `thing.m.device.token.create` (atop, rewritten `thing*`→`smartlife*`
  on the wire — `re/tuya_cloud_auth.md` §1a) v`2.0`, **session-required** (`sid`
  from login must be present — `re/tuya_cloud_auth.md` §3). The token is therefore
  issued **per logged-in account + home/region**.
- **Request postData:** the v2.0 `bdpdqbp(...)` builder adds no extra postData
  beyond the envelope (it relies on `sid` + the active home context). A home/group
  id is carried for the QR variant (`m.thing.device.qrcode.token.create` v2.0 puts
  `KEY_GID` ~:1388-1391). (confidence: likely — single builder body; the exact
  optional fields like `timeZoneId`/`uuid` are added by callers and are cleanest
  to confirm from one live capture.)
- **Response = `ActiveTokenBean`:** `token` (the provisioning token embedded into
  the EZ/AP/QR payload below), `secret`, `key`. The packed-string ctor shows the
  cloud may return a single string the SDK splits into `token = chars[2..10]` +
  `secret = chars[10..]` (an 8-char token core). **The `token` value is a secret**
  (per-session credential) — never written here.
- **Token renewal:** `m.thing.device.active.token.renewal`
  (`pqdppqd.java` `qpppdqb` ~:67, built ~:1585) refreshes an expiring token mid-pairing.

**Region embedding:** the token's region/datacenter is implicit — the token is
minted by the regional `mobileApiUrl` resolved at login (`re/tuya_cloud_auth.md`
§4). For EZ, the SDK also passes a **country code (`ccode`)** alongside the token
in the AP payload (§4); for EZ broadcast the region is carried inside the token
itself, not as a separate length-encoded field (§3).

---

## 2. EZ / SmartConfig — the JNI entry + arg order (confidence: confirmed)

Two independent sources: the Java native declaration
`ThingSmartLink.smartLink(String,String,String,int,int,int,int,int)`
(`decompiled/jadx/sources/com/thingclips/smart/android/device/ThingSmartLink.java`
~:47) AND the JNI export
`Java_com_thingclips_smart_android_device_ThingSmartLink_smartLink`
(`re/symbols/libThingSmartLink.dynsym.txt`, demangled
`_Z65Java_..._smartLinkP7_JNIEnvP7_jclassP8_jstringS4_S4_iiiii` @0x12520 →
`Thing_Native_SmartLink` @0x10f6bc, Ghidra `re/ghidra/smartlink_Thing_Native_SmartLink.c`).
Three jstrings + five ints in both — `confirmed`.

**Arg order (confirmed by the caller):** the camera activator calls
`ThingSmartLink.smartLink(ssid, password, token, 5, 2, 1000, 1, 1)`
(`com/thingclips/sdk/hardware/ppqdbbq.java` ~:235: `smartLink(ppqdbbqVar.dqdbbqp
/*ssid*/, ppqdbbqVar.dpdqppp /*password*/, ppqdbbqVar.bpbbqdb /*token*/, 5,2,1000,1,1)`;
`bpbbqdb = builder.getToken()` ~:1063) — and identically by the generic
`ThingEZConfig.b(ssid, pwd, token)` → `smartLink(str, str2, str3, 5,2,1000,1,1)`
(`com/thingclips/smart/config/ThingEZConfig.java` ~:39-47). So:

| smartLink arg | Meaning | Source |
|---|---|---|
| `str` (param_3) | **SSID** | router SSID (secret-adjacent) |
| `str2` (param_4) | **password** | router Wi-Fi password (**secret**) |
| `str3` (param_5) | **token** | the §1 pairing token (**secret**) |
| `i..i5` | `5,2,1000,1,1` | broadcast-count, multicast-count, inter-pkt delay ms, + two mode flags |

`Thing_Native_SmartLink` (`re/ghidra/smartlink_Thing_Native_SmartLink.c`) calls
`GetStringUTFChars` on the three jstrings, then
`thing_smart_link(ssid, pwd, token, p6, p7, p8, p9, p10)`.

---

## 3. EZ packet-length encoding scheme (libThingSmartLink.so) (confidence: likely)

Two independent sources: **Ghidra** headless decompilation of the encoder
functions (`libThingSmartLink.so@0x110b7c` etc., committed `re/ghidra/smartlink_*.c`,
image base 0x100000) AND a **radare2** cross-check disassembly of the same
addresses (`libThingSmartLink.so@0x10b7c` at `laddr 0`, §3c). They agree on the
structure, so this is `likely` (single binary source — Ghidra + r2 read the same `.so` = ONE source per TESTING.md). This is the classic Tuya **EZ
(SmartConfig)** scheme: data is carried in the **length** of otherwise-empty UDP
datagrams, not in their payload.

`thing_smart_link(ssid, pwd, token, …)`
(`re/ghidra/smartlink_thing_smart_link.c`, sym `_Z…thing_smart_linkPKcS0_S0_iiiii`
@0x123c8) allocates two global descriptors `broadcast_link_info` (0x18 bytes) and
`multicast_link_info` (0x40 bytes), calls `broadcast_body_encode(ssid,pwd,token)`
then `multicast_body_encode(ssid,pwd,token)`, then `send_data(...)`, then `release()`.

### 3a. Broadcast body — the length-sequence (confidence: likely)
Two sources: Ghidra C (`re/ghidra/smartlink_broadcast_body_encode.c`, sym
`_Z21broadcast_body_encodePKcS0_S0_`, `libThingSmartLink.so@0x110b7c`) AND the r2
disassembly of the same (`libThingSmartLink.so@0x10b7c`, §3c) — so `likely` (one binary, two tools = one source).
`broadcast_body_encode(ssid, pwd, token)`:

1. `len = strlen(ssid)+strlen(pwd)+strlen(token)` ; `dataLen = len+2`.
2. Build a contiguous source buffer (`malloc`, padded up to a multiple of 4):
   **`[len(pwd)] [pwd] [len(token)] [token] [ssid]`** — i.e. password and token are
   each prefixed with a 1-byte length; the SSID is appended last with no prefix
   (its length is derivable from the total).
3. A **CRC8** (table `crc8_table`, function `crc8` @0x10a60) over `dataLen` gives a
   length-checksum byte `bVar4`.
4. The output is an array of `ushort` "lengths". Each 4 source bytes expand to **6
   length-words** (`(dataLen>>2)*6 + 4` words total): a per-group CRC8 sequence
   number and four data bytes, each tagged with a **high-bit flag** that tells the
   receiver which field/phase the length belongs to:
   - data-byte words: value `| 0x100` (the 9th bit marks "data length").
   - sequence/index words: value `| 0x80`.
   - the 4 **head** words carry `dataLen` + its CRC8, nibble-split and tagged
     `| 0x10`, `| 0x20`, `| 0x30`, `| 0x40` (the four head markers):
     `out[0]=(dataLen>>4)&0xF |0x10; out[1]=dataLen&0xF |0x20; out[2]=(crc8>>4)|0x30;
     out[3]=(crc8&0xF)|0x40`.

So the receiver recovers the byte stream by reading the **packet lengths** modulo
these flag bases. This matches the public Tuya EZ/SmartConfig description.

### 3b. Multicast body — AES-CBC + multicast group addresses (confidence: likely)
Two sources: Ghidra C (`re/ghidra/smartlink_multicast_body_encode.c`, sym
`_Z21multicast_body_encodePKcS0_S0_`, `libThingSmartLink.so@0x111190`) AND the
exported AES primitive it calls (`AES128_CBC_encrypt_buffer`,
`libThingSmartLink.so@0x110350`, in `re/symbols/libThingSmartLink.dynsym.txt`) —
so `likely` (single binary source). `multicast_body_encode(ssid, pwd, token)`:

- Computes a **CRC32** (poly `0xEDB88320`, inlined) over each of ssid, pwd, token
  separately.
- **AES-128-CBC-encrypts the password field** (`AES128_CBC_encrypt_buffer`, exported
  @0x10350; key+IV from the lib's `.data` constants `_DAT_0012b0c0`/`_UNK_0012b0c8`)
  before transmission — so the password is not sent in clear even in the EZ
  length-channel. (The AES key here is a **fixed SDK constant**, the classic Tuya
  EZ "default" key; recoverable from `.data` but not a per-device secret — not
  written here.)
- Emits each (ssid/pwd/token) field via `xmitState(buf, len, crc32, baseFlag, idx,
  mode)` (sym `_Z9xmitStatePhiiiii` @0x10e68) which packs `(flag|seq, hi, lo)`
  triplets into `multicast_link_info`. The base-flag distinguishes fields:
  **`0x40` for ssid, `0x00` for the AES'd password, `0x20` for token**, plus a
  `0x78` group-header triplet (`multicast_body_encode` ~head). The recovered
  values become the **low bytes of multicast group IP addresses** (226.x/239.x
  range) the sender joins.

### 3c. UDP transmit loop (confidence: likely)
Two sources: Ghidra C `send_data` (`re/ghidra/smartlink_send_data.c`,
`libThingSmartLink.so@0x1121e4`) AND Ghidra C `send_data_thread`
(`re/ghidra/smartlink_send_data_thread.c`, `libThingSmartLink.so@0x1119ac`) —
two functions in the SAME binary, so `likely` (one source, not two independent ones).
`send_data(p4,p5,p6,p7,p8)` (sym `_Z9send_dataiiiii`) opens a UDP socket
(`socket(2,2,0)` = AF_INET/SOCK_DGRAM), clears `thing_quit_flag`, and spawns
`send_data_thread` (sym `_Z16send_data_threadPv`):

- **Broadcast leg:** `sendto(sock, buf, LENGTH, 0, 255.255.255.255:port, …)` where
  `LENGTH` walks the `broadcast_link_info` ushort length-array — the **datagram
  length is the data**; the 1-KB zero buffer content is irrelevant. Inter-packet
  pacing via `select()` timeout = the `1000` (delay) arg (`pkt_delay`, sym
  `_Z9pkt_delayjj` @0x11944).
- **Multicast leg:** `sendto(...)` to the group addresses derived in §3b, repeated
  `5` (broadcast-count) × `2` (multicast-count) rounds (the int args), checking
  `thing_quit_flag` between every packet. Stopped by `sendStatusStop()` JNI →
  `send_status_stop`.

### 3d. Ghidra-vs-radare2 cross-check (confidence: likely)
Two sources: the Ghidra C (`re/ghidra/smartlink_broadcast_body_encode.c`,
`libThingSmartLink.so@0x110b7c`) AND the independent r2 disassembly
(`libThingSmartLink.so@0x10b7c`) — same function, two tools (one binary source), so `likely`.
r2 (`r2 -m 0 … pi @ 0x10b7c`) on `broadcast_body_encode` confirms the Ghidra
reading: three `bl strlen` (ssid/pwd/token), `bl malloc`, `strb w,[x0],1` writing
the length-prefix at offset 1, `bl memcpy` of the fields, and the high-bit OR
flags (`orr w,w,0x80`, `orr w,w,0x30` observed). **Divergences (representation,
not semantics):** (1) r2's auto-analysis would not seed the function at the
ELF's real vaddr without `-m 0` (the lib is `laddr 0`; Ghidra used image base
0x100000 — the same file offset + 0x100000). (2) The 16-bit `|0x100`/`|0x10`/`|0x20`/`|0x40`
flags are materialised in the ARM64 as `movz`+`orr`/store rather than `orr`-immediate,
so only `0x80`/`0x30` show as literal `orr` immediates in r2; Ghidra's decompiler
folds them into the `ushort | 0xNN` expressions. No semantic disagreement found.

---

## 4. AP (soft-AP) mode — device-hosted config (confidence: confirmed)

Two independent sources: the AP config payload bean `APConfigBeanUDP`
(`decompiled/jadx/sources/com/thingclips/smart/config/bean/APConfigBeanUDP.java`:
fields `ssid` ~:10, `passwd` ~:8, `token` ~:11, `ccode` ~:7) AND the AP config
driver `ThingAPConfig`
(`decompiled/jadx/sources/com/thingclips/smart/config/ThingAPConfig.java`: serializes
`aPConfigBeanUDP` to JSON and `ThingNetworkInterface.sendBroadcast("255.255.255.255",
port, 500, jsonBytes, FrameType, …)`). They agree, so `confirmed`.

- **Transport:** the phone first **joins the camera's soft-AP** (the device hosts
  an open/WPA AP after factory reset). The app then sends the config to the device
  over the AP link — via **UDP broadcast** to `255.255.255.255` on a fixed config
  port (the `ThingNetworkInterface.sendBroadcast(...)` path in `ThingAPConfig`),
  with a TCP fallback (`IApConfigTcpCallback`). The exact port is an obfuscated
  constant (`pdqdqbd.pppbppp`) — **needs one capture to pin the number**
  (Tuya's documented soft-AP config port is 6669/UDP; labelled `likely` for the
  exact value here).
- **Payload:** JSON of `APConfigBeanUDP` = **`{"ssid":…, "passwd":…, "token":…,
  "ccode":…}`** (the §1 token + the country code). A simpler `APConfigBean`
  (`com/thingclips/sdk/config/bean/APConfigBean.java`) with just `{ssid, passwd}`
  exists for token-less variants. The device joins the router with these and then
  registers to cloud (→ bind-confirm §5).
- The discovery side (`ThingApSLConfig`/`HgwBean`) listens for the device's UDP
  advertisement (`gwId`/`uuid`/`ip`) to know when it has come up on the AP.

---

## 5. QR pairing payload (confidence: confirmed)

Two independent sources: the QR-string builder in the camera activator
(`decompiled/jadx/sources/com/thingclips/sdk/hardware/ppqdbbq.java` ~:1719:
`String str3 = "{\"p\":\"" + str2 + "\",\"s\":\"" + str + "\",\"t\":\"" +
this.bpbbqdb + "\"}"; … listener.onQRCodeSuccess(str3)` where `str2 =
dpdqppp /*password*/`, `str = dqdbbqp /*ssid*/`, `bpbbqdb = token`) AND the QR
cloud helpers `thing.m.qrcode.parse` / `m.thing.device.qrcode.token.create`
(`com/thingclips/sdk/hardware/pqdppqd.java`: `qdddbpp = "thing.m.qrcode.parse"`
~:64; `new ApiParams("m.thing.device.qrcode.token.create","2.0")` ~:1388). They
agree on the field set, so `confirmed`.

- **QR payload = JSON `{"p":"<password>","s":"<ssid>","t":"<token>"}`** — `p` =
  router password, `s` = router SSID, `t` = the §1 pairing token. The app renders
  this; the **camera scans it** with its own lens (this is "device scans phone's
  QR", the Tuya IPC QR-config flow). The SSID/password are escaped (`\` and `"`
  doubled) before embedding. (The on-device QR *scanner* uses ML Kit
  `libbarhopper_v3.so` — `re/native_libs.md` — but that is the camera's job; the
  app only needs to *generate* this JSON QR.)
- **Token for QR:** minted by `m.thing.device.qrcode.token.create` v2.0 (carries
  the home `KEY_GID`); `thing.m.qrcode.parse` decodes a scanned device QR back to
  a uuid/productKey if the app instead scans the *device's* label QR.
- All three of `p`/`s`/`t` are **secrets** (router creds + token) — never written here.

---

## 6. Bind-confirm polling + active/bind (confidence: confirmed)

Two independent sources: the poll request-builder
(`com/thingclips/sdk/hardware/pqdppqd.java` ~:136: `new
ApiParams("thing.m.device.list.token","5.0"); setSessionRequire(true);
putPostData("token", str); setBizDM("device_config_add"); syncRequest(apiParams,
ConfigDevResp.class)`) AND the active builders (`thing.m.device.local.device.active`
`dpdqppp` ~:50 built ~:896 with postData `uuid`/`groupType`/`gid`/`timeZoneId`;
`m.thing.device.local.device.active` `pqpbpqd` ~:62 built ~:920 adding
`hotspotName`/`pin`). They agree on the flow, so `confirmed`.

- **Poll:** after provisioning, the app repeatedly calls
  **`thing.m.device.list.token` v`5.0`** with postData **`token`** (the §1 token)
  and bizDM `device_config_add`. The response `ConfigDevResp` (interior bean `ln`)
  lists devices that have registered to cloud against that token. The poll loop
  lives in the obfuscated config drivers (`com/thingclips/sdk/hardware/qppddqq.java`,
  `dpqdqbb.java`) that consume `BusinessResult<ln>`. Polling ends when the device
  appears (success → `onActiveSuccess`) or the token/timeout expires
  (`STATUS_DEV_ALREADY_BIND`/`"1007"` error codes seen in `ppqdbbq.java` ~:2001-2003).
- **Active/bind:** the newly-seen device is activated/bound to the account via
  `thing.m.device.local.device.active` / `m.thing.device.local.device.active`
  (postData `uuid`, `groupType`, `gid`/homeId, `timeZoneId`, optional
  `hotspotName`/`pin`) or the device-manager `thing.m.dm.device.active`
  (`qqpdpbp` ~:70). After this the device is a normal **`DeviceBean`** in the home
  device-list — the same shape consumed in `re/tuya_cloud_auth.md` §5, carrying its
  `localKey`/`p2pId` for streaming.

---

## 7. ALREADY-PAIRED camera — the MINIMAL path (THIS USER'S CASE) (confidence: confirmed)

Two independent sources: the device-list container bean
`HomeBean.getDeviceList()` → `List<DeviceBean>`
(`decompiled/jadx/sources/com/thingclips/smart/home/sdk/bean/HomeBean.java`,
keyed by `homeId`; mapped in `re/tuya_cloud_auth.md` §5) AND the per-camera config
bean `CameraInfoBean`
(`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/bean/CameraInfoBean.java`,
fetched per `devId`). Neither the device-list query nor the camera-config fetch
takes a pairing token or invokes `ThingSmartLink` — they require only `sid`
(login session). They agree, so this conclusion is `confirmed`.

**For a camera already bound to the user's account, NO part of §1-§6 runs.**
The pairing token (§1), the EZ/AP/QR provisioning (§2-§5), and the bind-confirm
poll/active (§6) are **first-time-setup-only**. An already-bound device:

1. is returned in the home **device-list** (`HomeBean.deviceList`,
   `re/tuya_cloud_auth.md` §5a) keyed by the account's `homeId`;
2. carries its own `DeviceBean.localKey` / `uuid` / `productId` and the per-camera
   `CameraInfoBean` (`p2pId`, `p2pKey`, session creds — `re/tuya_cloud_auth.md` §5c)
   needed for the WebRTC/P2P stream;
3. needs **no re-binding** — re-binding only happens if the user explicitly
   removes the device or factory-resets the camera (which clears its token and
   forces a fresh §1-§6 cycle).

**Rust client consequence:** the Rust client's critical path is
**auth (login → `sid`) + device-list + camera-config**, exactly the
TASK-0012/0013 surface. It does **NOT** need a pairing module to view the
already-paired camera. **Pairing is NOT on the critical path** for this user's goal.

---

## 8. Static-complete vs live-gated (honest limitations) (confidence: confirmed)

This is a scoping record, not a new protocol claim; each row's basis is cited in
the sections above. Grounded in two independent committed artifacts: the native
encoder `libThingSmartLink.so@0x110b7c` (Ghidra C `re/ghidra/smartlink_*.c`, §3)
AND the Java cloud action table
`decompiled/jadx/sources/com/thingclips/sdk/hardware/pqdppqd.java`
(the `thing.m.device.*` constants, §1/§6).

| Item | Status | Note / unblock |
|---|---|---|
| EZ packet-length encoding (broadcast: `[len(pwd)][pwd][len(token)][token][ssid]`, CRC8 head `0x10/0x20/0x30/0x40`, data `\|0x100`, seq `\|0x80`) | **static-complete** | Ghidra + r2 agree (§3). Byte-exact replay still wants one capture to confirm the head port + the exact multicast group derivation. |
| EZ multicast AES-128-CBC of password + group-IP encoding | **static-complete (key is a fixed SDK constant)** | §3b. The fixed key/IV are in `.data`; a replay test confirms them. |
| `smartLink` arg order (ssid, pwd, token, 5,2,1000,1,1) | **static-complete** | §2 (two callers + JNI). |
| Pairing-token action `thing.m.device.token.create` v2.0 + `ActiveTokenBean` shape | **static-complete (shape)** | §1. The on-wire `a=` after `thing→smartlife` rewrite + exact postData fields = `needs-live` (one capture), as in `re/tuya_cloud_auth.md` §6-7. |
| AP-mode payload `{ssid,passwd,token,ccode}` | **static-complete (shape)** | §4. The **exact UDP config port** (obfuscated `pdqdqbd.pppbppp`; Tuya default 6669) = `needs-live`/`likely`. |
| QR payload `{"p","s","t"}` | **static-complete** | §5 (literal builder string). |
| Bind-confirm poll `thing.m.device.list.token` v5.0 (token, bizDM `device_config_add`) + active actions | **static-complete (shape)** | §6. Poll cadence/timeout + success criteria in obfuscated drivers = `likely`. |
| **Already-paired → no pairing needed** | **static-complete** | §7 — the decisive conclusion for this user. |

**Bottom line:** the pairing protocol is mapped to a useful depth — token issue,
the EZ length-encoding scheme (Ghidra-confirmed, r2-cross-checked), AP payload, QR
payload, and bind-confirm polling are all statically pinned in **shape**; only a
few exact numeric constants (config port, on-wire action spelling, poll timing)
need one live capture. **And pairing is NOT on the critical path for the user's
goal**: an already-paired camera needs only auth + device-list. A Rust pairing
module is therefore **low priority** (forward-carried to TASK-0036).
