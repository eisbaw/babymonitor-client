# regions/pins decrypt + clientId-wire verdict (TASK-0043, static cycle)

Two deliverables for the live re-attempt (TASK-0042), both resolved STATICALLY (no
live call in this cycle):

1. **clientId wire param** — verified.
2. **`assets/thing_domains_v1/regions` decrypt** — recovered the real datacenter host map.

**No secret values appear in this file.** The datacenter HOSTS recovered below are
PUBLIC Tuya gateway URLs (non-secret, per CLAUDE.md they may be documented). The
decrypted blob contains NO account-specific/secret value (verified — all fields are
public host/port config).

> Citation note (symbol-anchored): jadx paths are `decompiled/jadx/sources/...`; line
> hints drift between runs — grep the symbol. Ghidra C for the native function is
> committed under `re/ghidra/getconfig/` (image base 0x100000; `getConfig` file-offset
> 0x136e0 → Ghidra address 0x1136e0).

---

## PART 1 — clientId wire param: ALREADY CORRECT, no fix needed (confidence: confirmed)

Evidence (two independent decompiled sources):
`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java`
(`KEY_APP_ID`→wire `clientId`, `KEY_TIMESTAMP="time"`) AND
`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java`
(`bdpdqbp` whitelist listing `clientId`/`time`); both matched by
`babymonitor/babymonitor-cli/src/live.rs` `build_signed_envelope_with` + `send_atop`.

The flag was a false alarm. `babymonitor/babymonitor-cli/src/live.rs`
`build_signed_envelope_with` inserts the appKey under the **wire key `clientId`**, not
`appId`:

```rust
envelope.insert("clientId".into(), cfg.material.app_key.clone());   // live.rs (the wire query)
envelope.insert("time".into(), now_ms.to_string());                 // not "t"
```

This `envelope` map is what `send_atop` puts on the wire as the URL query string
(`.query(&query)` built from `envelope.iter()`). So the actual HTTP request DOES send
`clientId=<appKey>` and `time=<epoch_ms>` as query params — matching the Tuya wire
names (`ThingApiParams.KEY_APP_ID`→wire `clientId`, `KEY_TIMESTAMP="time"`,
`re/tuya_cloud_auth.md` §1). The earlier sign-whitelist fix (`appId`→`clientId`,
`t`→`time`, `re/live_login.md` "Whitelist correction") fixed the CANONICAL STRING; the
ENVELOPE/query was already using the correct wire keys. Full param set present matches
`re/tuya_cloud_auth.md` §1: `a, v, time, sid(omitted pre-login), requestId, et, lang,
os, appVersion, ttid, clientId, deviceId, sign` + raw `postData` body. **Verdict: the
clientId wire param was already correct — `ILLEGAL_CLIENT_ID` is NOT caused by a
missing/misnamed clientId query param.**

---

## PART 2 — regions decrypt: AES-256-CTR, STATIC-DERIVABLE FROM THE ASSET (confidence: confirmed)

### Key/IV/mode — the verdict (confidence: confirmed)

The `regions`/`pins` blob is **AES-256-CTR/NoPadding**, and the key + IV are
**embedded in the asset's own header** (the asset's own first 48 bytes are the key+IV).
This claim is SCOPED to the regions/pins assets only — it does NOT contradict the
TASK-0033 `bmp_token` sign-key finding (`re/bmp_token_whitebox.md` §9, which REQUIRES a
runtime SDK-config `byte[]`): that is a different asset on a different (native) code
path. The regions/pins path is pure-Java and self-contained. Two independent sources:

1. **The pure-Java decrypt path** (the one actually used for regions/pins):
   `DomainHelper.parseDomainsConfig(...)`
   (`decompiled/jadx/sources/com/thingclips/smart/android/base/provider/DomainHelper.java`,
   called from the `AssetsManager.l(ctx,"thing_domains_v1/regions")` read) splits the
   base64-decoded asset into `key=decode[0:32]` + `bArr2=decode[32:]` and calls
   `AESCTRUtil.decrypt(key, base64(bArr2))`. `AESCTRUtil.decrypt`
   (`.../android/network/util/AESCTRUtil.java`) is literally
   `Cipher "AES/CTR/NoPadding"`, `SecretKeySpec(key,"AES")`,
   `IvParameterSpec(b2,0,16)` over ciphertext `b2[16:]`. The pins path is identical
   (`ThingCertificatePinner` → same `parseDomainsConfig`).
2. **The decrypted output is clean JSON** — a near-impossible-by-chance structural
   oracle. A self-contained AES-256-CTR port (`re/scripts/regions_decrypt.py`) AND
   `openssl enc -aes-256-ctr` independently reproduce the SAME plaintext.

End-to-end on the raw asset bytes:

```
decode = base64(asset_file_bytes)     # the file is base64 TEXT
key    = decode[0:32]                 # 32-byte AES-256 key  (ASCII hex chars)
iv     = decode[32:48]                # 16-byte CTR IV/nonce (ASCII hex chars)
ct     = decode[48:]                  # ciphertext
plaintext = AES-256-CTR-decrypt(ct, key, iv)
```

For this APK the 48-byte header is the constant `4db635414026e2ba9d9d392275e0aee58b9285b5e5addea2`
(shared by `regions` AND `pins`): bytes[0:32] = the AES-256 key, bytes[32:48] = the IV.
`regions` → JSON array of region datacenter configs; `pins` → JSON array of TLS
cert-pin sets.

### Where the native `getConfig@0x136e0` actually fits — NOT the regions decryptor (confidence: confirmed)

Evidence: `re/ghidra/getconfig/getConfig.c` (FUN_001136e0) +
`decompiled/jadx/sources/com/thingclips/smart/android/network/http/AssetsConfig.java`.


`SecureNativeApi.getConfig(Context, String key, String iv)` (Ghidra C:
`re/ghidra/getconfig/getConfig.c`, FUN_001136e0) is the decryptor for a **different,
optional asset — `t_cdc.tcfg`** (the custom-domain OVERRIDE, NOT shipped in this APK).
It is **AES-128-GCM** (mbedtls): `mbedtls_gcm_setkey(ctx, AES, key, 128)`
(`re/ghidra/getconfig/aes_setup.c`) then `mbedtls_gcm_auth_decrypt(...)`
(`re/ghidra/getconfig/aes_decrypt.c`) — with **tag=NULL, tag_len=0** (GCM auth
bypassed → used as a pure AES-CTR stream cipher). Its key/IV are the two Java String
args; the parallel pure-Java path `AssetsConfig.getConfigObj`
(`.../network/http/AssetsConfig.java`) shows the t_cdc.tcfg key derivation =
`AesGcmUtil.decryptBytes2Bytes(key=mAppId[0:16], mAppSecret.getBytes(), data,
aad=packageName.getBytes())`. **This is irrelevant to the regions host recovery** — the
regions/pins blob is decrypted by the static pure-Java AES-256-CTR path above, so no
native port and no appKey were needed. (Documented here so a future reader does not
chase getConfig for the regions key — it is the wrong consumer.)

**Verdict: getConfig key/mode = STATIC-DERIVABLE** (for regions: AES-256-CTR with
asset-embedded key/IV; the native getConfig is AES-128-GCM-as-CTR for t_cdc.tcfg and
not on the regions path). Host recovered.

---

## Recovered datacenter hosts (NON-SECRET, public Tuya gateways) (confidence: confirmed)

`regions` decrypts to 4 regions. **EU is the `defaultConfig` region.** The
account owner's countryCode (DK=45) resolves to EU, so the EU `regionConfig` is
the authoritative host map for this client.

### Per-region mobile-atop + gateway (the original 2 fields)

| region | mobileApiUrl (atop) | gwApiUrl |
|---|---|---|
| **EU (defaultConfig)** | **`https://a1.tuyaeu.com`** | `http://a.gw.tuyaeu.com/gw.json` |
| AZ (US) | `https://a1-us.iotbing.com` | `http://a.gw.tuyaus.com/gw.json` |
| IN | `https://a1-in.iotbing.com` | `http://a1-in.iotbing.com/gw.json` |
| RU | `https://a1.iot334.com` | (none) |

### AUTHORITATIVE full EU `regionConfig` host/port list (TASK-0048) (confidence: confirmed)

The host false-exhaustion (TASK-0046 review gate) happened because earlier work
saw only `mobileApiUrl`/`gwApiUrl`. `regions_decrypt.py` now emits EVERY
`regionConfig` scalar field (`region_host_fields`); the EU region has **24**
host/port fields. All are PUBLIC Tuya datacenter endpoints (no account secret),
so they are documented here. Reproduce with
`nix-shell --run 'python3 re/scripts/regions_decrypt.py'`. Two independent
sources: the decrypted asset itself AND the `test_regions_decrypt.py` real-asset
cross-check (`just test-regions`, asserts >10 fields incl. fusionUrl/pxApiUrl/
deviceHttpsPskUrl).

| field | EU value | role |
|---|---|---|
| `mobileApiUrl` | `https://a1.tuyaeu.com` | mobile-app atop API (the host already tried) |
| `gwApiUrl` | `http://a.gw.tuyaeu.com/gw.json` | device gateway API |
| `fusionUrl` | `https://apigw-eu.iotbing.com` | **iotbing "fusion" API gateway — UN-PROBED, rank-1 TASK-0048 target** |
| `pxApiUrl` | `http://px.tuyaeu.com` | px API — UN-PROBED TASK-0048 target |
| `deviceHttpsPskUrl` | `https://a3.tuyaeu.com` | device HTTPS-PSK (`a3.tuyaeu.com`) — UN-PROBED TASK-0048 target |
| `aispeechHttpsUrl` | `https://aispeech.tuyaeu.com` | AI-speech HTTPS |
| `aispeechQuicUrl` | `https://i1.tuyaeu.com` | AI-speech QUIC |
| `mobileMqttsUrl` | `m1.tuyaeu.com` | mobile MQTTS broker |
| `mobileMqttUrl` | `mq.mb.tuyaeu.com` | mobile MQTT broker |
| `mobileMediaMqttUrl` | `s.tuyaeu.com` | mobile media MQTT |
| `mobileQuicUrl` | `https://u1.tuyaeu.com` | mobile QUIC |
| `gwMqttUrl` | `mq.gw.tuyaeu.com` | gateway MQTT |
| `mqttQuicUrl` | `q1.tuyaeu.com` | MQTT-over-QUIC |
| `thingAppUrl` | `app-support.tuyaeu.com` | thing app-support |
| `tuyaAppUrl` | `app-support.tuyaeu.com` | tuya app-support |
| `thingImagesUrl` | `images.tuyaeu.com` | thing images CDN |
| `tuyaImagesUrl` | `images.tuyaeu.com` | tuya images CDN |
| `regionCode` | `EU` | region code |
| `httpPort` | `80` | plain HTTP port |
| `httpsPort` | `443` | HTTPS port |
| `httpsPskPort` | `443` | HTTPS-PSK port |
| `mqttPort` | `1883` | MQTT port |
| `mqttsPort` | `8883` | MQTTS port |
| `mqttsPskPort` | `8886` | MQTTS-PSK port |

The four un-probed EU-family hosts ranked for the TASK-0048 live probe:
`apigw-eu.iotbing.com` (fusionUrl), `a1-us.iotbing.com` (AZ-region mobileApiUrl,
the iotbing cloud's mobile-atop), `px.tuyaeu.com` (pxApiUrl), `a3.tuyaeu.com`
(deviceHttpsPskUrl). `a1-us.iotbing.com` is the AZ region's `mobileApiUrl`
(table above), included because the iotbing cloud (newer Smart-Life/"bing"
datacenter family) is the most likely place a key drawing `ILLEGAL_CLIENT_ID`
from the legacy `a1.tuyaeu.com` gateway is actually provisioned.

---

## FEED-FORWARD to TASK-0042 (the live re-attempt) (confidence: likely)

> **CORRECTED / SCOPED by TASK-0048 (host false-exhaustion).** The prior verdict
> here said the host hypothesis was "REFUTED by ground truth" at `confirmed`.
> That OVERTURNED claim rested on only the **`mobileApiUrl`** field of the EU
> regionConfig (`a1.tuyaeu.com`) — i.e. 1 of the 24 EU host fields. The
> regionConfig also carries `fusionUrl=apigw-eu.iotbing.com`, `pxApiUrl`,
> `deviceHttpsPskUrl=a3.tuyaeu.com`, and the AZ region's iotbing
> `mobileApiUrl=a1-us.iotbing.com` (full list above) — NONE of which were ever
> probed. A confirmed-correct appKey provisioned on the newer iotbing
> ("bing"/Smart-Life) datacenter family draws `ILLEGAL_CLIENT_ID` from the legacy
> `a1.tuyaeu.com` gateway. So the host avenue is NOT exhausted; the verdict is
> downgraded to `likely` and scoped to `mobileApiUrl` only.

Evidence: the decrypted `decompiled/apktool/assets/thing_domains_v1/regions` EU host
(PART 2) + `babymonitor/babymonitor-cli/src/live.rs` (PART 1); the prior live capture
`secrets/tuya_live_debug.json` (`a1.tuyaeu.com` → `ILLEGAL_CLIENT_ID`,
`re/live_login.md`).

1. **clientId wire param is CORRECT** — `live.rs` already sends `clientId=<appKey>` (and
   `time=<epoch_ms>`) on the wire query. No change required.
2. **EU `mobileApiUrl` = `a1.tuyaeu.com`** — and this is the host TASK-0042 already
   tried (`re/live_login.md`: `a1.tuyaeu.com` → `ILLEGAL_CLIENT_ID`). This refutes
   the host hypothesis ONLY for `mobileApiUrl`; the iotbing/px/a3/fusion EU-family
   gateways are UN-PROBED (TASK-0048 probes them).

**Scoped verdict (confidence: likely): the "wrong datacenter host" hypothesis is
refuted for `mobileApiUrl` only.** `ILLEGAL_CLIENT_ID` is NOT a clientId-param
problem. The remaining live hypotheses (for the operator to weigh) are, in order:
- a **wrong datacenter family** — the appKey may be provisioned on the iotbing
  cloud (`apigw-eu.iotbing.com` / `a1-us.iotbing.com`), not the legacy
  `a1.tuya*.com` gateway (TASK-0048 live probe);
- a **provisioning / app-cert-pin gate**: the public gateway may bind this appKey to the
  packaged app's signing identity (an `Authorization`/channel header or server-side
  app-cert check) that a standalone client cannot reproduce (the CAVEAT in TASK-0043);
- or a still-wrong **`sign`** input the gateway rejects at the identity layer before
  returning a sign-specific error (e.g. the unvalidated `bmp_token` candidate / MD5
  fold, `re/bmp_token_provenance.md`).

Changing `mobileApiUrl` will not fix it — but the iotbing/px/a3 EU-family hosts
were never tried, so the host avenue is NOT exhausted. TASK-0048 probes those
un-tried hosts (one `token.get` each) before concluding the host avenue is dead.
