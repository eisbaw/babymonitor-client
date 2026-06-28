# Wave-1 Analysis — Honesty + Architecture Audit (TASK-0006)

Read-only audit of the Wave-1 reverse-engineering doc SET for **honesty**,
**grounding** (TESTING.md Part 1), and **cross-doc consistency**. Scope: the ten
`re/*.md` analysis docs. Method: read all ten; build a cross-doc consistency
matrix; spot-check load-bearing citations against the current `just decompile`
tree; classify findings by severity; file each substantive one as a backlog task.

This doc itself makes claims about the other docs, so it carries its own
confidence + citation discipline and must pass `just check-evidence`. Where a
section asserts a fact about the protocol/code (sign, key, token, frame, port…) it
cites the **decompiled symbol** that grounds it, not the sibling `.md` (a `.md`
cross-reference is a navigation pointer, not an evidence source — TESTING.md:46-49).

> Citation note (symbol-anchored — TASK-0024): cites name a **symbol**
> (class/method/field) or a committed `re/symbols/*.txt` dump; any
> `decompiled/jadx/sources/...File.java ~:NN` line is an **approximate hint** for
> the current tree (jadx line numbers drift — grep the symbol). `decompiled/...`
> trees are gitignored; run `just decompile` to resolve them.

---

## Overall verdict (confidence: confirmed)

**The Wave-1 static foundation is SOUND for the Rust slice (auth → device →
stream), with TWO recorded cross-doc contradictions (both traceable to
`milestone2_findings.md` being the stale entry doc) and a short list of lower-
severity coherence/honesty nits.** The two contradictions are: (1) the
streaming-transport one in `js_bundle_map.md` (F1, P0/blocking, TASK-0025), and
(2) the **sign-sufficiency** one in `milestone2_findings.md` (F5, P1/deferrable,
TASK-0027) — milestone2 frames the appKey/appSecret as SUFFICIENT to sign,
which the later TASK-0005 spike (`tuya_sign.md` verdict `needs-runtime-hook`,
since SUPERSEDED → `partially-recoverable` per TASK-0023 `re/tuya_sign_static.md`)
refutes. A prior version of this audit overclaimed "ONE contradiction"; F5 was
missed and is now recorded below. The SOUND-foundation verdict stands (the gaps
are honestly flagged and recoverable); only the completeness/ONE-contradiction
claim was wrong. Two independent grounds: (1) a spot-check of 12
load-bearing symbols resolved at their EXACT cited paths in the decompiled tree —
e.g. `ThingApiSignManager.swapSignString`
(`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java`),
`ThingCameraConstants.P2PType` `P2P_TYPE_PPCS(2)`/`P2P_TYPE_THING(4)`
(`decompiled/jadx/sources/com/thingclips/smart/camera/api/ThingCameraConstants.java` ~:1612),
`KEY_APP_ID = "clientId"`
(`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java` ~:39);
and (2) the existing grounding gates pass over all ten docs
(`re/scripts/check_evidence.py`, `re/scripts/secret_scan.sh` — both GREEN before
this doc was added). The auth→device→stream contract (atop login envelope, `sid`
session, `DeviceBean.localKey`/`CameraInfoBean.P2pConfig` device records, 302-MQTT
WebRTC signaling) is internally consistent **except** two stale `milestone2`
framings, both corrected below: the streaming-transport evidence echoed in
`re/js_bundle_map.md` (F1), and the sign-sufficiency claim in
`re/milestone2_findings.md` (F5).

The one blocking item is a **factual** defect, not a grounding-label defect: the
grounding lint validates citation SHAPE, not CONTENT (already filed as TASK-0021),
so it passed a now-refuted claim.

---

## Per-doc honesty / grounding verdict (confidence: confirmed)

Each doc was checked for: confidence labels present + co-located; `confirmed` only
where ≥2 truly independent sources; honest static-vs-live boundaries; no
adjective-only claims; no secret values. **Confirmed** because the verdict in each
row was cross-checked against (1) the lint result over all ten docs
(`re/scripts/check_evidence.py` reports OK) AND (2) a resolved symbol in the
decompiled tree — e.g. the `js_bundle_map` DEFECT row is grounded by the absence of
`RTCPeerConnection`/`ice-ufrag` tokens in `decompiled/js/assets/kit_js/*.pretty`
and the presence of the real signaling symbol
`P2PMQTTServiceManager.send302MessageThroughMqtt`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`).

| Doc | Grounding | Honesty boundary | Verdict |
|---|---|---|---|
| `milestone2_findings.md` | OK (canonical labels) | TWO **stale** framings vs later spikes: streaming (P2P-first steer, F3) and **sign-sufficiency** (appSecret-alone "signs every request", F5) | SOUND, two staleness nits (F3, F5) |
| `decompile_dex.md` | OK — `confirmed` scoped to symbol PRESENCE only, interpretation re-labelled | honest about the 4g OOM partial run + 1,806 undecompiled method bodies | SOUND |
| `manifest_analysis.md` | OK — component/permission claims cited to manifest lines | service *behavior* (MqttService=signaling) correctly flagged `likely` | SOUND |
| `js_bundle_map.md` | label OK, but **CONTENT wrong** in one confirmed row | self-refuted by streaming_mode | **DEFECT (F1, blocking)** |
| `native_libs.md` | OK — SONAME/size confirmed, role per cited string | "no code-offset analysis" stated; version literals `likely` | SOUND |
| `streaming_mode.md` | OK — honestly flags native+Java as one SDK source, leans on public ref | clearest static-vs-live boundary in the set (5 explicit live-only items) | SOUND (the canonical doc) |
| `tuya_sign.md` | OK — every key/sign claim cited to Java + native | verdict `needs-runtime-hook` was contract-correct for TASK-0005, now **SUPERSEDED by `tuya_sign_static.md` (TASK-0023) → `partially-recoverable`** (banner added) | SOUND |
| `tuya_cloud_auth.md` | OK — envelope/login/bean shapes cited; `DeviceBean` correctly `likely` (single source) | obfuscated `a=` action names honestly flagged needs-live | SOUND |
| `tuya_cloud_config.md` | OK — encrypted-blob + atop-gateway claims two-sourced | datacenter-from-login boundary explicit | SOUND |
| `review_gate_findings.md` | OK — process record labelled `confirmed` with script citations | F1–F5 hypotheses carry their own confidence | SOUND |

---

## Cross-doc consistency matrix (confidence: confirmed)

The contract a Rust implementer reads across docs. **Confirmed** because each row's
"winner" was re-verified against the decompiled tree, not just against a sibling
`.md`: e.g. the 302 message code resolves to
`P2PMQTTServiceManager.send302MessageThroughMqtt`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`),
and the transport enum to `ThingCameraConstants` `P2P_TYPE_THING(4)`
(`decompiled/jadx/sources/com/thingclips/smart/camera/api/ThingCameraConstants.java` ~:1613).

| Topic | milestone2 | js_bundle_map | native_libs | streaming_mode | cloud_auth | Consistent? |
|---|---|---|---|---|---|---|
| **Streaming transport** | "cloud-brokered P2P", libThingP2PSDK = AV channel (stale) | "PlayNetKit … ICE 73 hits" (**WRONG**) | WebRTC-over-MQTT + PPCS fallback | WebRTC-over-MQTT preferred, PPCS fallback (VERDICT) | `CameraInfoBean.P2pConfig` has `ices`/`session` (WebRTC-shaped) | **NO — F1; streaming_mode WINS** |
| **`p2pType` semantics** | — | — | `skill` in connect_v2 encodes capability | `P2P_TYPE_PPCS(2)`/`P2P_TYPE_THING(4)`, per-device from cloud | `CameraInfoBean.p2pType` int field | YES |
| **MQTT signaling code 302** | MqttService is signaling candidate | `TUNIMQTTManager` publish | `SendMessageThroughMqtt` string | `send302MessageThroughMqtt`, code 302 | `Domain.*MqttUrl` brokers | YES |
| **Sign scheme** | "Tuya cloud signs (HMAC) with appKey/appSecret" — implies appSecret-alone is **SUFFICIENT** (stale) | atop `apiRequestByAtop` carries sign | `libthing_security` whitebox flagged | (defers to tuya_sign) | atop envelope `sign` param | **milestone2 STALE (sign-sufficiency) — F5; tuya_sign WINS (TASK-0027). appSecret-alone-insufficient still holds; hash is plain MD5 not HMAC (TASK-0023, `tuya_sign_static.md`)** |
| **Sign verdict** | recovery is next task | — | flagged for task 5 | — | ~~`needs-runtime-hook`~~ → **`partially-recoverable`** (SUPERSEDED per TASK-0023, `tuya_sign_static.md`: cert-SHA256 offline-computable + hash is MD5; only the `t_s.bmp` decode (TASK-0029) remains — no device needed) | YES |
| **Datacenter selection** | region config bundled | not in JS (F5) | — | `Domain.*Url` brokers | runtime-from-login `User.domain` (F5) | YES |
| **Static vs live boundary** | P2P wire = speculative | auth/creds are native/live | no code-offset done | 5 explicit live-only items | §7 live-unknowns table | YES |
| **Secret handling** | location-only | schema names only, scan clean | symbol/string only | demo-bean values not reproduced | `localKey`/`p2pKey`/`password` = secret, secrets/ only | YES |

**Two recorded contradictions, both rooted in the stale `milestone2` entry doc:**
streaming transport (F1, `js_bundle_map` echoes it) and **sign-sufficiency** (F5,
`milestone2` claims appSecret-alone signs). Everywhere else the spot-checked rows
converge — but that convergence claim is bounded by the spot-check (see
Limitations): the SHAPE-not-CONTENT lint gap (F4/TASK-0021) means an
unspot-checked row could still hide a contradiction, exactly as F5 did until this
meta-review.

---

## Findings

Severity: **P0/blocking** = wrong on the wire / a Rust implementer would build the
wrong thing; **P1** = honesty/coherence gap that misleads but is recoverable; **P2**
= nit.

### F1 — `js_bundle_map.md` asserts a streaming-transport claim that `streaming_mode.md` refutes (P0, blocking) (confidence: confirmed)

`re/js_bundle_map.md` §kit_js (~:45) describes `miniapp_PlayNetKit.js` as
"streaming play-mode + ICE (73 `ice` hits)" inside a `confidence: confirmed`
section — implying WebRTC ICE primitives live in the JS. `re/streaming_mode.md`
(~:54-62, TASK-0017, the later doc) explicitly CORRECTS this as a false positive.
**Independently re-verified for this audit (two sources):** (1) a token grep of
the reflowed bundle — `rg -io '[a-z]*ice[a-z]*'
decompiled/js/assets/kit_js/miniapp_PlayNetKit.js.pretty` yields only
`onScanDeviceInfo`, `slice`, `connectMatterDevice`-style substrings, NO WebRTC
`ice`; and (2) a grep for real WebRTC handshake primitives —
`rg -lc 'RTCPeerConnection|createOffer|ice-ufrag'
decompiled/js/assets/kit_js/*.pretty` — returns **zero** hits. So the JS layer is
transport-agnostic; the real WebRTC SDP/ICE machinery is native
(`re/symbols/libThingP2PSDK.dynsym.txt`).
**(Superseded 2026-06-28, v0.1.0-live-stream):** F1's confirmed core stands — the
SDP/ICE/WebRTC-signaling machinery is native, not in the JS bundle, and ICE *is*
used for connectivity in the live pipeline. But the earlier media-crypto detail
"DTLS-SRTP" (dropped above) is FALSIFIED: the live media transport is KCP +
AES-128-CBC(inline-IV, PKCS7) per segment + 20-byte HMAC-SHA1(media_key16) per
datagram, NOT DTLS-SRTP (TASK-0083 DONE; keyframe decodes end-to-end).
**Why blocking:** a Rust implementer reading js_bundle_map first could chase a
non-existent JS WebRTC stack. **Winner: `streaming_mode.md`.**
**Fix:** correct the `js_bundle_map.md` PlayNetKit row to remove the "73 ice hits"
claim and point at the streaming_mode FP-correction; downgrade any inference that
ICE lives in JS. This is a CONTENT defect the SHAPE-only lint cannot catch (the
structural root cause is the open TASK-0021).

### F2 — `js_bundle_map.md` PlayNetKit role text overstates streaming capability (P2, folds into F1) (confidence: likely)

The same row labels PlayNetKit a "Play/network kit — streaming play-mode" as if it
carried session/ICE logic. The manifests it relies on
(`decompiled/js/assets/thing_uni_plugins/TUNIIPCCameraManager.json`,
`connect`/`createMediaDevice` with `{deviceId}`-only params per `streaming_mode.md`
~:46-52) show the JS only names the bridge `connect` verb — no media-session
fields. Single-source nit; fix alongside F1.

### F3 — `milestone2_findings.md` streaming framing is stale vs the TASK-0017 verdict (P1) (confidence: likely)

`re/milestone2_findings.md` (~:78,88,98) frames streaming as "P2P streaming … most
likely brokered through Tuya servers", calls `libThingP2PSDK` "the audio/video
session channel" and "the riskiest piece", with no pointer to the later
WebRTC-over-MQTT verdict. The relevant symbol — `ThingCameraConstants.P2PType`
`P2P_TYPE_THING(4)`
(`decompiled/jadx/sources/com/thingclips/smart/camera/api/ThingCameraConstants.java` ~:1613) —
shows WebRTC is the preferred per-device transport. The claims are labelled
`likely`/`speculative`, so this is NOT a grounding violation, but a reader hitting
milestone2 first gets a P2P-first steer the set later reverses. **Fix:** add a
one-line forward-pointer in milestone2 to the `streaming_mode.md` verdict (it is
the project's entry doc). Low risk, high navigational value.

### F4 — Grounding lint passed a refuted claim: SHAPE-not-CONTENT (P1, already filed) (confidence: confirmed)

F1 proves the concrete failure mode TASK-0021 predicted: the lint passed
`js_bundle_map.md` over 10 docs even though one confirmed-section claim is factually
false, because it checks for a citation TOKEN's presence, not that the token
actually supports the claim. Two independent grounds for THIS finding: (1) the
refuted claim cites a real-but-irrelevant bundle path
(`decompiled/js/assets/kit_js/miniapp_PlayNetKit.js`) that satisfies the SHAPE
check, while (2) the contradicting evidence is a different real symbol —
`P2PMQTTServiceManager.send302MessageThroughMqtt`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`) —
that the lint never compares against. No new task needed — TASK-0021
("check-evidence validates citation SHAPE not CONTENT, false-attribution passes")
already owns this; F1 should be cross-referenced to it as a real instance. Recorded
here for completeness, not re-filed.

### F5 — `milestone2_findings.md` frames appKey/appSecret as SUFFICIENT to sign; the TASK-0005 spike refutes it (P1, deferrable, filed TASK-0027) (confidence: confirmed)

`re/milestone2_findings.md` "What this means for the reimplementation" point #3
(~:84) states the embedded Tuya appKey/appSecret are the highest-value artifact
because "Tuya cloud signs every API request (HMAC) with these; they are required
to reimplement cloud auth" — framing appSecret as the SUFFICIENT sign key. The
later TASK-0005 spike (`re/tuya_sign.md`) refutes this: it proves appKey/appSecret
ALONE are INSUFFICIENT. **This was
MISSED by the first version of this audit, which overclaimed "ONE contradiction";
it is the second.** **SUPERSESSION (TASK-0023, `re/tuya_sign_static.md`):** the
appSecret-alone-insufficient conclusion STILL HOLDS (the key also folds in the
cert-SHA-256 and the decoded `t_s.bmp` token), but the earlier `needs-runtime-hook`
verdict cited below is now superseded by `partially-recoverable` — the static dive
showed the cert-SHA-256 is **offline-computable** from the APK signing cert and the
keyed hash is plain MD5, so a **device is NOT required**; only the `t_s.bmp`
token-decode port (TASK-0029) remains. Two independent grounds (decompiled-artifact, not sibling
`.md`): (1) the keyed-sign step is native — `pbddddb.bdpdqbp(String)` calls
`doCommandNative(context, 1, str2…)` (command code 1 = produce request signature)
in `decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java`, and the key
material (`generateCertificate`/`X509Certificate`/`SHA256`/`t_s.bmp` strings)
clusters in `lib/arm64-v8a/libthing_security.so` — so the sign KEY is
`key = [app_cert_SHA256]_[decoded_t_s.bmp_token]_[appSecret]` (review-gate F1),
and (2) the public mobile-sign write-up `nalajcie/tuya-sign-hacking` documents the
same cert+BMP+appSecret derivation, NOT a plain-appSecret HMAC. The earlier framing
held the app-cert SHA-256 to be a *runtime* input and the keyed-hash routine
un-recovered (`tuya_sign.md` "What is and isn't statically reproducible" table);
**TASK-0023 (`re/tuya_sign_static.md`) overturns the device-needed part:** the
cert-SHA-256 is offline-computable from the APK signing cert and the keyed hash was
disassembled to plain MD5, leaving ONLY the (deterministic, offline) `t_s.bmp`
matrix-deobfuscated token un-ported (TASK-0029) — so the ingredients are
statically/offline obtainable, not device-bound. **Why
deferrable:** milestone2's point #3 carries no canonical confidence label on the
sufficiency clause (it predates the spike), so this is a staleness/coherence
defect — the same class as F3, not a P0 wire-error. A reader hitting milestone2
first (the entry doc) is steered to believe appSecret alone unblocks cloud auth,
which the set later reverses. **Winner: `tuya_sign.md`.** **Fix (filed TASK-0027,
`--dep TASK-0005`/`TASK-0007`):** correct/forward-point milestone2 point #3 to the
`tuya_sign.md` verdict (now **`partially-recoverable`** per TASK-0023,
`re/tuya_sign_static.md`), stating appSecret alone is insufficient (also needs the
app-cert SHA-256 + decoded `t_s.bmp` token) — but note the app-cert SHA-256 is
offline-computable and the hash is MD5, so only the `t_s.bmp` decode (TASK-0029) is
un-ported and **no device is required**.

### Non-findings (avoided false positives, recorded for the reviewer)

- **`tuya_sign.md` verdict token `needs-runtime-hook`** (now SUPERSEDED → see
  `re/tuya_sign_static.md` / TASK-0023; retained here only as a token-set note) is
  NOT in TESTING.md's
  canonical `{recoverable-statically|partially|needs-live-capture}` set, but
  TASK-0005 AC#3 explicitly defines THIS spike's token set as
  `{recoverable-statically|needs-runtime-hook|needs-live-capture}`, and the
  labelled-verdict lint only enforces the canonical set on `re/p2p_protocol.md`
  (absent). Contract-correct, not a finding. (confidence: confirmed — TASK-0005
  AC#3 + `re/scripts/check_evidence.py` VERDICT_RE keys on `p2p_protocol.md`.)
- **`streaming_mode.md` "Transport identity" `confirmed`** rests on native+Java
  that the doc itself flags as "not fully independent, both are the Tuya SDK"
  (~:68); the genuinely-independent second source is the public ref
  `seydx/tuya-ipc-terminal`. The `confirmed` is defensible (≥2 distinct tokens, one
  a real public ref) AND the doc is honest about the SDK-layer dependency. Strength,
  not a finding. (confidence: likely.)
- **`tuya_cloud_auth.md` §5b `DeviceBean` labelled `likely` not `confirmed`** — it
  correctly refuses to count the sibling `re/review_gate_findings.md` note as a
  second source (single decompiled source = `likely`). Exactly the TASK-0024 rule
  applied honestly. (confidence: confirmed — `DeviceBean.localKey`
  `decompiled/jadx/sources/com/thingclips/smart/sdk/bean/DeviceBean.java` is one
  source.)

---

## Citation-rot spot-check result (confidence: confirmed)

12 load-bearing symbols across 6 docs were resolved at their EXACT cited paths in
the current `just decompile` tree; **all 12 resolve, zero rot.** Verified:
`swapSignString` + `generateSignatureSdk`
(`decompiled/jadx/sources/com/thingclips/sdk/network/ThingApiSignManager.java`);
`pbddddb.bdpdqbp`
(`decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java`);
`pqdbppq` `thing.m.user.*`/`sso.ticket`/`region.list` table
(`decompiled/jadx/sources/com/thingclips/sdk/user/pqdbppq.java`);
`checkAPIName` thing→smartlife rewrite + `KEY_APP_ID="clientId"`
(`decompiled/jadx/sources/com/thingclips/smart/android/network/ThingApiParams.java` ~:236,39);
`P2P_TYPE_PPCS(2)`/`P2P_TYPE_THING(4)`
(`decompiled/jadx/sources/com/thingclips/smart/camera/api/ThingCameraConstants.java` ~:1612);
`send302MessageThroughMqtt`
(`decompiled/jadx/sources/com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java`);
`IThingP2P.resendOffer` at line 57
(`decompiled/jadx/sources/com/thingclips/smart/p2p/api/IThingP2P.java`);
`CameraInfoBean.P2pConfig.p2pKey`
(`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/bean/CameraInfoBean.java`);
and the `||` sign separator `pbpdbqp = "||"`
(`decompiled/jadx/sources/com/thingclips/sdk/mqtt/pbbppqb.java` ~:26).
**Method caveat:** a naive `rg -l SYMBOL | head -1` returns WRONG files for
obfuscated names (`pbddddb`, `qpppdqb`, `LoginBusiness`, `P2pConfig` are reused
across many classes); the docs' fully-qualified PATHS disambiguate correctly. This
collision is itself the reason the symbol-anchored convention (TASK-0024) must
keep the path, not just the bare name.

---

## Architecture coherence for the Rust slice (confidence: confirmed)

The auth→device→stream contract is usable as a unit. Two independent grounds: the
login/envelope symbols resolve (`LoginBusiness`
`decompiled/jadx/sources/com/thingclips/smart/login/skt/business/LoginBusiness.java`,
`User.getSid`
`decompiled/jadx/sources/com/thingclips/smart/android/user/bean/User.java`) AND
the device/stream record symbols resolve (`DeviceBean`,
`CameraInfoBean.P2pConfig`). The contract:
1. **Auth:** atop gateway, 2-step ticket login (`username.token.get` →
   `email.password.login`), session = `sid`, datacenter = `User.domain.mobileApiUrl`
   — all symbol-grounded in `tuya_cloud_auth.md`.
2. **Device:** `HomeBean.deviceList` → `DeviceBean` (with secret `localKey`) →
   per-device `CameraInfoBean` fetch.
3. **Stream:** `p2pType`/`skill` select WebRTC-over-MQTT (code 302) vs PPCS; the
   `frame`/`packet` AV path is native and deferred to Wave-2 spikes
   (TASK-0009/0010). *(Forward-pointer, 2026-06-28, v0.1.0-live-stream: this
   Wave-1-era deferral is now resolved — the live media transport is implemented
   (TASK-0083 DONE) and a 1080p H.264 keyframe decodes end-to-end.)*

**Gaps a Rust implementer would trip on (all honestly flagged in the docs, none
hidden):** the byte-exact `sign` was `needs-runtime-hook` but is now
**`partially-recoverable`** (SUPERSEDED, TASK-0023 `re/tuya_sign_static.md`: hash is
MD5, cert-SHA-256 offline-computable; only the `t_s.bmp` decode (TASK-0029) remains —
no device); the on-wire `a=` action names are R8-obfuscated to `n`
(`tuya_cloud_auth.md` §6); the datacenter host is runtime-from-login. The contract is
internally INCONSISTENT in TWO places, both stale `milestone2` framings the later
spikes reverse: the streaming-transport evidence echoed in js_bundle_map (F1,
TASK-0025) and the sign-sufficiency claim in milestone2 (F5, TASK-0027) — fixing
both removes the last traps. (The byte-exact `sign` gap above is honestly flagged,
not a contradiction; F5 is specifically milestone2's *contradicting* framing of it
as appSecret-sufficient.)

---

## Triage — blocking vs deferrable (confidence: confirmed)

Each disposition's underlying finding is grounded in its F-section above; the two
deferred sign/streaming dispositions in particular rest on resolved decompiled
symbols — `pbddddb.bdpdqbp(String)` → `doCommandNative(…,1,…)`
(`decompiled/jadx/sources/com/thingclips/sdk/network/pbddddb.java`) for the F5
sign-sufficiency call, cross-checked against `nalajcie/tuya-sign-hacking` — not on
sibling `.md` cross-references.

| Finding | Severity | Filed as | Disposition |
|---|---|---|---|
| F1 — js_bundle_map streaming contradiction | **P0/blocking** | new task `--dep TASK-0003` | **BLOCKING** — must fix before Wave-1 closes (TASK-0015 gate); it is a factual cross-doc contradiction |
| F2 — PlayNetKit role overstated | P2 | folded into F1 task | fix with F1 |
| F3 — milestone2 streaming staleness | P1 | new task `--dep TASK-0017` | **DEFERRABLE** — labelled, not a grounding violation; fix is a one-line forward-pointer; do before re-plan (TASK-0016) |
| F4 — lint SHAPE-not-CONTENT | P1 | **already TASK-0021** | DEFERRED (open) — F1 is its concrete instance; cross-reference, do not re-file |
| F5 — milestone2 sign-sufficiency staleness | P1 | new task `--dep TASK-0005`/`TASK-0007` (TASK-0027) | **DEFERRABLE** — staleness/coherence, not a P0 wire-error; fix is a forward-pointer to the sign verdict (now `partially-recoverable`, SUPERSEDING `needs-runtime-hook` per TASK-0023 `re/tuya_sign_static.md`); do before re-plan (TASK-0016). MISSED by the first audit version — the "ONE contradiction" headline was wrong. |

The wave does not silently advance past F1: it is filed P0/blocking and deps the
streaming gate. F3 and F5 are consciously deferred (low-risk, navigational/coherence)
with reason, each with a filed fix task (TASK-0026, TASK-0027) due before re-plan.

---

## Limitations of this audit (confidence: confirmed)

- **Spot-check, not exhaustive — and DEMONSTRABLY so.** 12 of ~100+ citations
  across the set were resolved; the SHAPE-not-CONTENT gap (F4/TASK-0021) means an
  unspot-checked citation could still be mis-attributed. The first version of this
  audit proved the point against itself: it overclaimed "ONE contradiction" and
  MISSED F5 (the milestone2 sign-sufficiency staleness), caught only on
  meta-review. The convergence claim in the matrix is therefore bounded by the
  spot-check, not a guarantee. Cited evidence is `re/scripts/check_evidence.py`
  (passes all 11 docs) + the 12 resolved symbols above.
- **No code-offset/disassembly** was done here either — native claims
  (`libthing_security.so` cmd=1 sign, `libThingP2PSDK.so` framing) were taken as the
  docs present them (string/symbol level), consistent with the docs' own scope.
- **Live-only items inherited honestly.** The audit confirms the static-vs-live
  boundaries are drawn; it cannot confirm the live side (the SCD921 `p2pType`,
  byte-exact `sign`, real `localKey`) — those remain the gold-oracle's job
  (TESTING.md Part 2).
- **No secret value** appears in this doc; it records symbols and locations only.
  `just secret-scan` covers it.
