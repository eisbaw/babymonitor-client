# PII / Secret Exposure Inventory — IDENTIFY ONLY (TASK-0109)

A **map** of where PII and secrets live across this project. **Identification only —
nothing is scrubbed, redacted, moved, or modified by this task.** A separate
remediation task acts on these findings.

**No secret or PII value appears in this file.** Every entry references a
**location** (`file:line` / `secrets/` path / git object) plus a non-secret
descriptor (field name, char-count, type). Real recovered values live ONLY under
`secrets/` (gitignored) or in the live capture trees; this doc points at them, it
does not reproduce them.

Method: `git ls-files` / `git check-ignore` / `git log` for tracked-vs-ignored
state; `rg` over `decompiled/apktool` (post-R8 smali = ground truth for literals),
`decompiled/jadx/sources`, `decompiled/js`, committed `re/*.md` + `backlog/tasks/*.md`,
and the `secrets/` + `emulator_captures/` filenames. Values were never copied into
this doc. Confidence is stated per finding.

> Tracked-state legend (the classification the task asks for):
> - **TRACKED** — committed in git (already public to anyone with the repo).
> - **UNTRACKED-committable** — present in worktree, NOT gitignored → a `git add .`
>   would commit it next (accidental-commit risk surface).
> - **GITIGNORED** — excluded from commits (quarantined); still on local disk.
> - **HISTORY** — no longer in HEAD but retained as a git blob in past commits.

---

## 0. Verdict (confidence: high)

- **Live committed source is clean of credential *values*.** `just secret-scan`
  passes (worktree + pending diff + `backlog/tasks/*.md`). No appKey/appSecret/
  localKey/token/email/GPS *value* sits in a tracked text file.
- **Two real-value exposures DO sit in committed/committable text** that the scanner
  does not pattern-match: (a) the real Tuya **productId** (16-char model id) in
  several `re/*.md` + backlog tasks, and (b) **4-char value fingerprints** of the
  appKey/appSecret/encrypt-keys in `re/identity_enumeration.md`. Both are low-bit
  partial identifiers, not full secrets — see §2.
- **The single highest-severity finding is git HISTORY**, not the worktree: the
  cap0–cap3 raw mitmproxy capture blobs — which the `.gitignore` itself states
  contain real `localKey`/`devId`/`appKey`/media-keys/PII — were committed in 5
  past commits, removed from HEAD, and persist as retrievable git objects. The
  secret-scan does **not** scan history, so it is a blind spot (§5).
- All full-strength secrets (cloud creds, session tokens, device list, localKey,
  media keys, decoded baby-cam frames) are correctly quarantined under `secrets/`
  and `emulator_captures/`, both GITIGNORED (§4).

Severity scale used: **P0** = full secret/credential or account-identifying PII in
a committed/committable surface; **P1** = partial identifier or sensitive material in
history/ignored store; **P2** = low-bit identifier / synthetic / owner-self PII;
**info** = structural note, no exposure.

---

## 1. Hardcoded credentials / keys / endpoints in the APK & decompiled output (AC #2)

**All of `decompiled/**` and `extracted/**` are GITIGNORED** (`.gitignore:8-9`), so
none of the literals below are committed — they are recoverable only by re-running
jadx/apktool on the (also-gitignored) `*.xapk`. Tracked-state for this entire
section = **GITIGNORED (regenerable)**. Severity reflects intrinsic sensitivity of
the value, not commit exposure.

| # | Type | Location (evidence) | Field / descriptor | Severity |
|---|------|---------------------|--------------------|----------|
| 1.1 | Tuya mobile-app **appKey** (20-char) | `decompiled/apktool/smali_classes8/com/thingclips/sample/BuildConfig.smali:25`; R8-inlined at `…/com/smart/app/SmartApplication.smali:551` | `THING_SMART_APPKEY` → `mAppId` → wire `clientId` | P0 |
| 1.2 | Tuya mobile-app **appSecret** (32-char) | `…/thingclips/sample/BuildConfig.smali:29`; inlined `…/smart/app/SmartApplication.smali:555` | `THING_SMART_SECRET` → `mAppSecret` | P0 |
| 1.3 | Tuya **ttid / app-scheme** fingerprint | `…/thingclips/sample/BuildConfig.smali:33`; `decompiled/apktool/res/values/strings.xml:577` (`app_scheme`) | `THING_SMART_TTID` (raw, not the wire ttid) | P2 |
| 1.4 | Tuya **encryptImage key** (20-char) | `…/com/smart/app/ThingNGConfig.smali:68` | `appEncryptKeyProdV2` (media/image encrypt) | P1 |
| 1.5 | Tuya **CV encryptImage key** (20-char) | `…/com/smart/app/ThingNGConfig.smali:64` | `appEncryptKeyCvProdV2` (camera/CV encrypt) | P1 |
| 1.6 | **Firebase Web API key** (39-char) | `decompiled/apktool/res/values/strings.xml:2857` | `google_api_key` | P1 |
| 1.7 | **Firebase app id** (45-char) | `…/res/values/strings.xml:2858` | `google_app_id` | P1 |
| 1.8 | **Firebase crash-reporting API key** (39-char) | `…/res/values/strings.xml:2859` | `google_crash_reporting_api_key` | P1 |
| 1.9 | **Google OAuth web client id** (72-char) | `…/res/values/strings.xml:2193` | `default_web_client_id` | P1 |
| 1.10 | **FCM sender id** (12-digit) | `…/res/values/strings.xml:2813` | `gcm_defaultSenderId` | P2 |
| 1.11 | **Firebase project id** (15-char) | `…/res/values/strings.xml:7170` | `project_id` | P2 |
| 1.12 | Tuya **vdevo** virtual-device id (test/demo) | `decompiled/apktool/smali_classes8/com/gzl/smart/gzlminiapp/ide/dtools/DToolsSmartApiTestFragment.smali` (const-string) | demo device id, ruled out in `re/identity_enumeration.md` §3 | P2 |
| 1.13 | Embedded **sign-token assets** | `decompiled/apktool/assets/t_s.bmp`, `…/assets/fixed_key.bmp` | feed the native sign-key derivation (`re/bmp_token_whitebox.md`); not values themselves | P1 |

Confidence per row: **high** (each literal is at the cited smali/xml offset; the
appKey/appSecret wiring is cross-confirmed in `re/identity_enumeration.md` §1 via
both smali and jadx).

Notes (confidence: high):
- **Endpoints are NOT hardcoded as plaintext.** A smali sweep for `https://…tuya…`
  in `decompiled/apktool/smali_classes8` returns nothing; the datacenter host list
  is AES-256-CTR-encrypted in `decompiled/apktool/assets/thing_domains_v1` and
  decrypted at runtime (`re/regions_decrypt.md`). So there is no committed/plaintext
  endpoint secret to catalogue — only an encrypted asset + its asset-embedded key.
- **Per-vendor push slots are EMPTY** (informational, no exposure): `meizu_app_key`
  `mi_app_key` `oppo_app_key` `oppo_app_secret` `qqAppKey` `vivo_app_key`
  `simAppKey` `wxAppKey` `huawei_app_id` `honor_app_id` `xg_app_id` are all
  self-closing `<string name="…" />` in `decompiled/apktool/res/values/strings.xml`
  (lines 3300, 3833, 5552-5553, 5617-5618, 6851-6853, 7198, 7723-7724, 10811-10812,
  11042, 11045). They are key *slots* with no value.
- **Native libs carry no identity literal** — a `strings` sweep of
  `decompiled/nativelibs/*.so` finds no appKey/appSecret-shaped literal
  (`re/identity_enumeration.md` §5). The appKey is injected from Java at init.
- **The JS bundle (`decompiled/js/**`) holds no hardcoded secret values** — the
  `thing_uni_plugins/*.json` files are method/parameter *schema* maps (e.g.
  `TUNIIPCCameraManager.json`, `TUNIMQTTManager.json`) where keys equal their own
  names (`"deviceId":"deviceId"`); no credential value is embedded. (Also
  GITIGNORED under `decompiled/`.)

---

## 2. Committed / committable `re/*.md` docs & backlog task fields (AC #3 — highest accidental-commit risk)

This is the surface that gets pushed to a remote. Two real partial-value exposures
exist; per-unit account identifiers were kept out (good discipline).

### 2.1 Real Tuya **productId** (16-char device-model id) in committed/committable text — P2 (confidence: high)

The genuine SCD921 productId appears verbatim (the value, not a fingerprint) in:

| Location | Tracked-state |
|----------|---------------|
| `backlog/tasks/task-0017 - TRIAGE-WebRTC-over-MQTT-vs-P2P-streaming-mode-decision.md` (Notes) | **TRACKED** |
| `backlog/tasks/task-0065 - Complete-full-live-login-…device.list.md` (Notes) | **TRACKED** |
| `backlog/tasks/task-0067 - Unifysharpen-camera-detection-…disambiguation.md` (Notes) | **TRACKED** |
| `re/motion_detection.md` | **UNTRACKED-committable** |
| `re/video_diary.md` | **UNTRACKED-committable** |

Severity P2: a productId identifies the Tuya **product/firmware model** (shared by
every SCD921 unit), not the user's individual device or account — it is far less
sensitive than a per-unit `devId`/`localKey`. But it IS a real recovered identifier
and the PRD/CLAUDE.md "never leak a real … device id" rule is conservative, so it is
catalogued. The secret-scan has no productId pattern, so it does not catch this.

Good-discipline corollary (confidence: high): `task-0065` references the recovered
`devId` only by **char-count** ("devId recovered (22 chars)") — the per-unit value is
NOT printed. A structural sweep of committed `re/`+`backlog/` for unredacted
`devId`/`uid`/`homeId`/`p2pId`/`sessionId` *values* (≥12 alnum, minus synthetic
markers) returned **zero** hits — the truly sensitive per-account identifiers were
correctly kept out of committed text.

### 2.2 4-char value **fingerprints** of appKey/appSecret/encrypt-keys — P2 (confidence: high)

`re/identity_enumeration.md` (**TRACKED**) prints the last-4-char tails (e.g. in its
§0 prose and the §3 candidate table, lines ~30 and ~170-174) of the appKey (20-char),
appSecret (32-char), and the two `appEncryptKey*ProdV2` keys (20-char). Four trailing
chars is insufficient to reconstruct a key, but it is partial-value leakage of secret
material into a committed doc and is recorded here for the remediation pass.

### 2.3 Owner email (self-PII) in the scanner script — P2 (confidence: high)

`re/scripts/secret_scan.sh` (**TRACKED**) contains the project owner's own email in
the `ALLOW_SUBSTRINGS` allowlist (the entry comment) and in the `--selftest` "clean
file" fixture. This is the owner's own already-public address used for git-config
docs and is deliberately allowlisted — low severity, listed for completeness.

### 2.4 Synthetic test emails in Rust (committed, no real PII) — info (confidence: high)

`babymonitor/babymonitor-cli/src/live.rs` (**TRACKED**) uses placeholder login emails
in unit tests on an allowlisted documentation domain (`example.com`); these are
synthetic, not real PII. The scanner passes them via its `example.com` allowlist.

### 2.5 Field-name discussion is pervasive but value-free — info (confidence: high)

`localKey`/`devId`/`uid`/`homeId`/`p2pId`/`p2pType` appear as **field names** in
100+ committed docs/tasks (protocol description). That is expected and carries no
value exposure; only the §2.1/§2.2 items expose real partial values.

---

## 3. Test fixtures (committed) — SYNTHETIC, no exposure (AC #1 completeness) (confidence: high)

The only deliberately-committed JSON/JSONL "data" fixtures are synthetic and
un-ignored by name (`.gitignore:37-46`):

- `babymonitor/babymonitor-core/tests/fixtures/device_list.json` — **TRACKED**,
  every value `SYNTH_*`/`synth-*` (see its `_comment`); fake `devId`/`localKey`/
  `secKey`/`uuid`/`productId`.
- `…/tests/fixtures/camera_info.json` — **TRACKED**, synthetic.
- `…/tests/fixtures/signaling_cap3_redacted.jsonl` — **TRACKED**, redacted/synthetic
  cap3 signaling.
- `…/tests/fixtures/rtc_config_redacted.json` — **TRACKED**, synthetic ids/keys.

`fixtures/` is otherwise GITIGNORED by default (`.gitignore:31`) so a real captured
fixture cannot be committed accidentally. No real value present → **info**.

---

## 4. GITIGNORED secret/capture stores — quarantined (AC #1) (confidence: high)

Not committed (`git ls-files secrets/` and `git ls-files emulator_captures/` both
return 0; `.gitignore:14-15,75`). On local disk only. Catalogued by **filename type**
— values were not read into this doc.

### 4.1 `secrets/` (GITIGNORED — sanctioned secret store; the scanner deliberately skips it)

| Type | Files (secrets/…) | Severity if leaked |
|------|-------------------|--------------------|
| Tuya cloud creds (appKey/appSecret) | `tuya_appkey.json`, `tuya_appkey_candidates.json` | P0 |
| Session / auth tokens, MFA state | `tuya_session.json`, `tuya_login.json`, `tuya_2fa.txt`, `tuya_2fa_state.json`, `tuya_live_debug.json`, `tuya_live_debug_probe1_candidate.json` | P0 |
| Account profile PII | `android_profile.json` | P0 |
| Per-unit device data (devId/localKey/homeId/uid) | `tuya_device_list.json`, `tuya_home_list.json`, `device_id.txt`, `localkey.txt` | P0 |
| Derived crypto material | `chkey.txt`, `chkey.txt.stale-20260625232751`, `bmp_token.txt`, `aes_iv_const_0x85f5.bin`, `decoded_tecrkcehc_ext.bin` | P0 |
| RTC/stream signaling + media keys | `tuya_rtc_config.json`, `smartlife.m.rtc.config.get.json`, `smartlife.m.rtc.log.json`, `smartlife.m.p2p.main.pre.link.get.json`, `offer_302_frame.bin`, `cap4_keys.txt`, `cap1_rtc_decrypted/`, `cap5/` | P0 |
| Raw cloud API responses (account data) | `smartlife.m.api.batch.invoke.json`, `…invoke_1/_2/_3.json` | P0 |
| **Decoded baby-cam media (imagery/audio of the home)** | `cap4_video.h264`, `cap4_audio.wav`, `cap4_audio.s16le`, `cap4_frames/`, `frame_001.png`…`frame_008.png` | P0 (sensitive imagery) |
| Cert-pinning config | `cert_pinning_config.json` | P2 |

### 4.2 `emulator_captures/` (GITIGNORED in HEAD)

`cap0`…`cap6` — Frida/mitmproxy decrypted flows containing real `localKey`/`devId`/
`appKey`/media-keys/signatures/PII per the `.gitignore:70-75` warning. **Currently
none are tracked** (`git ls-files emulator_captures/` = 0). **But see §5 — they were
committed historically.**

---

## 5. git HISTORY exposure — the scanner's blind spot (HIGHEST SEVERITY) — P0 (confidence: high)

The secret-scan covers worktree + pending diff + `backlog/tasks/*.md` only; it does
**not** walk git history (`rg 'rev-list|git log|git show' re/scripts/secret_scan.sh`
= no match). The following real-PII capture blobs were committed and then removed
from HEAD, but remain retrievable as git objects:

- Committed in commits `20a6d67` (cap0+cap1), `5603d96` (cap2+cap3), `1a69576`,
  `d13317e`, `ac5ba55`. Files (18) include `emulator_captures/cap{0,1,2,3}/flows.json`,
  `flows.mitm`, `flows.full.txt`, and `cap3/signaling_plaintext.jsonl`.
- Removed from tracking in `ac5ba55` (`.gitignore` tightened); **HEAD tree count = 0**.
- **Blobs are still retrievable**, e.g. `git show 20a6d67:emulator_captures/cap0/flows.json`
  returns ~253 KB; `…cap1/flows.mitm` ~2.1 MB; `…cap3/signaling_plaintext.jsonl`
  ~8 KB. These carry the real cloud-API PII, localKey, and decrypted 302 signaling +
  media key that the `.gitignore` explicitly says must "never be committable".

This is the one place where full-strength secrets/PII sit in a versioned artifact.
Identification only — **no history rewrite is performed by this task.**

---

## 6. Severity roll-up

| Severity | Surface | Items |
|----------|---------|-------|
| **P0** | git HISTORY (versioned) | §5 — cap0–cap3 raw flows + decrypted signaling/media key |
| **P0** | GITIGNORED (local only) | §4 — all `secrets/**` + `emulator_captures/**` |
| **P0/P1** | GITIGNORED (regenerable from gitignored xapk) | §1 — appKey/appSecret/Firebase/encrypt-keys in `decompiled/**` |
| **P2** | TRACKED + UNTRACKED-committable text | §2.1 productId; §2.2 4-char fingerprints; §2.3 owner email |
| info | TRACKED | §3 synthetic fixtures; §2.4 synthetic test emails; §2.5 field names |

The **committed/committable** exposures are bounded: a real productId (model id) and
4-char key tails (§2), plus the owner's own email (§2.3). The **serious** material is
either gitignored (§1, §4) or in history (§5).

---

## 7. Residual unknowns & what would unblock (confidence: medium)

- **Full history sweep depth.** §5 verified the cap0–cap3 path by name and confirmed
  three blobs are non-empty. A complete audit would run a content scanner (e.g.
  `git log -p --all` piped through the secret patterns, or `trufflehog`/`gitleaks`
  in `--no-update` history mode) across **all** historical blobs, not just the
  emulator_captures path, to catch any other secret that transited a commit and was
  later removed. Not done here (identify-only, and would risk printing values).
- **Whether the productId counts as "device id" under the project rule.** Treated as
  P2 (a shared model id, not per-unit). If the remediation owner deems any device
  identifier in-scope, §2.1 escalates to a scrub target.
- **Exact intrinsic value of the Firebase keys (§1.6-1.11).** Firebase client keys
  are designed to be embedded in the app and are restricted server-side by package
  signature; their real-world risk is lower than a Tuya appSecret. Classified P1/P2
  conservatively. Confirming the API-key restriction state would need a live Google
  console check (out of static scope).
- **Decompiled-tree completeness.** §1 grepped `decompiled/apktool` (post-R8 smali)
  and `decompiled/jadx/sources`; a literal hidden only in a `.so` data section
  (not a `strings`-visible literal) would be missed. Native sign-key material is
  covered separately in `re/bmp_token_whitebox.md`.

## 8. Recommended remediation (OUT OF SCOPE here — for a separate task)

Listed so the map is actionable; **this task changes nothing**:
1. **History rewrite** to purge `emulator_captures/cap0–cap3` blobs (§5) — e.g.
   `git filter-repo`/BFG — before any push to a public remote. Highest priority.
2. **Scrub the real productId** from §2.1 (3 tracked tasks + 2 untracked docs);
   replace with a `<productId>` placeholder or char-count.
3. **Drop the 4-char fingerprints** in `re/identity_enumeration.md` (§2.2) to
   field-name + char-count only.
4. **Extend the secret-scan** with a productId/devId-shape pattern and an optional
   history mode, so §2.1/§5-class leaks become gated rather than blind spots.
</content>
</invoke>
