---
id: TASK-0043
title: >-
  RE SecureNativeApi.getConfig@0x136e0 to decrypt thing_domains_v1/regions ->
  real mobile-atop datacenter host
status: Done
assignee:
  - '@reverser'
created_date: '2026-06-25 12:16'
updated_date: '2026-06-25 12:40'
labels:
  - phase3
  - wave3
  - auth
  - native
  - ghidra
dependencies:
  - TASK-0042
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-3 unblock for the live login. TASK-0042 hit ILLEGAL_CLIENT_ID on the legacy a1.tuya{eu,us}.com hosts — the appKey is likely provisioned for the region-config datacenter host shipped ENCRYPTED in assets/thing_domains_v1/regions, decrypted at runtime by native SecureNativeApi.getConfig (@0x136e0 in libthing_security.so). The ported AES (AES-128-CBC key=MD5(t_s.bmp), and the localKey ECB) is the CERT-PINNING cipher — NO evidence it decrypts regions; getConfig is UN-RE-d. STATIC SPIKE: Ghidra-decompile getConfig + its key/IV/mode for the regions/pins blob (shared 4db6 envelope header), decrypt it, recover the EU mobileApiUrl/gwApiUrl host. Honest verdict if the key is itself runtime/unrecoverable. If recovered, the host feeds ONE more token.get (not lockout-sensitive). CAVEAT: even with the right host, ILLEGAL_CLIENT_ID may be a PROVISIONING/app-cert-pin gate a standalone client cannot reproduce — weigh that hypothesis too.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 getConfig key/IV/mode for the regions blob reverse-engineered (Ghidra-primary, symbol-anchored) OR an honest verdict it is itself runtime-only; if decryptable, the real EU mobile-atop host recovered (to secrets/ or doc as non-secret host) and fed to a single re-attempt
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Split per operator: THIS cycle is STATIC ONLY (no live). (1) verify/fix the clientId-vs-appId WIRE param in the login request envelope (live.rs) — operator flagged it as a likely ILLEGAL_CLIENT_ID cause; the sign-whitelist fix changed the canonical string, but confirm the actual HTTP query sends clientId=<appKey>, not appId. (2) Ghidra-RE getConfig@0x136e0 -> decrypt regions -> recover the EU mobile-atop host. The SINGLE live token.get re-attempt is the NEXT cycle (after this gates).

STATIC cycle DONE (clientId verified + getConfig verdict + EU host recovered).

PART 1 (clientId wire param): ALREADY CORRECT, no fix needed. live.rs build_signed_envelope_with inserts envelope['clientId']=appKey and envelope['time']=epoch_ms; send_atop puts that map on the wire query. The earlier appId->clientId / t->time fix was only the sign whitelist; the envelope/query already used the correct Tuya wire keys. So ILLEGAL_CLIENT_ID is NOT a clientId-param bug.

PART 2 (getConfig/regions): VERDICT = STATIC-DERIVABLE. The regions/pins blob is NOT decrypted by native getConfig at all. It is decrypted by a pure-Java path: DomainHelper.parseDomainsConfig -> AESCTRUtil.decrypt = AES-256-CTR/NoPadding, key=base64decode(asset)[0:32], IV=[32:48], ct=[48:]. The key+IV are EMBEDDED in the asset's own 48-byte header (constant 4db6...). Fully static, no appKey/runtime input. Reproduced two ways (self-contained AES-256-CTR port re/scripts/regions_decrypt.py AND openssl enc -aes-256-ctr) -> clean JSON.

Native SecureNativeApi.getConfig@0x136e0 (Ghidra C in re/ghidra/getconfig/) is AES-128-GCM (mbedtls, tag=NULL/tag_len=0 -> GCM-as-CTR stream) for a DIFFERENT asset: t_cdc.tcfg, the custom-domain override (NOT shipped). It is the WRONG consumer for regions - documented so nobody chases it again.

RECOVERED EU host (non-secret, public): mobileApiUrl=https://a1.tuyaeu.com (EU is defaultConfig), gwApiUrl=http://a.gw.tuyaeu.com/gw.json.

GOTCHA / feed-forward to TASK-0042: the EU host IS a1.tuyaeu.com == EXACTLY the host TASK-0042 already tried and got ILLEGAL_CLIENT_ID. So the 'wrong datacenter host' hypothesis is REFUTED by ground truth. ILLEGAL_CLIENT_ID is neither a host problem nor a clientId-param problem. Remaining live hypotheses: (a) provisioning / app-cert-pin / app-identity gate the standalone client cannot reproduce, or (b) a still-wrong sign (unvalidated bmp_token candidate / MD5 fold). Do NOT re-sweep hosts next cycle - vary the provisioning surface instead.

Docs: re/regions_decrypt.md (new), re/tuya_cloud_config.md (superseded note), re/ghidra/getconfig/*.c (Ghidra C).
<!-- SECTION:NOTES:END -->
