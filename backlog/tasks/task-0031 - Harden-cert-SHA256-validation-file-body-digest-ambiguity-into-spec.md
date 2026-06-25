---
id: TASK-0031
title: Harden cert-SHA256 validation + file body-digest ambiguity into spec
status: Done
assignee:
  - '@architect'
created_date: '2026-06-25 04:53'
updated_date: '2026-06-25 09:17'
labels:
  - rust
  - auth
  - review-followup
dependencies:
  - TASK-0012
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From cycle-14 review of TASK-0012 (both GO, P1/P2). The cert ingredient value is confirmed CORRECT (Rust hashes the raw embedded PKCS#7 leaf cert = Android signatures[0] semantics; the naive openssl `x509 -outform DER` re-encode is the misleading path) but its validation is weak: (P1a) extract_leaf_cert_der returns the FIRST DER SEQUENCE >=64 bytes — in a multi-cert PKCS#7 chain that may not be the leaf; add a guard or pick by leaf semantics. (P1b) the openssl byte-for-byte cross-check is claimed in notes but not committed; add an #[ignore]d test (or Justfile recipe) asserting app_cert_sha256_hex_from_apk equals SHA-256 of the raw embedded leaf cert via an independent reference (openssl pkcs7 -print_certs without the re-encoding x509 step), value withheld. (P2) file the 24-vs-32 swap/postData body-digest contradiction (md5AsBase64=24 chars vs swap slices 32) as a caveat into re/tuya_sign.md ~:83-89 (currently only in sign.rs rustdoc + task notes).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 extract_leaf_cert_der robust against multi-cert chains (or documented+guarded); a committed #[ignore]d test pins the cert digest against an independent reference (value withheld)
- [x] #2 re/tuya_sign.md records the body-digest 24-vs-32 ambiguity caveat; check-evidence green
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. HARDEN extract_leaf_cert_der: parse PKCS7 SignedData enough to (a) locate the certificates [0] IMPLICIT context tag (0xA0) within ContentInfo->SignedData, (b) enumerate ALL cert SEQUENCEs inside ONLY that block, (c) if 1 cert -> use it; if >1 -> select the end-entity/leaf (the cert that is NOT the issuer of any other in the set, i.e. its subject DN never appears as another cert's issuer DN); if the leaf is ambiguous, FAIL LOUD (Error::CertHash) rather than silently returning the first. Keep der_length helper; add a cert-shape guard (inner tbs SEQUENCE). Document the chosen strategy + its limitation in rustdoc.
2. COMMIT CROSS-CHECK: replace the weak #[ignore]d real_app_cert_sha256_is_64_hex (or add a sibling) with one that runs an INDEPENDENT reference via openssl asn1parse -strparse (NOT x509 -outform DER re-encode) over META-INF/BNDLTOOL.RSA to get the RAW embedded leaf cert bytes, SHA-256s them, and asserts EQUALITY with app_cert_sha256_hex_from_apk. Value WITHHELD (assert_eq on two computed hashes, never print/commit). Reproducible: invokes openssl from the test via std::process::Command; skips-with-panic if APK absent. Also add a Justfile recipe to run it.
3. CAVEAT: add one-line 24-vs-32 body-digest caveat into re/tuya_sign.md sec around :86-89 pointing to sign.rs post_data_digest rustdoc.
VERIFY: just e2e green; cross-check test PASS with --ignored; check-evidence + secret-scan green; assert-offline still green. One/two commits, no AI trailer.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPLEMENTED (cycle-14 follow-up).

AC#1 — extractor hardening (sign.rs):
- extract_leaf_cert_der no longer scans the WHOLE blob for the first >=64B SEQUENCE. It now navigates the real PKCS#7 structure: ContentInfo SEQUENCE -> skip contentType OID -> content [0] EXPLICIT -> SignedData SEQUENCE -> walk members to the certificates [0] IMPLICIT (0xA0) block, and enumerates cert SEQUENCEs ONLY inside that block (collect_certificates/enumerate_cert_seqs). This alone removes the old failure mode of matching the outer ContentInfo/SignedData/SignerInfo SEQUENCEs.
- Multi-cert leaf selection (select_leaf + cert_issuer_subject): for >1 cert, the leaf = the cert whose subject DN is not the issuer DN of any OTHER cert (raw-DER byte-equality on the Name SEQUENCEs). Exactly-one candidate -> return it; zero or >=2 -> FAIL LOUD (Error::CertHash 'ambiguous, refusing to guess'). Single-cert chains (the real APK) skip DN parsing entirely.
- Documented limitation in rustdoc: DN match is byte-equality, not RFC4518 canonical string matching; a pathological chain with two non-byte-identical encodings of the same DN would yield >=2 candidates -> errors loud (never silently wrong). Full ASN.1/DN-canon parser deliberately out of scope.
- New unit tests w/ synthetic-but-valid PKCS#7 builders (tlv/fake_cert/fake_pkcs7): single-cert recovery, multi-cert picks-the-leaf (CA listed FIRST so old code would mis-pick), ambiguous-chain fails-loud, no-cert errors. Old synthetic tests rewritten to build real ContentInfo (they used to rely on the first-SEQUENCE-anywhere behavior).

AC#1 — committed cross-check (the honesty fix), value WITHHELD:
- New #[ignore]d test real_app_cert_matches_openssl_reference: runs an INDEPENDENT reference via openssl asn1parse (NOT x509 -outform DER re-encode): unzip BNDLTOOL.RSA -> asn1parse to find the certificates [0] leaf SEQUENCE offset (leaf_cert_offset_from_asn1parse parses the offset col) -> asn1parse -strparse <off> lifts the RAW embedded leaf bytes verbatim -> sha256 -> assert_eq! against app_cert_sha256_hex_from_apk(apk). Two computed digests compared; the value is never printed/hardcoded.
- Justfile recipe 'just cert-crosscheck' runs it with a '1 passed' guard so a filter mismatch can't false-green.
- Cycle-14 fact re-confirmed locally: raw embedded leaf (962B, asn1parse -strparse 60) and Rust extractor agree; for THIS cert the openssl re-encode coincidentally agrees too (cert already canonical DER) but -strparse is the semantically-correct reference that doesn't rely on that coincidence.

AC#2 — re/tuya_sign.md ~:86 postData section: added a blockquote CAVEAT — md5AsBase64=24 chars vs swapSignString slices assume 32; OPEN ambiguity until a gold vector; points to sign.rs post_data_digest rustdoc; postData sign path unexercised/untrusted until then.

GATES (all green under nix-shell): just e2e (97 lib pass / 3 ignored incl. the 2 APK tests + pending byte-parity; assert-offline OK), just check-evidence, just secret-scan, just cert-crosscheck (--ignored PASS). No cert-hash value committed (rg over babymonitor/ re/ Justfile clean).

GOTCHAS / LIMITATIONS:
- The real APK is a SINGLE self-signed cert, so the multi-cert leaf-selection path is exercised ONLY by synthetic tests, not by the live cert. If Philips ever ships a multi-cert chain, the byte-equality DN match is the thing to re-validate.
- cert-crosscheck needs both the gitignored APK AND openssl on PATH (present under nix-shell). It is NOT in the e2e gate (needs the APK) — run it manually / pre-publish.
- leaf_cert_offset_from_asn1parse assumes the first d=4 SEQUENCE after the certificates 'cont [ 0 ]' line is the leaf; fine for the single-cert APK. The Rust extractor (not this reference helper) owns true multi-cert leaf selection.

Cycle-26 review: both GO. Extractor hardening sound (PKCS#7 nav + fail-loud leaf selection; architect fuzzed 8 malformed blobs = zero panics); cross-check PROVEN independent (architect measured raw d2d6.. != re-encode 06b9.. != whole-block 1a05..; Rust yields the raw = Android semantics); value withheld; body-digest caveat honest. CORRECTION to my impl-note: the earlier 'openssl re-encode coincidentally agrees (cert already canonical)' is FALSE — re-encode genuinely DIFFERS from the raw leaf for this cert (which makes the -strparse reference choice load-bearing, not incidental); do not cite re-encode as benign. P2 tracker-render artifact reconciled (Done).
<!-- SECTION:NOTES:END -->
