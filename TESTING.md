# TESTING.md — Grounding & Negative Feedback

This project has two kinds of deliverable, so it has two kinds of "good vs bad" and two
kinds of negative feedback. Phase 3's review gate and the implementer contract lean on this doc.

> Constraint: **static analysis only** for discovery. But the user **owns the real camera
> (SCD921/923) and a Tuya account**, so the *ultimate* acceptance signal — a Rust client that
> authenticates, binds the device, and renders a live frame — is reachable by running the CLI
> against the real device (manually, gated behind `#[ignore]`). That live run is the strongest
> oracle we have; everything else is a cheaper proxy for it.

---

## Part 1 — Reverse-engineering artifacts (analysis tasks)

These tasks produce **claims about a protocol**, not code. Claims are cheap to fabricate, so the
grounding is an **evidence + confidence discipline**, enforced as a reviewable gate.

### Acceptance signal
Every protocol/auth/pairing claim in an `re/*.md` doc carries:
1. an explicit **confidence** level: `confirmed` (cross-checked against ≥2 independent sources,
   e.g. decompiled Java *and* the JS bundle, or a public Tuya impl), `likely`, or `speculative`; and
2. an **evidence citation** — **symbol-anchored** (see below): the class/method/field/
   string-constant name, optionally with a `decompiled/...` path and an approximate line hint;
   `lib*.so@0xOFFSET`; a JS-bundle location; or a named public reference (e.g. tinytuya source).

### Symbol-anchored citations (TASK-0024 — line numbers drift across jadx runs)
jadx line numbers are **not stable**: they shift between decompile runs and configs (e.g.
`-Xmx12g --no-debug-info` vs default), so a bare `path:LINE` cite can rot and point into
obfuscation noise even when the class/field/method is unchanged. Therefore **the symbol is
authoritative and the line is only a hint.** Cite as:

- `Symbol.member (decompiled/.../File.java ~:NN)` — name the symbol; the `~:NN` is an
  *approximate* line hint for the current `just decompile` tree (the `~` reads "about here");
- `decompiled/.../File.java` — a bare source path when the symbol is named in the surrounding
  prose (no line needed);
- `decompiled/.../File.java:NN` — the legacy exact-line form is still accepted, but prefer a
  symbol so a future re-decompile does not silently invalidate the cite.

Rules for authors: every CLAIM's citation must resolve to a **real symbol** in the current
decompiled tree (verify with `rg 'class Foo|methodName|fieldName' decompiled/...`); fix the line
hint to the current tree if you give one. State once per doc that **line hints are approximate
(jadx-run-dependent) and symbols are authoritative**. `just check-evidence` accepts all three
forms as citation tokens; for `confirmed` (≥2 sources) the same file cited bare and again with a
hint counts as ONE source — the line hint is decoration, not a second source.
A cross-doc `.md` reference (e.g. citing `re/review_gate_findings.md`) is a **navigation pointer,
NOT an independent evidence source** — the `re/*.md` docs are siblings derived from the same
decompile, so a `.md` path does not count as a citation token and does not count toward the
≥2-source `confirmed` rule.

### Good vs bad (observable)
- GOOD: a reader can follow a citation to the exact decompiled line / symbol that supports the claim.
- BAD ("ungrounded"): an adjective ("the app uses a secure handshake") with no citation, a
  confidence label absent, or `confirmed` asserted from a single source.

### Negative feedback (how the system tells us we're wrong)
- `just check-evidence` — a lint over `re/*.md` that fails if a section making a protocol claim has
  no citation token or no confidence label. If nothing can fail this lint, the docs aren't grounded.
- **Cross-source contradiction is a finding, not a footnote.** When the JS bundle and decompiled
  Java disagree, the doc must record the conflict and which won, with reasoning.
- The honest-uncertainty rule: the P2P wire-format feasibility task MUST end with one of
  {`recoverable-statically`, `partially`, `needs-live-capture`} — a verdict that can be *wrong* and
  is testable later against the real device. "It's complicated" is not a permitted verdict.

---

## Part 2 — The Rust client (implementation tasks)

### Acceptance signals (strongest first)
1. **Live end-to-end (gold oracle, `#[ignore]`, manual):** `babymonitor-cli` logs into the user's
   Tuya account, lists devices and finds the SCD921, and — once P2P lands — renders ≥1 decoded
   video frame + plays audio from the real camera. Documented setup; creds from `secrets/`.
2. **Differential against a known-good impl:** Tuya **mobile-app SDK** request signing produces the
   same signature as an INDEPENDENT reference for identical fixed inputs. The reference is
   `nalajcie/tuya-sign-hacking` (mobile sign: `key = [cert_sha256]_[bmp_token]_[appSecret]`) or a
   live-captured request — NOT tinytuya (which implements the different OpenAPI/local scheme). Using
   our own decompiled reading as the oracle is circular and forbidden. This bites without any network.
3. **Fixture deserialization:** captured/real JSON responses (stored in `secrets/`, gitignored)
   deserialize into the typed models without error; structure asserted, not content.
4. **Unit/property:** crypto helpers (HMAC, AES, padding), framing parsers, and state machines have
   table/property tests with known vectors.

### Good vs bad (observable)
- GOOD: `just e2e` green; `just showcase` runs all non-destructive CLI commands without panic;
  signing matches the reference vector byte-for-byte; live test renders a frame.
- BAD: serde error on a real response; signature mismatch; P2P handshake rejected by the camera;
  a panic on the happy path; a stubbed function silently returning `Ok(())`.

### Negative feedback (gates)
- `just e2e` = `build` + `test` + `clippy -D warnings` + `fmt-check`. Must be green before any commit.
- `just showcase` = run every read-only CLI command; a regression tripwire after each change.
- **Prove the check bites:** for each parser/signer, include at least one test that fails on a
  deliberately corrupted input — a green suite that can't go red is not grounding.
- Stubs are not done. A task that leaves a `todo!()`/placeholder MUST file a follow-up task and say
  so in its notes; the review gate treats an unflagged stub as a failure.

---

## Definition of Done (every task)
- Acceptance criteria met and demonstrated (command output, test name, or citation — not assertion).
- For code: `just e2e` green; new logic has a test that can fail; no unflagged stubs.
- For analysis: claims carry confidence + evidence; `just check-evidence` green; contradictions recorded.
- Honest limitations written in the task's notes. Tangents filed as new tasks, not chased inline.

---

## Wave-1 lessons (for the Wave-2 re-plan)

What Wave-1 (static RE) taught, to fold into Wave-2 planning:

1. **The auth dead-end is the central constraint.** The Tuya signer is fully characterized
   (MD5(cert_sha256_"_"_bmp_token_"_"_appSecret); cert/appKey/appSecret recovered; the imath+matrix
   bmp_token decode ported byte-exact via Ghidra). BUT (TASK-0033, reviewer-confirmed) the decode
   keys off a **runtime JNI byte[] SDK-config** (doCommandNative param_6) — so the production token is
   **not computable under pure static analysis**. A working login needs the runtime config blob OR one
   live sign vector. **No oracle exists statically** — a self-derived signer is unverifiable.
   Wave-2 must sequence the auth DECISION first; everything (device list, stream) is gated on it.
2. **Streams are understood, unbuilt.** WebRTC-over-MQTT (302 signaling, DTLS-SRTP, H.264/Opus) is the
   confirmed transport; the Rust impl (webrtc-rs + rumqttc) is Wave-2 and ultimately needs auth for the
   device's p2p creds + a live device returning p2pType=4.
3. **The grounding gates work and caught real defects** — but the recurring failure mode was
   **verdict-overturn lag**: when a later spike overturned an earlier verdict, the entry/sibling docs
   kept asserting the old model (recurred 4×, each caught by the review gate, never the lint). Wave-2
   should implement the **verdict-overturn grep-guard** (TASK-0021): after a new verdict token is set,
   fail unless every old-token hit in re/ is history/SUPERSEDED with a forward-pointer.
4. **Two-tool corroboration matters.** radare2 alone mischaracterized fcn.11658 (called it white-box;
   it's AES) and miscounted xrefs/cmd-numbers; Ghidra's decompiler corrected these. Use Ghidra C as the
   primary source for any further deep native logic; cross-check vs r2.
5. **Honesty discipline held:** the client is token-pending (cannot log in) and says so everywhere —
   no fake login, secrets gitignored + redacted, #[ignore]d live tests that go red on faked success.
