#!/usr/bin/env python3
"""check_evidence.py — grounding lint for re/*.md (TASK-0011, AC #2/#5/#6).

Enforces the evidence + confidence discipline defined in TESTING.md Part 1.

THE RULE (pinned; documented here so it is auditable, not a black box):

  1. A markdown doc is split into *sections*. A section spans from a heading
     line up to (but not including) the next heading of EQUAL OR HIGHER level.
     Thus a `##` section owns its nested `###` children — confidence/evidence
     stated in a child satisfies the parent. This "section subtree" model is
     the correct, non-weakening interpretation: it neither demands every leaf
     repeat the citation, nor lets a single doc-wide token excuse everything.

  2. Fenced code blocks (``` ... ```) are stripped before lexicon matching so a
     pasted snippet does not, by itself, turn a section into a "claim section".

  2b. SYMBOL-ANCHORED CITATIONS (TASK-0024). jadx line numbers drift across
      decompile runs, so a citation's authoritative anchor is the SYMBOL
      (class/method/field/string-constant name); the line number is an OPTIONAL
      hint. The accepted forms are:
        - `Symbol.member (decompiled/.../File.java ~:NN)` — symbol + path + hint
        - `decompiled/.../File.java`                      — bare source path
        - `decompiled/.../File.java:NN`                   — legacy exact-line form
      A `~:NN` (tilde) hint reads as "approximate". The lint counts the source
      PATH as the citation token; the line hint is stripped when de-duplicating
      sources for rule 4b so one file cited twice (bare + hinted) is ONE source.

  3. CLAIM LEXICON (pinned, whole-word, case-insensitive):
       endpoint | HMAC | sign | token | magic | offset | packet | frame
       | handshake | port | AES | key
     A section whose (code-stripped) body matches the lexicon is a CLAIM SECTION.

  4. A claim section PASSES iff its subtree contains BOTH:
       a) a CONFIDENCE token — one of {confirmed, likely, speculative} — but only
          when it appears as a *label*, not as incidental prose. Accepted forms:
            confidence: likely      (confidence:-prefixed)
            **confirmed**           (bold)
            (confidence: likely…)   (parenthesised)
            - …: speculative        (trailing label on a bullet/clause)
          This deliberately REJECTS prose like "most likely brokered" so the
          lint cannot be satisfied by accident.
       b) an EVIDENCE CITATION — any of:
            decompiled/…:NN  |  any path…:NN  |  lib*.so (optionally @0xHEX)
            | assets/… path  |  *.js / *.ts path  |  http(s):// URL
            | a named public ref of the form `owner/repo`

  4b. CONFIRMED REQUIRES TWO INDEPENDENT SOURCES (TESTING.md:28-29: "`confirmed`
      asserted from a single source is BAD"). When a claim section's confidence
      label is `confirmed`, it must contain >= 2 DISTINCT citation tokens (e.g. a
      path-citation AND a named ref, or two distinct named refs, or two distinct
      paths). Exactly one citation under a `confirmed` label is a FINDING — the
      author must add the second source or downgrade to `likely`. Sections
      labelled only `likely`/`speculative` still need just one citation.

  5. p2p_protocol.md gate: WHEN re/p2p_protocol.md exists it MUST contain a
     LABELLED verdict line of the form `Verdict: <token>` (token one of
     {recoverable-statically, partially, needs-live-capture}). Bare prose
     mentioning "partially" does NOT satisfy the gate; the verdict must be an
     explicit, machine-checkable label. Zero or many labelled verdicts → fail.

  6. VERDICT-OVERTURN GUARD (TASK-0021). The project's recurring failure mode (4×,
     each caught by the human/review gate, NEVER by a lint) was "verdict-overturn
     lag": when a later spike OVERTURNED an earlier verdict, the old verdict token
     survived as a CURRENT claim in sibling docs. SUPERSEDED_VERDICTS is a small,
     data-driven table of (old_token, superseded_by); lint_verdicts() greps re/*.md
     and FAILS on any hit of an old token that is NOT inside a STRONG supersession
     frame. A frame is: a STRONG BANNER (SUPERSEDED/REFUTED/CORRECTED/RETRACTED/
     OVERTURNED/erratum) in the window or enclosing heading; a strikethrough
     `~~…~~`; an option-set `{a|token|b}` menu; a SOFT history word (historical/
     stale/obsolete/…) IN THE ENCLOSING HEADING; or a SOFT word PAIRED WITH a
     forward-pointer (→/see/per/a `.md`/`TASK-NNNN`/`§N` target). A bare free-
     floating soft word no longer frames (TASK-0038 — it was an exploitable false
     negative: an unrelated nearby "history"/"stale" let a current stale verdict
     pass). This is the mechanical guard that would have caught all four
     recurrences. Maintain the table: add a row whenever a spike overturns a verdict.

KNOWN LIMITATION — SHAPE, NOT CONTENT (TASK-0021 AC #1; documented + accepted).
  This lint validates the SHAPE of a citation (it matches a path:line / symbol /
  named-ref token and a confidence label) but NOT that the cited file/line actually
  CONTAINS the claimed symbol or content. A WRONG ATTRIBUTION — e.g. citing
  `dpdqppp.java` for a `nin/nout` topic prefix that file does not contain — passes
  the gate. Full content-validation is deliberately NOT implemented here because:
    (1) it needs the gitignored decompiled tree present (`just decompile`), which is
        not guaranteed in CI / a fresh checkout — an opportunistic grep would be
        GREEN-when-absent and so flaky/false-confidence; and
    (2) jadx line numbers drift (TASK-0024), so a line-anchored content grep would
        rot, and a symbol grep over a 100k-file tree on every lint is costly.
  Attribution ACCURACY is therefore owned by the human / mped-architect REVIEW GATE
  (which has reliably caught these), not this static linter. The verdict-overturn
  guard above is the one CONTENT-adjacent check that earns its keep mechanically
  (it cross-checks the *coherence* of verdict tokens across docs, not a single
  citation's truth). See TESTING.md Part 1 "Shape vs content" for the rationale.

Exit status: 0 = all clean; 1 = at least one finding. Findings are printed with
file:line so a human can jump straight to the offending section.

Self-test: run with `--selftest` to verify the lint BITES on a planted bad
fragment and PASSES a planted good fragment (AC #5). A green suite that cannot
go red is not grounding.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ── Pinned lexicons ──────────────────────────────────────────────────────────

CLAIM_LEXICON = [
    "endpoint", "HMAC", "sign", "token", "magic", "offset",
    "packet", "frame", "handshake", "port", "AES", "key",
]
# Whole-word, case-insensitive. \b around each term.
CLAIM_RE = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in CLAIM_LEXICON) + r")\b",
    re.IGNORECASE,
)

CONFIDENCE_TOKENS = ["confirmed", "likely", "speculative"]
# A confidence token only counts when it appears as a *label*. Each alternative
# below anchors the token to a labelling construct, not bare prose.
CONFIDENCE_RE = re.compile(
    r"(?:"
    r"confidence\s*[:=]\s*\**(?:confirmed|likely|speculative)"   # confidence: likely
    r"|\*\*(?:confirmed|likely|speculative)\*\*"                 # **confirmed**
    r"|\((?:[^)]*\b)?(?:confidence\s*[:=]?\s*)?(?:confirmed|likely|speculative)\b"  # (confidence: likely ...)
    r"|[:\-]\s*\**(?:confirmed|likely|speculative)\**\s*(?:$|[.,;)\n])"  # ...: likely  /  - ...: speculative
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# Named public references that count as evidence citations. TESTING.md Part 1
# explicitly sanctions "a named public reference (e.g. tinytuya source)" as a
# valid citation alongside paths/offsets/URLs. This pinned list is the set of
# public RE references established for THIS project (see review_gate_findings.md
# / prd.md). Add to it deliberately; it is not a wildcard.
NAMED_REFS = [
    "tinytuya", "localtuya", "tuya-iot-python-sdk", "tuya-sign-hacking",
    "tuya-ipc-terminal", "tuya-iotos-android-iot-p2p-demo", "videoP2Proxy",
    "wyzecam", "WyzeCam", "tutk", "ThingP2PSDK", "IOTC", "PPCS",
]
NAMED_REF_RE = re.compile(
    r"\b(" + "|".join(re.escape(r) for r in NAMED_REFS) + r")\b"
)

# Evidence citation forms.
#
# SYMBOL-ANCHORED CITES (TASK-0024). jadx line numbers DRIFT between decompile
# runs/configs, so the authoritative anchor is the SYMBOL (class/method/field/
# string-constant name) and the line is an OPTIONAL hint. The convention is
#
#     Symbol.member (decompiled/.../File.java ~:NN)     # ~:NN = approximate hint
#     decompiled/.../File.java                          # bare source path, symbol in prose
#     decompiled/.../File.java:NN                       # legacy exact-line form (still ok)
#
# So this regex must accept a decompiled/jadx SOURCE PATH *with or without* a
# trailing line hint, and must tolerate a `~:NN` (tilde) hint as well as `:NN`.
# The legacy `path:NN` alternative is kept verbatim so nothing already-green
# regresses; the new SOURCE_PATH alternative additionally accepts a *bare* source
# path (no line) and a `~:NN` hint. This widening is minimal: it only adds source
# files as a citation token, it does NOT relax the requirement that a claim
# section carry a confidence label AND >=1 citation (nor the >=2-source confirmed
# rule) — see lint_doc().
#
# NOTE (review fix to TASK-0024): `md` is DELIBERATELY NOT in SOURCE_EXT. A `.md`
# path is a DOC/navigation pointer, not a decompiled artifact, and the re/*.md docs
# are siblings derived from the same decompile — so a cross-doc `.md` reference is
# NOT an independent source and must not count toward the >=2-source `confirmed`
# rule (rule 4b). Adding `md` here re-opens that hole; see selftest case (e).
SOURCE_EXT = r"(?:java|kt|kts|smali|so|xml|json|js|ts|bmp|cfg|properties)"
CITATION_RE = re.compile(
    r"(?:"
    r"[\w./-]+:\d+"                       # path:NN (decompiled/foo.java:42) — legacy exact
    r"|[\w./-]+\." + SOURCE_EXT + r"(?:\s*~?:\d+)?\b"  # source path + optional ~:NN / :NN hint
    r"|lib[\w.-]*\.so(?:@0x[0-9A-Fa-f]+)?"  # lib*.so optionally @0xHEX
    r"|[\w./-]*lib[\w.-]*?\.(?:dynsym|dynamic|symbols|syms|rodata|strings)\.txt"  # readelf/nm dump of a .so (TASK-0020 #2)
    r"|assets/[\w./-]+"                   # assets/… path
    r"|https?://[^\s)]+"                  # URL
    r"|\b[\w.-]+/[\w.-]+\b(?=.*\b(?:repo|github|ref|reference)\b)"  # owner/repo near a ref word
    r"|github\.com/[\w./-]+"             # explicit github ref
    r")"
)

# Trailing positional hint on a citation, stripped when de-duplicating citation
# tokens so the SAME artifact cited two ways counts once (see distinct_citations).
# Two hint forms:
#   - a line hint  `:NN` / `~:NN`        (jadx line, approximate — TASK-0024)
#   - an offset    `@0xHEX`              (native `.so` byte offset — `lib*.so@0x11658`)
# Both are POSITIONAL DECORATION, not part of the artifact identity: `lib.so@0x11658`
# and `lib.so` are one source. The offset is stripped EXPLICITLY here (TASK-0038) so
# `_artifact_key` collapses `.so@0xHEX` deterministically — previously it collapsed
# only by a CITATION_RE alternation accident (the `.so\b` source-path alternative
# matched first and dropped the `@0xHEX`), which a future regex edit could silently
# break. `_artifact_key` also re-applies the offset strip defensively.
LINE_HINT_RE = re.compile(r"(?:\s*~?:\d+|@0x[0-9A-Fa-f]+)$")

# SAME-ARTIFACT COLLAPSE (TASK-0020 #2). Two readelf/nm dumps of the SAME native
# library — e.g. `re/symbols/libThingP2PSDK.dynsym.txt` (the symbol table) and
# `re/symbols/libThingP2PSDK.dynamic.txt` (the dynamic section), or the binary
# `libThingP2PSDK.so` itself — are TWO VIEWS of ONE artifact, not two independent
# sources. Counting them as 2 would let a `confirmed` claim satisfy the
# >=2-source rule (rule 4b) from a single binary. We therefore canonicalise any
# `.so` citation or any per-artifact symbol/section DUMP down to the library's
# base name so all views of one `.so` collapse to ONE source token.
#
# A dump filename is `<libbase>.<view>.txt` where <view> is a readelf/nm section
# we emit. The set is pinned (not a wildcard): adding a new dump suffix here is a
# deliberate act. Two DIFFERENT libraries (libFoo.so vs libBar.so) keep distinct
# base names and remain two independent sources, as intended.
SO_VIEW_SUFFIXES = ("dynsym", "dynamic", "symbols", "syms", "rodata", "strings")
# `<libbase>.<view>.txt`  (e.g. libThingP2PSDK.dynsym.txt) — captures libbase.
_SO_DUMP_RE = re.compile(
    r"(?:^|/)(lib[\w.-]*?)\.(?:" + "|".join(SO_VIEW_SUFFIXES) + r")\.txt$",
    re.IGNORECASE,
)
# `<path>/libbase.so`, optionally with an `@0xHEX` offset. The offset is matched and
# discarded HERE so the regex is self-sufficient (TASK-0038) — it no longer relies on
# the caller having pre-stripped `@0xHEX`. `_artifact_key` also strips it before this
# applies (belt and suspenders), so `lib.so@0x11658` and `lib.so` yield one key even
# if a future caller forgets to normalise.
_SO_BIN_RE = re.compile(r"(?:^|/)(lib[\w.-]*?)\.so(?:@0x[0-9A-Fa-f]+)?$", re.IGNORECASE)
# Explicit offset strip, re-applied inside _artifact_key (defence in depth).
_SO_OFFSET_RE = re.compile(r"@0x[0-9A-Fa-f]+$", re.IGNORECASE)


def _artifact_key(token: str) -> str:
    """Collapse a citation token to its underlying ARTIFACT identity.

    For a native lib — whether cited as the `.so` binary (optionally with an
    `@0xHEX` byte offset, e.g. `libthing_security.so@0x11658`) or as one of its
    readelf/nm DUMP views (`lib*.dynsym.txt`, `lib*.dynamic.txt`, …) — the key is
    the library base name (e.g. `libthingp2psdk`). Every view/offset of one `.so`
    thus maps to the SAME key and counts as ONE source for the >=2-source
    `confirmed` rule. All other tokens (source paths, named refs, URLs) are
    returned unchanged. Input is assumed already casefolded.

    The `@0xHEX` offset is a POSITIONAL pointer into the binary, not a separate
    artifact, so it is stripped here (TASK-0038) — explicitly, not by relying on a
    CITATION_RE alternation accident — before the base name is extracted.
    """
    # Strip an `@0xHEX` byte offset so `.so@0xHEX` keys identically to `.so`.
    token = _SO_OFFSET_RE.sub("", token)
    m = _SO_DUMP_RE.search(token)
    if m:
        return "so:" + m.group(1).casefold()
    m = _SO_BIN_RE.search(token)
    if m:
        return "so:" + m.group(1).casefold()
    return token


# ── Verdict-overturn guard (TASK-0021) ───────────────────────────────────────
# THE failure mode of this whole project (recurred 4×, every time caught by the
# human/review gate and NEVER by a lint): "verdict-overturn lag". When a later
# spike OVERTURNS an earlier verdict, the old verdict token survives as a CURRENT
# claim in the entry/sibling docs, producing a cross-doc contradiction. The manual
# checklist failed to prevent 4 recurrences, so this is now a MECHANICAL gate.
#
# THE RULE: for each known-superseded verdict token, grep re/*.md. Every hit must
# sit inside a STRONG supersession FRAME that genuinely points the reader away from
# the dead token toward the live verdict — NOT merely near an incidental "soft"
# word. A hit is framed iff ANY of:
#   - a STRONG BANNER word (SUPERSEDED / REFUTED / CORRECTED / RETRACTED /
#     OVERTURNED / erratum) appears within ±FRAME_WINDOW lines or in the enclosing
#     section heading — these words ASSERT an overturn, they don't merely allude to
#     age; OR
#   - the hit line is inside a `~~strikethrough~~` (crossed-out history); OR
#   - the hit sits inside a `{a | token | b}` option-set enumeration (a menu value,
#     not a current assertion); OR
#   - a SOFT history word (historical / stale / obsolete / deprecated / conservative
#     / …) appears IN THE ENCLOSING SECTION HEADING — marking a whole section as
#     history (e.g. `## 3. [HISTORICAL — WRONG] …`) is a deliberate, section-anchored
#     act, robust to line drift (TASK-0020 #3); OR
#   - a SOFT history word CO-OCCURS with an explicit FORWARD-POINTER (`→`/`->`/`see`/
#     `per`/`superseded by`, or a `.md`/`TASK-NNNN`/`§N` target reference) within the
#     window — "kept as history → see X". The forward-pointer is what makes it a real
#     supersession note rather than incidental prose.
# An un-framed hit is a FINDING: the doc still asserts a refuted verdict as current.
#
# WHY THE TIGHTENING (TASK-0038). The earlier rule let ANY soft word (history,
# stale, conservative, deprecated, obsolete) frame a hit by mere ±3-line proximity,
# with NO requirement the word refer to the verdict. Both review reviewers built
# adversarial docs where an UNRELATED nearby soft word ("we reviewed the commit
# history…", "a stale cache entry") let a genuinely-CURRENT stale verdict PASS — an
# exploitable false negative. Free-floating soft words therefore no longer frame on
# their own; they must be section-heading-anchored OR paired with a forward-pointer.
# (All 24 real-tree hits carry a strong banner / strikethrough / option-set, or — in
# exactly one case — a [HISTORICAL — WRONG] heading, so this tightening leaves the
# real tree green; verified by re/scripts/check_evidence.py --selftest.)
#
# Data-driven: SUPERSEDED_VERDICTS is the small maintained table of
# (old_token, superseded_by, pattern). Add a row when a spike overturns a verdict;
# the guard then enforces reconciliation across re/ mechanically. Keep it honest —
# a row here is a claim that `old` is dead and `superseded_by` is the live verdict.
#
# This is NOT a content validator; it is a coherence lint. It would have caught all
# four historical recurrences (TASK-0006/F5, TASK-0023's three docs, TASK-0033's
# three docs).

# STRONG BANNER words: each ASSERTS that a verdict was overturned. Whole-word,
# case-insensitive. A banner anywhere in the ±window OR in the enclosing heading
# frames the hit on its own (it is an unambiguous supersession signal).
STRONG_BANNER_WORDS = [
    "superseded", "supersede", "supersedes", "superseding",
    "refuted", "refute", "refutes",
    "corrected", "correction",
    "retracted", "retract",
    "overturned", "overturn", "overturns",
    "erratum", "errata",
]
STRONG_BANNER_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in STRONG_BANNER_WORDS) + r")\b",
    re.IGNORECASE,
)

# SOFT history words: they connote age/staleness but do NOT, by themselves, assert
# that THIS token was overturned. They frame a hit ONLY when they are in the
# enclosing SECTION HEADING (a deliberate section-level history mark) or when they
# CO-OCCUR with a forward-pointer (see FORWARD_PTR_RE). A bare soft word in body
# prose near the hit does NOT frame it (TASK-0038 — the false-negative hole).
SOFT_HISTORY_WORDS = [
    "historical", "history",
    "deprecated", "obsolete", "stale", "outdated",
    "pre-disassembly", "conservative",
    "no longer", "was wrong", "now wrong",
]
SOFT_HISTORY_RE = re.compile(
    r"(?:" + "|".join(re.escape(w) for w in SOFT_HISTORY_WORDS) + r")",
    re.IGNORECASE,
)

# A FORWARD-POINTER: an explicit redirect from the dead token to the live verdict.
# Either a navigation arrow/verb (`→`, `->`, `see`, `per`, `superseded by`) OR a
# concrete target reference (a `.md` doc, a `TASK-NNNN`, or a `§N` section). When a
# SOFT history word co-occurs with one of these in the window, the construct reads
# as a genuine supersession note ("kept as history → see tuya_sign_static.md") and
# the hit is framed. `now` is DELIBERATELY excluded — it is too weak a pointer to
# rescue a soft word on its own (it would re-open the false-negative hole).
FORWARD_PTR_RE = re.compile(
    r"(?:→|->|\bsee\b|\bper\b|\bsuperseded by\b|[\w./-]+\.md|TASK-\d+|§\d+)",
    re.IGNORECASE,
)

# Strikethrough span `~~ … ~~` — a hit inside one is framed as crossed-out history.
STRIKE_RE = re.compile(r"~~.*?~~", re.DOTALL)
# An option-set enumeration `{ a | b | c }` — the token is a menu VALUE, not a
# current assertion (e.g. the per-spike "{recoverable-statically | needs-runtime-hook
# | needs-live-capture}" token set). Such a hit is exempt.
OPTION_SET_RE = re.compile(r"\{[^{}]*\|[^{}]*\}")

# How many lines above/below a hit are scanned for a frame word. A forward-pointer
# is usually on the same line or a banner a couple of lines away (e.g. a `>` quote
# block above a `Verdict:` line). 3 is generous without swallowing a whole section.
FRAME_WINDOW = 3


@dataclass(frozen=True)
class SupersededVerdict:
    old: str            # the dead verdict token (human label)
    superseded_by: str  # the live verdict that replaced it
    pattern: str        # ERE/Python regex matching the old token in prose

    @property
    def regex(self) -> "re.Pattern[str]":
        return re.compile(self.pattern, re.IGNORECASE)


# The maintained table. EACH ROW is a reconciliation contract: `old` is dead,
# `superseded_by` is live; every surviving `old` hit in re/ must be framed.
SUPERSEDED_VERDICTS: list[SupersededVerdict] = [
    SupersededVerdict(
        old="needs-runtime-hook",
        superseded_by="partially-recoverable (TASK-0023, tuya_sign_static.md)",
        pattern=r"needs-runtime-hook",
    ),
    SupersededVerdict(
        old="white-box table cipher (the wall)",
        superseded_by="AES-128-CBC (TASK-0030, bmp_token_whitebox.md)",
        pattern=r"white-box table cipher",
    ),
    SupersededVerdict(
        old="no runtime input / static-config-only decode",
        superseded_by="runtime SDK-config byte[] required (TASK-0033, "
                      "doCommandNative param_6)",
        pattern=r"no runtime input",
    ),
    SupersededVerdict(
        old="statically-recoverable-in-principle (bmp_token decode)",
        superseded_by="runtime SDK-config byte[] required (TASK-0033)",
        pattern=r"statically-recoverable-in-principle",
    ),
]


def _enclosing_heading(lines: list[str], idx: int) -> str:
    """The nearest markdown heading at-or-above line `idx` (0-based), or ""."""
    for j in range(idx, -1, -1):
        if HEADING_RE.match(lines[j]):
            return lines[j]
    return ""


def _is_framed(lines: list[str], idx: int) -> bool:
    """True iff the hit on line `idx` (0-based) sits inside a STRONG supersession frame.

    A hit is framed when ANY of (see the module-level rule comment for rationale):
      - a STRONG BANNER word (SUPERSEDED/REFUTED/CORRECTED/RETRACTED/OVERTURNED/
        erratum) appears within ±FRAME_WINDOW lines OR in the enclosing section
        heading — these words assert an overturn outright, so they frame alone; OR
      - the hit line is inside a `~~ … ~~` strikethrough (crossed-out history); OR
      - the hit sits inside a `{ a | b | c }` option-set enumeration (a menu value,
        not a current assertion); the enumeration may wrap across lines, so the
        ±window text is checked, not just the single hit line; OR
      - a SOFT history word (historical/stale/obsolete/…) is IN THE ENCLOSING SECTION
        HEADING (`## 3. [HISTORICAL — WRONG] …`) — section-anchored history marking,
        robust to line drift (TASK-0020 #3); OR
      - a SOFT history word CO-OCCURS with a FORWARD-POINTER (`→`/`see`/`per`/a
        `.md`/`TASK-NNNN`/`§N` target) within the window — a genuine "kept as history
        → see X" supersession note.

    A bare, free-floating SOFT word in body prose near the hit does NOT frame it
    (TASK-0038): that was the exploitable false negative (an unrelated "commit
    history"/"stale cache" rescuing a genuinely-current stale verdict).
    """
    lo = max(0, idx - FRAME_WINDOW)
    hi = min(len(lines), idx + FRAME_WINDOW + 1)
    window = "\n".join(lines[lo:hi])
    heading = _enclosing_heading(lines, idx)

    # Strong banner anywhere in the window or the enclosing heading frames alone.
    if STRONG_BANNER_RE.search(window) or STRONG_BANNER_RE.search(heading):
        return True
    # Strikethrough on the hit line = crossed-out history.
    if STRIKE_RE.search(lines[idx]):
        return True
    # Option-set enumeration may span lines (`{a |\n b | c}`); check the window.
    if OPTION_SET_RE.search(window):
        return True
    # Soft history word in the SECTION HEADING marks the whole section as history.
    if SOFT_HISTORY_RE.search(heading):
        return True
    # Soft history word ONLY frames in body prose when paired with a forward-pointer.
    if SOFT_HISTORY_RE.search(window) and FORWARD_PTR_RE.search(window):
        return True
    return False


def lint_verdicts(re_dir: Path) -> list[Finding]:
    """Verdict-overturn guard: every superseded-token hit must be framed."""
    findings: list[Finding] = []
    md_files = [
        p for p in sorted(re_dir.glob("*.md")) if p.name not in EXCLUDED_DOCS
    ]
    for md in md_files:
        lines = md.read_text(encoding="utf-8").splitlines()
        for sv in SUPERSEDED_VERDICTS:
            rx = sv.regex
            for i, ln in enumerate(lines):
                if not rx.search(ln):
                    continue
                if _is_framed(lines, i):
                    continue
                findings.append(
                    Finding(
                        str(md), i + 1,
                        f"(verdict-overturn guard: '{sv.old}')",
                        [
                            f"superseded verdict token asserted WITHOUT a "
                            f"SUPERSEDED/REFUTED/CORRECTED/HISTORICAL frame — it "
                            f"was overturned by {sv.superseded_by}; add a "
                            f"forward-pointer or strike it as history"
                        ],
                    )
                )
    return findings


# ── Baseline waiver ratchet ──────────────────────────────────────────────────
# Pre-existing grounding debt, locked in so the gate FAILS on regressions while
# the filed remediation (TASK-0018) is pending. Each entry is (filename, heading
# title) of a section authored BEFORE the canonical-vocabulary discipline.
# Waivers are reported, never silently dropped. This is a ratchet, NOT a mute:
# any NEW claim section without grounding still fails. Remove entries (not the
# mechanism) as TASK-0018 fixes each doc; the goal is an empty list.
# EMPTY as of TASK-0018: milestone2_findings.md and review_gate_findings.md were
# rewritten into the canonical {confirmed|likely|speculative} vocabulary with
# co-located labels + citations, so they now pass the lint on their own merits.
# The ratchet MECHANISM is retained (a future pre-existing-debt case can be added
# here, reported-never-muted), but the goal state — zero waivers — is reached.
BASELINE_WAIVERS: set[tuple[str, str]] = set()

VERDICT_TOKENS = ["recoverable-statically", "partially", "needs-live-capture"]
# The verdict must be a LABELLED line, not bare prose. Anchored to start-of-line
# (multiline), an optional bold wrapper, the literal word "Verdict", a ':' or '='
# separator, and then exactly one of the canonical tokens. This rejects prose
# like "the framing is partially recoverable" (TASK-0019 P1-2) — only an explicit
# `Verdict: partially` style label counts.
VERDICT_RE = re.compile(
    r"^\s*(?:\*\*)?Verdict(?:\*\*)?\s*[:=]\s*\**\s*"
    r"(recoverable-statically|partially|needs-live-capture)\b",
    re.IGNORECASE | re.MULTILINE,
)

# A confidence label is "confirmed" when the matched label text contains the word
# "confirmed". Used to trigger the >=2-citation requirement (rule 4b).
CONFIRMED_RE = re.compile(
    r"(?:"
    r"confidence\s*[:=]\s*\**confirmed"
    r"|\*\*confirmed\*\*"
    r"|\((?:[^)]*\b)?(?:confidence\s*[:=]?\s*)?confirmed\b"
    r"|[:\-]\s*\**confirmed\**\s*(?:$|[.,;)\n])"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

FENCE_RE = re.compile(r"^```")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")


@dataclass
class Section:
    """A heading-rooted section subtree."""
    level: int
    title: str
    start_line: int  # 1-based line of the heading
    lines: list[str]  # body lines (excluding the heading line itself)


def strip_code_fences(lines: list[str]) -> list[str]:
    """Returns lines with fenced code blocks removed (kept as blank lines so
    line counts are preserved for diagnostics)."""
    out: list[str] = []
    in_fence = False
    for ln in lines:
        if FENCE_RE.match(ln.strip()):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else ln)
    return out


def parse_sections(text: str) -> list[Section]:
    """Splits text into section subtrees (see module docstring rule 1)."""
    raw = text.splitlines()
    # Index every heading.
    headings: list[tuple[int, int, str]] = []  # (line_idx, level, title)
    for i, ln in enumerate(raw):
        m = HEADING_RE.match(ln)
        if m:
            headings.append((i, len(m.group(1)), m.group(2).strip()))

    sections: list[Section] = []
    for hi, (line_idx, level, title) in enumerate(headings):
        # Subtree ends at the next heading of equal-or-higher level (smaller or
        # equal level number).
        end = len(raw)
        for j in range(hi + 1, len(headings)):
            if headings[j][1] <= level:
                end = headings[j][0]
                break
        body = raw[line_idx + 1:end]
        sections.append(Section(level, title, line_idx + 1, body))
    return sections


def section_text(sec: Section) -> str:
    # Include the heading TITLE: docs in this repo legitimately carry the
    # confidence label and refs in the heading, e.g.
    #   "### F1 — … (confidence: likely)".
    # Excluding it produced false positives, so the searchable text is the
    # title plus the body subtree.
    return sec.title + "\n" + "\n".join(sec.lines)


def is_claim_section(sec: Section) -> bool:
    body = "\n".join(strip_code_fences(sec.lines))
    # Also drop inline code spans `...` so a bare `key` inside backticks in a
    # table of lib names still counts (it should — it's a real claim), but a
    # fenced example block does not. We KEEP inline spans for lexicon matching
    # because RE claims legitimately reference `key`, `sign`, etc. inline.
    return bool(CLAIM_RE.search(body))


def has_confidence(sec: Section) -> bool:
    return bool(CONFIDENCE_RE.search(section_text(sec)))


def has_citation(sec: Section) -> bool:
    txt = section_text(sec)
    return bool(CITATION_RE.search(txt) or NAMED_REF_RE.search(txt))


def is_confirmed(sec: Section) -> bool:
    return bool(CONFIRMED_RE.search(section_text(sec)))


def distinct_citations(sec: Section) -> set[str]:
    """Returns the set of DISTINCT citation tokens in a section's subtree.

    A "citation token" is any path/lib/URL/JS-bundle citation matched by
    CITATION_RE OR any named public reference matched by NAMED_REF_RE. The set is
    de-duplicated case-insensitively so the same reference written twice counts
    once — `confirmed` demands two *independent* sources, not one source repeated
    (TESTING.md:28-29). Used to enforce rule 4b.
    """
    txt = section_text(sec)
    tokens: set[str] = set()
    for m in CITATION_RE.finditer(txt):
        # Normalise away the (optional) line hint so the SAME source path cited
        # twice — once bare, once with a `:NN`/`~:NN` hint — counts as ONE source,
        # not two. Otherwise the symbol-anchored convention (TASK-0024) could game
        # the >=2-source `confirmed` rule (rule 4b) by re-citing one file with and
        # without a line. The hint is decoration; the path/symbol is the source.
        tok = LINE_HINT_RE.sub("", m.group(0)).strip().casefold()
        # Collapse all views of one native artifact (the `.so` and its readelf/nm
        # dumps) to a single source key (TASK-0020 #2) so two dumps of the SAME
        # `.so` cannot satisfy the >=2-source `confirmed` rule on their own.
        tokens.add(_artifact_key(tok))
    for m in NAMED_REF_RE.finditer(txt):
        tokens.add(m.group(0).casefold())
    return tokens


@dataclass
class Finding:
    file: str
    line: int
    title: str
    missing: list[str]

    def render(self) -> str:
        return (
            f"{self.file}:{self.line}: claim section "
            f"'{self.title}' missing {', '.join(self.missing)}"
        )


def lint_doc(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    for sec in parse_sections(text):
        if not is_claim_section(sec):
            continue
        missing: list[str] = []
        if not has_confidence(sec):
            missing.append("confidence label {confirmed|likely|speculative}")
        cites = distinct_citations(sec)
        if not cites:
            missing.append("evidence citation")
        elif is_confirmed(sec) and len(cites) < 2:
            # Rule 4b: a `confirmed` label needs >= 2 independent sources.
            missing.append(
                "second independent citation (confidence=confirmed needs >=2 "
                f"distinct sources, found {len(cites)}; add a source or "
                "downgrade to 'likely')"
            )
        if missing:
            findings.append(
                Finding(str(path), sec.start_line, sec.title, missing)
            )
    return findings


def lint_p2p(path: Path) -> list[Finding]:
    """p2p_protocol.md verdict gate (AC #6)."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    hits = VERDICT_RE.findall(text)
    if len(hits) == 1:
        return []
    return [
        Finding(
            str(path),
            1,
            "(verdict gate)",
            [
                f"exactly one verdict token of {{{'|'.join(VERDICT_TOKENS)}}} "
                f"required, found {len(hits)}"
            ],
        )
    ]


# Docs that are NOT protocol-claim docs and are therefore out of scope for the
# evidence discipline. TESTING.md Part 1 scopes the rule to "protocol/auth/
# pairing claim in an re/*.md doc"; the PRD is the requirements/planning spec,
# not a claims doc, so linting it for per-section citations is a category error.
# This is an explicit, auditable exclusion — NOT a wildcard that could hide
# real findings docs.
EXCLUDED_DOCS = {"prd.md"}


def run(re_dir: Path) -> int:
    findings: list[Finding] = []
    md_files = [
        p for p in sorted(re_dir.glob("*.md")) if p.name not in EXCLUDED_DOCS
    ]
    for md in md_files:
        findings.extend(lint_doc(md))
    findings.extend(lint_p2p(re_dir / "p2p_protocol.md"))
    # Verdict-overturn guard (TASK-0021): the mechanical catch for the project's
    # recurring "old verdict survives as a current claim" failure mode.
    findings.extend(lint_verdicts(re_dir))

    active: list[Finding] = []
    waived: list[Finding] = []
    matched_waivers: set[tuple[str, str]] = set()
    for f in findings:
        key = (Path(f.file).name, f.title)
        if key in BASELINE_WAIVERS:
            waived.append(f)
            matched_waivers.add(key)
        else:
            active.append(f)

    # Stale waiver detection: a waiver that no longer matches any finding means
    # the doc was fixed but the waiver entry was left behind. Treat as an active
    # failure so the list is forced to shrink toward empty (the ratchet tightens,
    # never loosens silently).
    stale = BASELINE_WAIVERS - matched_waivers
    for fname, title in sorted(stale):
        active.append(
            Finding(
                fname, 0, title,
                ["stale BASELINE_WAIVER — this section now passes; remove the "
                 "waiver entry (TASK-0018)"],
            )
        )

    if waived:
        print(
            f"check-evidence: {len(waived)} baseline-waived finding(s) "
            f"(pre-existing debt, tracked in TASK-0018):",
            file=sys.stderr,
        )
        for f in waived:
            print(f"  [WAIVED] {f.render()}", file=sys.stderr)

    if active:
        print(f"check-evidence: {len(active)} ACTIVE finding(s):", file=sys.stderr)
        for f in active:
            print(f"  {f.render()}", file=sys.stderr)
        return 1

    print(
        f"check-evidence: OK ({len(md_files)} doc(s); "
        f"{len(waived)} waived via TASK-0018)"
    )
    return 0


# ── Self-test (AC #5): prove the lint bites ──────────────────────────────────

GOOD_FRAGMENT = """\
## Tuya mobile-app request signing

The app signs requests with HMAC-SHA256 (confidence: likely). The sign key is
derived from the app cert plus an embedded BMP token; see
decompiled/jadx/com/tuya/Sign.java:128 and lib reference libthing_security.so.
Cross-checked against github.com/nalajcie/tuya-sign-hacking.
"""

BAD_FRAGMENT = """\
## The handshake

The app uses a secure handshake and a strong key exchange to protect the stream.
It is very robust.
"""


def selftest() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        good = tdir / "good.md"
        bad = tdir / "bad.md"
        good.write_text(GOOD_FRAGMENT, encoding="utf-8")
        bad.write_text(BAD_FRAGMENT, encoding="utf-8")

        good_findings = lint_doc(good)
        bad_findings = lint_doc(bad)

        if good_findings:
            print(
                "SELFTEST FAIL: good fragment was flagged: "
                + "; ".join(f.render() for f in good_findings),
                file=sys.stderr,
            )
            failures += 1

        if not bad_findings:
            print(
                "SELFTEST FAIL: bad fragment (adjective claim, no citation) "
                "was NOT flagged — the lint does not bite.",
                file=sys.stderr,
            )
            failures += 1

    # Verdict-gate self-test: zero / one / many + the negative prose case
    # (P1-2: a labelled `Verdict: <token>` is required; bare prose must NOT count).
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        zero = tdir / "p2p_protocol.md"
        zero.write_text("# P2P\nNo verdict here.\n", encoding="utf-8")
        if not lint_p2p(zero):
            print("SELFTEST FAIL: zero-verdict p2p doc not flagged", file=sys.stderr)
            failures += 1
        one = tdir / "p2p_protocol.md"
        one.write_text(
            "# P2P\nVerdict: partially\n\nThe framing is partially recoverable; "
            "the session key needs-live-capture in prose only.\n",
            encoding="utf-8",
        )
        # Exactly ONE labelled verdict, despite extra bare-prose token mentions.
        if lint_p2p(one):
            print(
                "SELFTEST FAIL: single LABELLED-verdict p2p doc flagged "
                "(bare-prose tokens must not be counted)",
                file=sys.stderr,
            )
            failures += 1
        many = tdir / "p2p_protocol.md"
        many.write_text(
            "# P2P\nVerdict: partially\n\n## Audio\nVerdict: needs-live-capture\n",
            encoding="utf-8",
        )
        if not lint_p2p(many):
            print("SELFTEST FAIL: multi-LABELLED-verdict p2p doc not flagged", file=sys.stderr)
            failures += 1
        # NEGATIVE: a doc with the bare word "partially" in prose but NO labelled
        # `Verdict:` line must FAIL (it has zero labelled verdicts).
        prose = tdir / "p2p_protocol.md"
        prose.write_text(
            "# P2P\nThe framing is partially recoverable from static analysis, "
            "but the per-session key likely needs a live capture.\n",
            encoding="utf-8",
        )
        if not lint_p2p(prose):
            print(
                "SELFTEST FAIL: bare-prose 'partially' (no labelled Verdict line) "
                "was accepted — the verdict gate does not require a label.",
                file=sys.stderr,
            )
            failures += 1

    # Confirmed-needs-two-sources self-test (P1-1 / rule 4b): a `confirmed`
    # section with ONE citation must FLAG; with TWO distinct citations must PASS.
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        one_cite = tdir / "confirmed_one.md"
        one_cite.write_text(
            "## Sign key derivation\n\n"
            "The cloud sign uses an HMAC over the request (confidence: confirmed); "
            "see decompiled/jadx/com/tuya/Sign.java:128.\n",
            encoding="utf-8",
        )
        f1 = lint_doc(one_cite)
        if not f1:
            print(
                "SELFTEST FAIL: confirmed section with ONE citation was not "
                "flagged — the >=2-source rule does not bite.",
                file=sys.stderr,
            )
            failures += 1
        two_cite = tdir / "confirmed_two.md"
        two_cite.write_text(
            "## Sign key derivation\n\n"
            "The cloud sign uses an HMAC over the request (confidence: confirmed); "
            "see decompiled/jadx/com/tuya/Sign.java:128 and cross-checked against "
            "github.com/nalajcie/tuya-sign-hacking.\n",
            encoding="utf-8",
        )
        f2 = lint_doc(two_cite)
        if f2:
            print(
                "SELFTEST FAIL: confirmed section with TWO distinct citations was "
                "flagged: " + "; ".join(f.render() for f in f2),
                file=sys.stderr,
            )
            failures += 1

    # Ratchet self-test: with a waiver in place for one bad section, a SECOND,
    # non-waived bad section must still make the whole run fail (the waiver is a
    # ratchet, not a global mute).
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        (tdir / "waived_doc.md").write_text(BAD_FRAGMENT, encoding="utf-8")
        (tdir / "new_doc.md").write_text(BAD_FRAGMENT, encoding="utf-8")
        saved = set(BASELINE_WAIVERS)
        try:
            BASELINE_WAIVERS.clear()
            BASELINE_WAIVERS.add(("waived_doc.md", "The handshake"))
            rc = run(tdir)
        finally:
            BASELINE_WAIVERS.clear()
            BASELINE_WAIVERS.update(saved)
        if rc == 0:
            print(
                "SELFTEST FAIL: ratchet leaked — a new ungrounded section "
                "passed while a waiver was present.",
                file=sys.stderr,
            )
            failures += 1

    # Symbol-anchored citation self-test (TASK-0024): the new cite forms — a bare
    # source path and a `Symbol (path ~:NN)` hinted form — must be ACCEPTED as a
    # valid citation, while a claim with NO citation must still FAIL. Also prove
    # the `confirmed` >=2-source rule is NOT gamed by citing one file twice (bare
    # + hinted): that is still ONE source and must flag.
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)

        # (a) symbol + hinted-path cite, likely → must PASS.
        hinted = tdir / "sym_hint.md"
        hinted.write_text(
            "## API name rewrite\n\n"
            "The `a=` action is rewritten thing→smartlife by "
            "`ThingApiParams.checkAPIName` "
            "(decompiled/jadx/sources/com/x/ThingApiParams.java ~:192) "
            "(confidence: likely).\n",
            encoding="utf-8",
        )
        if lint_doc(hinted):
            print(
                "SELFTEST FAIL: symbol-anchored hinted cite "
                "'(...File.java ~:192)' was NOT accepted as a citation.",
                file=sys.stderr,
            )
            failures += 1

        # (b) bare source path (symbol named in prose, no line) → must PASS.
        bare = tdir / "sym_bare.md"
        bare.write_text(
            "## Session token\n\n"
            "The session token is the `User.sid` field declared in "
            "decompiled/jadx/sources/com/x/User.java (confidence: likely).\n",
            encoding="utf-8",
        )
        if lint_doc(bare):
            print(
                "SELFTEST FAIL: bare source-path cite '(...User.java)' was NOT "
                "accepted as a citation.",
                file=sys.stderr,
            )
            failures += 1

        # (c) NEGATIVE: a claim section naming a symbol but with NO citation at
        # all (no path, no ref) must STILL FAIL — the widening must not let a bare
        # symbol name masquerade as evidence.
        nocite = tdir / "sym_nocite.md"
        nocite.write_text(
            "## API name rewrite\n\n"
            "The `a=` action token is rewritten thing→smartlife by the "
            "checkAPIName method (confidence: likely).\n",
            encoding="utf-8",
        )
        nf = lint_doc(nocite)
        if not any("evidence citation" in m for f in nf for m in f.missing):
            print(
                "SELFTEST FAIL: a claim naming a symbol but citing NO path/ref "
                "was accepted — the citation rule does not bite.",
                file=sys.stderr,
            )
            failures += 1

        # (d) `confirmed` with the SAME file cited bare + hinted is ONE source →
        # must flag (rule 4b not gamed by the line-hint normalisation).
        gamed = tdir / "sym_confirmed_one.md"
        gamed.write_text(
            "## Sign envelope\n\n"
            "The envelope keys carry the `sign` token (confidence: confirmed); "
            "see decompiled/jadx/sources/com/x/ThingApiParams.java and again "
            "decompiled/jadx/sources/com/x/ThingApiParams.java ~:407.\n",
            encoding="utf-8",
        )
        if not lint_doc(gamed):
            print(
                "SELFTEST FAIL: confirmed section citing ONE file twice (bare + "
                "hinted) passed — the >=2-source rule was gamed by the line hint.",
                file=sys.stderr,
            )
            failures += 1

        # (d2) SAME-ARTIFACT collapse (TASK-0020 #2). A `confirmed` section whose
        #      two citations are two DUMP VIEWS of the SAME `.so` — the symbol
        #      table and the dynamic section, OR a dump + the `.so` binary — is
        #      ONE source, not two, and must FLAG. A `confirmed` section citing two
        #      DIFFERENT `.so` artifacts must PASS (they are genuinely independent).
        same_so = tdir / "same_so.md"
        same_so.write_text(
            "## Native signaling exports\n\n"
            "The WebRTC signaling strings carry the `handshake` token "
            "(confidence: confirmed); see "
            "re/symbols/libThingP2PSDK.dynsym.txt and "
            "re/symbols/libThingP2PSDK.dynamic.txt.\n",
            encoding="utf-8",
        )
        if not lint_doc(same_so):
            print(
                "SELFTEST FAIL: confirmed section citing TWO dumps of the SAME "
                ".so (dynsym + dynamic) passed — same-artifact views counted as "
                "two independent sources (TASK-0020 #2 hole open).",
                file=sys.stderr,
            )
            failures += 1

        same_so_bin = tdir / "same_so_bin.md"
        same_so_bin.write_text(
            "## Native signaling exports\n\n"
            "The signaling strings carry the `handshake` token "
            "(confidence: confirmed); see re/symbols/libThingP2PSDK.dynsym.txt "
            "and the binary decompiled/nativelibs/libThingP2PSDK.so.\n",
            encoding="utf-8",
        )
        if not lint_doc(same_so_bin):
            print(
                "SELFTEST FAIL: confirmed section citing a .so dump AND the same "
                ".so binary passed — they are one artifact (TASK-0020 #2).",
                file=sys.stderr,
            )
            failures += 1

        diff_so = tdir / "diff_so.md"
        diff_so.write_text(
            "## Two native libs\n\n"
            "The `handshake` is split across libs (confidence: confirmed); see "
            "re/symbols/libThingP2PSDK.dynsym.txt and "
            "re/symbols/libThingCameraSDK.dynsym.txt.\n",
            encoding="utf-8",
        )
        if lint_doc(diff_so):
            print(
                "SELFTEST FAIL: confirmed section citing two DIFFERENT .so "
                "artifacts was flagged — distinct libs must count as two sources: "
                + "; ".join(f.render() for f in lint_doc(diff_so)),
                file=sys.stderr,
            )
            failures += 1

        # (e) `.md` IS NOT A SOURCE (review fix to TASK-0024). A cross-doc `.md`
        # reference is a navigation pointer, not an independent decompiled artifact.
        #   (e1) a `confirmed` section whose two citations are two different `.md`
        #        files must FLAG as <2 independent sources.
        #   (e2) a claim whose ONLY citation is a `.md` path must FLAG as missing
        #        an evidence citation (a `.md` path is not a citation token at all).
        # Both prove `md` removed from SOURCE_EXT closes the hole that let a sibling
        # `.md` doc masquerade as the second source for a `confirmed` claim.
        md_two = tdir / "md_two.md"
        md_two.write_text(
            "## Device secrets\n\n"
            "The `localKey` is a secret AES key (confidence: confirmed); see "
            "`re/review_gate_findings.md` and `re/streaming_mode.md`.\n",
            encoding="utf-8",
        )
        mf = lint_doc(md_two)
        # Must flag: zero real citations → "evidence citation" missing (the two
        # `.md` paths are not citation tokens, so the section has NO source at all).
        if not mf:
            print(
                "SELFTEST FAIL: confirmed section whose only 'sources' are two "
                "different `.md` docs was NOT flagged — `.md` is being counted as "
                "an independent source (the TASK-0024 hole is open).",
                file=sys.stderr,
            )
            failures += 1

        md_only = tdir / "md_only.md"
        md_only.write_text(
            "## Local key handling\n\n"
            "The per-device `key` material is documented in "
            "`re/review_gate_findings.md` (confidence: likely).\n",
            encoding="utf-8",
        )
        mo = lint_doc(md_only)
        if not any("evidence citation" in m for f in mo for m in f.missing):
            print(
                "SELFTEST FAIL: a claim whose ONLY citation is a `.md` path was "
                "accepted — `.md` must not count as a decompiled-artifact citation.",
                file=sys.stderr,
            )
            failures += 1

    # ── Verdict-overturn guard self-test (TASK-0021) ─────────────────────────
    # The mechanical catch for the project's 4×-recurring failure mode. Prove it
    # BITES: a doc asserting a superseded token as CURRENT must FAIL; the SAME
    # token framed as SUPERSEDED/HISTORICAL/struck-out/option-set must PASS.
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)

        # (vg-a) BAD: a superseded verdict asserted as a CURRENT claim, no frame.
        stale = tdir / "stale_verdict.md"
        stale.write_text(
            "## Sign verdict\n\n"
            "The signer cannot be reproduced offline; the production token is "
            "`needs-runtime-hook` and a device is required to proceed.\n",
            encoding="utf-8",
        )
        if not lint_verdicts(tdir):
            print(
                "SELFTEST FAIL: an un-framed superseded verdict "
                "('needs-runtime-hook' asserted as current) was NOT flagged — the "
                "verdict-overturn guard does not bite (this is the 4×-recurring "
                "failure mode).",
                file=sys.stderr,
            )
            failures += 1
        Path(stale).unlink()

        # (vg-b1) GOOD: same token, framed by a SUPERSEDED banner within window.
        framed_banner = tdir / "framed_banner.md"
        framed_banner.write_text(
            "## Sign verdict (SUPERSEDED)\n\n"
            "> SUPERSEDED by TASK-0023 (`tuya_sign_static.md`): the verdict below "
            "is kept only as history.\n\n"
            "Verdict: needs-runtime-hook\n",
            encoding="utf-8",
        )
        if lint_verdicts(tdir):
            print(
                "SELFTEST FAIL: a superseded token carrying a SUPERSEDED frame was "
                "flagged: "
                + "; ".join(f.render() for f in lint_verdicts(tdir)),
                file=sys.stderr,
            )
            failures += 1
        Path(framed_banner).unlink()

        # (vg-b2) GOOD: framed by an enclosing [HISTORICAL — WRONG] heading far
        # above the hit (section-anchored frame, robust to line drift).
        framed_heading = tdir / "framed_heading.md"
        framed_heading.write_text(
            "## 3. [HISTORICAL — WRONG] the old cipher claim\n\n"
            + "filler line\n" * 12
            + "The core transform is a white-box table cipher — the wall.\n",
            encoding="utf-8",
        )
        if lint_verdicts(tdir):
            print(
                "SELFTEST FAIL: a superseded token under a [HISTORICAL] heading "
                "(far above the hit) was flagged — section-anchored framing fails: "
                + "; ".join(f.render() for f in lint_verdicts(tdir)),
                file=sys.stderr,
            )
            failures += 1
        Path(framed_heading).unlink()

        # (vg-b3) GOOD: framed by strikethrough and by an option-set enumeration.
        framed_misc = tdir / "framed_misc.md"
        framed_misc.write_text(
            "## Verdict menu and crossed-out history\n\n"
            "Token set for this spike: {recoverable-statically | "
            "needs-runtime-hook | needs-live-capture}.\n\n"
            "The old call ~~the core transform is a white-box table cipher~~ is "
            "retracted.\n",
            encoding="utf-8",
        )
        if lint_verdicts(tdir):
            print(
                "SELFTEST FAIL: a superseded token inside an option-set OR a "
                "strikethrough was flagged: "
                + "; ".join(f.render() for f in lint_verdicts(tdir)),
                file=sys.stderr,
            )
            failures += 1
        Path(framed_misc).unlink()

    # ── Frame-tightening self-test (TASK-0038) ───────────────────────────────
    # The OLD rule let ANY soft word (history/stale/conservative/deprecated/
    # obsolete) frame a hit by mere ±3-line proximity, with no requirement it
    # refer to the verdict. Both reviewers planted an UNRELATED nearby soft word
    # next to a genuinely-CURRENT stale verdict and it PASSED (false negative).
    # These cases prove the tightened rule now BITES on a free-floating soft word
    # while still PASSING genuine strong frames and the soft-word-in-heading and
    # soft-word+forward-pointer forms.
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)

        def _verdict_findings(name: str, body: str):
            p = tdir / name
            p.write_text(body, encoding="utf-8")
            fs = lint_verdicts(tdir)
            p.unlink()
            return fs

        # (vg-tn1) ADVERSARIAL: unrelated "commit history" near a CURRENT stale
        #          verdict — must now FLAG (the soft word does not refer to the
        #          verdict and there is no forward-pointer).
        adv_history = (
            "## Sign verdict (current)\n\n"
            "We reviewed the commit history of the signer before concluding.\n"
            "The production token is `needs-runtime-hook` and a device is "
            "required to proceed. This remains our live verdict.\n"
        )
        if not _verdict_findings("adv_history.md", adv_history):
            print(
                "SELFTEST FAIL (TASK-0038): an unrelated nearby 'history' soft "
                "word let a CURRENT `needs-runtime-hook` verdict pass — the "
                "free-floating-soft-word false negative is still open.",
                file=sys.stderr,
            )
            failures += 1

        # (vg-tn2) ADVERSARIAL: unrelated "stale cache entry" near a CURRENT
        #          `no runtime input` verdict — must now FLAG.
        adv_stale = (
            "## Decode model (current)\n\n"
            "A stale cache entry was cleared during testing, no impact.\n"
            "The decode has no runtime input and is static-config-only as of "
            "this writing. This is the active model.\n"
        )
        if not _verdict_findings("adv_stale.md", adv_stale):
            print(
                "SELFTEST FAIL (TASK-0038): an unrelated nearby 'stale' soft word "
                "let a CURRENT `no runtime input` verdict pass.",
                file=sys.stderr,
            )
            failures += 1

        # (vg-tn3) ADVERSARIAL: unrelated "conservative memory budget" near a
        #          CURRENT white-box-cipher verdict — must now FLAG.
        adv_consv = (
            "## Cipher classification (current)\n\n"
            "We used a conservative memory budget for the disassembler.\n"
            "The core transform is a white-box table cipher — the wall, and "
            "that stands.\n"
        )
        if not _verdict_findings("adv_consv.md", adv_consv):
            print(
                "SELFTEST FAIL (TASK-0038): an unrelated nearby 'conservative' "
                "soft word let a CURRENT white-box-cipher verdict pass.",
                file=sys.stderr,
            )
            failures += 1

        # (vg-tn4) GOOD: a SOFT word IN THE ENCLOSING HEADING still frames (the
        #          section-anchored history mark — the one real-tree pattern that
        #          relies on a soft word, bmp_token_decode.md §3).
        soft_heading = (
            "## 3. [HISTORICAL — WRONG] the old cipher claim\n\n"
            + "filler\n" * 6
            + "The core transform is a white-box table cipher — the wall.\n"
        )
        if _verdict_findings("soft_heading.md", soft_heading):
            print(
                "SELFTEST FAIL (TASK-0038): a soft word in the SECTION HEADING "
                "([HISTORICAL — WRONG]) failed to frame — section-anchored history "
                "marking must still pass.",
                file=sys.stderr,
            )
            failures += 1

        # (vg-tn5) GOOD: a SOFT word PAIRED WITH a forward-pointer frames (a
        #          genuine "kept as history → see X" note).
        soft_fwd = (
            "## Sign verdict\n\n"
            "This `needs-runtime-hook` line is kept only as history → see "
            "tuya_sign_static.md for the live verdict.\n"
        )
        if _verdict_findings("soft_fwd.md", soft_fwd):
            print(
                "SELFTEST FAIL (TASK-0038): a soft word PAIRED with a forward-"
                "pointer (→ / .md target) failed to frame — a genuine "
                "supersession note must pass.",
                file=sys.stderr,
            )
            failures += 1

        # (vg-tn6) GOOD: each STRONG banner alone frames (sanity over the banner
        #          set, independent of any soft word).
        for banner in ("SUPERSEDED", "REFUTED", "CORRECTED", "RETRACTED",
                       "OVERTURNED", "erratum"):
            body = (
                "## Sign verdict\n\n"
                f"> {banner} by TASK-0023 (tuya_sign_static.md).\n\n"
                "Verdict: needs-runtime-hook\n"
            )
            if _verdict_findings("banner.md", body):
                print(
                    f"SELFTEST FAIL (TASK-0038): a '{banner}' banner failed to "
                    "frame a superseded token.",
                    file=sys.stderr,
                )
                failures += 1

        # (vg-tn7) RE-PROVE the 4 historical recurrence forms still FLAG when
        #          UN-FRAMED (one per SUPERSEDED_VERDICTS row). Each asserts the
        #          dead token as a current claim with NO frame of any kind.
        recurrences = {
            "rec_runtime.md": (
                "## Sign\n\nThe signer needs-runtime-hook to produce a token.\n"
            ),
            "rec_whitebox.md": (
                "## Cipher\n\nfcn.11658 is a white-box table cipher we cannot "
                "port.\n"
            ),
            "rec_noinput.md": (
                "## Decode\n\nThe decode takes no runtime input; it is fully "
                "static.\n"
            ),
            "rec_static.md": (
                "## Decode\n\nThe token is statically-recoverable-in-principle "
                "from the BMP.\n"
            ),
        }
        for name, body in recurrences.items():
            if not _verdict_findings(name, body):
                print(
                    f"SELFTEST FAIL (TASK-0038): un-framed recurrence form "
                    f"'{name}' did NOT flag — the guard must still bite on every "
                    "SUPERSEDED_VERDICTS row.",
                    file=sys.stderr,
                )
                failures += 1

    # ── _artifact_key @0xHEX collapse self-test (TASK-0038 P2) ────────────────
    # The `@0xHEX` offset is positional decoration, not a separate artifact:
    # `lib.so@0x1234`, `lib.so`, and a readelf dump of the same lib must collapse
    # to ONE artifact key. Previously this worked only by a CITATION_RE alternation
    # accident; now _artifact_key strips the offset explicitly. Prove the collapse
    # directly AND end-to-end (a `confirmed` section citing `.so@0xHEX` + the same
    # `.so` bare is ONE source and must FLAG).
    k_off = _artifact_key("libthing_security.so@0x11658".casefold())
    k_bare = _artifact_key("libthing_security.so".casefold())
    k_dump = _artifact_key("re/symbols/libthing_security.dynsym.txt".casefold())
    if not (k_off == k_bare == k_dump == "so:libthing_security"):
        print(
            "SELFTEST FAIL (TASK-0038): `.so@0xHEX`, bare `.so`, and the `.so` "
            f"dump did not collapse to one artifact key (got {k_off!r}, "
            f"{k_bare!r}, {k_dump!r}).",
            file=sys.stderr,
        )
        failures += 1

    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        # A `confirmed` claim whose two "sources" are the SAME `.so` at two offsets
        # is ONE source → must FLAG (the offset must not game the >=2-source rule).
        so_off = tdir / "so_offset.md"
        so_off.write_text(
            "## Native cipher\n\n"
            "The `key` schedule lives in libthing_security.so@0x11658 and the "
            "round at libthing_security.so@0x11afc (confidence: confirmed).\n",
            encoding="utf-8",
        )
        if not lint_doc(so_off):
            print(
                "SELFTEST FAIL (TASK-0038): a confirmed section citing the SAME "
                ".so at two @0xHEX offsets passed — the offset gamed the "
                ">=2-source rule (it is one artifact).",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"check-evidence selftest: {failures} failure(s)", file=sys.stderr)
        return 1
    print(
        "check-evidence selftest: OK (bites on bad, passes good, "
        "verdict-gate works, ratchet holds, symbol-anchored cites accepted "
        "while no-citation claims still fail, same-artifact .so dumps + @0xHEX "
        "offsets collapse, verdict-overturn guard bites on un-framed stale tokens "
        "AND on free-floating soft words while strong/heading/soft+pointer frames "
        "pass)"
    )
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    # Default: lint the re/ directory (the dir containing scripts/ ..).
    script_dir = Path(__file__).resolve().parent
    re_dir = script_dir.parent  # re/
    return run(re_dir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
