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
    r"|assets/[\w./-]+"                   # assets/… path
    r"|https?://[^\s)]+"                  # URL
    r"|\b[\w.-]+/[\w.-]+\b(?=.*\b(?:repo|github|ref|reference)\b)"  # owner/repo near a ref word
    r"|github\.com/[\w./-]+"             # explicit github ref
    r")"
)

# Trailing line hint on a citation: `:NN` or `~:NN` (with optional whitespace).
# Stripped when de-duplicating citation tokens so a path cited bare and again with
# a hint counts once (see distinct_citations).
LINE_HINT_RE = re.compile(r"\s*~?:\d+$")

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
        tokens.add(tok)
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

    if failures:
        print(f"check-evidence selftest: {failures} failure(s)", file=sys.stderr)
        return 1
    print(
        "check-evidence selftest: OK (bites on bad, passes good, "
        "verdict-gate works, ratchet holds, symbol-anchored cites accepted "
        "while no-citation claims still fail)"
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
