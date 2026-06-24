#!/usr/bin/env bash
# stub_grep.sh — fail if production Rust code contains stub panic macros
# (todo!/unimplemented!/unreachable!) outside #[cfg(test)] (TASK-0011, AC #7).
#
# Why: "stubs are not done" (TESTING.md Part 2). A todo!()/unimplemented!() on a
# non-test path is a silent landmine that panics at runtime. The honest pattern
# is a typed `Error::NotImplemented(...)` + a filed follow-up task. unreachable!
# is likewise forbidden in production paths (it asserts an invariant by panic).
#
# Test code legitimately uses these (e.g. unreachable! in an exhaustive match
# arm a test forces), so #[cfg(test)] modules are excluded. Exclusion is done by
# a brace-balanced Python pass, not a fragile line regex.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SRC_DIR="$REPO_ROOT/babymonitor"

if [ ! -d "$SRC_DIR" ]; then
  echo "stub-grep: OK (no babymonitor/ sources yet)"
  exit 0
fi

python3 - "$SRC_DIR" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
MACROS = ("todo!", "unimplemented!", "unreachable!")
# Match the macro followed by ( or [ or { (Rust allows all three delimiters).
MACRO_RE = re.compile(r"\b(todo|unimplemented|unreachable)\s*!\s*[\(\[\{]")
CFG_TEST_RE = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")

findings = []

for rs in sorted(src.rglob("*.rs")):
    # Skip generated/target trees defensively.
    if "target" in rs.parts:
        continue
    text = rs.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # Mark byte ranges that belong to #[cfg(test)] items by brace-matching the
    # block that immediately follows a #[cfg(test)] attribute.
    test_spans = []  # (start_char, end_char)
    for m in CFG_TEST_RE.finditer(text):
        # Find the first '{' after the attribute (start of the mod/fn body).
        i = text.find("{", m.end())
        if i == -1:
            continue
        depth = 0
        j = i
        while j < len(text):
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        test_spans.append((m.start(), j))

    def in_test(pos: int) -> bool:
        return any(s <= pos <= e for s, e in test_spans)

    for lineno, line in enumerate(lines, start=1):
        # Ignore matches inside line comments.
        code = line.split("//", 1)[0]
        for mm in MACRO_RE.finditer(code):
            # Char offset of this match within the whole file.
            char_pos = sum(len(l) + 1 for l in lines[: lineno - 1]) + mm.start()
            if in_test(char_pos):
                continue
            findings.append(f"{rs}:{lineno}: stub macro `{mm.group(0)}` in production code")

if findings:
    print(f"stub-grep: {len(findings)} forbidden stub(s) outside #[cfg(test)]:", file=sys.stderr)
    for f in findings:
        print(f"  {f}", file=sys.stderr)
    sys.exit(1)

print("stub-grep: OK (no todo!/unimplemented!/unreachable! in production code)")
PY
