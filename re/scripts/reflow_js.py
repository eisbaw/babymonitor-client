#!/usr/bin/env python3
"""reflow_js.py — lightweight, string-aware beautifier for minified RN bundles.

Not a full JS formatter (no node dep): inserts newlines + indentation after
`{` `}` `;` while respecting string/template-literal/regex-ish quoting, so the
already-plain-JS kit_js / mini_app_js bundles become greppable and readable.
Output goes to <file>.pretty alongside the (gitignored) original. Bundles that
are already multi-line are copied through unchanged.
"""
import glob
import os
import sys

QUOTES = "\"'`"


def reflow(s: str) -> str:
    out = []
    i = 0
    n = len(s)
    q = None
    depth = 0
    while i < n:
        c = s[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in QUOTES:
            q = c
            out.append(c)
            i += 1
            continue
        if c == "{":
            depth += 1
            out.append(c)
            out.append("\n" + "  " * depth)
            i += 1
            continue
        if c == "}":
            depth = max(0, depth - 1)
            out.append("\n" + "  " * depth)
            out.append(c)
            i += 1
            continue
        if c == ";":
            out.append(c)
            out.append("\n" + "  " * depth)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def main(base: str) -> int:
    count = 0
    for d in ("kit_js", "mini_app_js"):
        for f in sorted(glob.glob(os.path.join(base, d, "*.js"))):
            try:
                s = open(f, encoding="utf-8", errors="replace").read()
            except OSError as e:
                print("skip", f, e, file=sys.stderr)
                continue
            dst = f + ".pretty"
            if s.count("\n") > 50:
                open(dst, "w", encoding="utf-8").write(s)
            else:
                open(dst, "w", encoding="utf-8").write(reflow(s))
            count += 1
    print(f"reflow_js: wrote {count} .pretty files under {base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "decompiled/js/assets"))
