#!/usr/bin/env bash
# secret_scan.sh — pre-push secret/PII gate (TASK-0011, AC #4).
#
# Scans three surfaces for leaked Tuya credentials, auth tokens, emails, and GPS
# coordinates:
#   1. tracked files   (git ls-files)
#   2. pending diff    (git diff  +  git diff --cached  — unstaged + staged)
#   3. backlog/tasks/*.md  (task fields are a known leak channel; see CLAUDE.md)
#
# Rationale (CLAUDE.md "never leak secrets"): a recovered Tuya appKey/appSecret/
# sign-key, any bearer/JWT/session token, a real account id, an email, or GPS
# coordinates must NEVER enter a committed file, a task field, or a summary.
# This gate fails (exit 1) on any match so it can run pre-commit / pre-push.
#
# Self-test: `secret_scan.sh --selftest` plants a fake secret in a temp file,
# proves the patterns FLAG it, then proves a clean file PASSES. A scanner that
# can't go red is not a gate.
#
# Scope notes:
#   - Binary/large/regenerable trees are excluded (extracted/, decompiled/,
#     secrets/, target/, *.xapk …) — they are gitignored and not tracked anyway.
#   - secrets/ is the SANCTIONED home for real creds; it is gitignored, so we do
#     NOT scan it (scanning it would just re-flag legitimately-quarantined data).

set -uo pipefail

# ── Patterns ────────────────────────────────────────────────────────────────
# Each entry: "RULE_NAME|<ERE pattern>". Patterns target *value shapes*, not
# english words, to keep false positives low. Tuned for this project's threats.
#
# Tuya appKey/appSecret: Tuya keys are 20/32-char lowercase-hex-ish a-z0-9
# blobs, usually assigned to an appKey/appSecret/secret/signKey field. We anchor
# on the FIELD NAME + a long token value to avoid matching prose.
# Separator between a field name and its value: any run of quote/space/:/=  .
# NOTE the correct ERE bracket class is [[:space:]'":=] — earlier versions
# mis-nested [:space:] and silently failed to match. Self-test guards this.
PATTERNS=(
  "Tuya appKey/appSecret|(app[_-]?key|app[_-]?secret|sign[_-]?key|signkey|secretkey)[[:space:]'\":=]+[A-Za-z0-9]{16,}"
  "Bearer token|[Bb]earer[[:space:]]+[A-Za-z0-9._~+/-]{16,}=*"
  "JWT|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}"
  "Session/access token|(access[_-]?token|session[_-]?(id|token)|sessiontoken)[[:space:]'\":=]+[A-Za-z0-9._-]{16,}"
  "Tuya localKey|local[_-]?key[[:space:]'\":=]+[A-Za-z0-9]{8,}"
  "Email address|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
  "GPS coordinates|[\"'(]?-?[0-9]{1,3}\.[0-9]{4,}[\"']?[[:space:]]*,[[:space:]]*[\"'(]?-?[0-9]{1,3}\.[0-9]{4,}"
)

# Paths never scanned (gitignored / regenerable / sanctioned-secret store).
EXCLUDE_GLOBS=(
  ":!secrets/**" ":!extracted/**" ":!decompiled/**" ":!analysis/**"
  ":!reports/**" ":!target/**" ":!**/*.xapk" ":!**/*.apk" ":!**/*.png"
  ":!**/*.jpg" ":!**/*.bmp" ":!Cargo.lock"
)

# Allowlist: substrings that are known-safe (the user's own committed email in
# CLAUDE.md context is the project owner's address used for git config docs).
# Keep this TIGHT and documented; it is not a wildcard.
ALLOW_SUBSTRINGS=(
  "noreply@anthropic.com"        # co-author trailer, not a secret
  "***REMOVED-PII***"              # project owner's own address (already public in repo config docs)
  "example.com"                  # documentation placeholder domain
  "user@host"                    # doc placeholder
)

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT" || exit 2

# Inline allow-marker: any line containing this literal token is exempt. Used to
# whitelist the scanner's OWN test fixtures (obviously-fake planted values) and
# any intentional placeholder. Auditable and greppable — `rg secret-scan:allow`
# shows every exemption. NOT a wildcard: only marked lines are skipped.
ALLOW_MARKER='secret-scan:allow'

is_allowed() {
  local line="$1"
  [[ "$line" == *"$ALLOW_MARKER"* ]] && return 0
  for s in "${ALLOW_SUBSTRINGS[@]}"; do
    [[ "$line" == *"$s"* ]] && return 0
  done
  return 1
}

# Scan a blob of "path:line:content" candidate hits against all patterns.
# Args: $1 = source label, $2 = file containing candidate text lines.
HITS=0
scan_stream() {
  local label="$1" content_file="$2"
  for entry in "${PATTERNS[@]}"; do
    local rule="${entry%%|*}"
    local pat="${entry#*|}"
    # grep -aEn: -a forces TEXT mode so a stray NUL byte from an adjacent binary
    # blob in the concatenated stream cannot silently flip grep into "binary file
    # matches" mode and suppress the per-line output (which would let a real
    # secret next to a binary file go UNREPORTED). -n adds line numbers.
    while IFS= read -r match; do
      [ -z "$match" ] && continue
      if is_allowed "$match"; then
        continue
      fi
      # Redact for safe printing (P1-3): NEVER echo the secret value region into
      # hook/CI logs. Mask from the matched VALUE, not the first N chars of the
      # LINE (TASK-0020 #1). The old code kept `match:0:5` — safe only when a
      # `path:`/`LINE:` prefix happened to lead the line, but a VALUE-LEADING line
      # (a JWT/email/GPS at column 0, e.g. a raw `eyJ…` token or `victim@…`) would
      # leak its first 5 chars (header/local-part). Instead, find WHERE the matched
      # value starts inside the line and mask from there, keeping only the
      # surrounding non-secret context (path/field-name prefix). The value is
      # extracted with the SAME pattern via `grep -oiE` so the offset is exact.
      local value off prefix vlen
      value="$(printf '%s' "$match" | grep -oiE -m1 -- "$pat" 2>/dev/null)"
      if [ -z "$value" ]; then
        # Should not happen (the line matched the pattern), but fail safe: if we
        # cannot isolate the value, redact the WHOLE line rather than risk a leak.
        printf 'SECRET[%s] (%s): [REDACTED %d chars — value not isolable]\n' \
          "$label" "$rule" "${#match}" >&2
        HITS=$((HITS + 1))
        continue
      fi
      # Byte offset of the value within the line (prefix = everything before it).
      prefix="${match%%"$value"*}"
      off="${#prefix}"
      vlen="${#value}"
      # Cap the shown prefix so a long path/field-name does not itself become a
      # leak channel and the locator stays short. The value region is ALWAYS fully
      # masked regardless of where it sits in the line.
      if [ "$off" -gt 32 ]; then
        prefix="…${prefix: -31}"
      fi
      printf 'SECRET[%s] (%s): %s[REDACTED %d chars]\n' \
        "$label" "$rule" "$prefix" "$vlen" >&2
      HITS=$((HITS + 1))
    done < <(grep -anEhi -- "$pat" "$content_file" 2>/dev/null)
  done
}

scan_worktree() {
  local tmp
  tmp="$(mktemp)"
  # Everything that would be committed: tracked files PLUS untracked-but-not-
  # gitignored files (new files a `git add .` would stage). Both honor the
  # exclude globs. Missing the untracked set was a real gap — a brand-new file
  # full of secrets would otherwise sail through. Self-test guards this.
  {
    git ls-files -- "${EXCLUDE_GLOBS[@]}"
    git ls-files --others --exclude-standard -- "${EXCLUDE_GLOBS[@]}"
  } | sort -u | while IFS= read -r f; do
    [ -f "$f" ] || continue
    # Skip clearly-binary files.
    case "$f" in
      *.so|*.dex|*.png|*.jpg|*.jpeg|*.gif|*.bmp|*.ico|*.zip|*.gz|*.xapk|*.apk|*.pyc|*/__pycache__/*) continue;;
    esac
    # prefix each line with the path for context
    sed "s#^#${f}:#" "$f" 2>/dev/null
  done > "$tmp"
  scan_stream "worktree" "$tmp"
  rm -f "$tmp"
}

scan_diff() {
  local tmp
  tmp="$(mktemp)"
  # Added lines from unstaged + staged diffs (the pre-commit/pre-push surface).
  { git diff; git diff --cached; } 2>/dev/null \
    | grep -E '^\+' | grep -vE '^\+\+\+' | sed 's/^+//' > "$tmp"
  scan_stream "diff" "$tmp"
  rm -f "$tmp"
}

scan_backlog() {
  local tmp
  tmp="$(mktemp)"
  if [ -d backlog/tasks ]; then
    while IFS= read -r f; do
      sed "s#^#${f}:#" "$f" 2>/dev/null
    done < <(find backlog/tasks -name '*.md' 2>/dev/null) > "$tmp"
    scan_stream "backlog" "$tmp"
  fi
  rm -f "$tmp"
}

# ── Self-test (AC #4): prove the gate bites ─────────────────────────────────
selftest() {
  local td
  td="$(mktemp -d)"
  local fails=0

  # 1) Planted fake secret MUST be flagged.
  local bad="$td/bad.txt"
  # The trailing `# secret-scan:allow` comments exempt THESE SOURCE LINES from
  # the worktree scan (they hold obviously-fake fixtures). The marker is a shell
  # comment, so it is NOT part of the echoed string — the runtime fixture file
  # has no marker and is still correctly flagged below.
  {
    echo "appKey: a1b2c3d4e5f6a7b8c9d0e1f2"                        # secret-scan:allow
    echo 'appSecret = "zzzz1111yyyy2222xxxx3333"'                  # secret-scan:allow
    echo "Authorization: Bearer abcdef0123456789ABCDEF0123456789"  # secret-scan:allow
    echo "token=eyJhbGciOi.JSUzI1NiIsInR5.cCI6IkpXVCJ9"            # secret-scan:allow
    echo "home location 55.67611, 12.56838"                        # secret-scan:allow
    echo "contact victim@gmail.com"                                # secret-scan:allow
  } > "$bad"
  local before="$HITS"
  HITS=0
  scan_stream "selftest-bad" "$bad"
  if [ "$HITS" -lt 5 ]; then
    echo "SELFTEST FAIL: planted secrets under-detected (got $HITS hits, want >=5)" >&2
    fails=$((fails + 1))
  else
    echo "selftest: planted fake secrets flagged ($HITS hits) — gate bites" >&2
  fi

  # 1b) Redaction MUST NOT echo the full secret value (P1-3). Plant a secret with
  #     a known, distinctive value substring, capture the scanner's stderr, and
  #     assert that substring is absent from the output. A redactor that prints
  #     the value is a leak channel into hook/CI logs.
  local redact="$td/redact.txt"
  local planted_val="supersecretvalue9988776655zzzz"
  printf 'appSecret = "%s"\n' "$planted_val" > "$redact"
  # Capture stderr in a subshell. Derive the hit count from the captured SECRET[
  # lines (NOT the global HITS, which a command-substitution subshell cannot
  # mutate in the parent).
  local out hit_lines
  out="$(scan_stream "selftest-redact" "$redact" 2>&1)"
  hit_lines="$(printf '%s\n' "$out" | grep -c 'SECRET\[' || true)"
  if printf '%s' "$out" | grep -qF -- "$planted_val"; then
    echo "SELFTEST FAIL: redaction leaked the full secret value into output:" >&2
    echo "  $out" >&2
    fails=$((fails + 1))
  elif [ "$hit_lines" -lt 1 ]; then
    echo "SELFTEST FAIL: redaction test planted secret was not detected at all" >&2
    fails=$((fails + 1))
  else
    echo "selftest: redaction masks the value — full secret NOT printed (output: $out)" >&2
  fi

  # 1c) VALUE-LEADING redaction (TASK-0020 #1). A line whose secret value sits at
  #     column 0 (no path:/field: prefix) MUST still be masked from the value, not
  #     have its leading chars printed. Plant a JWT and an email at line start and
  #     assert neither distinctive value substring appears in the output. The old
  #     `match:0:5` redactor leaked the first 5 chars of such lines.
  local vlead="$td/vlead.txt"
  {
    echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrIn0.zzzleaktoken"  # secret-scan:allow
    echo "victimleaduser@gmail.com"                                                # secret-scan:allow
  } > "$vlead"
  local vout vhits
  vout="$(scan_stream "selftest-vlead" "$vlead" 2>&1)"
  vhits="$(printf '%s\n' "$vout" | grep -c 'SECRET\[' || true)"
  if [ "$vhits" -lt 2 ]; then
    echo "SELFTEST FAIL: value-leading lines under-detected (got $vhits, want >=2)" >&2
    fails=$((fails + 1))
  elif printf '%s' "$vout" | grep -qiE 'eyJhbGci|victimleaduser'; then
    echo "SELFTEST FAIL: redaction leaked a value-leading secret prefix into output:" >&2
    echo "  $vout" >&2
    fails=$((fails + 1))
  else
    echo "selftest: value-leading lines masked from the value (output: $vout)" >&2
  fi

  # 2) Clean file MUST pass (allowlisted owner email + harmless prose).
  local good="$td/good.txt"
  {
    echo "This module parses the device list."
    echo "Owner contact: ***REMOVED-PII***"
    echo "See example.com for docs."
    echo "The handshake uses a session key (no value shown here)."
  } > "$good"
  HITS=0
  scan_stream "selftest-good" "$good"
  if [ "$HITS" -ne 0 ]; then
    echo "SELFTEST FAIL: clean file produced $HITS false-positive hit(s)" >&2
    fails=$((fails + 1))
  else
    echo "selftest: clean file passed (0 hits)" >&2
  fi

  # 3) End-to-end worktree bite: plant an untracked file in the repo, confirm a
  #    full scan_worktree FAILS, then confirm it passes once removed. This guards
  #    the regression where untracked files were not scanned at all.
  local planted="$REPO_ROOT/.secret_scan_selftest_planted.txt"
  printf 'appSecret = "deadbeefcafe1234deadbeefcafe5678"\n' > "$planted"  # secret-scan:allow
  HITS=0
  scan_worktree
  if [ "$HITS" -lt 1 ]; then
    echo "SELFTEST FAIL: planted UNTRACKED worktree file not flagged (regression)" >&2
    fails=$((fails + 1))
  else
    echo "selftest: planted untracked worktree file flagged — worktree scan bites" >&2
  fi
  rm -f "$planted"
  HITS=0
  scan_worktree
  if [ "$HITS" -ne 0 ]; then
    echo "SELFTEST FAIL: worktree not clean after removing planted file ($HITS hits)" >&2
    fails=$((fails + 1))
  fi

  HITS="$before"
  rm -rf "$td"
  if [ "$fails" -ne 0 ]; then
    echo "secret-scan selftest: $fails failure(s)" >&2
    return 1
  fi
  echo "secret-scan selftest: OK (bites on planted secret, passes clean input)"
  return 0
}

main() {
  if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
  fi

  scan_worktree
  scan_diff
  scan_backlog

  if [ "$HITS" -gt 0 ]; then
    echo "secret-scan: FAILED — $HITS potential secret/PII finding(s) above. Move real values to secrets/ (gitignored)." >&2
    exit 1
  fi
  echo "secret-scan: OK (no secrets in tracked files, pending diff, or backlog tasks)"
  exit 0
}

main "$@"
