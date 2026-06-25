# Philips Avent Baby Monitor+ RE — task runner.
#
# Run recipes from inside the nix shell so every tool (cargo, clippy, rustfmt,
# python3, ripgrep, grep) resolves through shell.nix:
#     nix-shell --run 'just e2e'
# `just` itself runs under nix-shell, and child processes inherit that PATH —
# so recipes call tools directly rather than wrapping each in `nix-shell --run`.

MANIFEST := "babymonitor/Cargo.toml"

# List available recipes.
default:
    @just --list

# Compile the whole workspace.
[group('build')]
build:
    cargo build --manifest-path {{MANIFEST}}

# Remove Rust build artifacts.
[group('build')]
clean:
    cargo clean --manifest-path {{MANIFEST}}

# Run unit and integration tests (offline; live tests are #[ignore]d).
[group('test')]
test:
    cargo test --manifest-path {{MANIFEST}}

# Run clippy with warnings denied.
[group('quality')]
lint:
    cargo clippy --manifest-path {{MANIFEST}} --all-targets -- -D warnings

# Format all code in place.
[group('quality')]
fmt:
    cargo fmt --manifest-path {{MANIFEST}} --all

# Verify formatting without modifying files.
[group('quality')]
fmt-check:
    cargo fmt --manifest-path {{MANIFEST}} --all -- --check

# Fail on todo!/unimplemented!/unreachable! in production code (outside #[cfg(test)]).
[group('quality')]
stub-grep:
    @bash re/scripts/stub_grep.sh

# End-to-end gate (build+test+lint+fmt-check+stub-grep+offline). Green before any commit.
[group('test')]
e2e: build test lint fmt-check stub-grep assert-offline

# Assert the test suite needs no network (--offline build + enumerate).
[group('test')]
assert-offline:
    cargo test --manifest-path {{MANIFEST}} --offline -- --include-ignored --list >/dev/null
    @echo "assert-offline: OK (test binaries build & enumerate with --offline; no network)"

# Run the CLI. Pass args after `--`, e.g. `just run info --json`.
[group('run')]
run *ARGS:
    cargo run --manifest-path {{MANIFEST}} --bin babymonitor-cli -- {{ARGS}}

# Regression tripwire: run every non-destructive CLI command; must not panic.
[group('run')]
showcase:
    #!/usr/bin/env bash
    set -uo pipefail
    A="cargo run --quiet --manifest-path {{MANIFEST}} --bin babymonitor-cli --"
    fail=0
    show() { echo "=== $1 ==="; shift; $A "$@" || { echo "(FAILED)"; fail=1; }; echo; }
    show "version"     --version
    show "help"        --help
    show "info"        info
    show "info --json" info --json
    show "default (no subcommand)"
    if [ "$fail" -ne 0 ]; then echo "showcase: a command failed"; exit 1; fi
    echo "showcase: OK (all read-only commands ran without panic)"

# Grounding lint over re/*.md (each protocol-claim section needs confidence + citation).
[group('grounding')]
check-evidence:
    python3 re/scripts/check_evidence.py

# Prove check-evidence bites: flags a planted bad fragment, passes a good one.
[group('grounding')]
check-evidence-selftest:
    python3 re/scripts/check_evidence.py --selftest

# Secret/PII gate over tracked files + pending diff + backlog tasks.
[group('grounding')]
secret-scan:
    @bash re/scripts/secret_scan.sh

# Prove secret-scan bites: plants a fake secret it must flag.
[group('grounding')]
secret-scan-selftest:
    @bash re/scripts/secret_scan.sh --selftest

# Run the script self-tests that prove the grounding gates can go red.
[group('grounding')]
gates-selftest: check-evidence-selftest secret-scan-selftest

# Install the tracked pre-push hook (secret-scan + e2e) into .git/hooks/.
[group('grounding')]
install-hooks:
    @ln -sf ../../re/scripts/pre-push "$(git rev-parse --git-dir)/hooks/pre-push"
    @chmod +x re/scripts/pre-push
    @echo "installed pre-push hook -> re/scripts/pre-push"

# Regenerate the gitignored jadx Java tree so re/*.md `decompiled/jadx/...:line`
# citations resolve locally. Heap must go via JADX_OPTS (see re/decompile_dex.md).
[group('grounding')]
decompile:
    @test -f extracted/xapk/com.philips.ph.babymonitorplus.apk || \
        { echo "missing extracted/xapk/com.philips.ph.babymonitorplus.apk (acquire the APK first)"; exit 1; }
    JADX_OPTS="-Xmx12g" jadx --no-debug-info \
        --output-dir decompiled/jadx \
        extracted/xapk/com.philips.ph.babymonitorplus.apk
