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

# Unit-test the offline t_s.bmp token-decode port + nalajcie cross-check (TASK-0029).
[group('test')]
test-bmp-decode:
    cd re/scripts && python3 test_bmp_token_decode.py
    cd re/scripts && python3 test_bmp_token_aes.py
    cd re/scripts && python3 test_bmp_token_ghidra.py

# Unit-test regions_decrypt.py host enumeration (>2 host fields; TASK-0048).
[group('test')]
test-regions:
    cd re/scripts && python3 test_regions_decrypt.py

# End-to-end gate (build+test+lint+fmt-check+stub-grep+offline). Green before any commit.
[group('test')]
e2e: build test lint fmt-check stub-grep assert-offline test-bmp-decode test-regions

# Assert the test suite needs no network (--offline build + enumerate).
[group('test')]
assert-offline:
    cargo test --manifest-path {{MANIFEST}} --offline -- --include-ignored --list >/dev/null
    @echo "assert-offline: OK (test binaries build & enumerate with --offline; no network)"

# Differentially validate the app-cert digest: the pure-Rust extractor MUST
# match an independent `openssl asn1parse -strparse` reference over the raw
# embedded leaf cert (needs the gitignored APK + openssl; value withheld).
[group('test')]
cert-crosscheck:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(cargo test --manifest-path {{MANIFEST}} -p babymonitor-core \
        sign::tests::real_app_cert_matches_openssl_reference -- --ignored --exact 2>&1)
    echo "$out"
    # Guard against a false-green: the filter MUST have actually run the test.
    echo "$out" | grep -q "1 passed" \
        || { echo "cert-crosscheck: test did not run (filter mismatch)"; exit 1; }
    echo "cert-crosscheck: OK (Rust extractor == openssl raw-embedded reference)"

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
    show "version"             --version
    show "help"                --help
    show "info"                info
    show "info --json"         info --json
    show "default (no subcommand)"
    show "auth login (identity-gate blocked)" auth login
    show "auth login --json"   --json auth login
    show "auth status"         auth status
    show "auth status --json"  --json auth status
    show "devices list (fixture)" devices list
    show "devices list --json" --json devices list
    show "devices show camera" devices show synth-dev-0001-camera
    show "devices show --json" --json devices show synth-dev-0001-camera
    # NB: `devices list --live` is intentionally OMITTED — it is blocked by the
    # server-side identity gate (no session, no fetch) and exits non-zero by design
    # (an honest "I couldn't do the live fetch"), which is correct error semantics
    # but would (correctly) fail this all-must-pass gate.
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
