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
e2e: build test lint fmt-check stub-grep assert-offline test-bmp-decode test-regions stream-validate

# Offline-validate the `stream` mux/serve path (TASK-0070/0073): synthesize an
# Annex-B H.264 sample + a 16 kHz mono S16LE downstream-audio sample, replay them
# through the real RTP depacketizer + ffmpeg A/V muxer, and assert with ffprobe
# that the produced MPEG-TS carries a decodable h264 video AND an audio track.
# No network/camera; uses ffmpeg/ffprobe from shell.nix.
[group('test')]
stream-validate:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v ffmpeg  >/dev/null || { echo "stream-validate: ffmpeg not in PATH (shell.nix provides it)"; exit 1; }
    command -v ffprobe >/dev/null || { echo "stream-validate: ffprobe not in PATH (shell.nix provides it)"; exit 1; }
    WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
    # 1. Synthetic Annex-B H.264 (baseline, no B-frames, keyframe every 15 frames).
    ffmpeg -hide_banner -loglevel error -y -f lavfi -i testsrc=size=320x240:rate=15:duration=1 \
        -c:v libx264 -profile:v baseline -pix_fmt yuv420p -g 15 -bf 0 -f h264 "$WORK/sample.264"
    # 1b. Synthetic downstream audio = 16 kHz mono S16LE PCM (the cap4 format).
    ffmpeg -hide_banner -loglevel error -y -f lavfi -i "sine=frequency=440:duration=1:sample_rate=16000" \
        -ac 1 -f s16le "$WORK/audio.s16le"
    # 2. Build + run the VIDEO-ONLY replay -> MPEG-TS through the real depacketizer.
    cargo build --quiet --manifest-path {{MANIFEST}} --bin babymonitor-cli
    BIN=$(dirname {{MANIFEST}})/target/debug/babymonitor-cli
    "$BIN" stream --replay-annexb "$WORK/sample.264" --output ts --ts-out "$WORK/out.ts"
    # first_line: capture a probe value with NO pipe (a `grep -q`/`head` reader that
    # closes early can SIGPIPE ffprobe and trip `pipefail`), then take line 1 via
    # bash param-expansion (ffprobe over a TS can list the stream row twice).
    first_line() { local v; v="$1"; printf '%s' "${v%%$'\n'*}"; }
    probe() { ffprobe -hide_banner -loglevel error "$@"; }
    # 3. ffprobe: the produced TS must carry an h264 video stream.
    VCODEC=$(first_line "$(probe -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 "$WORK/out.ts")")
    [ "$VCODEC" = h264 ] || { echo "stream-validate: produced TS is not h264 (got '$VCODEC')"; exit 1; }
    # 4. The stream must actually decode (>=1 frame -> a keyframe renders).
    N=$(first_line "$(probe -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of csv=p=0 "$WORK/out.ts")")
    [ "${N:-0}" -ge 1 ] || { echo "stream-validate: TS decoded 0 frames"; exit 1; }
    ffmpeg -hide_banner -loglevel error -i "$WORK/out.ts" -f null - >/dev/null 2>&1 \
        || { echo "stream-validate: ffmpeg failed to decode the TS"; exit 1; }
    # 5. A/V mux: replay video + the downstream S16LE audio -> MPEG-TS, assert the
    #    TS carries BOTH an h264 video track and an audio track (downstream audio is
    #    S16LE @ 16 kHz, NOT G.711 — encoded to AAC for the TS).
    "$BIN" stream --replay-annexb "$WORK/sample.264" --replay-audio "$WORK/audio.s16le" \
        --output ts --ts-out "$WORK/av.ts"
    AV_VCODEC=$(first_line "$(probe -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 "$WORK/av.ts")")
    [ "$AV_VCODEC" = h264 ] || { echo "stream-validate: A/V TS has no h264 video (got '$AV_VCODEC')"; exit 1; }
    AV_ATYPE=$(first_line "$(probe -select_streams a:0 -show_entries stream=codec_type -of csv=p=0 "$WORK/av.ts")")
    [ "$AV_ATYPE" = audio ] || { echo "stream-validate: A/V TS has no audio track (got '$AV_ATYPE')"; exit 1; }
    echo "stream-validate: OK (replay -> depacketize -> MPEG-TS; ffprobe=h264, $N frames decoded; A/V mux carries video+audio)"

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
