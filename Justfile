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

# Compile, test, and lint the live-feature orchestration using injected/loopback I/O.
[group('test')]
test-live:
    cargo test --manifest-path {{MANIFEST}} -p babymonitor-cli --features live
    cargo clippy --manifest-path {{MANIFEST}} -p babymonitor-cli --all-targets --features live -- -D warnings

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

# End-to-end gate (default/live tests + lint + formatting + offline integration).
[group('test')]
e2e: build test test-live lint fmt-check stub-grep assert-offline test-bmp-decode test-regions stream-validate
    cd re/scripts && python3 test_camera_surface_probe.py

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

# Watch the camera live: build + start the `--features live` pipeline, wait for it
# to answer, then open VLC on it automatically and stop everything when VLC closes.
# Needs the owner's gitignored secrets/ + a valid session (run `auth live-login`
# first if it has expired). Opening VLC promptly is what keeps the KCP window
# advancing — if the player attaches late the camera can freeze (~12 frames, TASK-0085).
[group('run')]
live-stream port="8556":
    #!/usr/bin/env bash
    set -uo pipefail
    PORT="{{port}}"
    LOG="$(mktemp)"
    echo "live-stream: building + starting the camera pipeline on :$PORT (this can take ~30-60s)…"
    cargo run --quiet --manifest-path babymonitor/babymonitor-cli/Cargo.toml \
        --features live --bin babymonitor-cli -- stream --output http --port "$PORT" >"$LOG" 2>&1 &
    SPID=$!
    cleanup() { kill "$SPID" 2>/dev/null; pkill -P "$SPID" 2>/dev/null; pkill -f "babymonitor-cli -- stream --output http --port $PORT" 2>/dev/null; rm -f "$LOG"; }
    trap cleanup EXIT INT TERM
    echo "live-stream: waiting for the camera to answer + the server to come up…"
    if ! timeout 150 bash -c "tail -n +1 -f '$LOG' | grep -m1 'pumping; connect a player'"; then
        echo "live-stream: did not come up in time. Last log:"; tail -25 "$LOG"; exit 1
    fi
    echo "live-stream: serving http://127.0.0.1:$PORT/stream.ts — opening VLC (close VLC to stop)…"
    sleep 1
    # --network-caching gives VLC a ~1.5s jitter cushion; the client's bounded
    # video queue (LiveAvSink) keeps the camera's KCP window advancing so the
    # source itself does not freeze (TASK-0085).
    vlc --no-video-title-show --network-caching=1500 "http://127.0.0.1:$PORT/stream.ts" >/dev/null 2>&1 || true
    echo "live-stream: VLC closed; stopping pipeline."

# Live camera in an in-app SDL2 window (no external player / HTTP): the
# `--features live,gui` pipeline with `--output window` (in-process libavcodec decode
# -> SDL window). Needs the owner's gitignored secrets/ + a valid session (run
# `auth live-login` first if it has expired). The binary is run directly (not via
# `cargo run`) so signals reach it, not an orphaned grandchild. The window has a
# working close button, and Ctrl-C / SIGTERM also stop it (gui::close_requested); the
# foreground shell ALSO traps Ctrl-C/TERM/HUP as a SIGKILL backstop. Stop it by
# closing the window or pressing Ctrl-C in this terminal.
[group('run')]
gui-stream:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "gui-stream: building the live GUI window pipeline (first build can take ~30-60s)…"
    cargo build --quiet --manifest-path babymonitor/babymonitor-cli/Cargo.toml \
        --features live,gui --bin babymonitor-cli
    BIN=babymonitor/target/debug/babymonitor-cli
    echo "gui-stream: starting — a window opens once the camera answers (stages 1-6)."
    echo "gui-stream: press Ctrl-C HERE (or close this terminal) to stop."
    "$BIN" stream --output window &
    SPID=$!
    # The binary now stops itself on close / Ctrl-C / SIGTERM (gui::close_requested);
    # this trap is a belt-and-suspenders SIGKILL backstop (terminal close/HUP, or a
    # wedged window) so we never leave an orphan.
    trap 'kill -9 "$SPID" 2>/dev/null' EXIT INT TERM HUP
    wait "$SPID"
    echo "gui-stream: stream stopped."

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
# NOTE: the scanner lives under secrets/ (gitignored) so its owner-email allowlist
# is not a tracked file; it is therefore local-only and absent on a fresh clone.
[group('grounding')]
secret-scan:
    @bash secrets/secret_scan.sh

# Prove secret-scan bites: plants a fake secret it must flag.
[group('grounding')]
secret-scan-selftest:
    @bash secrets/secret_scan.sh --selftest

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
