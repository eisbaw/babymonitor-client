{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # APK acquisition
    apkeep

    # Extraction & analysis
    unzip file tree findutils binwalk binutils p7zip

    # Android decompilation / resources
    android-tools apktool jadx jdk radare2 ghidra

    # Text processing
    ripgrep jq xmlstarlet

    # Media muxer/probe for the `stream` subcommand + offline TS validation.
    # ffmpeg also provides libav* (libavcodec/libavutil/libswscale) for the in-app
    # GUI video decoder (TASK-0115, `gui` feature). Pinned to ffmpeg_7 because the
    # ffmpeg-sys-the-third 3.0.1 binding supports <=7.1 (ffmpeg 8.0 removed avfft.h
    # which the binding still references). Muxing for the `stream` path is unaffected.
    ffmpeg_7

    # In-app GUI video window (TASK-0115, `gui` feature): SDL2 = native render
    # window + YUV texture present + audio out. nix wires its X11 runpath so the
    # window finds libX11 etc. at runtime.
    SDL2

    # Rust toolchain
    rustc cargo clippy rustfmt rust-analyzer pkg-config openssl.dev

    # libclang for bindgen — the in-process libav decoder binding for the GUI
    # window (TASK-0115, `gui` feature) generates from the ffmpeg headers.
    llvmPackages.libclang clang

    # Project management & docs
    just git git-filter-repo curl wget pandoc graphviz

    # Python for ad-hoc scripts
    python3 python3Packages.requests python3Packages.lxml
  ];

  shellHook = ''
    export JADX_OPTS="-Xmx4g"
    export JAVA_OPTS="-Xmx4g"
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
    # bindgen's libclang invocation does not inherit the nix cc wrapper's header
    # paths, so it cannot find libc (<stdlib.h>) or clang's builtin headers. Point
    # it at glibc's dev headers + the clang resource dir (TASK-0115 gui decoder).
    export BINDGEN_EXTRA_CLANG_ARGS="-isystem ${pkgs.glibc.dev}/include -isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.libclang.version}/include -isystem ${pkgs.ffmpeg_7.dev}/include"
    mkdir -p extracted decompiled analysis reports secrets
  '';
}
