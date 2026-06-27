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
    ffmpeg

    # Rust toolchain
    rustc cargo clippy rustfmt rust-analyzer pkg-config openssl.dev

    # Project management & docs
    just git curl wget pandoc graphviz

    # Python for ad-hoc scripts
    python3 python3Packages.requests python3Packages.lxml
  ];

  shellHook = ''
    export JADX_OPTS="-Xmx4g"
    export JAVA_OPTS="-Xmx4g"
    mkdir -p extracted decompiled analysis reports secrets
  '';
}
