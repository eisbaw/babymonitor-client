//! `babymonitor-cli` — command-line viewer for the Philips Avent Baby Monitor+.
//!
//! Scaffold only: the real subcommands (`login`, `devices`, `stream`, control)
//! arrive with later backlog tasks. Today it offers `--version` and a no-op
//! `info` subcommand so `just showcase` and the e2e gates have something real,
//! non-destructive, and offline to exercise.
//!
//! Output policy (matches the skill's CLI guidance): every subcommand supports
//! a `--json` flag for machine consumption alongside the default human output.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

/// Top-level CLI definition.
#[derive(Debug, Parser)]
#[command(
    name = "babymonitor-cli",
    version,
    about = "Rust client for the Philips Avent Baby Monitor+ (Tuya IPC camera)",
    long_about = None
)]
struct Cli {
    /// Emit machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Available subcommands. Read-only / non-destructive only, for now.
#[derive(Debug, Subcommand)]
enum Command {
    /// Print build/scaffold info. A safe smoke-test target for `just showcase`.
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // Default (no subcommand): behave like `info` so `showcase` always has
        // a happy path and the binary never panics on a bare invocation.
        None | Some(Command::Info) => print_info(cli.json),
    }
}

/// Prints scaffold/build information.
///
/// Kept tiny and total — no I/O beyond stdout, no network — so the e2e gate's
/// offline assertion holds and `showcase` can never panic here.
fn print_info(json: bool) {
    let id = babymonitor_core::build_identifier();
    let cli_version = env!("CARGO_PKG_VERSION");

    if json {
        // Hand-rolled to avoid pulling serde_json into the scaffold; later tasks
        // that need real JSON output will add it. Values are static and safe.
        println!(
            "{{\"cli\":\"babymonitor-cli\",\"cli_version\":\"{cli_version}\",\"core\":\"{id}\",\"status\":\"scaffold\"}}"
        );
    } else {
        println!("babymonitor-cli {cli_version}");
        println!("core: {id}");
        println!("status: scaffold (no network commands yet)");
    }
}
