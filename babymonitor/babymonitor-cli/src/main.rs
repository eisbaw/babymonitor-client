//! `babymonitor-cli` — command-line viewer for the Philips Avent Baby Monitor+
//! (a white-labeled Tuya IPC camera, hardware SCD921/SCD923).
//!
//! This surfaces the offline-doable parts of `babymonitor-core` as subcommands:
//!
//! - `auth status` / `auth logout` — work fully OFFLINE against the on-disk
//!   [`SessionStore`] (no network).
//! - `auth login` — **token-pending**: the client cannot actually log in yet. A
//!   valid request signature needs the `bmp_token` decoded from `assets/t_s.bmp`
//!   (TASK-0030). `login` reports that honestly via
//!   [`babymonitor_core::Error::BmpTokenPending`] and NEVER fabricates a session.
//! - `devices list` / `devices show <id>` — parse + display a device list. The
//!   OFFLINE path reads a response **body** from a `--fixture` file (default: the
//!   synthetic test fixture) so the model layer is exercised without a network.
//!   The `--live` path is token-pending (same `bmp_token` gate) and says so.
//!
//! Output policy: every subcommand supports `--json` for machine consumption
//! alongside the default human text.
//!
//! Secrets policy (CLAUDE.md / TASK-0014): secret/PII fields (`localKey`,
//! `secKey`, `password`, `p2pKey`, `initStr`, session/relay descriptors) are
//! REDACTED by default. `--show-secrets` opts into printing them; even then it
//! prints a stderr warning and is intended ONLY for the user's own synthetic /
//! authorized data. Because this build has no live fetch, the only data it can
//! print comes from a fixture the caller supplies.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use babymonitor_core::device::{self, CameraView, DeviceBean, DeviceList};
use babymonitor_core::session::SessionStore;
use babymonitor_core::Error;
use clap::{Args, Parser, Subcommand};

/// Path (relative to this crate) of the synthetic device-list fixture used as the
/// default OFFLINE body. It is committed, obviously-synthetic test data — never a
/// real capture.
const DEFAULT_DEVICE_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../babymonitor-core/tests/fixtures/device_list.json"
);

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

/// Available subcommands. Read-only / non-destructive (plus `auth logout`, which
/// only clears the local session file).
#[derive(Debug, Subcommand)]
enum Command {
    /// Print build/scaffold info. A safe smoke-test target for `just showcase`.
    Info,
    /// Account session commands (status/logout offline; login is token-pending).
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Device-list commands (offline against a fixture body; live is token-pending).
    Devices {
        #[command(subcommand)]
        action: DevicesAction,
    },
}

/// `auth` subcommands.
#[derive(Debug, Subcommand)]
enum AuthAction {
    /// Attempt account login. TOKEN-PENDING: the client cannot log in yet — a
    /// valid sign needs the bmp_token (TASK-0030). Reports the pending state
    /// honestly; never fabricates a session.
    Login,
    /// Show the on-disk session state (offline; no network).
    Status,
    /// Clear the on-disk session (offline; idempotent).
    Logout,
}

/// `devices` subcommands.
#[derive(Debug, Subcommand)]
enum DevicesAction {
    /// List devices parsed from a response body (offline fixture by default).
    List(DevicesSource),
    /// Show a single device by `devId` (offline fixture by default).
    Show {
        /// The `devId` to show.
        dev_id: String,
        #[command(flatten)]
        source: DevicesSource,
    },
}

/// Where the device-list body comes from, and the secret-reveal opt-in.
#[derive(Debug, Args)]
struct DevicesSource {
    /// Read the device-list response body from this file (offline). Defaults to
    /// the synthetic test fixture so the command always has something to show.
    #[arg(long)]
    fixture: Option<PathBuf>,
    /// Attempt the LIVE cloud fetch instead of a fixture. TOKEN-PENDING: returns
    /// the honest pending state (no network is touched) — a valid sign needs the
    /// bmp_token (TASK-0030).
    #[arg(long)]
    live: bool,
    /// Reveal secret/PII fields (localKey, p2pKey, …) in the output. OFF by
    /// default. Even when set, prints a stderr warning; intended only for the
    /// user's own authorized/synthetic data.
    #[arg(long)]
    show_secrets: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;

    let result = match cli.command {
        None | Some(Command::Info) => {
            print_info(json);
            Ok(())
        }
        Some(Command::Auth { action }) => run_auth(action, json),
        Some(Command::Devices { action }) => run_devices(action, json),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, json);
            ExitCode::FAILURE
        }
    }
}

/// Print a typed error to stderr (human or JSON) so failures are loud + traceable.
fn report_error(err: &Error, json: bool) {
    if json {
        eprintln!("{{\"error\":{}}}", json_str(&err.to_string()));
    } else {
        eprintln!("error: {err}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// info
// ─────────────────────────────────────────────────────────────────────────────

/// Prints build information. Total, offline, never panics.
fn print_info(json: bool) {
    let id = babymonitor_core::build_identifier();
    let cli_version = env!("CARGO_PKG_VERSION");

    if json {
        println!(
            "{{\"cli\":\"babymonitor-cli\",\"cli_version\":{},\"core\":{},\"login\":\"token-pending\"}}",
            json_str(cli_version),
            json_str(&id)
        );
    } else {
        println!("babymonitor-cli {cli_version}");
        println!("core: {id}");
        println!("login: token-pending (cannot log in yet — bmp_token / TASK-0030)");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// auth
// ─────────────────────────────────────────────────────────────────────────────

fn run_auth(action: AuthAction, json: bool) -> Result<(), Error> {
    match action {
        AuthAction::Login => auth_login(json),
        AuthAction::Status => auth_status(json),
        AuthAction::Logout => auth_logout(json),
    }
}

/// HONEST token-pending login. This is NOT a failure of the command — the
/// command ran and correctly reported that login is not yet possible. So it
/// returns `Ok(())` (exit 0) after printing the pending state; it never
/// fabricates a session and never claims success at logging in.
fn auth_login(json: bool) -> Result<(), Error> {
    // The pending state is sourced from the core's typed error so the CLI and
    // library agree on the single source of truth for the message.
    let pending = Error::BmpTokenPending.to_string();
    if json {
        println!(
            "{{\"command\":\"auth login\",\"logged_in\":false,\"status\":\"token-pending\",\"reason\":{},\"blocked_on\":\"TASK-0030\"}}",
            json_str(&pending)
        );
    } else {
        println!("auth login: NOT logged in — login is token-pending.");
        println!("reason: {pending}");
        println!("The client cannot authenticate until the bmp_token is ported (TASK-0030).");
    }
    Ok(())
}

/// Show the on-disk session state. Offline: reads the [`SessionStore`] only.
fn auth_status(json: bool) -> Result<(), Error> {
    let store = SessionStore::default_path()?;
    let session = store.load()?;
    let path = store.path().display().to_string();

    match session {
        Some(s) => {
            // Session Debug already redacts sid/uid; we surface only non-secret
            // fields explicitly so nothing secret can leak here.
            let needs_refresh = s.needs_refresh();
            if json {
                println!(
                    "{{\"command\":\"auth status\",\"logged_in\":true,\"store\":{},\"mobile_api_base\":{},\"needs_refresh\":{},\"expires_at\":{}}}",
                    json_str(&path),
                    json_str(&s.mobile_api_base),
                    needs_refresh,
                    json_str(&s.expires_at.to_rfc3339()),
                );
            } else {
                println!("auth status: a session is stored (sid/uid redacted).");
                println!("store: {path}");
                println!("mobile_api_base: {}", s.mobile_api_base);
                println!("expires_at: {}", s.expires_at.to_rfc3339());
                println!("needs_refresh: {needs_refresh}");
            }
        }
        None => {
            if json {
                println!(
                    "{{\"command\":\"auth status\",\"logged_in\":false,\"store\":{}}}",
                    json_str(&path)
                );
            } else {
                println!("auth status: no session stored (not logged in).");
                println!("store: {path}");
                println!(
                    "note: login is token-pending (TASK-0030), so no session can be created yet."
                );
            }
        }
    }
    Ok(())
}

/// Clear the on-disk session. Offline + idempotent (missing file is success).
fn auth_logout(json: bool) -> Result<(), Error> {
    let store = SessionStore::default_path()?;
    store.clear()?;
    let path = store.path().display().to_string();
    if json {
        println!(
            "{{\"command\":\"auth logout\",\"cleared\":true,\"store\":{}}}",
            json_str(&path)
        );
    } else {
        println!("auth logout: session cleared (idempotent).");
        println!("store: {path}");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// devices
// ─────────────────────────────────────────────────────────────────────────────

fn run_devices(action: DevicesAction, json: bool) -> Result<(), Error> {
    match action {
        DevicesAction::List(source) => {
            let list = load_device_list(&source)?;
            print_device_list(&list, json, source.show_secrets);
            Ok(())
        }
        DevicesAction::Show { dev_id, source } => {
            let list = load_device_list(&source)?;
            let dev = list
                .all_devices()
                .find(|d| d.dev_id == dev_id)
                .ok_or_else(|| {
                    Error::DeviceMismatch(format!("no device with devId={dev_id} in the list"))
                })?;
            print_device_show(dev, json, source.show_secrets);
            Ok(())
        }
    }
}

/// Resolve the device-list body, then parse it.
///
/// `--live` is token-pending: it threads through the same signer gate as the core
/// and surfaces [`Error::BmpTokenPending`] without touching the network. Otherwise
/// the body is read from `--fixture` (default: the synthetic fixture).
fn load_device_list(source: &DevicesSource) -> Result<DeviceList, Error> {
    if source.live {
        // No network is touched: probe the (pending) signer and surface the
        // honest token-pending state. This keeps the "live" wiring real and
        // reviewable without fabricating a response.
        return live_device_list();
    }
    let path = source
        .fixture
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DEVICE_FIXTURE));
    let body = std::fs::read(&path)
        .map_err(|e| Error::DeviceParse(format!("read body {}: {e}", path.display())))?;
    device::parse_device_list(&body)
}

/// The live fetch path: token-pending. Uses the default [`PendingBmpToken`] so it
/// returns [`Error::BmpTokenPending`] the instant a signature would be required —
/// it never makes a live call. (When TASK-0030 unblocks signing, the real fetch
/// is wired here behind a rate-limited/single-shot HTTP client.)
fn live_device_list() -> Result<DeviceList, Error> {
    use babymonitor_core::sign::{PendingBmpToken, SigningKeyMaterial};
    // Placeholder material: never read from secrets here, never used to sign
    // anything because the token probe fails first. Synthetic-by-construction.
    let material = SigningKeyMaterial {
        app_key: String::new(),
        app_secret: String::new(),
        app_cert_sha256_hex: String::new(),
        ttid: String::new(),
    };
    device::list_devices(&material, &PendingBmpToken, "", "")
}

/// Render a device list. Secret fields are redacted unless `show_secrets`.
fn print_device_list(list: &DeviceList, json: bool, show_secrets: bool) {
    warn_if_revealing(show_secrets);
    let devices: Vec<&DeviceBean> = list.all_devices().collect();

    if json {
        let items: Vec<String> = devices
            .iter()
            .map(|d| device_json(d, show_secrets))
            .collect();
        println!(
            "{{\"command\":\"devices list\",\"count\":{},\"devices\":[{}]}}",
            items.len(),
            items.join(",")
        );
        return;
    }

    println!("devices: {} found", devices.len());
    for d in &devices {
        let cam = if d.is_camera() { " [camera]" } else { "" };
        let online = if d.online() { "online" } else { "offline" };
        println!(
            "  {}  {}  category={}  {}{}",
            d.dev_id,
            d.name.as_deref().unwrap_or("(no name)"),
            d.category.as_deref().unwrap_or("(none)"),
            online,
            cam,
        );
    }
    match list.find_camera_device() {
        Some(c) => println!(
            "camera: {} (use `devices show {}` for detail)",
            c.dev_id, c.dev_id
        ),
        None => println!("camera: none found"),
    }
}

/// Render a single device. If it is a camera, also note that the per-camera P2P
/// record is fetched separately (token-pending / not wired here).
fn print_device_show(dev: &DeviceBean, json: bool, show_secrets: bool) {
    warn_if_revealing(show_secrets);
    if json {
        println!(
            "{{\"command\":\"devices show\",\"device\":{}}}",
            device_json(dev, show_secrets)
        );
        return;
    }
    println!("devId: {}", dev.dev_id);
    println!("name: {}", dev.name.as_deref().unwrap_or("(no name)"));
    println!("category: {}", dev.category.as_deref().unwrap_or("(none)"));
    println!(
        "product_id: {}",
        dev.product_id.as_deref().unwrap_or("(none)")
    );
    println!("pv: {}", dev.pv.as_deref().unwrap_or("(none)"));
    println!("uuid: {}", dev.uuid.as_deref().unwrap_or("(none)"));
    println!("online: {}", dev.online());
    println!("is_camera: {}", dev.is_camera());
    println!("local_key: {}", secret_field(&dev.local_key, show_secrets));
    println!("sec_key: {}", secret_field(&dev.sec_key, show_secrets));
    if dev.is_camera() {
        // The CameraView pairing needs a separately-fetched CameraInfoBean; that
        // fetch is token-pending. We surface the seam honestly rather than
        // pretending we have the P2P handles here.
        println!(
            "p2p: per-camera CameraInfoBean is fetched separately (token-pending, TASK-0030);"
        );
        println!("     parse one offline with the core `parse_camera_info` + `CameraView::pair`.");
        let _ = CameraView::pair; // documents the intended composition seam.
    }
}

/// One device as a JSON object. Secret values are redacted unless `show_secrets`.
fn device_json(d: &DeviceBean, show_secrets: bool) -> String {
    format!(
        "{{\"dev_id\":{},\"name\":{},\"category\":{},\"product_id\":{},\"online\":{},\"is_camera\":{},\"local_key\":{},\"sec_key\":{}}}",
        json_str(&d.dev_id),
        opt_json(&d.name),
        opt_json(&d.category),
        opt_json(&d.product_id),
        d.online(),
        d.is_camera(),
        secret_json(&d.local_key, show_secrets),
        secret_json(&d.sec_key, show_secrets),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// secret-handling + tiny JSON helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Print a stderr warning once when the user opts into revealing secrets.
fn warn_if_revealing(show_secrets: bool) {
    if show_secrets {
        eprintln!(
            "warning: --show-secrets is on; secret/PII fields will be printed. Use only for your own authorized/synthetic data."
        );
    }
}

/// Human rendering of a secret field: redacted unless explicitly revealed.
fn secret_field(v: &Option<String>, show_secrets: bool) -> String {
    match (v, show_secrets) {
        (None, _) => "(none)".to_string(),
        (Some(_), false) => "<redacted> (use --show-secrets to reveal)".to_string(),
        (Some(s), true) => s.clone(),
    }
}

/// JSON rendering of a secret field: a redaction marker string unless revealed.
fn secret_json(v: &Option<String>, show_secrets: bool) -> String {
    match (v, show_secrets) {
        (None, _) => "null".to_string(),
        (Some(_), false) => json_str("<redacted>"),
        (Some(s), true) => json_str(s),
    }
}

/// JSON for an `Option<String>`: the quoted string or `null`.
fn opt_json(v: &Option<String>) -> String {
    match v {
        Some(s) => json_str(s),
        None => "null".to_string(),
    }
}

/// Encode a string as a JSON string literal (via serde_json so escaping is
/// correct — never hand-roll quoting around untrusted content).
fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the default fixture path actually resolves to the committed
    // synthetic fixture, so `devices list` (no args) — exercised by showcase —
    // always has a body to parse.
    #[test]
    fn default_fixture_path_resolves() {
        let p = PathBuf::from(DEFAULT_DEVICE_FIXTURE);
        assert!(
            p.exists(),
            "default device fixture missing at {}",
            p.display()
        );
        let body = std::fs::read(&p).unwrap();
        let list = device::parse_device_list(&body).expect("default fixture must parse");
        assert!(list.find_camera_device().is_some());
    }

    // The live path must be token-pending and touch no network.
    #[test]
    fn live_device_list_is_token_pending() {
        assert!(matches!(live_device_list(), Err(Error::BmpTokenPending)));
    }

    // Secret rendering must redact by default and reveal only on opt-in.
    #[test]
    fn secret_field_redacts_by_default() {
        let v = Some("SYNTH-SECRET-VALUE".to_string());
        let redacted = secret_field(&v, false);
        assert!(!redacted.contains("SYNTH-SECRET-VALUE"));
        assert!(redacted.contains("redacted"));
        assert_eq!(secret_field(&v, true), "SYNTH-SECRET-VALUE");
        assert_eq!(secret_field(&None, false), "(none)");
    }

    #[test]
    fn secret_json_redacts_by_default() {
        let v = Some("SYNTH-SECRET-VALUE".to_string());
        assert!(!secret_json(&v, false).contains("SYNTH-SECRET-VALUE"));
        assert_eq!(secret_json(&None, true), "null");
    }

    // device_json must never leak a secret value when show_secrets is off.
    #[test]
    fn device_json_redacts_secrets_by_default() {
        let body = br#"{"deviceList":[{"devId":"d1","category":"sp","localKey":"SYNTH-LK","secKey":"SYNTH-SK"}]}"#;
        let list = device::parse_device_list(body).unwrap();
        let d = list.all_devices().next().unwrap();
        let j = device_json(d, false);
        assert!(!j.contains("SYNTH-LK"), "localKey leaked: {j}");
        assert!(!j.contains("SYNTH-SK"), "secKey leaked: {j}");
        // Parses as valid JSON.
        let _: serde_json::Value =
            serde_json::from_str(&j).expect("device_json must be valid JSON");
    }

    // json_str must escape embedded quotes (don't hand-roll quoting).
    #[test]
    fn json_str_escapes() {
        assert_eq!(json_str("a\"b"), "\"a\\\"b\"");
    }
}
