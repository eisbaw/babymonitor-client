//! `babymonitor-cli` — command-line viewer for the Philips Avent Baby Monitor+
//! (a white-labeled Tuya IPC camera, hardware SCD921/SCD923).
//!
//! This surfaces the offline-doable parts of `babymonitor-core` as subcommands:
//!
//! - `auth status` / `auth logout` — work fully OFFLINE against the on-disk
//!   [`SessionStore`] (no network).
//! - `auth login` — offline status only. The previous identity-gate conclusion is
//!   superseded: the APK sends encrypted `postData` and signed ATOP params in the
//!   form body, not signed params in the URL query. `auth live-login` is the gated
//!   network path that can perform a fresh authorized probe; `auth login` never
//!   fabricates a session. The client is still **token-injectable**: supply one
//!   captured live session (TASK-0022) and the same code path runs for real (see
//!   the top-level README §6).
//! - `devices list` / `devices show <id>` — parse + display a device list. The
//!   OFFLINE path reads a response **body** from a `--fixture` file (default: the
//!   synthetic test fixture) so the model layer is exercised without a network.
//!   `devices list --live` is the INJECTED-SESSION consumer (TASK-0055): under the
//!   gated `--features live` build with a captured session in the on-disk store it
//!   loads the injected `sid` and drives a real signed `device.list` call with it
//!   (bypassing login); with no session injected (or in the default non-live
//!   build) it reports the honest no-session/non-live state and touches no
//!   network.
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

// The AUTHORIZED one-time live login path is compiled ONLY under `--features
// live`, so the default build (and `just e2e`) never pulls reqwest/rsa or touches
// the network (TASK-0042).
#[cfg(feature = "live")]
mod live;

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
    /// Account session commands (status/logout offline; live-login is gated
    /// network I/O).
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Device-list commands (offline against a fixture body; live consumes an
    /// injected session under `--features live`).
    Devices {
        #[command(subcommand)]
        action: DevicesAction,
    },
}

/// `auth` subcommands.
#[derive(Debug, Subcommand)]
enum AuthAction {
    /// Offline login placeholder. The real network path is `auth live-login`,
    /// gated behind `--features live`; this command never fabricates a session.
    /// The session slot is injectable (TASK-0022).
    Login,
    /// Show the on-disk session state (offline; no network).
    Status,
    /// Clear the on-disk session (offline; idempotent).
    Logout,
    /// AUTHORIZED one-time LIVE login against the REAL Tuya cloud (TASK-0042).
    /// Compiled only under `--features live`. Hits real infra with the account
    /// owner's real credentials from `secrets/`; READ-ONLY; attempts
    /// `password.login` AT MOST ONCE; stops at 2FA. See `re/live_login.md`.
    #[cfg(feature = "live")]
    LiveLogin(LiveLoginArgs),
}

/// Args for the gated live login.
#[cfg(feature = "live")]
#[derive(Debug, Args)]
struct LiveLoginArgs {
    /// Directory holding the gitignored secrets (login/appkey/bmp_token).
    #[arg(long, default_value = "secrets")]
    secrets_dir: PathBuf,
    /// Path to the extracted base APK (offline app-cert SHA-256 source).
    #[arg(
        long,
        default_value = "extracted/xapk/com.philips.ph.babymonitorplus.apk"
    )]
    apk: PathBuf,
    /// Override the atop gateway host (default: the EU mobile gateway). Use to
    /// pin the appKey's provisioned regional gateway if a fresh probe is rejected
    /// with ILLEGAL_CLIENT_ID. Network-level routing, not an extra login attempt.
    #[arg(long)]
    host: Option<String>,
    /// PROBE-ONLY (TASK-0048 Stage B): send EXACTLY ONE `token.get` to `--host`
    /// and STOP — never proceed to `password.login`, even on success. Use this to
    /// sweep datacenter gateways for ILLEGAL_CLIENT_ID without risking the
    /// lockout-sensitive login step.
    #[arg(long)]
    probe_only: bool,
    /// CORRUPT-SIGN differential (TASK-0050): only meaningful with --probe-only.
    /// After building the fully-signed token.get envelope, flip exactly ONE hex
    /// nibble of the `sign` value before sending — everything else byte-identical.
    /// The corrupted sign keeps its 32-char lowercase-hex shape so the gateway
    /// parses it and reaches sign-verification. Used to prove whether
    /// ILLEGAL_CLIENT_ID is sign-sensitive (our candidate sign is wrong) or
    /// sign-insensitive (an identity/provisioning gate upstream of sign-verify).
    #[arg(long)]
    corrupt_sign: bool,
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
    /// Consume an INJECTED captured session instead of a fixture (TASK-0055).
    /// Under the gated `--features live` build with a session in the on-disk store,
    /// this LOADS the injected `sid` and drives a real, signed `device.list` atop
    /// call carrying it. With NO session injected (or in the default non-live
    /// build) it reports the honest no-session/non-live state and touches no
    /// network. Inject a captured session (TASK-0022; README §6), or use
    /// `auth live-login` after a successful fresh probe, to drive the real read
    /// path.
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
            "{{\"cli\":\"babymonitor-cli\",\"cli_version\":{},\"core\":{},\"login\":\"pending-live-retest\",\"login_blocked_on\":null}}",
            json_str(cli_version),
            json_str(&id)
        );
    } else {
        println!("babymonitor-cli {cli_version}");
        println!("core: {id}");
        println!("login: request-shape corrected; fresh guarded live probe pending");
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
        #[cfg(feature = "live")]
        AuthAction::LiveLogin(args) => auth_live_login(&args, json),
    }
}

/// Drive the AUTHORIZED one-time live login (gated). Prints only NON-SECRET
/// outcome facts; every captured value lands in `secrets/` (see `live`).
#[cfg(feature = "live")]
fn auth_live_login(args: &LiveLoginArgs, json: bool) -> Result<(), Error> {
    if args.probe_only {
        return auth_token_get_probe(args, json);
    }
    match live::run_live_login(&args.secrets_dir, &args.apk, args.host.as_deref()) {
        Ok(live::LiveOutcome::Needs2fa) => {
            // The orchestrator contract: surface the literal phrase.
            if json {
                println!("{{\"command\":\"auth live-login\",\"signer_validated\":true,\"status\":\"NEED 2FA CODE\",\"state\":\"secrets/tuya_2fa_state.json\"}}");
            } else {
                println!("auth live-login: signer VALIDATED; reached 2FA email-code challenge.");
                println!("NEED 2FA CODE");
                println!(
                    "Challenge state captured to secrets/tuya_2fa_state.json (values withheld)."
                );
            }
            Ok(())
        }
        Ok(live::LiveOutcome::LoggedIn {
            camera_found,
            p2p_type,
        }) => {
            if json {
                println!(
                    "{{\"command\":\"auth live-login\",\"logged_in\":true,\"camera_found\":{},\"p2p_type\":{}}}",
                    camera_found,
                    p2p_type.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
                );
            } else {
                println!(
                    "auth live-login: LOGIN SUCCESS (session + device-list captured to secrets/)."
                );
                println!("camera_found: {camera_found}");
                match p2p_type {
                    Some(t) => println!("p2p_type: {t}"),
                    None => println!("p2p_type: (not surfaced in this response)"),
                }
            }
            Ok(())
        }
        Err(e) => {
            // A live failure (sign-rejected / network / 2FA-capture). Surface the
            // typed message (server code+msg only — no secret) and exit non-zero.
            eprintln!("auth live-login: {e}");
            Err(Error::NotImplemented(
                "live login did not complete (see message above)",
            ))
        }
    }
}

/// Drive the PROBE-ONLY token.get sweep (TASK-0048 Stage B). Sends EXACTLY ONE
/// `token.get` to `--host` and STOPS — never `password.login`. Prints only the
/// server error code (non-secret) or the ACCEPTED verdict; the raw response is in
/// the gitignored `secrets/tuya_live_debug.json`. `--host` is REQUIRED (no
/// silent default — a probe must target an explicit host).
#[cfg(feature = "live")]
fn auth_token_get_probe(args: &LiveLoginArgs, json: bool) -> Result<(), Error> {
    let host = match args.host.as_deref() {
        Some(h) => h,
        None => {
            eprintln!("auth live-login --probe-only: --host is REQUIRED for a probe.");
            return Err(Error::NotImplemented("probe requires an explicit --host"));
        }
    };
    // TASK-0050: the corrupted-sign differential. `--corrupt-sign` flips one hex
    // nibble of the signature post-build so we can tell a sign-sensitive reject
    // (candidate sign/body shape is wrong) from a sign-insensitive upstream gate.
    let corrupt = args.corrupt_sign;
    let variant = if corrupt {
        "corrupt-sign"
    } else {
        "candidate-sign"
    };
    match live::run_token_get_probe(&args.secrets_dir, &args.apk, host, corrupt) {
        Ok(live::ProbeOutcome::Accepted) => {
            if json {
                println!(
                    "{{\"command\":\"auth live-login --probe-only\",\"host\":\"{host}\",\"variant\":\"{variant}\",\"accepted\":true,\"errorCode\":null}}"
                );
            } else {
                println!("probe {host} [{variant}]: token.get ACCEPTED — sign oracle reachable. STOPPED before login.");
            }
            Ok(())
        }
        Ok(live::ProbeOutcome::ServerError { code, msg }) => {
            // Print the server-supplied code (non-secret). The msg may echo the
            // code's human text; print it too — it is server-side, not ours.
            if json {
                println!(
                    "{{\"command\":\"auth live-login --probe-only\",\"host\":\"{host}\",\"variant\":\"{variant}\",\"accepted\":false,\"errorCode\":\"{code}\"}}"
                );
            } else {
                println!(
                    "probe {host} [{variant}]: token.get server error — errorCode={code} ({msg})"
                );
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("auth live-login --probe-only ({host}): {e}");
            Err(Error::NotImplemented(
                "probe did not complete (see message above)",
            ))
        }
    }
}

/// The single source of truth for the current login status exposed by the offline
/// `auth login` command. The earlier identity-gate conclusion is superseded by the
/// APK request-shape correction in the live builder.
const LOGIN_STATUS_REASON: &str = "auth login is offline-only in this CLI surface. \
    The previous ILLEGAL_CLIENT_ID identity-gate verdict is superseded: the live \
    request builder now matches the APK form-body/encrypted-postData shape and \
    needs a fresh guarded auth live-login probe.";

/// HONEST login-status report. This is NOT a failure of the command — the command
/// ran and correctly reported that the offline surface cannot create a session. It
/// returns `Ok(())` (exit 0) after printing the status; it never fabricates a
/// session and never claims success.
fn auth_login(json: bool) -> Result<(), Error> {
    if json {
        println!(
            "{{\"command\":\"auth login\",\"logged_in\":false,\"status\":\"pending-live-retest\",\"reason\":{},\"blocked_on\":null}}",
            json_str(LOGIN_STATUS_REASON)
        );
    } else {
        println!("auth login: NOT logged in — live login needs a fresh guarded probe.");
        println!("reason: {LOGIN_STATUS_REASON}");
        println!("Use `auth live-login` under `--features live`, or inject a captured session.");
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
                    "note: no session is stored. Run `auth live-login` under `--features live` \
                     after the fresh probe path is validated, or inject a captured session to \
                     populate this store (TASK-0022; README §6)."
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
            // `--live` consumes an injected captured session (TASK-0055): under the
            // gated `live` build it LOADS the SessionStore sid and drives a real
            // device.list; without the feature (or with no session injected) it
            // reports the no-session/non-live state honestly. This is the
            // "token-injectable" consumer the README §6 describes.
            if source.live {
                return devices_list_live(json);
            }
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

/// `devices list --live`: consume an INJECTED captured session.
///
/// Under the gated `live` build, this LOADS the on-disk [`SessionStore`] sid and
/// drives a real, byte-faithful `device.list` atop call carrying that sid
/// (BYPASSING login). If no session is injected it reports the honest no-session
/// state and touches no network.
///
/// In the DEFAULT (non-`live`) build the live network tree is not compiled in, so
/// it reports the same honest no-session/non-live state offline (the
/// `--features live` build is required to actually send a request — see README
/// §6).
#[cfg(feature = "live")]
fn devices_list_live(json: bool) -> Result<(), Error> {
    let secrets_dir = PathBuf::from("secrets");
    let apk = PathBuf::from("extracted/xapk/com.philips.ph.babymonitorplus.apk");
    let store = SessionStore::default_path()?;
    match live::run_injected_device_list(&secrets_dir, &apk, &store) {
        Ok(live::InjectedOutcome::NoSession) => {
            live_device_list_blocked(json);
            Ok(())
        }
        Ok(live::InjectedOutcome::Fetched {
            camera_found,
            p2p_type,
        }) => {
            if json {
                println!(
                    "{{\"command\":\"devices list --live\",\"source\":\"injected-session\",\"camera_found\":{},\"p2p_type\":{}}}",
                    camera_found,
                    p2p_type
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "null".into())
                );
            } else {
                println!(
                    "devices list --live: fetched via INJECTED session (raw captured to secrets/)."
                );
                println!("camera_found: {camera_found}");
                match p2p_type {
                    Some(t) => println!("p2p_type: {t}"),
                    None => println!("p2p_type: (not surfaced in this response)"),
                }
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("devices list --live: {e}");
            Err(Error::NotImplemented(
                "live device.list did not complete (see message above)",
            ))
        }
    }
}

/// `devices list --live` in the DEFAULT (non-`live`) build: the live network tree
/// is not compiled in, so report the honest non-live/no-session state offline. To
/// actually consume an injected session, build with `--features live`.
#[cfg(not(feature = "live"))]
fn devices_list_live(json: bool) -> Result<(), Error> {
    live_device_list_blocked(json);
    Ok(())
}

/// Print the honest `--live` report (no session injected / non-live build).
/// `Ok`-status report (the command ran correctly); never fabricates a list.
fn live_device_list_blocked(json: bool) {
    if json {
        println!(
            "{{\"command\":\"devices list --live\",\"fetched\":false,\"status\":\"no-session\",\"blocked_on\":\"missing-session\",\"reason\":{}}}",
            json_str(LOGIN_STATUS_REASON)
        );
    } else {
        println!(
            "devices list --live: NOT fetched — no injected session is stored for the live read path."
        );
        println!("reason: {LOGIN_STATUS_REASON}");
        println!(
            "Inject a captured live session into the session store (TASK-0022; see README §6), \
             then re-run with `--features live` to drive the real device.list."
        );
    }
}

/// Resolve the device-list body, then parse it.
///
/// `--live` needs an authenticated session. Without one, the CLI reports an
/// honest no-session state instead of fabricating a response. Otherwise the body
/// is read from `--fixture` (default: the synthetic fixture).
fn load_device_list(source: &DevicesSource) -> Result<DeviceList, Error> {
    if source.live {
        // No network is touched without a session. Surface the honest status; keep
        // the live wiring real and reviewable without fabricating a response.
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

/// The default-build live fetch path: makes no live call. A real fetch needs an
/// authenticated session and the `live` feature. Uses the default
/// [`PendingBmpToken`] so it returns [`Error::BmpTokenPending`] the instant a
/// signature would be required in non-live builds. The real fetch runs the moment
/// a captured session is injected under `--features live` (TASK-0022).
fn live_device_list() -> Result<DeviceList, Error> {
    use babymonitor_core::sign::{PendingBmpToken, SigningKeyMaterial};
    // Placeholder material: never read from secrets here, never used to sign
    // anything because the token probe fails first. Synthetic-by-construction.
    let material = SigningKeyMaterial {
        app_key: String::new(),
        app_secret: String::new(),
        app_cert_sha256: [0u8; 32],
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
/// record is fetched separately (needs an injected session / not wired here).
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
        // fetch needs an authenticated session the identity gate denies a
        // from-scratch client. We surface the seam honestly rather than pretending
        // we have the P2P handles here.
        println!(
            "p2p: per-camera CameraInfoBean is fetched separately (needs an injected session, TASK-0022);"
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

    // The live path must be blocked (no session, no network). The signer's
    // un-validated 6th ingredient trips first, so the concrete variant is still
    // BmpTokenPending; either way no live call is made.
    #[test]
    fn live_device_list_is_blocked() {
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
