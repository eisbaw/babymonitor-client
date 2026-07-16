//! Read-only Tuya OTA metadata acquisition and provenance-preserving downloads.
//!
//! The only Tuya actions named here are metadata queries. Upgrade confirmation,
//! start, cancel, and device-control actions are deliberately absent.

use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use babymonitor_core::session::SessionStore;
use md5::Context as Md5Context;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
use super::{atomic_write_private, ensure_private_directory};
use super::{
    build_signed_envelope_with, host_from_mobile_api_base, load_config,
    send_atop_without_debug_capture, sid_extra, AtopResponse, LiveConfig, LiveError,
    PinnedPrivateDirectory, THING_SDK_VERSION,
};

const MAX_FIRMWARE_BYTES: u64 = 512 * 1024 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// Read-only OTA metadata endpoint. No mutation endpoint exists in this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FirmwareInfoEndpoint {
    action: &'static str,
    version: &'static str,
    source: &'static str,
    response_name: &'static str,
}

const PRIMARY_ENDPOINT: FirmwareInfoEndpoint = FirmwareInfoEndpoint {
    action: "m.thing.firmware.upgrade.info.get",
    version: "1.1",
    source: "ui-v1.1",
    response_name: "primary-response.json",
};

const LEGACY_ENDPOINT: FirmwareInfoEndpoint = FirmwareInfoEndpoint {
    action: "thing.m.device.upgrade.info",
    version: "1.2",
    source: "legacy-v1.2",
    response_name: "legacy-response.json",
};

/// Non-secret OTA metadata safe to print. URLs, checksums, signatures, device
/// IDs, and raw server data stay within the private acquisition directory.
#[derive(Debug)]
pub struct FirmwareRecordSummary {
    pub source: String,
    pub channel: String,
    pub server_current_version: Option<String>,
    pub server_offered_version: Option<String>,
    pub can_upgrade: Option<bool>,
    pub upgrade_status: Option<i64>,
    pub package_url_present: bool,
    pub integrity_metadata_present: bool,
    pub download_eligible: bool,
    pub expected_bytes: Option<u64>,
    /// `None` means Tuya did not report the field; callers must not infer that
    /// the package is a complete installed-flash image.
    pub diff_ota: Option<bool>,
}

/// One privately persisted OTA artifact, without its URL or digest values.
#[derive(Debug)]
pub struct FirmwareDownloadSummary {
    pub path: PathBuf,
    pub bytes: u64,
    pub md5_verified: bool,
    pub server_signature_present: bool,
    pub server_signature_verified: bool,
}

/// Result of one immutable read-only acquisition.
#[derive(Debug)]
pub struct FirmwareFetchOutcome {
    pub acquisition_path: PathBuf,
    pub manifest_path: PathBuf,
    pub metadata_paths: Vec<PathBuf>,
    pub records: Vec<FirmwareRecordSummary>,
    pub downloads: Vec<FirmwareDownloadSummary>,
    /// Fixed, non-sensitive notices. Raw server/transport errors are never used.
    pub notices: Vec<String>,
}

/// Private `UpgradeInfoBean` representation. Deliberately no `Debug`: URL,
/// checksum, and signature values are private acquisition metadata.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirmwareInfoRecord {
    #[serde(default)]
    can_upgrade: Option<bool>,
    #[serde(default)]
    current_version: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    file_size: Option<u64>,
    #[serde(default)]
    md5: Option<String>,
    #[serde(default)]
    sign: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    upgrade_status: Option<i64>,
    #[serde(default, rename = "type")]
    firmware_type: Option<i64>,
    #[serde(default)]
    dev_type: Option<i64>,
    #[serde(default)]
    diff_ota: Option<bool>,
}

struct QueryReply {
    success: bool,
    failure: Option<QueryFailure>,
    result: serde_json::Value,
    raw: serde_json::Value,
}

/// Intentionally contains no underlying text. A transport stack or untrusted
/// server error can carry a signed URL, device ID, or account data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryFailure {
    Config,
    Session,
    Signing,
    Transport,
    Protocol,
    Server,
    Crypto,
}

impl From<LiveError> for QueryFailure {
    fn from(error: LiveError) -> Self {
        match error {
            LiveError::Config(_) => Self::Config,
            LiveError::Cert(_) | LiveError::SignRejected { .. } => Self::Signing,
            LiveError::Network(_) => Self::Transport,
            LiveError::Protocol(_) => Self::Protocol,
            LiveError::Server { code, .. } => classify_server_rejection(&code),
            LiveError::Crypto(_) => Self::Crypto,
        }
    }
}

trait FirmwareQuery {
    fn query(&mut self, endpoint: FirmwareInfoEndpoint) -> Result<QueryReply, QueryFailure>;
}

struct AtopFirmwareQuery<'a> {
    client: &'a reqwest::blocking::Client,
    host: &'a str,
    cfg: &'a LiveConfig,
    sid: &'a str,
    ecode: Option<&'a str>,
    dev_id: &'a str,
}

impl FirmwareQuery for AtopFirmwareQuery<'_> {
    fn query(&mut self, endpoint: FirmwareInfoEndpoint) -> Result<QueryReply, QueryFailure> {
        let response = send_firmware_info(
            self.client,
            self.host,
            self.cfg,
            self.sid,
            self.ecode,
            endpoint,
            self.dev_id,
        )
        .map_err(QueryFailure::from)?;
        let failure = (!response.success).then(|| {
            response
                .error_code
                .as_deref()
                .map(classify_server_rejection)
                .unwrap_or(QueryFailure::Server)
        });
        Ok(QueryReply {
            success: response.success,
            failure,
            result: response.result,
            raw: response.raw,
        })
    }
}

struct EndpointCapture {
    endpoint: FirmwareInfoEndpoint,
    raw: serde_json::Value,
    success: bool,
}

#[derive(Clone, Copy)]
enum LegacyQueryStatus {
    NotNeeded,
    Success,
    Unavailable,
}

impl LegacyQueryStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotNeeded => "not-needed",
            Self::Success => "success",
            Self::Unavailable => "unavailable",
        }
    }
}

struct QueriedMetadata {
    records: Vec<(FirmwareInfoEndpoint, FirmwareInfoRecord)>,
    captures: Vec<EndpointCapture>,
    legacy_status: LegacyQueryStatus,
    notices: Vec<String>,
}

/// Query the exact key-proven camera and publish one immutable provenance run.
/// Production firmware bytes are fetched only from HTTPS URLs, redirects are
/// disabled, and no package is published without a valid authenticated MD5.
pub fn fetch_firmware_candidates(
    secrets_dir: &Path,
    apk_path: &Path,
    store: &SessionStore,
    dev_id: &str,
    download: bool,
) -> Result<FirmwareFetchOutcome, LiveError> {
    if dev_id.trim().is_empty() {
        return Err(LiveError::Config(
            "firmware metadata query requires a non-empty key-proven device ID".into(),
        ));
    }
    let session = store
        .load()
        .map_err(|error| LiveError::Config(format!("session store: {error}")))?
        .ok_or_else(|| {
            LiveError::Config(
                "no session is stored; firmware metadata requires an owner cloud session".into(),
            )
        })?;
    ensure_session_fresh(&session)?;
    let host = host_from_mobile_api_base(&session.mobile_api_base)?;
    let cfg = load_config(secrets_dir, apk_path)?;
    let user_agent = format!(
        "Thing-UA=APP/Android/{}/SDK/{}",
        cfg.app_version, THING_SDK_VERSION
    );
    let client = build_firmware_client(&user_agent)?;
    let mut query = AtopFirmwareQuery {
        client: &client,
        host: &host,
        cfg: &cfg,
        sid: &session.sid,
        ecode: session.ecode.as_deref(),
        dev_id,
    };
    let queried = orchestrate_queries(&mut query)?;
    publish_acquisition(
        secrets_dir,
        &client,
        queried,
        download,
        AcquisitionContext {
            url_policy: DownloadUrlPolicy::ProductionHttps,
            max_firmware_bytes: MAX_FIRMWARE_BYTES,
            gateway_host: &host,
            dev_id,
        },
    )
}

fn ensure_session_fresh(session: &babymonitor_core::session::Session) -> Result<(), LiveError> {
    if session.needs_refresh() {
        return Err(LiveError::Config(
            "stored owner session is expired or near expiry; authenticate again before querying firmware"
                .into(),
        ));
    }
    Ok(())
}

fn build_firmware_client(user_agent: &str) -> Result<reqwest::blocking::Client, LiveError> {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent)
        .build()
        .map_err(|_| LiveError::Network("could not build the firmware HTTP client".into()))
}

fn send_firmware_info(
    client: &reqwest::blocking::Client,
    host: &str,
    cfg: &LiveConfig,
    sid: &str,
    ecode: Option<&str>,
    endpoint: FirmwareInfoEndpoint,
    dev_id: &str,
) -> Result<AtopResponse, LiveError> {
    let post_data = firmware_info_post_data(dev_id);
    let (envelope, wire_post_data) = build_signed_envelope_with(
        cfg,
        endpoint.action,
        endpoint.version,
        &post_data,
        &sid_extra(sid),
        ecode,
    )?;
    send_atop_without_debug_capture(client, host, cfg, &envelope, Some(&wire_post_data), ecode)
}

fn firmware_info_post_data(dev_id: &str) -> String {
    serde_json::json!({ "devId": dev_id }).to_string()
}

fn classify_server_rejection(code: &str) -> QueryFailure {
    let upper = code.to_ascii_uppercase();
    if upper.contains("SESSION") || upper.contains("TOKEN") || upper.contains("LOGIN") {
        QueryFailure::Session
    } else if upper.contains("SIGN") || upper.contains("CLIENT_ID") || upper.contains("APP_KEY") {
        QueryFailure::Signing
    } else {
        QueryFailure::Server
    }
}

fn primary_query_error(failure: QueryFailure) -> LiveError {
    match failure {
        QueryFailure::Config => {
            LiveError::Config("firmware metadata query configuration failed".into())
        }
        QueryFailure::Session => LiveError::Config(
            "owner session was rejected; authenticate again before querying firmware".into(),
        ),
        QueryFailure::Signing => {
            LiveError::Protocol("firmware metadata request signing was rejected".into())
        }
        QueryFailure::Transport => {
            LiveError::Network("primary firmware metadata transport failed".into())
        }
        QueryFailure::Protocol => {
            LiveError::Protocol("primary firmware metadata response was invalid".into())
        }
        QueryFailure::Server => {
            LiveError::Protocol("primary firmware metadata query was rejected".into())
        }
        QueryFailure::Crypto => {
            LiveError::Crypto("firmware metadata response decryption failed".into())
        }
    }
}

fn orchestrate_queries(query: &mut impl FirmwareQuery) -> Result<QueriedMetadata, LiveError> {
    let primary = query.query(PRIMARY_ENDPOINT).map_err(primary_query_error)?;
    let mut captures = vec![EndpointCapture {
        endpoint: PRIMARY_ENDPOINT,
        raw: primary.raw,
        success: primary.success,
    }];
    if !primary.success {
        return Err(primary_query_error(
            primary.failure.unwrap_or(QueryFailure::Server),
        ));
    }
    let primary_records = parse_firmware_records(primary.result)?;
    let mut records = primary_records
        .into_iter()
        .map(|record| (PRIMARY_ENDPOINT, record))
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let legacy_status = if records.iter().any(|(_, record)| has_firmware_url(record)) {
        LegacyQueryStatus::NotNeeded
    } else {
        match query.query(LEGACY_ENDPOINT) {
            Ok(legacy) => {
                captures.push(EndpointCapture {
                    endpoint: LEGACY_ENDPOINT,
                    raw: legacy.raw,
                    success: legacy.success,
                });
                if legacy.success {
                    match parse_firmware_records(legacy.result) {
                        Ok(legacy_records) => {
                            // Surface every safe legacy record, even when it has no URL.
                            records.extend(
                                legacy_records
                                    .into_iter()
                                    .map(|record| (LEGACY_ENDPOINT, record)),
                            );
                            LegacyQueryStatus::Success
                        }
                        Err(_) => {
                            notices.push(legacy_unavailable_notice());
                            LegacyQueryStatus::Unavailable
                        }
                    }
                } else {
                    notices.push(legacy_unavailable_notice());
                    LegacyQueryStatus::Unavailable
                }
            }
            Err(_) => {
                notices.push(legacy_unavailable_notice());
                LegacyQueryStatus::Unavailable
            }
        }
    };
    Ok(QueriedMetadata {
        records,
        captures,
        legacy_status,
        notices,
    })
}

fn legacy_unavailable_notice() -> String {
    "legacy firmware metadata fallback was unavailable; primary results were preserved".into()
}

fn parse_firmware_records(value: serde_json::Value) -> Result<Vec<FirmwareInfoRecord>, LiveError> {
    serde_json::from_value(value).map_err(|_| {
        LiveError::Protocol(
            "firmware metadata result did not have the expected channel-array shape".into(),
        )
    })
}

fn has_firmware_url(record: &FirmwareInfoRecord) -> bool {
    record
        .url
        .as_deref()
        .map(str::trim)
        .is_some_and(|url| !url.is_empty())
}

fn firmware_summary(
    endpoint: FirmwareInfoEndpoint,
    record: &FirmwareInfoRecord,
    index: usize,
    dev_id: &str,
) -> FirmwareRecordSummary {
    let package_url_present = has_firmware_url(record);
    let integrity_metadata_present = has_integrity_metadata(record);
    FirmwareRecordSummary {
        source: endpoint.source.into(),
        channel: record_channel(record, index),
        server_current_version: public_firmware_version(
            record.current_version.as_deref(),
            dev_id,
            record.url.as_deref(),
        ),
        server_offered_version: public_firmware_version(
            record.version.as_deref(),
            dev_id,
            record.url.as_deref(),
        ),
        can_upgrade: record.can_upgrade,
        upgrade_status: record.upgrade_status,
        package_url_present,
        integrity_metadata_present,
        download_eligible: package_url_present
            && integrity_metadata_present
            && validated_download_url(record.url.as_deref(), DownloadUrlPolicy::ProductionHttps)
                .is_ok()
            && normalized_expected_md5(record).is_ok(),
        expected_bytes: expected_size(record),
        diff_ota: record.diff_ota,
    }
}

fn public_firmware_version(
    value: Option<&str>,
    dev_id: &str,
    package_url: Option<&str>,
) -> Option<String> {
    let value = value?.trim();
    if value.is_empty()
        || value.len() > 32
        || !value.is_ascii()
        || (!dev_id.is_empty() && value.contains(dev_id))
        || package_url.is_some_and(|url| !url.is_empty() && value.contains(url))
    {
        return None;
    }
    let numeric = value.strip_prefix('v').unwrap_or(value);
    if !numeric.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || !numeric.contains('.')
        || !numeric
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
    {
        return None;
    }
    Some(value.to_string())
}

fn has_integrity_metadata(record: &FirmwareInfoRecord) -> bool {
    record
        .md5
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn expected_size(record: &FirmwareInfoRecord) -> Option<u64> {
    record.file_size.filter(|size| *size > 0)
}

fn record_channel(record: &FirmwareInfoRecord, index: usize) -> String {
    record
        .firmware_type
        .map(|value| format!("type-{value}"))
        .or_else(|| record.dev_type.map(|value| format!("devtype-{value}")))
        .unwrap_or_else(|| format!("record-{index}"))
}

fn nonempty_owned(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[derive(Clone, Copy)]
enum DownloadUrlPolicy {
    ProductionHttps,
    #[cfg(test)]
    LoopbackHttpForTest,
}

fn validated_download_url(
    raw_url: Option<&str>,
    policy: DownloadUrlPolicy,
) -> Result<reqwest::Url, LiveError> {
    let raw_url = raw_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .ok_or_else(|| LiveError::Protocol("firmware record has no download URL".into()))?;
    let url = reqwest::Url::parse(raw_url)
        .map_err(|_| LiveError::Protocol("firmware record has an invalid download URL".into()))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(LiveError::Protocol(
            "firmware URL must not contain embedded credentials".into(),
        ));
    }
    let allowed = match policy {
        DownloadUrlPolicy::ProductionHttps => url.scheme() == "https",
        #[cfg(test)]
        DownloadUrlPolicy::LoopbackHttpForTest => {
            url.scheme() == "http"
                && url
                    .host_str()
                    .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback())
        }
    };
    if !allowed {
        return Err(LiveError::Protocol(
            "firmware URL is not permitted by the HTTPS-only download policy".into(),
        ));
    }
    Ok(url)
}

fn normalized_expected_md5(record: &FirmwareInfoRecord) -> Result<String, LiveError> {
    let expected = record
        .md5
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            LiveError::Protocol(
                "firmware package has no verifiable MD5; refusing to publish it".into(),
            )
        })?;
    if expected.len() != 32 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LiveError::Protocol(
            "firmware metadata MD5 is not 32 hexadecimal characters".into(),
        ));
    }
    Ok(expected.to_ascii_lowercase())
}

struct DownloadedArtifact {
    filename: String,
    bytes: u64,
    md5: String,
    sha256: String,
}

#[derive(Clone, Copy)]
enum AcquisitionFailureClass {
    UrlPolicy,
    IntegrityMetadata,
    Transport,
    HttpStatus,
    Size,
    Integrity,
    Storage,
}

impl AcquisitionFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::UrlPolicy => "url-policy",
            Self::IntegrityMetadata => "integrity-metadata",
            Self::Transport => "transport",
            Self::HttpStatus => "http-status",
            Self::Size => "size",
            Self::Integrity => "integrity",
            Self::Storage => "storage",
        }
    }
}

struct AcquisitionFailure {
    class: AcquisitionFailureClass,
    error: LiveError,
}

impl AcquisitionFailure {
    fn new(class: AcquisitionFailureClass, error: LiveError) -> Self {
        Self { class, error }
    }

    fn into_preserved_error(self, path: &Path) -> LiveError {
        let suffix = format!(
            "private metadata and failure provenance were preserved at {}",
            path.display()
        );
        match self.error {
            LiveError::Config(message) => LiveError::Config(format!("{message}; {suffix}")),
            LiveError::Cert(message) => LiveError::Cert(format!("{message}; {suffix}")),
            LiveError::Network(message) => LiveError::Network(format!("{message}; {suffix}")),
            LiveError::Protocol(message) => LiveError::Protocol(format!("{message}; {suffix}")),
            LiveError::SignRejected { .. } => {
                LiveError::Protocol(format!("firmware signing was rejected; {suffix}"))
            }
            LiveError::Server { .. } => {
                LiveError::Protocol(format!("firmware request was rejected; {suffix}"))
            }
            LiveError::Crypto(message) => LiveError::Crypto(format!("{message}; {suffix}")),
        }
    }
}

struct PartialPackage<'a> {
    directory: &'a PinnedPrivateDirectory,
    name: OsString,
    retained: bool,
}

impl Drop for PartialPackage<'_> {
    fn drop(&mut self) {
        if !self.retained {
            let _ = self.directory.unlink_file(&self.name);
        }
    }
}

fn stream_firmware_record(
    client: &reqwest::blocking::Client,
    stage_directory: &PinnedPrivateDirectory,
    endpoint: FirmwareInfoEndpoint,
    record: &FirmwareInfoRecord,
    index: usize,
    policy: DownloadUrlPolicy,
    max_firmware_bytes: u64,
) -> Result<DownloadedArtifact, AcquisitionFailure> {
    let url = validated_download_url(record.url.as_deref(), policy)
        .map_err(|error| AcquisitionFailure::new(AcquisitionFailureClass::UrlPolicy, error))?;
    let expected_md5 = normalized_expected_md5(record).map_err(|error| {
        AcquisitionFailure::new(AcquisitionFailureClass::IntegrityMetadata, error)
    })?;
    let expected_bytes = expected_size(record);
    if expected_bytes.is_some_and(|size| size > max_firmware_bytes) {
        return Err(AcquisitionFailure::new(
            AcquisitionFailureClass::Size,
            LiveError::Protocol(format!(
                "firmware metadata exceeds the {max_firmware_bytes}-byte safety limit"
            )),
        ));
    }
    let mut response = client.get(url).send().map_err(|_| {
        AcquisitionFailure::new(
            AcquisitionFailureClass::Transport,
            LiveError::Network("firmware download request failed".into()),
        )
    })?;
    if !response.status().is_success() {
        return Err(AcquisitionFailure::new(
            AcquisitionFailureClass::HttpStatus,
            LiveError::Network(format!(
                "firmware download returned HTTP {}",
                response.status().as_u16()
            )),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_firmware_bytes)
    {
        return Err(AcquisitionFailure::new(
            AcquisitionFailureClass::Size,
            LiveError::Protocol(format!(
                "firmware HTTP body exceeds the {max_firmware_bytes}-byte safety limit"
            )),
        ));
    }

    let channel = safe_filename_component(&record_channel(record, index));
    let source = safe_filename_component(endpoint.source);
    let filename = format!("{index:02}-{source}-{channel}.bin");
    let partial_name = OsString::from(format!(".{filename}.part"));
    let mut partial = PartialPackage {
        directory: stage_directory,
        name: partial_name.clone(),
        retained: false,
    };
    let mut output = stage_directory
        .create_new_private_file(&partial_name)
        .map_err(|error| AcquisitionFailure::new(AcquisitionFailureClass::Storage, error))?;
    let mut md5 = Md5Context::new();
    let mut sha256 = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    loop {
        let read = response.read(&mut buffer).map_err(|_| {
            AcquisitionFailure::new(
                AcquisitionFailureClass::Transport,
                LiveError::Network("could not read firmware response body".into()),
            )
        })?;
        if read == 0 {
            break;
        }
        let read_u64 = read as u64;
        if total > max_firmware_bytes.saturating_sub(read_u64) {
            return Err(AcquisitionFailure::new(
                AcquisitionFailureClass::Size,
                LiveError::Protocol(format!(
                    "firmware body exceeds the {max_firmware_bytes}-byte safety limit"
                )),
            ));
        }
        output.write_all(&buffer[..read]).map_err(|error| {
            AcquisitionFailure::new(
                AcquisitionFailureClass::Storage,
                LiveError::Config(format!("write staged firmware file: {error}")),
            )
        })?;
        md5.consume(&buffer[..read]);
        sha256.update(&buffer[..read]);
        total += read_u64;
    }
    if total == 0 {
        return Err(AcquisitionFailure::new(
            AcquisitionFailureClass::Size,
            LiveError::Protocol("firmware download is empty".into()),
        ));
    }
    if let Some(expected) = expected_bytes {
        if total != expected {
            return Err(AcquisitionFailure::new(
                AcquisitionFailureClass::Size,
                LiveError::Protocol(format!(
                    "firmware size mismatch: expected {expected} bytes, received {total}"
                )),
            ));
        }
    }
    let actual_md5 = format!("{:x}", md5.compute());
    if actual_md5 != expected_md5 {
        return Err(AcquisitionFailure::new(
            AcquisitionFailureClass::Integrity,
            LiveError::Protocol("firmware MD5 does not match authenticated OTA metadata".into()),
        ));
    }
    let actual_sha256 = hex::encode(sha256.finalize());
    output.sync_all().map_err(|error| {
        AcquisitionFailure::new(
            AcquisitionFailureClass::Storage,
            LiveError::Config(format!("sync staged firmware file: {error}")),
        )
    })?;
    drop(output);
    stage_directory
        .rename_noreplace(&partial_name, OsStr::new(&filename))
        .map_err(|error| AcquisitionFailure::new(AcquisitionFailureClass::Storage, error))?;
    partial.retained = true;
    Ok(DownloadedArtifact {
        filename,
        bytes: total,
        md5: actual_md5,
        sha256: actual_sha256,
    })
}

fn safe_filename_component(value: &str) -> String {
    let mut safe = String::with_capacity(value.len().min(64));
    for character in value.trim().chars().take(64) {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
            safe.push(character);
        } else {
            safe.push('_');
        }
    }
    if safe.is_empty() {
        "unknown".into()
    } else {
        safe
    }
}

struct AcquisitionStage {
    parent_directory: PinnedPrivateDirectory,
    staging_directory: PinnedPrivateDirectory,
    staging_name: OsString,
    final_name: OsString,
    final_path: PathBuf,
    published: bool,
}

impl AcquisitionStage {
    fn new(secrets_dir: &Path) -> Result<Self, LiveError> {
        let secrets_directory = PinnedPrivateDirectory::open(secrets_dir, false)?;
        let parent = secrets_dir.join("firmware");
        let parent_directory = secrets_directory.ensure_child_directory(OsStr::new("firmware"))?;
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ");
        let id = format!("acquisition-{timestamp}-{}", hex::encode(random));
        Self::new_in_parent(parent_directory, parent, &id)
    }

    #[cfg(test)]
    fn new_named(parent: &Path, id: &str) -> Result<Self, LiveError> {
        let parent_directory = PinnedPrivateDirectory::open(parent, true)?;
        Self::new_in_parent(parent_directory, parent.to_path_buf(), id)
    }

    fn new_in_parent(
        parent_directory: PinnedPrivateDirectory,
        parent_path: PathBuf,
        id: &str,
    ) -> Result<Self, LiveError> {
        if safe_filename_component(id) != id || id.is_empty() {
            return Err(LiveError::Config("invalid acquisition identifier".into()));
        }
        let staging_name = OsString::from(format!(".{id}.part"));
        let final_name = OsString::from(id);
        if parent_directory.entry_kind(&final_name)?.is_some() {
            return Err(LiveError::Config(
                "acquisition destination already exists; refusing overwrite".into(),
            ));
        }
        let staging_directory = parent_directory.create_child_directory(&staging_name)?;
        Ok(Self {
            final_path: parent_path.join(&final_name),
            parent_directory,
            staging_directory,
            staging_name,
            final_name,
            published: false,
        })
    }

    fn publish(mut self) -> Result<PathBuf, LiveError> {
        self.staging_directory.sync()?;
        self.parent_directory
            .rename_noreplace(&self.staging_name, &self.final_name)?;
        self.published = true;
        self.parent_directory.sync().map_err(|error| {
            LiveError::Config(format!(
                "firmware acquisition was published at {}, but directory durability could not be confirmed: {error}",
                self.final_path.display()
            ))
        })?;
        Ok(self.final_path.clone())
    }
}

impl Drop for AcquisitionStage {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.staging_directory.remove_nondirectory_entries();
            let _ = self
                .parent_directory
                .unlink_child_directory(&self.staging_name);
        }
    }
}

#[derive(Serialize)]
struct AcquisitionManifest {
    schema_version: u32,
    fetch_timestamp: String,
    operation: &'static str,
    completed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_class: Option<&'static str>,
    upgrade_request_sent: bool,
    gateway: ManifestGateway,
    device_id_sha256: String,
    legacy_query_status: &'static str,
    endpoint_responses: Vec<ManifestEndpoint>,
    channels: Vec<ManifestChannel>,
}

#[derive(Serialize)]
struct ManifestGateway {
    scheme: &'static str,
    host: String,
    port: u16,
    request_path: &'static str,
}

#[derive(Serialize)]
struct ManifestEndpoint {
    source: &'static str,
    action: &'static str,
    version: &'static str,
    response_file: &'static str,
    success: bool,
    session_required: bool,
    mutation: bool,
    request_fields: [&'static str; 1],
}

#[derive(Serialize)]
struct ManifestChannel {
    source: &'static str,
    channel: String,
    server_current_version: Option<String>,
    server_offered_version: Option<String>,
    expected_size: Option<u64>,
    expected_md5: Option<String>,
    signature_present: bool,
    signature_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_ota: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_sha256: Option<String>,
}

#[derive(Clone, Copy)]
struct AcquisitionContext<'a> {
    url_policy: DownloadUrlPolicy,
    max_firmware_bytes: u64,
    gateway_host: &'a str,
    dev_id: &'a str,
}

fn publish_acquisition(
    secrets_dir: &Path,
    client: &reqwest::blocking::Client,
    queried: QueriedMetadata,
    download: bool,
    context: AcquisitionContext<'_>,
) -> Result<FirmwareFetchOutcome, LiveError> {
    let stage = AcquisitionStage::new(secrets_dir)?;
    for capture in &queried.captures {
        let bytes = serde_json::to_vec_pretty(&capture.raw).map_err(|_| {
            LiveError::Protocol("could not serialize a private firmware response".into())
        })?;
        stage.staging_directory.atomic_write(
            OsStr::new(capture.endpoint.response_name),
            &bytes,
            false,
        )?;
    }

    let mut artifacts: Vec<Option<DownloadedArtifact>> =
        (0..queried.records.len()).map(|_| None).collect();
    let mut failure = None;

    // Validate every candidate before the first GET. This prevents a valid
    // first record from causing network I/O when a later record is ineligible,
    // while the already-written private endpoint responses preserve the offer.
    if download {
        for (_, record) in queried
            .records
            .iter()
            .filter(|(_, record)| has_firmware_url(record))
        {
            if let Err(error) = normalized_expected_md5(record) {
                failure = Some(AcquisitionFailure::new(
                    AcquisitionFailureClass::IntegrityMetadata,
                    error,
                ));
                break;
            }
            if let Err(error) = validated_download_url(record.url.as_deref(), context.url_policy) {
                failure = Some(AcquisitionFailure::new(
                    AcquisitionFailureClass::UrlPolicy,
                    error,
                ));
                break;
            }
        }
    }
    if download && failure.is_none() {
        for (index, (endpoint, record)) in queried.records.iter().enumerate() {
            if has_firmware_url(record) {
                match stream_firmware_record(
                    client,
                    &stage.staging_directory,
                    *endpoint,
                    record,
                    index,
                    context.url_policy,
                    context.max_firmware_bytes,
                ) {
                    Ok(artifact) => artifacts[index] = Some(artifact),
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
        }
    }

    let manifest = build_manifest(
        &queried,
        &artifacts,
        download,
        failure.as_ref().map(|item| item.class),
        context.gateway_host,
        context.dev_id,
    );
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| LiveError::Protocol("could not serialize acquisition manifest".into()))?;
    stage
        .staging_directory
        .atomic_write(OsStr::new("manifest.json"), &manifest_bytes, false)?;

    let summaries = queried
        .records
        .iter()
        .enumerate()
        .map(|(index, (endpoint, record))| {
            firmware_summary(*endpoint, record, index, context.dev_id)
        })
        .collect::<Vec<_>>();
    let final_path = stage.final_path.clone();
    let metadata_paths = queried
        .captures
        .iter()
        .map(|capture| final_path.join(capture.endpoint.response_name))
        .collect();
    let downloads = queried
        .records
        .iter()
        .enumerate()
        .filter_map(|(index, (_, record))| {
            artifacts[index]
                .as_ref()
                .map(|artifact| FirmwareDownloadSummary {
                    path: final_path.join(&artifact.filename),
                    bytes: artifact.bytes,
                    md5_verified: true,
                    server_signature_present: record
                        .sign
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|value| !value.is_empty()),
                    server_signature_verified: false,
                })
        })
        .collect();
    let notices = queried.notices.clone();
    let published = stage.publish()?;
    debug_assert_eq!(published, final_path);
    if let Some(failure) = failure {
        return Err(failure.into_preserved_error(&published));
    }
    Ok(FirmwareFetchOutcome {
        acquisition_path: final_path.clone(),
        manifest_path: final_path.join("manifest.json"),
        metadata_paths,
        records: summaries,
        downloads,
        notices,
    })
}

fn build_manifest(
    queried: &QueriedMetadata,
    artifacts: &[Option<DownloadedArtifact>],
    download: bool,
    failure: Option<AcquisitionFailureClass>,
    gateway_host: &str,
    dev_id: &str,
) -> AcquisitionManifest {
    AcquisitionManifest {
        schema_version: 1,
        fetch_timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        operation: if download { "download" } else { "info" },
        completed: failure.is_none(),
        failure_class: failure.map(AcquisitionFailureClass::as_str),
        upgrade_request_sent: false,
        gateway: ManifestGateway {
            scheme: "https",
            host: gateway_host.to_string(),
            port: 443,
            request_path: "/api.json",
        },
        device_id_sha256: hex::encode(Sha256::digest(dev_id.as_bytes())),
        legacy_query_status: queried.legacy_status.as_str(),
        endpoint_responses: queried
            .captures
            .iter()
            .map(|capture| ManifestEndpoint {
                source: capture.endpoint.source,
                action: capture.endpoint.action,
                version: capture.endpoint.version,
                response_file: capture.endpoint.response_name,
                success: capture.success,
                session_required: true,
                mutation: false,
                request_fields: ["devId"],
            })
            .collect(),
        channels: queried
            .records
            .iter()
            .enumerate()
            .map(|(index, (endpoint, record))| {
                let artifact = artifacts[index].as_ref();
                ManifestChannel {
                    source: endpoint.source,
                    channel: record_channel(record, index),
                    server_current_version: nonempty_owned(record.current_version.as_deref()),
                    server_offered_version: nonempty_owned(record.version.as_deref()),
                    expected_size: expected_size(record),
                    expected_md5: nonempty_owned(record.md5.as_deref()),
                    signature_present: record
                        .sign
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|value| !value.is_empty()),
                    signature_verified: false,
                    diff_ota: record.diff_ota,
                    package_file: artifact.map(|item| item.filename.clone()),
                    actual_size: artifact.map(|item| item.bytes),
                    actual_md5: artifact.map(|item| item.md5.clone()),
                    actual_sha256: artifact.map(|item| item.sha256.clone()),
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::thread;

    use super::*;

    enum MockResult {
        Reply(QueryReply),
        Failure(QueryFailure),
    }

    struct MockQuery {
        results: VecDeque<MockResult>,
        actions: Vec<&'static str>,
    }

    impl FirmwareQuery for MockQuery {
        fn query(&mut self, endpoint: FirmwareInfoEndpoint) -> Result<QueryReply, QueryFailure> {
            self.actions.push(endpoint.action);
            match self.results.pop_front().expect("mock query result") {
                MockResult::Reply(reply) => Ok(reply),
                MockResult::Failure(failure) => Err(failure),
            }
        }
    }

    fn reply(success: bool, result: serde_json::Value, raw: serde_json::Value) -> MockResult {
        MockResult::Reply(QueryReply {
            success,
            failure: (!success).then_some(QueryFailure::Server),
            result,
            raw,
        })
    }

    fn query_with(results: Vec<MockResult>) -> MockQuery {
        MockQuery {
            results: results.into(),
            actions: Vec::new(),
        }
    }

    #[test]
    fn firmware_info_request_is_read_only_and_device_id_only() {
        assert_eq!(PRIMARY_ENDPOINT.action, "m.thing.firmware.upgrade.info.get");
        assert_eq!(PRIMARY_ENDPOINT.version, "1.1");
        assert_eq!(LEGACY_ENDPOINT.action, "thing.m.device.upgrade.info");
        assert_eq!(LEGACY_ENDPOINT.version, "1.2");
        assert_eq!(
            firmware_info_post_data("synthetic-camera"),
            r#"{"devId":"synthetic-camera"}"#
        );
    }

    #[test]
    fn primary_url_skips_legacy_in_exact_action_order() {
        let mut query = query_with(vec![reply(
            true,
            serde_json::json!([{ "url": "https://example.invalid/fw.bin" }]),
            serde_json::json!({"success": true}),
        )]);
        let result = orchestrate_queries(&mut query).unwrap();
        assert_eq!(query.actions, vec![PRIMARY_ENDPOINT.action]);
        assert_eq!(result.records.len(), 1);
        assert!(matches!(result.legacy_status, LegacyQueryStatus::NotNeeded));
    }

    #[test]
    fn primary_without_url_queries_legacy_and_surfaces_all_safe_records() {
        let mut query = query_with(vec![
            reply(
                true,
                serde_json::json!([{ "currentVersion": "1.4.0", "type": 1 }]),
                serde_json::json!({"success": true}),
            ),
            reply(
                true,
                serde_json::json!([{ "currentVersion": "1.4.0", "type": 2 }]),
                serde_json::json!({"success": true}),
            ),
        ]);
        let result = orchestrate_queries(&mut query).unwrap();
        assert_eq!(
            query.actions,
            vec![PRIMARY_ENDPOINT.action, LEGACY_ENDPOINT.action]
        );
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.captures.len(), 2);
        assert!(result.notices.is_empty());
    }

    #[test]
    fn primary_rejection_redacts_untrusted_server_message_and_values() {
        let secret = "https://signed.invalid/fw?token=secret-device-id";
        let mut query = query_with(vec![reply(
            false,
            serde_json::Value::Null,
            serde_json::json!({"errorCode": secret, "errorMsg": secret}),
        )]);
        let text = match orchestrate_queries(&mut query) {
            Ok(_) => panic!("primary rejection must fail"),
            Err(error) => error.to_string(),
        };
        assert!(!text.contains("signed.invalid"));
        assert!(!text.contains("secret-device-id"));
        assert_eq!(query.actions, vec![PRIMARY_ENDPOINT.action]);
    }

    #[test]
    fn legacy_transport_and_server_failures_are_nonfatal_and_generic() {
        for legacy in [
            MockResult::Failure(QueryFailure::Transport),
            reply(
                false,
                serde_json::Value::Null,
                serde_json::json!({"errorMsg": "https://signed.invalid/?device=secret"}),
            ),
        ] {
            let mut query = query_with(vec![
                reply(true, serde_json::json!([]), serde_json::json!({})),
                legacy,
            ]);
            let result = orchestrate_queries(&mut query).unwrap();
            assert_eq!(result.records.len(), 0);
            assert_eq!(result.notices, vec![legacy_unavailable_notice()]);
            assert!(!result.notices[0].contains("signed.invalid"));
        }
    }

    #[test]
    fn malformed_legacy_success_is_nonfatal_and_generic() {
        let mut query = query_with(vec![
            reply(true, serde_json::json!([]), serde_json::json!({})),
            reply(
                true,
                serde_json::json!({"unexpected": "https://signed.invalid/?device=secret"}),
                serde_json::json!({"success": true}),
            ),
        ]);
        let result = orchestrate_queries(&mut query).unwrap();
        assert!(result.records.is_empty());
        assert_eq!(result.notices, vec![legacy_unavailable_notice()]);
        assert!(!result.notices[0].contains("signed.invalid"));
    }

    #[test]
    fn primary_query_failure_preserves_redacted_category() {
        let mut session = query_with(vec![MockResult::Failure(QueryFailure::Session)]);
        let session_error = orchestrate_queries(&mut session)
            .err()
            .expect("session failure must be rejected")
            .to_string();
        assert!(session_error.contains("session"));
        assert!(!session_error.contains("network"));

        let mut transport = query_with(vec![MockResult::Failure(QueryFailure::Transport)]);
        let transport_error = orchestrate_queries(&mut transport)
            .err()
            .expect("transport failure must be rejected")
            .to_string();
        assert!(transport_error.contains("transport"));
    }

    #[test]
    fn expired_session_is_rejected_before_firmware_work() {
        let now = chrono::Utc::now();
        let expired = babymonitor_core::session::Session {
            sid: "SYNTH_SID".into(),
            uid: "SYNTH_UID".into(),
            ecode: Some("SYNTH_ECODE".into()),
            mobile_api_base: "https://a1.tuyaeu.com".into(),
            issued_at: now - chrono::Duration::hours(2),
            expires_at: now - chrono::Duration::hours(1),
        };
        assert!(ensure_session_fresh(&expired).is_err());
    }

    #[test]
    fn public_versions_reject_hostile_or_sensitive_success_values() {
        let dev_id = "sensitive-device-id";
        for value in [
            "1.4.0\u{1b}[31m",
            "https://signed.invalid/fw?token=secret",
            "1.4.sensitive-device-id",
            "123456789012345678901234567890123",
            "release-without-dot",
        ] {
            assert_eq!(public_firmware_version(Some(value), dev_id, None), None);
        }
        assert_eq!(
            public_firmware_version(Some("v1.4.0-rc1"), dev_id, None).as_deref(),
            Some("v1.4.0-rc1")
        );
    }

    #[test]
    fn summary_separates_url_integrity_and_download_eligibility() {
        let records = parse_firmware_records(serde_json::json!([
            {
                "currentVersion": "1.4.0",
                "version": "1.5.0",
                "url": "http://127.0.0.1/fw.bin",
                "md5": "900150983cd24fb0d6963f7d28e17f72",
                "fileSize": 0
            },
            {
                "version": "1.5.0",
                "url": "https://cdn.invalid/fw.bin",
                "md5": "not-a-valid-md5"
            },
            {
                "version": "1.5.0",
                "url": "https://cdn.invalid/fw.bin",
                "md5": "900150983cd24fb0d6963f7d28e17f72"
            }
        ]))
        .unwrap();
        let http = firmware_summary(PRIMARY_ENDPOINT, &records[0], 0, "synthetic-camera");
        assert!(http.package_url_present);
        assert!(http.integrity_metadata_present);
        assert!(!http.download_eligible);
        assert_eq!(http.expected_bytes, None);
        let invalid_md5 = firmware_summary(PRIMARY_ENDPOINT, &records[1], 1, "synthetic-camera");
        assert!(invalid_md5.integrity_metadata_present);
        assert!(!invalid_md5.download_eligible);
        let eligible = firmware_summary(PRIMARY_ENDPOINT, &records[2], 2, "synthetic-camera");
        assert!(eligible.download_eligible);
    }

    #[test]
    fn production_rejects_http_while_test_policy_allows_literal_loopback_only() {
        assert!(validated_download_url(
            Some("http://127.0.0.1:1234/fw.bin"),
            DownloadUrlPolicy::ProductionHttps
        )
        .is_err());
        assert!(validated_download_url(
            Some("http://127.0.0.1:1234/fw.bin"),
            DownloadUrlPolicy::LoopbackHttpForTest
        )
        .is_ok());
        assert!(validated_download_url(
            Some("http://example.invalid/fw.bin"),
            DownloadUrlPolicy::LoopbackHttpForTest
        )
        .is_err());
    }

    #[test]
    fn manifest_omits_diff_ota_when_server_did_not_send_it() {
        let channel = ManifestChannel {
            source: PRIMARY_ENDPOINT.source,
            channel: "type-1".into(),
            server_current_version: Some("1.4.0".into()),
            server_offered_version: None,
            expected_size: None,
            expected_md5: None,
            signature_present: false,
            signature_verified: false,
            diff_ota: None,
            package_file: None,
            actual_size: None,
            actual_md5: None,
            actual_sha256: None,
        };
        let value = serde_json::to_value(channel).unwrap();
        assert!(value.get("diff_ota").is_none());
    }

    fn temp_root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "babymonitor-{label}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn only_acquisition(root: &Path) -> PathBuf {
        let mut entries = std::fs::read_dir(root.join("firmware"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("acquisition-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "expected one published acquisition");
        entries.pop().unwrap()
    }

    fn read_manifest(acquisition: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(acquisition.join("manifest.json")).unwrap()).unwrap()
    }

    fn directory_has_package_or_partial(acquisition: &Path) -> bool {
        std::fs::read_dir(acquisition).unwrap().any(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            name.ends_with(".bin") || name.ends_with(".part")
        })
    }

    fn test_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn spawn_body_server(
        declared_length: usize,
        body: Vec<u8>,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(header.as_bytes()).unwrap();
            socket.write_all(&body).unwrap();
        });
        (address, server)
    }

    fn publish_test_acquisition(
        root: &Path,
        queried: QueriedMetadata,
        download: bool,
        max_firmware_bytes: u64,
    ) -> Result<FirmwareFetchOutcome, LiveError> {
        publish_acquisition(
            root,
            &test_client(),
            queried,
            download,
            AcquisitionContext {
                url_policy: DownloadUrlPolicy::LoopbackHttpForTest,
                max_firmware_bytes,
                gateway_host: "a1.tuyaeu.com",
                dev_id: "synthetic-camera",
            },
        )
    }

    fn queried_records(records: Vec<FirmwareInfoRecord>) -> QueriedMetadata {
        QueriedMetadata {
            records: records
                .into_iter()
                .map(|record| (PRIMARY_ENDPOINT, record))
                .collect(),
            captures: vec![EndpointCapture {
                endpoint: PRIMARY_ENDPOINT,
                raw: serde_json::json!({"success": true}),
                success: true,
            }],
            legacy_status: LegacyQueryStatus::NotNeeded,
            notices: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn streamed_package_and_manifest_publish_atomically_with_private_modes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = socket.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /ota.bin "));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
                .unwrap();
        });
        let root = temp_root("firmware-publish");
        let records = parse_firmware_records(serde_json::json!([{
            "currentVersion": "1.4.0",
            "version": "1.5.0",
            "fileSize": 3,
            "md5": "900150983cd24fb0d6963f7d28e17f72",
            "sign": "unknown-algorithm-signature",
            "url": format!("http://{address}/ota.bin"),
            "type": 9,
            "diffOta": true
        }]))
        .unwrap();
        let queried = QueriedMetadata {
            records: records
                .into_iter()
                .map(|record| (PRIMARY_ENDPOINT, record))
                .collect(),
            captures: vec![EndpointCapture {
                endpoint: PRIMARY_ENDPOINT,
                raw: serde_json::json!({"success": true}),
                success: true,
            }],
            legacy_status: LegacyQueryStatus::NotNeeded,
            notices: Vec::new(),
        };
        let outcome = publish_test_acquisition(&root, queried, true, 3).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.downloads.len(), 1);
        assert_eq!(std::fs::read(&outcome.downloads[0].path).unwrap(), b"abc");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&outcome.manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["upgrade_request_sent"], false);
        assert_eq!(manifest["completed"], true);
        assert_eq!(manifest["gateway"]["host"], "a1.tuyaeu.com");
        assert_eq!(manifest["endpoint_responses"][0]["mutation"], false);
        assert_eq!(manifest["device_id_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(
            manifest["channels"][0]["actual_sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(manifest["channels"][0]["signature_verified"], false);
        assert_eq!(
            std::fs::metadata(&outcome.acquisition_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(root.join("firmware"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in [
            &outcome.manifest_path,
            &outcome.metadata_paths[0],
            &outcome.downloads[0].path,
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!std::fs::read_dir(root.join("firmware"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.')));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unverifiable_download_preserves_metadata_without_network() {
        let root = temp_root("firmware-no-md5");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let records = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "url": format!("http://{address}/ota.bin"),
            "type": 9
        }]))
        .unwrap();
        let queried = QueriedMetadata {
            records: records
                .into_iter()
                .map(|record| (PRIMARY_ENDPOINT, record))
                .collect(),
            captures: vec![EndpointCapture {
                endpoint: PRIMARY_ENDPOINT,
                raw: serde_json::json!({"success": true}),
                success: true,
            }],
            legacy_status: LegacyQueryStatus::NotNeeded,
            notices: Vec::new(),
        };
        let result = publish_test_acquisition(&root, queried, true, MAX_FIRMWARE_BYTES);
        assert!(matches!(result, Err(LiveError::Protocol(_))));
        assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
        let acquisition = only_acquisition(&root);
        let manifest = read_manifest(&acquisition);
        assert_eq!(manifest["completed"], false);
        assert_eq!(manifest["failure_class"], "integrity-metadata");
        assert_eq!(manifest["upgrade_request_sent"], false);
        assert!(acquisition.join("primary-response.json").is_file());
        assert!(!directory_has_package_or_partial(&acquisition));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_md5_preserves_metadata_without_network() {
        let root = temp_root("firmware-invalid-md5");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let records = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "md5": "not-an-md5",
            "url": format!("http://{address}/ota.bin")
        }]))
        .unwrap();
        let result =
            publish_test_acquisition(&root, queried_records(records), true, MAX_FIRMWARE_BYTES);
        assert!(matches!(result, Err(LiveError::Protocol(_))));
        assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
        let acquisition = only_acquisition(&root);
        assert_eq!(
            read_manifest(&acquisition)["failure_class"],
            "integrity-metadata"
        );
        assert!(!directory_has_package_or_partial(&acquisition));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn size_mismatch_preserves_failure_manifest_and_removes_bytes() {
        let (address, server) = spawn_body_server(3, b"abc".to_vec());
        let root = temp_root("firmware-size-failure");
        let records = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "fileSize": 4,
            "md5": "900150983cd24fb0d6963f7d28e17f72",
            "url": format!("http://{address}/ota.bin"),
            "type": 9
        }]))
        .unwrap();
        let result =
            publish_test_acquisition(&root, queried_records(records), true, MAX_FIRMWARE_BYTES);
        server.join().unwrap();
        assert!(matches!(result, Err(LiveError::Protocol(_))));
        let acquisition = only_acquisition(&root);
        let manifest = read_manifest(&acquisition);
        assert_eq!(manifest["completed"], false);
        assert_eq!(manifest["failure_class"], "size");
        assert!(!directory_has_package_or_partial(&acquisition));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn digest_mismatch_preserves_failure_manifest_and_removes_bytes() {
        let (address, server) = spawn_body_server(3, b"abc".to_vec());
        let root = temp_root("firmware-digest-failure");
        let records = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "fileSize": 3,
            "md5": "00000000000000000000000000000000",
            "url": format!("http://{address}/ota.bin"),
            "type": 9
        }]))
        .unwrap();
        let result =
            publish_test_acquisition(&root, queried_records(records), true, MAX_FIRMWARE_BYTES);
        server.join().unwrap();
        assert!(matches!(result, Err(LiveError::Protocol(_))));
        let acquisition = only_acquisition(&root);
        let manifest = read_manifest(&acquisition);
        assert_eq!(manifest["failure_class"], "integrity");
        assert!(!directory_has_package_or_partial(&acquisition));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_body_preserves_failure_provenance_without_partial_bytes() {
        let (address, server) = spawn_body_server(5, b"abc".to_vec());
        let root = temp_root("firmware-interrupted");
        let records = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "fileSize": 5,
            "md5": "900150983cd24fb0d6963f7d28e17f72",
            "url": format!("http://{address}/ota.bin")
        }]))
        .unwrap();
        let result =
            publish_test_acquisition(&root, queried_records(records), true, MAX_FIRMWARE_BYTES);
        server.join().unwrap();
        assert!(result.is_err());
        let acquisition = only_acquisition(&root);
        let class = read_manifest(&acquisition)["failure_class"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(matches!(class.as_str(), "transport" | "size"));
        assert!(!directory_has_package_or_partial(&acquisition));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn body_cap_failure_preserves_metadata_without_partial_bytes() {
        let (address, server) = spawn_body_server(3, b"abc".to_vec());
        let root = temp_root("firmware-cap-failure");
        let records = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "md5": "900150983cd24fb0d6963f7d28e17f72",
            "url": format!("http://{address}/ota.bin")
        }]))
        .unwrap();
        let result = publish_test_acquisition(&root, queried_records(records), true, 2);
        server.join().unwrap();
        assert!(matches!(result, Err(LiveError::Protocol(_))));
        let acquisition = only_acquisition(&root);
        assert_eq!(read_manifest(&acquisition)["failure_class"], "size");
        assert!(!directory_has_package_or_partial(&acquisition));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn second_package_failure_retains_verified_sibling_only() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for body in [b"abc".as_slice(), b"xyz".as_slice()] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).unwrap();
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n")
                    .unwrap();
                socket.write_all(body).unwrap();
            }
        });
        let root = temp_root("firmware-second-failure");
        let records = parse_firmware_records(serde_json::json!([
            {
                "version": "1.5.0",
                "fileSize": 3,
                "md5": "900150983cd24fb0d6963f7d28e17f72",
                "url": format!("http://{address}/first.bin"),
                "type": 0
            },
            {
                "version": "1.5.0",
                "fileSize": 3,
                "md5": "00000000000000000000000000000000",
                "url": format!("http://{address}/second.bin"),
                "type": 9
            }
        ]))
        .unwrap();
        let result =
            publish_test_acquisition(&root, queried_records(records), true, MAX_FIRMWARE_BYTES);
        server.join().unwrap();
        assert!(matches!(result, Err(LiveError::Protocol(_))));
        let acquisition = only_acquisition(&root);
        let manifest = read_manifest(&acquisition);
        assert_eq!(manifest["completed"], false);
        assert_eq!(manifest["failure_class"], "integrity");
        let first_file = manifest["channels"][0]["package_file"].as_str().unwrap();
        assert_eq!(std::fs::read(acquisition.join(first_file)).unwrap(), b"abc");
        assert!(manifest["channels"][1].get("package_file").is_none());
        assert!(!std::fs::read_dir(&acquisition).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".part")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_publish_target_is_rejected_and_partial_stage_is_removed() {
        use std::os::unix::fs::symlink;

        let root = temp_root("firmware-symlink");
        let parent = root.join("firmware");
        ensure_private_directory(&parent).unwrap();
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        let stage = AcquisitionStage::new_named(&parent, "acquisition-fixed").unwrap();
        stage
            .staging_directory
            .atomic_write(OsStr::new("manifest.json"), b"{}", false)
            .unwrap();
        symlink(&target, &stage.final_path).unwrap();
        assert!(stage.publish().is_err());
        assert!(std::fs::symlink_metadata(parent.join("acquisition-fixed"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!parent.join(".acquisition-fixed.part").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn acquisition_stage_cannot_be_redirected_by_parent_path_swap() {
        let root = temp_root("firmware-parent-swap");
        let parent = root.join("firmware");
        ensure_private_directory(&parent).unwrap();
        let stage = AcquisitionStage::new_named(&parent, "acquisition-fixed").unwrap();

        let moved_parent = root.join("firmware-moved");
        std::fs::rename(&parent, &moved_parent).unwrap();
        ensure_private_directory(&parent).unwrap();
        stage
            .staging_directory
            .atomic_write(OsStr::new("manifest.json"), b"{}", false)
            .unwrap();
        let _reported_path = stage.publish().unwrap();

        assert!(moved_parent
            .join("acquisition-fixed")
            .join("manifest.json")
            .is_file());
        assert!(!parent.join("acquisition-fixed").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn acquisition_publish_sync_failure_preserves_published_provenance() {
        let root = temp_root("firmware-publish-sync-failure");
        let parent = root.join("firmware");
        ensure_private_directory(&parent).unwrap();
        let stage = AcquisitionStage::new_named(&parent, "acquisition-fixed").unwrap();
        stage
            .staging_directory
            .atomic_write(OsStr::new("manifest.json"), b"{}", false)
            .unwrap();
        let final_path = stage.final_path.clone();
        stage.parent_directory.fail_next_sync_for_test();

        let error = stage.publish().unwrap_err().to_string();

        assert!(error.contains("directory durability could not be confirmed"));
        assert!(error.contains(&final_path.display().to_string()));
        assert!(final_path.join("manifest.json").is_file());
        assert!(!parent.join(".acquisition-fixed.part").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_writer_rejects_dangling_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = temp_root("private-output-symlink");
        let output = root.join("capture.json");
        symlink(root.join("missing-target"), &output).unwrap();
        assert!(atomic_write_private(&output, b"private", false).is_err());
        assert!(std::fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!root.join("missing-target").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redirect_is_not_followed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).unwrap();
            socket
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let root = temp_root("firmware-redirect");
        let record = parse_firmware_records(serde_json::json!([{
            "version": "1.5.0",
            "fileSize": 3,
            "md5": "900150983cd24fb0d6963f7d28e17f72",
            "url": format!("http://{address}/ota.bin")
        }]))
        .unwrap()
        .remove(0);
        let directory = PinnedPrivateDirectory::open(&root, true).unwrap();
        let result = stream_firmware_record(
            &test_client(),
            &directory,
            PRIMARY_ENDPOINT,
            &record,
            0,
            DownloadUrlPolicy::LoopbackHttpForTest,
            MAX_FIRMWARE_BYTES,
        );
        let error = match result {
            Ok(_) => panic!("redirect response must not be followed or accepted"),
            Err(error) => error.error.to_string(),
        };
        server.join().unwrap();
        assert!(error.contains("HTTP 302"));
        assert!(!error.contains("127.0.0.1:9"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
