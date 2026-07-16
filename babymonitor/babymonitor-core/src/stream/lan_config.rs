//! Secure durable metadata for cloud-independent LAN signaling.
//!
//! This file is an owner-provisioned cache, not a local credential-discovery
//! mechanism. The localKey and account/sender metadata must currently be
//! supplied out of band. ICE credentials, media keys, trace IDs and session
//! IDs are minted anew for every stream and are never serialized here. The
//! camera-info media password may be cached when supplied, but its stability
//! across a reset or a later `rtc.config.get` refresh is not yet proven.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::stream::tuya_lan::{LanKey, LanProtocolVersion, TUYA_LAN_PORT};
use crate::Error;

const CONFIG_DIR: &str = "philips-babymonitor";
const CONFIG_FILE: &str = "lan.json";

fn default_lan_port() -> u16 {
    TUYA_LAN_PORT
}

/// Owner-provisioned camera values cached for LAN mode.
#[derive(Clone, Serialize, Deserialize)]
pub struct LanDeviceConfig {
    /// Camera address on the local network.
    pub camera_ip: IpAddr,
    /// Tuya LAN TCP port (defaults to 6668).
    #[serde(default = "default_lan_port")]
    pub port: u16,
    /// Camera Tuya device id used in signaling routing headers.
    pub device_id: String,
    /// Pre-provisioned account/sender id used as `header.from` and SDP cname.
    pub sender_id: String,
    /// Device localKey.  Secret; never printed by `Debug`.
    pub local_key: String,
    /// `HgwBean.version`, currently supported values 3.4 and 3.5.
    pub hgw_version: String,
    /// Optional cached camera-info password used to derive conv=0 media auth.
    /// Its stability across reset/config refresh is unproven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_auth_password: Option<String>,
}

impl LanDeviceConfig {
    /// Validate all load-bearing values without exposing secret contents.
    pub fn validate(&self) -> Result<(), Error> {
        if self.camera_ip.is_unspecified() || self.camera_ip.is_multicast() {
            return Err(Error::StreamConfig(
                "LAN camera_ip must be a concrete unicast address".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(Error::StreamConfig(
                "LAN camera port must be non-zero".to_string(),
            ));
        }
        if self.device_id.trim().is_empty() {
            return Err(Error::StreamConfig(
                "LAN device_id must not be empty".to_string(),
            ));
        }
        if self.sender_id.trim().is_empty() {
            return Err(Error::StreamConfig(
                "LAN sender_id must not be empty (it is header.from/SDP cname)".to_string(),
            ));
        }
        LanKey::from_local_key(&self.local_key)?;
        LanProtocolVersion::from_hgw_version(&self.hgw_version)?;
        Ok(())
    }

    /// Authenticated camera endpoint.
    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.camera_ip, self.port)
    }

    /// Parsed LAN protocol version.
    pub fn protocol_version(&self) -> Result<LanProtocolVersion, Error> {
        LanProtocolVersion::from_hgw_version(&self.hgw_version)
    }

    /// Parsed, redacting local key.
    pub fn lan_key(&self) -> Result<LanKey, Error> {
        LanKey::from_local_key(&self.local_key)
    }
}

impl std::fmt::Debug for LanDeviceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LanDeviceConfig")
            .field("camera_ip", &self.camera_ip)
            .field("port", &self.port)
            .field("device_id", &"[REDACTED]")
            .field("sender_id", &"[REDACTED]")
            .field("local_key", &"[REDACTED]")
            .field("hgw_version", &self.hgw_version)
            .field(
                "media_auth_password",
                &self.media_auth_password.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Drop for LanDeviceConfig {
    fn drop(&mut self) {
        self.local_key.zeroize();
        if let Some(password) = &mut self.media_auth_password {
            password.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryPolicy {
    /// The application's default private directory. It may be created, but an
    /// existing directory is validated rather than having its mode changed.
    Dedicated,
    /// A caller-selected location. Its parent must already exist and is never
    /// created or chmodded by this module.
    Explicit,
}

/// Filesystem-backed secure LAN configuration store.
#[derive(Clone, Debug)]
pub struct LanConfigStore {
    path: PathBuf,
    directory_policy: DirectoryPolicy,
}

impl LanConfigStore {
    /// Default per-user path: `$XDG_CONFIG_HOME/philips-babymonitor/lan.json`.
    pub fn default_path() -> Result<Self, Error> {
        let base = dirs::config_dir().ok_or_else(|| {
            Error::StreamConfig("cannot determine per-user configuration directory".to_string())
        })?;
        Ok(Self {
            path: base.join(CONFIG_DIR).join(CONFIG_FILE),
            directory_policy: DirectoryPolicy::Dedicated,
        })
    }

    /// Construct a store at an explicit path.
    ///
    /// The parent directory must already exist, must not be a symlink, and on
    /// Unix must not be group/world-writable. It is never created or chmodded.
    /// This avoids silently changing permissions on arbitrary caller-selected
    /// directories.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            directory_policy: DirectoryPolicy::Explicit,
        }
    }

    /// Config file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load and validate a config, rejecting symlinks and group/world-readable
    /// files before reading any secret bytes.
    ///
    /// On Unix the file is opened once with `O_NOFOLLOW`; all type and mode
    /// checks use metadata from that already-open descriptor. This prevents a
    /// check-then-open swap from redirecting the read to a symlink target.
    pub fn load(&self) -> Result<LanDeviceConfig, Error> {
        let parent = self.parent()?;
        validate_existing_directory(parent, self.directory_policy)?;

        let mut file = open_read_no_follow(&self.path).map_err(|error| {
            Error::StreamConfig(format!(
                "open LAN config {} without following symlinks: {error}",
                self.path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            Error::StreamConfig(format!(
                "inspect opened LAN config {}: {error}",
                self.path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(Error::StreamConfig(format!(
                "LAN config {} must be a regular file",
                self.path.display()
            )));
        }
        reject_unsafe_mode(&self.path, &metadata)?;

        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes).map_err(|error| {
            Error::StreamConfig(format!("read LAN config {}: {error}", self.path.display()))
        })?;
        let config: LanDeviceConfig =
            serde_json::from_slice(bytes.as_slice()).map_err(|error| {
                Error::StreamConfig(format!("parse LAN config {}: {error}", self.path.display()))
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Atomically persist a validated config with mode 0600.
    ///
    /// The default store creates only its dedicated application directory at
    /// mode 0700. An explicit store requires an existing safe parent and never
    /// changes that parent's mode.
    pub fn save(&self, config: &LanDeviceConfig) -> Result<(), Error> {
        config.validate()?;
        let parent = self.parent()?;
        prepare_directory(parent, self.directory_policy)?;
        reject_non_regular_destination(&self.path)?;

        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(CONFIG_FILE);
        let temp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
        let result = (|| -> Result<(), Error> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            set_create_mode_600(&mut options);
            let mut file = options.open(&temp).map_err(|error| {
                Error::StreamConfig(format!("create temporary LAN config: {error}"))
            })?;
            let mut encoded = Zeroizing::new(Vec::new());
            serde_json::to_writer_pretty(&mut *encoded, config)
                .map_err(|error| Error::StreamConfig(format!("serialize LAN config: {error}")))?;
            encoded.push(b'\n');
            file.write_all(encoded.as_slice()).map_err(|error| {
                Error::StreamConfig(format!("write temporary LAN config: {error}"))
            })?;
            file.sync_all().map_err(|error| {
                Error::StreamConfig(format!("sync temporary LAN config: {error}"))
            })?;
            drop(file);
            fs::rename(&temp, &self.path).map_err(|error| {
                Error::StreamConfig(format!("install LAN config atomically: {error}"))
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn parent(&self) -> Result<&Path, Error> {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                Error::StreamConfig("LAN config path has no parent directory".to_string())
            })
    }
}

#[cfg(unix)]
fn open_read_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow(&mut options);
    options.open(path)
}

#[cfg(not(unix))]
fn open_read_no_follow(path: &Path) -> std::io::Result<File> {
    // std exposes no portable no-follow open flag outside Unix. Preserve an
    // explicit symlink/reparse-point rejection where the platform reports it;
    // unlike the Unix implementation this cannot eliminate the race.
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "LAN config path is a symlink",
        ));
    }
    File::open(path)
}

fn prepare_directory(path: &Path, policy: DirectoryPolicy) -> Result<(), Error> {
    if policy == DirectoryPolicy::Dedicated {
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(path)?;
            }
            Err(error) => {
                return Err(Error::StreamConfig(format!(
                    "inspect dedicated LAN config directory {}: {error}",
                    path.display()
                )));
            }
        }
    }
    validate_existing_directory(path, policy)
}

fn validate_existing_directory(path: &Path, policy: DirectoryPolicy) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let qualifier = if policy == DirectoryPolicy::Explicit {
            "explicit LAN config parent must already exist"
        } else {
            "inspect dedicated LAN config directory"
        };
        Error::StreamConfig(format!("{qualifier} {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::StreamConfig(format!(
            "LAN config parent {} must be a real directory, not a symlink",
            path.display()
        )));
    }
    reject_unsafe_directory_mode(path, &metadata, policy)
}

fn reject_non_regular_destination(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::StreamConfig(format!(
                "LAN config destination {} must be absent or a regular non-symlink file",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::StreamConfig(format!(
            "inspect LAN config destination {}: {error}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
fn reject_unsafe_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::StreamConfig(format!(
            "LAN config {} has unsafe mode {mode:04o}; require 0600 (no group/world access)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_unsafe_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_unsafe_directory_mode(
    path: &Path,
    metadata: &fs::Metadata,
    policy: DirectoryPolicy,
) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o777;
    let unsafe_mode = match policy {
        DirectoryPolicy::Dedicated => mode != 0o700,
        DirectoryPolicy::Explicit => mode & 0o022 != 0,
    };
    if unsafe_mode {
        let requirement = match policy {
            DirectoryPolicy::Dedicated => "require exactly 0700",
            DirectoryPolicy::Explicit => "must not be group/world-writable",
        };
        return Err(Error::StreamConfig(format!(
            "LAN config parent {} has unsafe mode {mode:04o}; {requirement}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_unsafe_directory_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _policy: DirectoryPolicy,
) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| {
        Error::StreamConfig(format!(
            "create private LAN config directory {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), Error> {
    fs::create_dir(path).map_err(|error| {
        Error::StreamConfig(format!(
            "create private LAN config directory {}: {error}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_create_mode_600(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_create_mode_600(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_config() -> LanDeviceConfig {
        LanDeviceConfig {
            camera_ip: "192.0.2.10".parse().unwrap(),
            port: TUYA_LAN_PORT,
            device_id: "SYNTH_DEVICE_ID".to_string(),
            sender_id: "SYNTH_SENDER_ID".to_string(),
            local_key: "0123456789abcdef".to_string(), // secret-scan:allow synthetic
            hgw_version: "3.5".to_string(),
            media_auth_password: Some("SYNTH_MEDIA_PASSWORD".to_string()), // secret-scan:allow synthetic
        }
    }

    fn temp_store(label: &str) -> (PathBuf, LanConfigStore) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "babymonitor-lan-config-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let store = LanConfigStore::new(dir.join("lan.json"));
        (dir, store)
    }

    fn dedicated_store(label: &str) -> (PathBuf, PathBuf, LanConfigStore) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "babymonitor-lan-config-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        let dedicated = base.join(CONFIG_DIR);
        let store = LanConfigStore {
            path: dedicated.join(CONFIG_FILE),
            directory_policy: DirectoryPolicy::Dedicated,
        };
        (base, dedicated, store)
    }

    #[test]
    fn explicit_save_load_is_owner_only_and_does_not_mutate_parent_mode() {
        let (dir, store) = temp_store("roundtrip");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        }
        let config = synthetic_config();
        store.save(&config).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.camera_ip, config.camera_ip);
        assert_eq!(loaded.port, TUYA_LAN_PORT);
        assert_eq!(loaded.hgw_version, "3.5");

        let json = fs::read_to_string(store.path()).unwrap();
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("session_id"));
        assert!(!json.contains("ice_ufrag"));
        assert!(!json.contains("media_key"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(store.path()).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o750);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dedicated_save_creates_private_directory_and_round_trips() {
        let (base, dedicated, store) = dedicated_store("dedicated");
        let config = synthetic_config();
        store.save(&config).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.camera_ip, config.camera_ip);
        assert_eq!(loaded.device_id, config.device_id);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&dedicated).unwrap().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(store.path()).unwrap().mode() & 0o777, 0o600);
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = temp_store("mode");
        store.save(&synthetic_config()).unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o640)).unwrap();
        let error = store.load().unwrap_err().to_string();
        assert!(error.contains("unsafe mode"), "{error}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlink_before_reading_secret_bytes() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (dir, store) = temp_store("symlink");
        let target = dir.join("target.json");
        fs::write(&target, serde_json::to_vec(&synthetic_config()).unwrap()).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, store.path()).unwrap();
        let error = store.load().unwrap_err().to_string();
        assert!(error.contains("without following symlinks"), "{error}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn save_and_load_reject_symlink_parent_without_touching_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (base, _, _) = dedicated_store("parent-symlink");
        let real_parent = base.join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = base.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let store = LanConfigStore::new(linked_parent.join("lan.json"));

        let save_error = store.save(&synthetic_config()).unwrap_err().to_string();
        assert!(save_error.contains("not a symlink"), "{save_error}");
        assert!(!real_parent.join("lan.json").exists());

        let load_error = store.load().unwrap_err().to_string();
        assert!(load_error.contains("not a symlink"), "{load_error}");
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn explicit_save_rejects_writable_parent_without_chmodding_it() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (dir, store) = temp_store("writable-parent");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();

        let error = store.save(&synthetic_config()).unwrap_err().to_string();
        assert!(error.contains("group/world-writable"), "{error}");
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o775);
        assert!(!store.path().exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicit_save_does_not_create_an_injected_parent() {
        let (dir, store) = temp_store("missing-parent");
        fs::remove_dir(&dir).unwrap();
        let error = store.save(&synthetic_config()).unwrap_err().to_string();
        assert!(error.contains("must already exist"), "{error}");
        assert!(!dir.exists());
    }

    #[test]
    fn debug_redacts_all_identity_and_secret_fields() {
        let config = synthetic_config();
        let debug = format!("{config:?}");
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("SYNTH_MEDIA_PASSWORD"));
        assert!(!debug.contains("SYNTH_DEVICE_ID"));
        assert!(!debug.contains("SYNTH_SENDER_ID"));
        assert!(debug.contains("[REDACTED]"));
    }
}
