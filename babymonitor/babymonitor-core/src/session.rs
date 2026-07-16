//! Session token store for the Tuya mobile-app ("atop") flow.
//!
//! The mobile login flow has **no OAuth refresh-token rotation**: the session is
//! the `User.sid` issued by the login response, and on session-invalid the client
//! RE-LOGINS (`re/tuya_cloud_auth.md` §3). So this store persists the issued
//! session (`sid`, `uid`, optional `ecode`, region domain base, and an expiry) to
//! disk and answers one question the caller needs before every request: *does this
//! session need a refresh (re-login) before I use it?* — [`Session::needs_refresh`].
//!
//! Persistence target: `~/.local/share/babymonitor/session.json` (XDG data dir
//! via the `dirs` crate), mirroring the app's on-device MMKV `User` JSON
//! (`re/tuya_cloud_auth.md` §3). The `sid`/`uid`/`ecode` are **secrets** (CLAUDE.md):
//! this module writes them to the gitignored data dir, never a tracked file, and
//! redacts them from `Debug`.
//!
//! No live calls are made here — this is structure + persistence + the
//! refresh-decision policy only. The actual re-login that produces a fresh
//! [`Session`] lands with the login flow in a later task.

use std::ffi::{OsStr, OsString};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Error;

/// Refresh buffer: treat a session as needing refresh this long BEFORE its
/// actual expiry, so a request is never sent with a token about to die
/// mid-flight. Mirrors the skill's "refresh before expiry (2 min buffer)"
/// guidance.
pub const REFRESH_BUFFER: Duration = Duration::minutes(2);

/// A persisted Tuya session. Field names map to the login `User`
/// (`re/tuya_cloud_auth.md` §3): `sid` is the session token, `uid` the account
/// id, `mobile_api_base` the datacenter base URL (`User.domain.mobileApiUrl`).
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session token — the `sid` envelope param on every signed request. SECRET.
    pub sid: String,
    /// Account user id (`User.uid`). SECRET (account-linked PII).
    pub uid: String,
    /// User encryption code (`User.ecode`) used by native `getEncryptoKey` on
    /// session-required encrypted requests. SECRET when present.
    #[serde(default)]
    pub ecode: Option<String>,
    /// Datacenter mobile API base URL (`User.domain.mobileApiUrl`), runtime-
    /// resolved at login. Not a secret, but account/region-revealing.
    pub mobile_api_base: String,
    /// When this session was issued (UTC).
    pub issued_at: DateTime<Utc>,
    /// When this session expires (UTC). The mobile flow does not advertise an
    /// explicit TTL, so the caller sets a conservative value at login; the store
    /// only enforces the refresh-before-expiry policy against it.
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for Session {
    /// Redacts `sid`/`uid`/`ecode` so a session never leaks via `{:?}` into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("sid", &"<redacted>")
            .field("uid", &"<redacted>")
            .field(
                "ecode",
                &self
                    .ecode
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("<none>"),
            )
            .field("mobile_api_base", &self.mobile_api_base)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Session {
    /// Whether the session needs a refresh (re-login) *as of `now`*, applying
    /// [`REFRESH_BUFFER`]. Returns `true` once `now + buffer >= expires_at` —
    /// i.e. while there is still buffer headroom it returns `false`.
    #[must_use]
    pub fn needs_refresh_at(&self, now: DateTime<Utc>) -> bool {
        now + REFRESH_BUFFER >= self.expires_at
    }

    /// Convenience: [`Session::needs_refresh_at`] using the current UTC time.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_at(Utc::now())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DirectoryPolicy {
    /// The application's default private directory. It may be created, but an
    /// existing directory is validated rather than silently chmodded.
    Dedicated,
    /// A caller-selected location. Its parent must already exist and is never
    /// created or chmodded by this module.
    Explicit,
}

/// On-disk session store. Holds only the file path; the [`Session`] is read/
/// written on demand (single source of truth = the file, no cached duplicate
/// state). Construct with [`SessionStore::default_path`] or [`SessionStore::at`].
#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    directory_policy: DirectoryPolicy,
}

impl SessionStore {
    /// Store at the default XDG data location
    /// `~/.local/share/babymonitor/session.json`.
    ///
    /// # Errors
    /// [`Error::SessionStore`] if no data dir can be resolved (e.g. `$HOME`
    /// unset).
    pub fn default_path() -> Result<Self, Error> {
        let base = dirs::data_dir().ok_or_else(|| {
            Error::SessionStore("cannot resolve XDG data dir (is $HOME set?)".into())
        })?;
        Ok(Self {
            path: base.join("babymonitor").join("session.json"),
            directory_policy: DirectoryPolicy::Dedicated,
        })
    }

    /// Store at an explicit path. Used by tests (a temp dir) and by callers that
    /// want a non-default location. Its parent must already be a real directory
    /// and, on Unix, must not be group/world-writable. The parent is never
    /// created or chmodded by this module.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            directory_policy: DirectoryPolicy::Explicit,
        }
    }

    /// The backing file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the persisted session, or `Ok(None)` if none has been saved yet.
    ///
    /// # Errors
    /// [`Error::SessionStore`] if the file exists but is a symlink, is not a
    /// regular file, is not exactly mode 0600 on Unix, or cannot be read or
    /// parsed. A corrupt or unsafe store fails loud; it is never silently
    /// treated as "no session".
    pub fn load(&self) -> Result<Option<Session>, Error> {
        let Some(parent) = self.validate_directory_for_load()? else {
            return Ok(None);
        };
        let file_name = self.file_name()?;

        let mut file = match parent.open_read(file_name) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::SessionStore(format!(
                    "open session store {} without following symlinks: {error}",
                    self.path.display()
                )));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            Error::SessionStore(format!(
                "inspect opened session store {}: {error}",
                self.path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(Error::SessionStore(format!(
                "session store {} must be a regular file",
                self.path.display()
            )));
        }
        reject_unsafe_file_mode(&self.path, &metadata)?;

        // The serialized sid/uid/ecode are secrets. Zeroize their raw JSON as
        // soon as parsing is complete (including every error path).
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes).map_err(|error| {
            Error::SessionStore(format!(
                "read session store {}: {error}",
                self.path.display()
            ))
        })?;
        let session = serde_json::from_slice(bytes.as_slice()).map_err(|error| {
            Error::SessionStore(format!(
                "corrupt session store {}: {error}",
                self.path.display()
            ))
        })?;

        Ok(Some(session))
    }

    /// Atomically persist a session with mode 0600.
    ///
    /// The default store creates only its dedicated application directory at
    /// mode 0700. An explicit store requires an existing safe parent. The
    /// temporary file and containing directory are synced before success is
    /// returned, so a successful save is durable across a crash.
    ///
    /// # Errors
    /// [`Error::SessionStore`] on an unsafe target or any create, write, sync,
    /// or atomic-install failure.
    pub fn save(&self, session: &Session) -> Result<(), Error> {
        let parent_path = self.parent()?;
        let parent = prepare_directory(parent_path, self.directory_policy)?;
        let file_name = self.file_name()?;
        parent.reject_non_regular_destination(file_name, &self.path)?;

        let mut encoded = Zeroizing::new(Vec::new());
        serde_json::to_writer_pretty(&mut *encoded, session)
            .map_err(|error| Error::SessionStore(format!("serialize session: {error}")))?;
        encoded.push(b'\n');

        let (temp_name, mut temp_file) = parent.create_private_temp_file(file_name)?;
        let result = (|| -> Result<(), Error> {
            temp_file.write_all(encoded.as_slice()).map_err(|error| {
                Error::SessionStore(format!("write temporary session store: {error}"))
            })?;
            temp_file.sync_all().map_err(|error| {
                Error::SessionStore(format!("sync temporary session store: {error}"))
            })?;
            drop(temp_file);

            // Re-check immediately before installation. The validated parent is
            // not writable by group/other, so an unprivileged peer cannot swap
            // the destination between this check and rename.
            parent.reject_non_regular_destination(file_name, &self.path)?;
            parent
                .rename_replace(&temp_name, file_name)
                .map_err(|error| {
                    Error::SessionStore(format!("install session store atomically: {error}"))
                })?;
            parent.sync().map_err(|error| {
                Error::SessionStore(format!(
                    "sync session store parent {}: {error}",
                    parent_path.display()
                ))
            })
        })();
        if result.is_err() {
            let _ = parent.unlink_file(&temp_name);
        }
        result
    }

    /// Delete the persisted session (logout). Idempotent: missing file is `Ok`.
    ///
    /// # Errors
    /// [`Error::SessionStore`] on a delete failure other than "not found".
    pub fn clear(&self) -> Result<(), Error> {
        let parent_path = self.parent()?.to_path_buf();
        let Some(parent) = self.validate_directory_for_load()? else {
            return Ok(());
        };
        let file_name = self.file_name()?;
        match parent.inspect_regular_destination(file_name, &self.path)? {
            Destination::Absent => Ok(()),
            Destination::Regular => {
                parent.unlink_file(file_name).map_err(|error| {
                    Error::SessionStore(format!("remove {}: {error}", self.path.display()))
                })?;
                parent.sync().map_err(|error| {
                    Error::SessionStore(format!(
                        "sync session store parent {} after clear: {error}",
                        parent_path.display()
                    ))
                })
            }
        }
    }

    fn parent(&self) -> Result<&Path, Error> {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                Error::SessionStore("session store path has no parent directory".to_string())
            })
    }

    fn file_name(&self) -> Result<&OsStr, Error> {
        self.path
            .file_name()
            .ok_or_else(|| Error::SessionStore("session store path has no filename".to_string()))
    }

    /// Validate the store parent for a read/delete. A missing dedicated default
    /// directory means the store genuinely does not exist yet; an explicit
    /// parent must always exist.
    fn validate_directory_for_load(&self) -> Result<Option<PinnedStoreDirectory>, Error> {
        let parent = self.parent()?;
        PinnedStoreDirectory::open_optional(
            parent,
            self.directory_policy,
            self.directory_policy == DirectoryPolicy::Dedicated,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Destination {
    Absent,
    Regular,
}

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A validated, opened session-store parent. Every file operation is relative
/// to this held descriptor, so an ancestor rename after validation cannot
/// redirect secrets to another directory.
struct PinnedStoreDirectory {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl PinnedStoreDirectory {
    fn open_optional(
        path: &Path,
        policy: DirectoryPolicy,
        missing_is_none: bool,
    ) -> Result<Option<Self>, Error> {
        match open_directory_file(path) {
            Ok(file) => Self::from_open_file(path, policy, file).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && missing_is_none => {
                Ok(None)
            }
            Err(error) => Err(directory_inspection_error(path, policy, error)),
        }
    }

    fn open(path: &Path, policy: DirectoryPolicy) -> Result<Self, Error> {
        Self::open_optional(path, policy, false)?.ok_or_else(|| {
            Error::SessionStore(format!(
                "session store parent {} is missing",
                path.display()
            ))
        })
    }

    fn from_open_file(path: &Path, policy: DirectoryPolicy, file: File) -> Result<Self, Error> {
        let metadata = file.metadata().map_err(|error| {
            Error::SessionStore(format!(
                "inspect opened session store parent {}: {error}",
                path.display()
            ))
        })?;
        validate_directory_metadata(path, &metadata, policy)?;
        Ok(Self {
            #[cfg(unix)]
            file,
            #[cfg(not(unix))]
            path: path.to_path_buf(),
        })
    }

    fn open_read(&self, name: &OsStr) -> std::io::Result<File> {
        #[cfg(unix)]
        {
            let fd = rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map_err(errno_to_io)?;
            Ok(File::from(fd))
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(name);
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "session store path is a symlink",
                ));
            }
            File::open(path)
        }
    }

    fn inspect_regular_destination(
        &self,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<Destination, Error> {
        #[cfg(unix)]
        let result = rustix::fs::statat(&self.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(errno_to_io)
            .map(|stat| rustix::fs::FileType::from_raw_mode(stat.st_mode));
        #[cfg(not(unix))]
        let result = fs::symlink_metadata(self.path.join(name)).map(|metadata| {
            if metadata.file_type().is_symlink() {
                None
            } else if metadata.is_file() {
                Some(())
            } else {
                None
            }
        });

        #[cfg(unix)]
        match result {
            Ok(rustix::fs::FileType::RegularFile) => Ok(Destination::Regular),
            Ok(_) => Err(non_regular_destination_error(display_path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Destination::Absent),
            Err(error) => Err(Error::SessionStore(format!(
                "inspect session store destination {}: {error}",
                display_path.display()
            ))),
        }
        #[cfg(not(unix))]
        match result {
            Ok(Some(())) => Ok(Destination::Regular),
            Ok(None) => Err(non_regular_destination_error(display_path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Destination::Absent),
            Err(error) => Err(Error::SessionStore(format!(
                "inspect session store destination {}: {error}",
                display_path.display()
            ))),
        }
    }

    fn reject_non_regular_destination(
        &self,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<(), Error> {
        self.inspect_regular_destination(name, display_path)
            .map(|_| ())
    }

    fn create_private_temp_file(&self, destination: &OsStr) -> Result<(OsString, File), Error> {
        let destination = destination.to_string_lossy();
        for _ in 0..128 {
            let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(
                ".{destination}.{}.{}.tmp",
                std::process::id(),
                counter
            ));
            match self.create_new_private_file(&name) {
                Ok(file) => {
                    if let Err(error) = enforce_private_file_mode(&file) {
                        drop(file);
                        let _ = self.unlink_file(&name);
                        return Err(error);
                    }
                    return Ok((name, file));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Error::SessionStore(format!(
                        "create temporary session store: {error}"
                    )))
                }
            }
        }
        Err(Error::SessionStore(
            "could not allocate a unique temporary session store".into(),
        ))
    }

    fn create_new_private_file(&self, name: &OsStr) -> std::io::Result<File> {
        #[cfg(unix)]
        {
            let fd = rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(errno_to_io)?;
            Ok(File::from(fd))
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
        }
    }

    fn rename_replace(&self, source: &OsStr, destination: &OsStr) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            rustix::fs::renameat(&self.file, source, &self.file, destination).map_err(errno_to_io)
        }
        #[cfg(not(unix))]
        {
            fs::rename(self.path.join(source), self.path.join(destination))
        }
    }

    fn unlink_file(&self, name: &OsStr) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::empty())
                .map_err(errno_to_io)
        }
        #[cfg(not(unix))]
        {
            fs::remove_file(self.path.join(name))
        }
    }

    fn sync(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            rustix::fs::fsync(&self.file).map_err(errno_to_io)
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

fn prepare_directory(path: &Path, policy: DirectoryPolicy) -> Result<PinnedStoreDirectory, Error> {
    if policy == DirectoryPolicy::Dedicated {
        if let Some(directory) = PinnedStoreDirectory::open_optional(path, policy, true)? {
            Ok(directory)
        } else {
            create_dedicated_directory(path)
        }
    } else {
        PinnedStoreDirectory::open(path, policy)
    }
}

#[cfg(unix)]
fn create_dedicated_directory(path: &Path) -> Result<PinnedStoreDirectory, Error> {
    let container_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            Error::SessionStore(format!(
                "dedicated session directory {} has no parent",
                path.display()
            ))
        })?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::SessionStore("dedicated session directory has no filename".into()))?;
    let container = PinnedStoreDirectory::open(container_path, DirectoryPolicy::Explicit)?;
    let created = match rustix::fs::mkdirat(&container.file, name, rustix::fs::Mode::RWXU) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => {
            return Err(Error::SessionStore(format!(
                "create dedicated session directory {}: {}",
                path.display(),
                errno_to_io(error)
            )))
        }
    };
    if created {
        container.sync().map_err(|error| {
            Error::SessionStore(format!(
                "sync parent {} after creating dedicated session directory: {error}",
                container_path.display()
            ))
        })?;
    }
    let fd = rustix::fs::openat(
        &container.file,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(errno_to_io)
    .map_err(|error| directory_inspection_error(path, DirectoryPolicy::Dedicated, error))?;
    let file = File::from(fd);
    if created {
        rustix::fs::fchmod(&file, rustix::fs::Mode::RWXU)
            .map_err(errno_to_io)
            .map_err(|error| {
                Error::SessionStore(format!(
                    "set dedicated session directory {} mode to 0700: {error}",
                    path.display()
                ))
            })?;
    }
    PinnedStoreDirectory::from_open_file(path, DirectoryPolicy::Dedicated, file)
}

#[cfg(not(unix))]
fn create_dedicated_directory(path: &Path) -> Result<PinnedStoreDirectory, Error> {
    match create_private_directory(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::SessionStore(format!(
                "create dedicated session directory {}: {error}",
                path.display()
            )))
        }
    }
    PinnedStoreDirectory::open(path, DirectoryPolicy::Dedicated)
}

fn non_regular_destination_error(path: &Path) -> Error {
    Error::SessionStore(format!(
        "session store destination {} must be absent or a regular non-symlink file",
        path.display()
    ))
}

fn directory_inspection_error(
    path: &Path,
    policy: DirectoryPolicy,
    error: std::io::Error,
) -> Error {
    let context = match policy {
        DirectoryPolicy::Dedicated => "inspect dedicated session directory",
        DirectoryPolicy::Explicit => "explicit session parent must already exist",
    };
    Error::SessionStore(format!("{context} {}: {error}", path.display()))
}

fn validate_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    policy: DirectoryPolicy,
) -> Result<(), Error> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::SessionStore(format!(
            "session store parent {} must be a real directory, not a symlink",
            path.display()
        )));
    }
    reject_unsafe_directory_mode(path, metadata, policy)
}

#[cfg(unix)]
fn open_directory_file(path: &Path) -> std::io::Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(errno_to_io)?;
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_directory_file(path: &Path) -> std::io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session store parent must be a real directory",
        ));
    }
    File::open(path)
}

#[cfg(unix)]
fn errno_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(unix)]
fn enforce_private_file_mode(file: &File) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            Error::SessionStore(format!("set temporary session store mode to 0600: {error}"))
        })?;
    let metadata = file.metadata().map_err(|error| {
        Error::SessionStore(format!("inspect temporary session store: {error}"))
    })?;
    reject_unsafe_file_mode(Path::new("<temporary session store>"), &metadata)
}

#[cfg(not(unix))]
fn enforce_private_file_mode(_file: &File) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_unsafe_file_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o7777;
    if mode != 0o600 {
        return Err(Error::SessionStore(format!(
            "session store {} has unsafe mode {mode:04o}; require exactly 0600",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_unsafe_file_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_unsafe_directory_mode(
    path: &Path,
    metadata: &fs::Metadata,
    _policy: DirectoryPolicy,
) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o7777;
    let unsafe_mode = mode & 0o022 != 0;
    if unsafe_mode {
        return Err(Error::SessionStore(format!(
            "session store parent {} has unsafe mode {mode:04o}; must not be group/world-writable",
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

#[cfg(all(unix, test))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_session(issued: DateTime<Utc>, ttl_minutes: i64) -> Session {
        Session {
            // SYNTHETIC values only — never a real sid/uid.
            sid: "SYNTH_SID_0000".into(),
            uid: "SYNTH_UID_0000".into(),
            ecode: Some("SYNTH_ECODE_0000".into()),
            mobile_api_base: "https://example.invalid/api".into(),
            issued_at: issued,
            expires_at: issued + Duration::minutes(ttl_minutes),
        }
    }

    fn temp_store() -> (SessionStore, tempdir::TempDirGuard) {
        let guard = tempdir::TempDirGuard::new();
        let parent = guard.path().join("babymonitor");
        create_private_directory(&parent).unwrap();
        let store = SessionStore::at(parent.join("session.json"));
        (store, guard)
    }

    fn dedicated_store() -> (SessionStore, tempdir::TempDirGuard) {
        let guard = tempdir::TempDirGuard::new();
        let store = SessionStore {
            path: guard
                .path()
                .join("dedicated-session-store")
                .join("session.json"),
            directory_policy: DirectoryPolicy::Dedicated,
        };
        (store, guard)
    }

    #[test]
    fn round_trips_through_disk() {
        let (store, _g) = temp_store();
        assert!(store.load().unwrap().is_none(), "empty store -> None");

        let issued = Utc::now();
        let s = synth_session(issued, 60);
        store.save(&s).unwrap();

        let loaded = store.load().unwrap().expect("session present after save");
        assert_eq!(loaded.sid, s.sid);
        assert_eq!(loaded.uid, s.uid);
        assert_eq!(loaded.ecode, s.ecode);
        assert_eq!(loaded.mobile_api_base, s.mobile_api_base);
        assert_eq!(loaded.expires_at, s.expires_at);
    }

    #[test]
    fn clear_is_idempotent() {
        let (store, _g) = temp_store();
        store.clear().unwrap(); // no file yet -> Ok
        store.save(&synth_session(Utc::now(), 60)).unwrap();
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        store.clear().unwrap(); // again -> Ok
    }

    // Refresh-before-expiry policy: the core AC#2 unit test.
    #[test]
    fn needs_refresh_respects_buffer() {
        let issued = Utc::now();
        // Fresh 60-min session: at issue time, plenty of headroom -> no refresh.
        let s = synth_session(issued, 60);
        assert!(!s.needs_refresh_at(issued));

        // 1 minute before expiry: inside the 2-min buffer -> needs refresh.
        let near = s.expires_at - Duration::minutes(1);
        assert!(s.needs_refresh_at(near));

        // Exactly at the buffer edge (expires_at - 2min): boundary -> refresh.
        let edge = s.expires_at - REFRESH_BUFFER;
        assert!(s.needs_refresh_at(edge));

        // 3 minutes before expiry: just outside the buffer -> no refresh.
        let safe = s.expires_at - Duration::minutes(3);
        assert!(!s.needs_refresh_at(safe));
    }

    // NEGATIVE: an already-expired session must report needing refresh (prove
    // the policy bites; a green check that can't go red is not grounding).
    #[test]
    fn expired_session_needs_refresh() {
        let issued = Utc::now() - Duration::hours(2);
        let s = synth_session(issued, 60); // expired ~1h ago
        assert!(s.needs_refresh());
    }

    // NEGATIVE: a corrupt store must error, not be silently treated as "no
    // session" (which would mask data loss).
    #[test]
    fn corrupt_store_errors_loud() {
        let (store, _g) = temp_store();
        std::fs::write(store.path(), b"{ this is not valid json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(store.load(), Err(Error::SessionStore(_))));
    }

    #[test]
    fn explicit_parent_must_already_exist() {
        let guard = tempdir::TempDirGuard::new();
        let store = SessionStore::at(guard.path().join("missing").join("session.json"));
        let load_error = store.load().unwrap_err().to_string();
        assert!(load_error.contains("must already exist"));
        let save_error = store
            .save(&synth_session(Utc::now(), 60))
            .unwrap_err()
            .to_string();
        assert!(save_error.contains("must already exist"));
        assert!(!store.path().parent().unwrap().exists());
    }

    #[test]
    fn missing_dedicated_directory_is_an_empty_store() {
        let (store, _guard) = dedicated_store();
        assert!(store.load().unwrap().is_none());
        store.clear().unwrap();
        assert!(!store.path().parent().unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn dedicated_directory_and_file_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _guard) = dedicated_store();
        store.save(&synth_session(Utc::now(), 60)).unwrap();

        let parent_mode = std::fs::symlink_metadata(store.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        let file_mode = std::fs::symlink_metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn accepts_non_writable_legacy_dedicated_directory_and_rejects_writable_one() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _guard) = dedicated_store();
        let parent = store.path().parent().unwrap();
        std::fs::create_dir(parent).unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        store.save(&synth_session(Utc::now(), 60)).unwrap();
        std::fs::remove_file(store.path()).unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o775)).unwrap();
        let error = store.save(&synth_session(Utc::now(), 60)).unwrap_err();
        assert!(error.to_string().contains("group/world-writable"));
        assert!(!store.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_every_file_mode_other_than_exactly_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _guard) = temp_store();
        store.save(&synth_session(Utc::now(), 60)).unwrap();

        for mode in [0o400, 0o640, 0o600 | 0o4000] {
            std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let error = store.load().unwrap_err().to_string();
            assert!(
                error.contains("require exactly 0600"),
                "mode {mode:04o} unexpectedly accepted: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_store_without_touching_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (store, _guard) = temp_store();
        let victim = store.path().parent().unwrap().join("victim.json");
        let original = b"SYNTHETIC VICTIM CONTENT";
        std::fs::write(&victim, original).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&victim, store.path()).unwrap();

        assert!(store.load().is_err(), "load must not follow a symlink");
        assert!(
            store.save(&synth_session(Utc::now(), 60)).is_err(),
            "save must reject a symlink destination"
        );
        assert!(store.clear().is_err(), "clear must reject a symlink");
        assert_eq!(std::fs::read(&victim).unwrap(), original);
        assert!(std::fs::symlink_metadata(store.path())
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_writable_explicit_parents() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let guard = tempdir::TempDirGuard::new();
        let real_parent = guard.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = guard.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let linked_store = SessionStore::at(linked_parent.join("session.json"));
        assert!(linked_store.load().is_err());
        assert!(linked_store.save(&synth_session(Utc::now(), 60)).is_err());

        let writable_parent = guard.path().join("writable-parent");
        std::fs::create_dir(&writable_parent).unwrap();
        std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let writable_store = SessionStore::at(writable_parent.join("session.json"));
        let error = writable_store
            .save(&synth_session(Utc::now(), 60))
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be group/world-writable"));
    }

    #[cfg(unix)]
    #[test]
    fn pinned_parent_cannot_be_redirected_by_ancestor_swap() {
        use std::io::Write as _;

        let guard = tempdir::TempDirGuard::new();
        let visible = guard.path().join("visible-parent");
        create_private_directory(&visible).unwrap();
        let pinned = PinnedStoreDirectory::open(&visible, DirectoryPolicy::Explicit).unwrap();

        let moved = guard.path().join("moved-parent");
        std::fs::rename(&visible, &moved).unwrap();
        create_private_directory(&visible).unwrap();

        let mut file = pinned
            .create_new_private_file(OsStr::new("session.json"))
            .unwrap();
        file.write_all(b"SYNTHETIC").unwrap();
        file.sync_all().unwrap();
        pinned.sync().unwrap();

        assert_eq!(
            std::fs::read(moved.join("session.json")).unwrap(),
            b"SYNTHETIC"
        );
        assert!(!visible.join("session.json").exists());
    }

    #[test]
    fn rejects_non_regular_destination() {
        let (store, _guard) = temp_store();
        std::fs::create_dir(store.path()).unwrap();
        assert!(store.load().is_err());
        assert!(store.save(&synth_session(Utc::now(), 60)).is_err());
        assert!(store.clear().is_err());
        assert!(store.path().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn save_atomically_replaces_the_previous_inode() {
        use std::os::unix::fs::MetadataExt;

        let (store, _guard) = temp_store();
        let mut old = synth_session(Utc::now(), 60);
        old.sid = "SYNTH_OLD_SID".into();
        store.save(&old).unwrap();
        let old_inode = std::fs::metadata(store.path()).unwrap().ino();
        let mut old_handle = std::fs::File::open(store.path()).unwrap();

        let mut new = synth_session(Utc::now(), 30);
        new.sid = "SYNTH_NEW_SID".into();
        store.save(&new).unwrap();
        let new_inode = std::fs::metadata(store.path()).unwrap().ino();
        assert_ne!(
            old_inode, new_inode,
            "save must replace, not truncate in place"
        );

        let mut old_bytes = Zeroizing::new(Vec::new());
        old_handle.read_to_end(&mut old_bytes).unwrap();
        let old_from_open_handle: Session = serde_json::from_slice(old_bytes.as_slice()).unwrap();
        assert_eq!(old_from_open_handle.sid, "SYNTH_OLD_SID");
        assert_eq!(store.load().unwrap().unwrap().sid, "SYNTH_NEW_SID");

        let temp_files = std::fs::read_dir(store.path().parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temp_files, 0, "successful save left a temporary file");
    }

    // The persisted session holds SECRET sid/uid/ecode → its file MUST be 0600
    // (owner-only), never group/world-readable at the default umask.
    #[cfg(unix)]
    #[test]
    fn saved_session_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let (store, _g) = temp_store();
        store.save(&synth_session(Utc::now(), 60)).unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "session file must be 0600; got {mode:o}"
        );

        // Re-saving over an existing (possibly wider-perm) file must keep it 0600.
        store.save(&synth_session(Utc::now(), 30)).unwrap();
        let mode2 = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode2 & 0o777,
            0o600,
            "re-save must stay 0600; got {mode2:o}"
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let s = synth_session(Utc::now(), 60);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("SYNTH_SID_0000"));
        assert!(!dbg.contains("SYNTH_UID_0000"));
    }

    // Minimal temp-dir helper (no external dev-dep): a unique dir under the
    // system temp, removed on drop. Kept in #[cfg(test)] so it never ships.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempDirGuard {
            path: PathBuf,
        }

        impl TempDirGuard {
            pub fn new() -> Self {
                let mut base = std::env::temp_dir();
                let unique = format!(
                    "bmp-session-test-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                base.push(unique);
                std::fs::create_dir_all(&base).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                Self { path: base }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}
