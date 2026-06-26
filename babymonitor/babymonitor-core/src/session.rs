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

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

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

/// On-disk session store. Holds only the file path; the [`Session`] is read/
/// written on demand (single source of truth = the file, no cached duplicate
/// state). Construct with [`SessionStore::default_path`] or [`SessionStore::at`].
#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
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
        })
    }

    /// Store at an explicit path. Used by tests (a temp dir) and by callers that
    /// want a non-default location.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The backing file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the persisted session, or `Ok(None)` if none has been saved yet.
    ///
    /// # Errors
    /// [`Error::SessionStore`] if the file exists but cannot be read or parsed
    /// (corrupt store fails loud — we do NOT silently treat a corrupt file as
    /// "no session", which would mask data loss).
    pub fn load(&self) -> Result<Option<Session>, Error> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let s = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::SessionStore(format!(
                        "corrupt session store {}: {e}",
                        self.path.display()
                    ))
                })?;
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::SessionStore(format!(
                "read {}: {e}",
                self.path.display()
            ))),
        }
    }

    /// Persist a session, creating the parent directory if needed.
    ///
    /// # Errors
    /// [`Error::SessionStore`] on any directory-create or write failure.
    pub fn save(&self, session: &Session) -> Result<(), Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::SessionStore(format!("create {}: {e}", parent.display())))?;
        }
        let json = serde_json::to_vec_pretty(session)
            .map_err(|e| Error::SessionStore(format!("serialize session: {e}")))?;
        // sid/uid/ecode are SECRETS — persist the file with owner-only (0600)
        // permissions on Unix so they are never group/world-readable at the default
        // umask. A plain `std::fs::write` would leave it at e.g. 0644.
        write_private(&self.path, &json)
            .map_err(|e| Error::SessionStore(format!("write {}: {e}", self.path.display())))
    }

    /// Delete the persisted session (logout). Idempotent: missing file is `Ok`.
    ///
    /// # Errors
    /// [`Error::SessionStore`] on a delete failure other than "not found".
    pub fn clear(&self) -> Result<(), Error> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::SessionStore(format!(
                "remove {}: {e}",
                self.path.display()
            ))),
        }
    }
}

/// Write `bytes` to `path` (truncating) with owner-only (`0600`) permissions on
/// Unix so the secret `sid`/`uid`/`ecode` are never group/world-readable.
///
/// On Unix the file is created with mode `0600` via `OpenOptions` (the mode is
/// applied atomically at create time, so a fresh file is never briefly readable at
/// the process umask) and the mode is re-asserted afterwards so an EXISTING file —
/// created before this hardening or by another tool — is also tightened (the
/// `OpenOptions` mode only takes effect when the file is newly created). On
/// non-Unix targets it falls back to a plain truncating write.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        Ok(())
    }
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
        let store = SessionStore::at(guard.path().join("babymonitor").join("session.json"));
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
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        std::fs::write(store.path(), b"{ this is not valid json").unwrap();
        assert!(matches!(store.load(), Err(Error::SessionStore(_))));
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
