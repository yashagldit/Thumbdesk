//! OS-keyring secret storage with file-based fallback.
//!
//! Long-lived host secrets (the ED25519 private key and the refresh token)
//! used to live in plaintext in `~/.thumbdesk/state.json`. Mode 0o600 made
//! that *acceptable* but not great: any backup/sync tool, disk image, or
//! user-mode process running as the same UID could lift them. This module
//! pushes those secrets into the platform-native keychain (macOS Keychain,
//! Windows Credential Manager, libsecret/kwallet on Linux) and falls back to
//! a 0o600-protected file only when the keyring is unavailable (typical on
//! headless Linux servers without secret-service).
//!
//! The module is intentionally narrow: callers see `get` / `put` / `clear`
//! and don't have to care which backend served the value.
//!
//! Migration: on first save after upgrade, plaintext fields in `state.json`
//! are moved into the keyring and replaced with empty strings. On read, an
//! empty field falls through to the keyring.
//!
//! The keyring service was `pocketshell-host-agent` before the rename. A
//! secret not found under the new name is read from the old one, copied to
//! the new one, and deleted from the old one only once the copy is in.

use crate::error::Result;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, warn};

const SERVICE: &str = "thumbdesk-host-agent";

/// The service name every agent before the rename stored its secrets under.
/// Read when the new name has nothing, so an existing host keeps its key.
const LEGACY_SERVICE: &str = "pocketshell-host-agent";

/// Whether to consult the OS keyring at all. The `linux-native` keyring
/// backend is the kernel keyutils session keyring, which is scoped per
/// process-tree — secrets written from a `sudo thumbdesk pair` invocation
/// are not visible to a separately-launched daemon, leading to silent loss
/// of the host signing key. Default off on Linux; the file fallback in this
/// module's state dir is the canonical store. Set
/// `THUMBDESK_USE_KEYRING=1` (or `POCKETSHELL_USE_KEYRING=1`) to opt back
/// in (e.g. when building against
/// `sync-secret-service` on a desktop with gnome-keyring/kwallet).
///
/// macOS and Windows ship persistent per-user keychains, so the keyring is
/// safe (and preferred) there.
///
/// Unit tests never use it: the service name is the real one, so a test that
/// saved or cleared a state store would replace or delete this machine's host
/// key.
fn use_keyring() -> bool {
    if cfg!(test) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        crate::env_var!("USE_KEYRING")
            .get_os()
            .map(|v| v != "0" && !v.is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Key under which the host's ED25519 private key is stored.
pub const KEY_HOST_PRIVATE: &str = "host-private-key";
/// Key under which the long-lived refresh token is stored.
pub const KEY_REFRESH_TOKEN: &str = "host-refresh-token";

/// Try the OS keyring first; fall back to a 0o600 file on failure.
#[derive(Debug)]
pub struct SecretStore {
    fallback_dir: PathBuf,
}

impl SecretStore {
    /// `fallback_dir` should be the daemon's state dir (already 0o700).
    pub fn new(fallback_dir: PathBuf) -> Self {
        Self { fallback_dir }
    }

    /// Read a secret. Returns `Ok(None)` if neither the keyring nor the
    /// fallback file holds a value (first-run case).
    pub fn get(&self, name: &str) -> Result<Option<String>> {
        if !use_keyring() {
            return self.get_file(name);
        }
        match keyring::Entry::new(SERVICE, name) {
            Ok(entry) => match entry.get_password() {
                Ok(v) => return Ok(Some(v)),
                Err(keyring::Error::NoEntry) => {
                    if let Some(v) = self.take_legacy(name, &entry) {
                        return Ok(Some(v));
                    }
                }
                Err(e) => {
                    debug!(
                        "keyring get({}/{}) unavailable: {} — falling back to file",
                        SERVICE, name, e
                    );
                }
            },
            Err(e) => {
                debug!(
                    "keyring entry construct failed for {}/{}: {} — using file fallback",
                    SERVICE, name, e
                );
            }
        }
        self.get_file(name)
    }

    /// The secret as an agent from before the rename stored it, under
    /// [`LEGACY_SERVICE`], moved to `entry` (the new service). The old item
    /// is deleted only after the new one is written: a failed write leaves
    /// it, to be moved on the next read, and the value is returned either way.
    fn take_legacy(&self, name: &str, entry: &keyring::Entry) -> Option<String> {
        let legacy = keyring::Entry::new(LEGACY_SERVICE, name).ok()?;
        let value = match legacy.get_password() {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => return None,
            Err(e) => {
                debug!("keyring get({LEGACY_SERVICE}/{name}) unavailable: {e}");
                return None;
            }
        };
        match entry.set_password(&value) {
            Ok(()) => match entry.get_password() {
                // Read back before the only other copy goes.
                Ok(copied) if copied == value => {
                    if let Err(e) = legacy.delete_credential() {
                        debug!("keyring delete({LEGACY_SERVICE}/{name}) error: {e}");
                    }
                    debug!("moved keyring secret {name} from {LEGACY_SERVICE} to {SERVICE}");
                }
                _ => warn!("keyring copy of {name} to {SERVICE} did not read back; keeping {LEGACY_SERVICE}"),
            },
            Err(e) => warn!("keyring set({SERVICE}/{name}) failed: {e}; keeping {LEGACY_SERVICE}"),
        }
        Some(value)
    }

    /// Write a secret. Prefers the OS keyring; falls back to a 0o600 file
    /// only if the keyring rejects the write (e.g., headless Linux).
    pub fn put(&self, name: &str, value: &str) -> Result<()> {
        if !use_keyring() {
            return self.put_file(name, value);
        }
        match keyring::Entry::new(SERVICE, name) {
            Ok(entry) => match entry.set_password(value) {
                Ok(()) => {
                    // Successfully stored in keyring — wipe any stale file
                    // copy so disk state never has the secret again.
                    let _ = fs::remove_file(self.fallback_path(name));
                    // Nor an older copy under the service name from before
                    // the rename (a new refresh token makes it stale).
                    if let Ok(legacy) = keyring::Entry::new(LEGACY_SERVICE, name) {
                        let _ = legacy.delete_credential();
                    }
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "keyring set({}/{}) failed: {} — falling back to 0o600 file",
                        SERVICE, name, e
                    );
                }
            },
            Err(e) => {
                warn!(
                    "keyring entry construct failed for {}/{}: {} — using 0o600 file",
                    SERVICE, name, e
                );
            }
        }
        self.put_file(name, value)
    }

    /// Remove a secret from both backends — used on logout and account
    /// deletion. Best-effort; ignores "not found" errors.
    pub fn clear(&self, name: &str) -> Result<()> {
        if use_keyring() {
            // The old service too: a logout must not leave a copy for a
            // later read to bring back.
            for service in [SERVICE, LEGACY_SERVICE] {
                if let Ok(entry) = keyring::Entry::new(service, name) {
                    match entry.delete_credential() {
                        Ok(()) | Err(keyring::Error::NoEntry) => {}
                        Err(e) => debug!("keyring delete({}/{}) error: {}", service, name, e),
                    }
                }
            }
        }
        let _ = fs::remove_file(self.fallback_path(name));
        Ok(())
    }

    fn fallback_path(&self, name: &str) -> PathBuf {
        // Filename is just the key — the parent dir is already 0o700.
        self.fallback_dir.join(format!("secret_{name}"))
    }

    fn get_file(&self, name: &str) -> Result<Option<String>> {
        let p = self.fallback_path(name);
        if !p.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&p)?;
        Ok(Some(raw))
    }

    fn put_file(&self, name: &str, value: &str) -> Result<()> {
        if !self.fallback_dir.exists() {
            fs::create_dir_all(&self.fallback_dir)?;
        }
        let p = self.fallback_path(name);
        // Atomic write + 0o600 chmod-before-rename prevents (a) empty file on
        // mid-truncate crash and (b) the secret being briefly observable at
        // default umask between `fs::write` and the chmod. Shared with the
        // state.json writer in `store.rs`.
        crate::store::atomic_write(&p, value.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Tests use a per-test fallback dir; OS keyring may or may not be
    /// available in CI, so all tests force the file path by using a
    /// throwaway service name unlikely to clash with the host's real
    /// keychain. The underlying `keyring` crate's mock backend is not
    /// public, so we just exercise the file fallback paths directly.
    #[test]
    fn put_and_get_via_file_fallback() {
        let dir = tempdir().unwrap();
        let store = SecretStore::new(dir.path().to_path_buf());
        // Force file fallback by writing through put_file directly.
        store.put_file("test-key", "secret-value").unwrap();
        let got = store.get_file("test-key").unwrap();
        assert_eq!(got.as_deref(), Some("secret-value"));
    }

    #[test]
    fn get_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        let store = SecretStore::new(dir.path().to_path_buf());
        // Use a name that's almost certainly not in the host keyring.
        let got = store.get("absent-test-secret-9b7c4a").unwrap();
        assert!(got.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn fallback_file_is_chmod_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let store = SecretStore::new(dir.path().to_path_buf());
        store.put_file("perm-test", "x").unwrap();
        let mode = fs::metadata(store.fallback_path("perm-test"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
