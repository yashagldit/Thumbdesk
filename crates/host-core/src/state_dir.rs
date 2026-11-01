//! Where the agent keeps its state: `~/.thumbdesk`, which was `~/.pocketshell`
//! before the rename.
//!
//! An install from before the rename is moved on the first run of a binary
//! from after it ([`migrate`], called first thing in `main`): the directory is
//! renamed, and the old name is left as a link to the new one, so anything
//! still holding the old path keeps working. That is a daemon from the old
//! binary still running, the hook commands written into Claude's, Codex's and
//! Grok's configs (`.pocketshell/hook-events.jsonl`, until the daemon's hook
//! repair rewrites them), an older `pocketshell` binary elsewhere on the
//! PATH, a downgrade, or a script of the user's.
//!
//! The move is a single `rename`, so a crash leaves either the old directory
//! or the new one, never half of each, and nothing in it is ever deleted. Two
//! processes starting at once (the CLI and the service's daemon) race safely:
//! one rename wins, the other finds the new directory and only checks the
//! link. While a daemon from before the rename holds its lock in the old
//! directory the move waits for a later run, and until it happens
//! [`state_dir_in`] keeps naming the old directory, so the state is never
//! split between the two.

use crate::error::{HostError, Result};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The state directory's name under the user's home.
pub const STATE_DIR_NAME: &str = ".thumbdesk";

/// Its name before the rename. Kept as a link to [`STATE_DIR_NAME`] after the
/// move: released agents, the hook commands they wrote and users' scripts name
/// it.
pub const LEGACY_STATE_DIR_NAME: &str = ".pocketshell";

/// Left in the directory by the move. Says that the old name is owed a link,
/// should the process that moved it end before making one; a fresh install,
/// which never had the old directory, gets no link.
const MOVED_MARKER: &str = ".moved-from-pocketshell";

/// The state directory under `home`: `.thumbdesk`, or `.pocketshell` while an
/// install from before the rename has not been moved yet.
pub fn state_dir_in(home: &Path) -> PathBuf {
    let current = home.join(STATE_DIR_NAME);
    if current.symlink_metadata().is_ok() {
        return current;
    }
    let legacy = home.join(LEGACY_STATE_DIR_NAME);
    // `is_dir` follows a link: a link to a `.thumbdesk` since deleted names
    // nothing, and a fresh state directory goes under the new name.
    if legacy.is_dir() {
        return legacy;
    }
    current
}

/// What [`migrate`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// No state from before the rename, or it was moved on an earlier run.
    NothingToDo,
    /// `~/.pocketshell` was renamed to `~/.thumbdesk` and is now a link to it.
    Moved,
    /// The move was left for a later run, for the reason given.
    Deferred(String),
    /// The move, or the link after it, failed. The state is still whole, in
    /// whichever directory [`state_dir_in`] names.
    Failed(String),
}

static OUTCOME: OnceLock<Migration> = OnceLock::new();

/// Move the state directory of an install from before the rename, under the
/// user's home. Once per process; quiet, as it runs before logging is set up
/// ([`log_migration`] reports it afterwards).
pub fn migrate_home() {
    OUTCOME.get_or_init(|| match crate::config::resolved_home_dir() {
        Some(home) => migrate(&home),
        None => Migration::NothingToDo,
    });
}

/// Log what [`migrate_home`] did, once logging is up.
pub fn log_migration() {
    match OUTCOME.get() {
        Some(Migration::Moved) => tracing::info!(
            "moved ~/{LEGACY_STATE_DIR_NAME} to ~/{STATE_DIR_NAME}; the old path is a link to it"
        ),
        Some(Migration::Deferred(why)) => {
            tracing::info!("~/{LEGACY_STATE_DIR_NAME} stays where it is for now: {why}")
        }
        Some(Migration::Failed(why)) => {
            tracing::warn!("could not move ~/{LEGACY_STATE_DIR_NAME} to ~/{STATE_DIR_NAME}: {why}")
        }
        Some(Migration::NothingToDo) | None => {}
    }
}

/// Move `home/.pocketshell` to `home/.thumbdesk` and link the old name to the
/// new one. Idempotent: run again, it only repairs a link that is owed.
pub fn migrate(home: &Path) -> Migration {
    let current = home.join(STATE_DIR_NAME);
    let legacy = home.join(LEGACY_STATE_DIR_NAME);

    let legacy_is_dir = legacy
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_dir());
    // An empty `.thumbdesk` (made by hand, or by a tool that only probed for
    // it) is no reason to leave a real install where it is. `remove_dir`
    // removes nothing that is not empty.
    if legacy_is_dir
        && current
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_dir())
    {
        let _ = fs::remove_dir(&current);
    }

    match current.symlink_metadata() {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if !legacy_is_dir {
                return Migration::NothingToDo;
            }
            if legacy_daemon_running(&legacy) {
                return Migration::Deferred(
                    "a daemon from before the rename is running from it".to_string(),
                );
            }
            // Before the rename, so that it moves with the directory.
            let _ = fs::write(legacy.join(MOVED_MARKER), b"");
            if let Err(err) = fs::rename(&legacy, &current) {
                // Another process starting at the same time may have won.
                if current.symlink_metadata().is_err() {
                    let _ = fs::remove_file(legacy.join(MOVED_MARKER));
                    return Migration::Failed(format!(
                        "rename {} to {}: {err}",
                        legacy.display(),
                        current.display()
                    ));
                }
            }
        }
        Err(err) => return Migration::Failed(format!("{}: {err}", current.display())),
    }

    match link_legacy(home) {
        Ok(true) => Migration::Moved,
        Ok(false) => Migration::NothingToDo,
        Err(err) => Migration::Failed(err.to_string()),
    }
}

/// Make `home/.pocketshell` a link to `home/.thumbdesk` where it is owed one:
/// the move marker is there, or a stray `.pocketshell` came back (a process
/// still holding the old path created it in the instant between the rename
/// and the link). True when a link was made.
fn link_legacy(home: &Path) -> Result<bool> {
    let current = home.join(STATE_DIR_NAME);
    let legacy = home.join(LEGACY_STATE_DIR_NAME);
    match legacy.symlink_metadata() {
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if !current.join(MOVED_MARKER).exists() {
                return Ok(false);
            }
        }
        Err(err) => return Err(HostError::Config(format!("{}: {err}", legacy.display()))),
        Ok(meta) if meta.file_type().is_dir() => {
            if legacy_daemon_running(&legacy) {
                return Ok(false);
            }
            absorb_stray(&legacy, &current, home)?;
        }
        // A link already (made by a process that raced this one, or by the
        // user, wherever it leads), or a file of the user's: left as it is.
        Ok(_) => {
            let _ = fs::remove_file(current.join(MOVED_MARKER));
            return Ok(false);
        }
    }
    match make_dir_link(&current, &legacy) {
        Ok(()) => {
            // Owed no longer: a link the user deletes later stays deleted.
            let _ = fs::remove_file(current.join(MOVED_MARKER));
            Ok(true)
        }
        // Another process made it first.
        Err(_)
            if legacy
                .symlink_metadata()
                .is_ok_and(|meta| !meta.file_type().is_dir()) =>
        {
            Ok(false)
        }
        Err(err) => Err(HostError::Config(format!(
            "link {} to {}: {err}",
            legacy.display(),
            current.display()
        ))),
    }
}

/// Fold a stray `.pocketshell` into `.thumbdesk`: every entry `.thumbdesk`
/// lacks is moved in; whatever is left (the same name in both) stays in the
/// stray, which is moved aside to `.pocketshell.stray-<time>` so the link can
/// take its place. Nothing is deleted.
fn absorb_stray(stray: &Path, current: &Path, home: &Path) -> Result<()> {
    let config = |what: &str, err: std::io::Error| HostError::Config(format!("{what}: {err}"));
    for entry in fs::read_dir(stray).map_err(|e| config("read the stray state dir", e))? {
        let entry = entry.map_err(|e| config("read the stray state dir", e))?;
        let name = entry.file_name();
        if name == MOVED_MARKER {
            let _ = fs::remove_file(entry.path());
            continue;
        }
        let target = current.join(&name);
        if target.symlink_metadata().is_err() {
            fs::rename(entry.path(), &target)
                .map_err(|e| config(&format!("move {}", entry.path().display()), e))?;
        }
    }
    if fs::remove_dir(stray).is_ok() {
        return Ok(());
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let aside = home.join(format!("{LEGACY_STATE_DIR_NAME}.stray-{stamp}"));
    fs::rename(stray, &aside).map_err(|e| config("move the stray state dir aside", e))
}

/// Remove `~/.pocketshell` where it is the link the move left, for an
/// uninstall that has removed the state directory it led to.
pub fn remove_legacy_link() {
    let Some(home) = crate::config::resolved_home_dir() else {
        return;
    };
    let legacy = home.join(LEGACY_STATE_DIR_NAME);
    if legacy
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        // A junction on Windows is removed as a directory, a symlink as a file.
        let _ = fs::remove_file(&legacy).or_else(|_| fs::remove_dir(&legacy));
    }
}

/// Whether a daemon holds its lock in the state directory `dir`. Moving the
/// directory under a running old daemon would work on Unix (it keeps its open
/// files, and reaches the rest through the link), but a file it creates in
/// the instant between the rename and the link would land in a new, stray
/// directory, and on Windows the move cannot happen at all; so it waits for
/// the daemon to restart, which is what an update does next.
fn legacy_daemon_running(dir: &Path) -> bool {
    // The file the daemon locks: the pid file on Unix, a lock file of its own
    // on Windows (`daemon::runtime::acquire_daemon_pid_lock`).
    #[cfg(windows)]
    let lock = dir.join(crate::service::DAEMON_LOCK_FILE);
    #[cfg(not(windows))]
    let lock = dir.join("daemon.pid");
    let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(&lock) else {
        return false;
    };
    // Taken only to see whether it can be; released when `file` drops.
    match crate::platform::try_lock_exclusive(&file) {
        Ok(()) => false,
        Err(err) => crate::platform::is_lock_contended(&err),
    }
}

/// Put a link at `link` that leads to the directory `target`. On Unix a
/// relative symlink, so it keeps working if the home directory is moved; on
/// Windows a junction, which needs no privilege (a symlink would).
fn make_dir_link(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let relative = target
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| target.to_path_buf());
        std::os::unix::fs::symlink(relative, link)
    }
    #[cfg(windows)]
    {
        let output = crate::platform::host_command("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(std::io::Error::other("no directory links on this platform"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn old_install(home: &Path) {
        let legacy = home.join(LEGACY_STATE_DIR_NAME);
        fs::create_dir_all(legacy.join("agents")).unwrap();
        fs::write(legacy.join("state.json"), b"{\"host\":1}").unwrap();
        fs::write(legacy.join("agents/a.json"), b"{}").unwrap();
    }

    #[test]
    fn an_old_install_is_moved_and_the_old_name_links_to_it() {
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());

        assert_eq!(migrate(home.path()), Migration::Moved);

        let current = home.path().join(STATE_DIR_NAME);
        let legacy = home.path().join(LEGACY_STATE_DIR_NAME);
        assert!(current.symlink_metadata().unwrap().is_dir());
        assert_eq!(
            fs::read(current.join("state.json")).unwrap(),
            b"{\"host\":1}"
        );
        assert_eq!(fs::read_link(&legacy).unwrap(), Path::new(STATE_DIR_NAME));
        // Through the old path, the same files.
        assert_eq!(fs::read(legacy.join("agents/a.json")).unwrap(), b"{}");
        assert_eq!(state_dir_in(home.path()), current);
    }

    #[test]
    fn running_again_changes_nothing() {
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());
        assert_eq!(migrate(home.path()), Migration::Moved);
        assert_eq!(migrate(home.path()), Migration::NothingToDo);
        assert_eq!(migrate(home.path()), Migration::NothingToDo);
        assert!(home
            .path()
            .join(LEGACY_STATE_DIR_NAME)
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_fresh_install_gets_the_new_name_and_no_link() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(state_dir_in(home.path()), home.path().join(STATE_DIR_NAME));
        assert_eq!(migrate(home.path()), Migration::NothingToDo);
        fs::create_dir(home.path().join(STATE_DIR_NAME)).unwrap();
        fs::write(home.path().join(STATE_DIR_NAME).join("state.json"), b"{}").unwrap();
        assert_eq!(migrate(home.path()), Migration::NothingToDo);
        assert!(home
            .path()
            .join(LEGACY_STATE_DIR_NAME)
            .symlink_metadata()
            .is_err());
    }

    #[test]
    fn a_link_owed_by_an_interrupted_move_is_made() {
        // The process that renamed the directory ended before linking it.
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());
        let legacy = home.path().join(LEGACY_STATE_DIR_NAME);
        fs::write(legacy.join(MOVED_MARKER), b"").unwrap();
        fs::rename(&legacy, home.path().join(STATE_DIR_NAME)).unwrap();

        assert_eq!(migrate(home.path()), Migration::Moved);
        assert!(legacy.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn until_it_is_moved_the_old_directory_is_the_state_dir() {
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());
        assert_eq!(
            state_dir_in(home.path()),
            home.path().join(LEGACY_STATE_DIR_NAME)
        );
    }

    #[test]
    fn a_running_old_daemon_defers_the_move() {
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());
        let legacy = home.path().join(LEGACY_STATE_DIR_NAME);
        let pid = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(legacy.join("daemon.pid"))
            .unwrap();
        crate::platform::try_lock_exclusive(&pid).unwrap();

        assert!(matches!(migrate(home.path()), Migration::Deferred(_)));
        assert!(
            legacy.symlink_metadata().unwrap().is_dir(),
            "left where it is"
        );
        assert!(!home.path().join(STATE_DIR_NAME).exists());
        assert_eq!(state_dir_in(home.path()), legacy);

        drop(pid);
        assert_eq!(migrate(home.path()), Migration::Moved);
    }

    #[test]
    fn an_empty_new_directory_does_not_strand_an_old_install() {
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());
        fs::create_dir(home.path().join(STATE_DIR_NAME)).unwrap();

        assert_eq!(migrate(home.path()), Migration::Moved);
        assert!(home.path().join(STATE_DIR_NAME).join("state.json").exists());
    }

    #[test]
    fn a_stray_old_directory_is_folded_in_without_losing_anything() {
        let home = tempfile::tempdir().unwrap();
        old_install(home.path());
        assert_eq!(migrate(home.path()), Migration::Moved);
        let current = home.path().join(STATE_DIR_NAME);
        let legacy = home.path().join(LEGACY_STATE_DIR_NAME);
        // Something holding the old path recreated it as a directory.
        fs::remove_file(&legacy).unwrap();
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("audit.log"), b"late line").unwrap();
        fs::write(legacy.join("state.json"), b"{\"stray\":1}").unwrap();

        assert_eq!(migrate(home.path()), Migration::Moved);

        assert_eq!(fs::read(current.join("audit.log")).unwrap(), b"late line");
        // The same name in both: the moved state stays, the stray's is kept aside.
        assert_eq!(
            fs::read(current.join("state.json")).unwrap(),
            b"{\"host\":1}"
        );
        let aside: Vec<_> = fs::read_dir(home.path())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pocketshell.stray-")
            })
            .collect();
        assert_eq!(aside.len(), 1);
        assert_eq!(
            fs::read(aside[0].path().join("state.json")).unwrap(),
            b"{\"stray\":1}"
        );
        assert!(legacy.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn two_processes_moving_at_once_both_end_up_on_the_new_directory() {
        for _ in 0..20 {
            let home = tempfile::tempdir().unwrap();
            old_install(home.path());
            let path = home.path().to_path_buf();
            let racers: Vec<_> = (0..4)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || migrate(&path))
                })
                .collect();
            let outcomes: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();
            assert!(
                outcomes
                    .iter()
                    .all(|o| matches!(o, Migration::Moved | Migration::NothingToDo)),
                "{outcomes:?}"
            );
            let current = path.join(STATE_DIR_NAME);
            assert_eq!(
                fs::read(current.join("state.json")).unwrap(),
                b"{\"host\":1}"
            );
            assert!(path
                .join(LEGACY_STATE_DIR_NAME)
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            // No stray copies.
            let entries = fs::read_dir(&path).unwrap().count();
            assert_eq!(entries, 2, "only .thumbdesk and the link");
        }
    }

    #[test]
    fn a_link_the_user_made_elsewhere_is_left_alone() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("state.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.path().join(LEGACY_STATE_DIR_NAME)).unwrap();
        // Not a real directory: nothing is renamed, and it stays the state dir.
        assert_eq!(migrate(home.path()), Migration::NothingToDo);
        assert_eq!(
            state_dir_in(home.path()),
            home.path().join(LEGACY_STATE_DIR_NAME)
        );
    }
}
