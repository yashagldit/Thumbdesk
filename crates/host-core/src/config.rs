use crate::error::{HostError, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub backend_base_url: String,
    pub ws_url: String,
    pub app_version: String,
    pub min_backend_host_version: Option<String>,
    pub heartbeat_interval_secs: u64,
    pub stats_interval_secs: u64,
    pub summary_interval_secs: u64,
    pub session_limit: usize,
    pub stale_session_secs: u64,
    pub detach_max_secs: u64,
    pub alert_check_interval_secs: u64,
    pub trusted_devices_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
    pub audit_file: PathBuf,
}

impl AppConfig {
    pub fn from_env() -> Self {
        // Backend URLs are not hardcoded in source. Production binaries bake
        // them in at compile time via the THUMBDESK_DEFAULT_BACKEND_URL /
        // THUMBDESK_DEFAULT_WS_URL env vars (see option_env! below; the
        // POCKETSHELL_DEFAULT_* names from before the rename still work, so
        // a build script or CI secret not yet renamed bakes the same URLs).
        // Builds from source without them start with empty defaults, and
        // must supply THUMBDESK_BACKEND_URL / THUMBDESK_WS_URL at runtime.
        // Every runtime variable here is also read under its POCKETSHELL_
        // name (`brand::EnvVar`).
        let backend_base_url = crate::env_var!("BACKEND_URL")
            .get()
            .filter(|s| !s.is_empty())
            .or_else(|| default_backend_url().map(str::to_string))
            .unwrap_or_default();
        let ws_url = crate::env_var!("WS_URL")
            .get()
            .filter(|s| !s.is_empty())
            .or_else(|| default_ws_url().map(str::to_string))
            .unwrap_or_default();
        let app_version = crate::env_var!("APP_VERSION")
            .get()
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
        let min_backend_host_version = crate::env_var!("MIN_HOST_VERSION").get();

        let heartbeat_interval_secs = crate::env_var!("HEARTBEAT_SECS").parse().unwrap_or(20);
        let stats_interval_secs = crate::env_var!("STATS_SECS").parse().unwrap_or(5);
        let summary_interval_secs = crate::env_var!("SUMMARY_SECS").parse().unwrap_or(15);
        let session_limit = crate::env_var!("SESSION_LIMIT").parse().unwrap_or(20);
        let stale_session_secs = crate::env_var!("STALE_SESSION_SECS").parse().unwrap_or(300);
        // 24 hours default
        let detach_max_secs = crate::env_var!("DETACH_MAX_SECS").parse().unwrap_or(86400);
        let alert_check_interval_secs = crate::env_var!("ALERT_CHECK_SECS").parse().unwrap_or(60);

        // Trust sync used to fire every 30s — at 2K hosts that was 66 req/s
        // of redundant lookups. 5 min is plenty for revocations to propagate;
        // mobile-driven approval flows take seconds, not minutes, anyway.
        let trusted_devices_interval_secs = crate::env_var!("TRUSTED_DEVICES_SECS")
            .parse()
            .unwrap_or(300);

        Self {
            backend_base_url,
            ws_url,
            app_version,
            min_backend_host_version,
            heartbeat_interval_secs,
            stats_interval_secs,
            summary_interval_secs,
            session_limit,
            stale_session_secs,
            detach_max_secs,
            alert_check_interval_secs,
            trusted_devices_interval_secs,
        }
    }

    pub fn paths() -> Result<AppPaths> {
        let home = resolved_home_dir()
            .ok_or_else(|| HostError::Config("unable to resolve home directory".to_string()))?;

        // `~/.thumbdesk`, or `~/.pocketshell` until an install from before
        // the rename has been moved (`state_dir`).
        let state_dir = crate::state_dir::state_dir_in(&home);
        let state_file = state_dir.join("state.json");
        let pid_file = state_dir.join("daemon.pid");
        let log_file = state_dir.join("daemon.log");
        let audit_file = state_dir.join("audit.log");

        Ok(AppPaths {
            state_dir,
            state_file,
            pid_file,
            log_file,
            audit_file,
        })
    }

    pub fn default_shell() -> String {
        // Explicit override wins on every platform.
        if let Some(s) = crate::env_var!("SHELL").get() {
            if !s.is_empty() {
                return s;
            }
        }

        #[cfg(windows)]
        {
            // PowerShell ships on all supported Windows versions and gives a
            // far better remote-terminal experience than cmd.exe. `cmd.exe`
            // remains reachable via THUMBDESK_SHELL for users who prefer it.
            "powershell.exe".to_string()
        }
        #[cfg(not(windows))]
        {
            std::env::var("SHELL").unwrap_or_else(|_| {
                if cfg!(target_os = "macos") {
                    "/bin/zsh".to_string()
                } else {
                    "/bin/bash".to_string()
                }
            })
        }
    }
}

/// The compile-time backend URL, under its new or its old build variable.
fn default_backend_url() -> Option<&'static str> {
    option_env!("THUMBDESK_DEFAULT_BACKEND_URL")
        .filter(|s| !s.is_empty())
        .or(option_env!("THUMBDESK_DEFAULT_BACKEND_URL"))
}

/// The compile-time host WebSocket URL, under its new or its old build
/// variable.
fn default_ws_url() -> Option<&'static str> {
    option_env!("THUMBDESK_DEFAULT_WS_URL")
        .filter(|s| !s.is_empty())
        .or(option_env!("THUMBDESK_DEFAULT_WS_URL"))
}

/// The user's home. Tests redirect it with `THUMBDESK_TEST_HOME` (or
/// `POCKETSHELL_TEST_HOME`), because on Windows `dirs::home_dir()` ignores
/// the environment.
pub(crate) fn resolved_home_dir() -> Option<PathBuf> {
    #[cfg(test)]
    {
        if let Some(path) = crate::env_var!("TEST_HOME")
            .get_os()
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
        {
            return Some(path);
        }
    }
    dirs::home_dir()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
    use crate::test_support::HOME_LOCK as ENV_LOCK;
    #[cfg(unix)]
    use std::env;

    #[cfg(unix)]
    const ALL_VARS: &[&str] = &[
        "THUMBDESK_BACKEND_URL",
        "THUMBDESK_WS_URL",
        "THUMBDESK_APP_VERSION",
        "THUMBDESK_MIN_HOST_VERSION",
        "THUMBDESK_HEARTBEAT_SECS",
        "THUMBDESK_STATS_SECS",
        "THUMBDESK_SUMMARY_SECS",
        "THUMBDESK_SESSION_LIMIT",
        "THUMBDESK_STALE_SESSION_SECS",
        "THUMBDESK_DETACH_MAX_SECS",
        "THUMBDESK_ALERT_CHECK_SECS",
        "THUMBDESK_TRUSTED_DEVICES_SECS",
    ];

    #[cfg(unix)]
    fn clear_all() {
        for v in ALL_VARS {
            let legacy = v.replacen("THUMBDESK_", "POCKETSHELL_", 1);
            // SAFETY: tests serialize via ENV_LOCK.
            unsafe {
                env::remove_var(v);
                env::remove_var(legacy);
            }
        }
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn from_env_uses_documented_defaults() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        let cfg = AppConfig::from_env();
        // backend_base_url and ws_url have no in-source default — they're
        // injected at compile time for production builds and fall back to
        // empty otherwise. We don't assert on their value here to avoid
        // pinning a URL into source-controlled tests.
        assert_eq!(cfg.app_version, env!("CARGO_PKG_VERSION"));
        assert!(cfg.min_backend_host_version.is_none());
        assert_eq!(cfg.heartbeat_interval_secs, 20);
        assert_eq!(cfg.stats_interval_secs, 5);
        assert_eq!(cfg.summary_interval_secs, 15);
        assert_eq!(cfg.session_limit, 20);
        assert_eq!(cfg.stale_session_secs, 300);
        assert_eq!(cfg.detach_max_secs, 86400);
        assert_eq!(cfg.alert_check_interval_secs, 60);
        assert_eq!(cfg.trusted_devices_interval_secs, 300);
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn from_env_custom_overrides() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("THUMBDESK_BACKEND_URL", "https://example.test");
            env::set_var("THUMBDESK_WS_URL", "wss://example.test/ws");
            env::set_var("THUMBDESK_APP_VERSION", "9.9.9");
            env::set_var("THUMBDESK_MIN_HOST_VERSION", "1.2.3");
            env::set_var("THUMBDESK_HEARTBEAT_SECS", "7");
            env::set_var("THUMBDESK_STATS_SECS", "11");
            env::set_var("THUMBDESK_SUMMARY_SECS", "23");
            env::set_var("THUMBDESK_SESSION_LIMIT", "42");
            env::set_var("THUMBDESK_STALE_SESSION_SECS", "600");
            env::set_var("THUMBDESK_DETACH_MAX_SECS", "100");
            env::set_var("THUMBDESK_ALERT_CHECK_SECS", "30");
            env::set_var("THUMBDESK_TRUSTED_DEVICES_SECS", "120");
        }
        let cfg = AppConfig::from_env();
        assert_eq!(cfg.backend_base_url, "https://example.test");
        assert_eq!(cfg.ws_url, "wss://example.test/ws");
        assert_eq!(cfg.app_version, "9.9.9");
        assert_eq!(cfg.min_backend_host_version.as_deref(), Some("1.2.3"));
        assert_eq!(cfg.heartbeat_interval_secs, 7);
        assert_eq!(cfg.stats_interval_secs, 11);
        assert_eq!(cfg.summary_interval_secs, 23);
        assert_eq!(cfg.session_limit, 42);
        assert_eq!(cfg.stale_session_secs, 600);
        assert_eq!(cfg.detach_max_secs, 100);
        assert_eq!(cfg.alert_check_interval_secs, 30);
        assert_eq!(cfg.trusted_devices_interval_secs, 120);
        clear_all();
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn from_env_reads_the_names_from_before_the_rename() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("POCKETSHELL_BACKEND_URL", "https://old.example.test");
            env::set_var("POCKETSHELL_HEARTBEAT_SECS", "9");
            env::set_var("POCKETSHELL_STATS_SECS", "13");
            env::set_var("THUMBDESK_STATS_SECS", "14");
        }
        let cfg = AppConfig::from_env();
        assert_eq!(cfg.backend_base_url, "https://old.example.test");
        assert_eq!(cfg.heartbeat_interval_secs, 9);
        assert_eq!(cfg.stats_interval_secs, 14, "the new name wins");
        clear_all();
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn from_env_invalid_numeric_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("THUMBDESK_HEARTBEAT_SECS", "not-a-number");
            env::set_var("THUMBDESK_SESSION_LIMIT", "-5"); // invalid for usize
        }
        let cfg = AppConfig::from_env();
        assert_eq!(cfg.heartbeat_interval_secs, 20);
        assert_eq!(cfg.session_limit, 20);
        clear_all();
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn paths_builds_under_home_dir() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        // dirs::home_dir() on unix respects $HOME.
        let prev_home = env::var_os("HOME");
        unsafe { env::set_var("HOME", tmp.path()) };

        let paths = AppConfig::paths().expect("paths should resolve");
        assert_eq!(paths.state_dir, tmp.path().join(".thumbdesk"));
        // An install from before the rename that has not been moved yet is
        // still found where it is.
        std::fs::create_dir(tmp.path().join(".pocketshell")).unwrap();
        let unmoved = AppConfig::paths().expect("paths should resolve");
        assert_eq!(unmoved.state_dir, tmp.path().join(".pocketshell"));
        std::fs::remove_dir(tmp.path().join(".pocketshell")).unwrap();
        assert_eq!(
            paths.state_file,
            tmp.path().join(".thumbdesk").join("state.json")
        );
        assert_eq!(
            paths.pid_file,
            tmp.path().join(".thumbdesk").join("daemon.pid")
        );
        assert_eq!(
            paths.log_file,
            tmp.path().join(".thumbdesk").join("daemon.log")
        );
        assert_eq!(
            paths.audit_file,
            tmp.path().join(".thumbdesk").join("audit.log")
        );

        // restore
        unsafe {
            match prev_home {
                Some(v) => env::set_var("HOME", v),
                None => env::remove_var("HOME"),
            }
        }
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn default_shell_honors_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let prev = env::var_os("SHELL");
        unsafe { env::set_var("SHELL", "/opt/custom/fish") };
        assert_eq!(AppConfig::default_shell(), "/opt/custom/fish");

        unsafe { env::remove_var("SHELL") };
        let fallback = AppConfig::default_shell();
        if cfg!(target_os = "macos") {
            assert_eq!(fallback, "/bin/zsh");
        } else {
            assert_eq!(fallback, "/bin/bash");
        }

        unsafe {
            match prev {
                Some(v) => env::set_var("SHELL", v),
                None => env::remove_var("SHELL"),
            }
        }
    }
}
