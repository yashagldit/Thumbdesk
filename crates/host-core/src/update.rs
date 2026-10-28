//! Self-update for the host agent.
//!
//! Downloads the matching pre-built binary from GitHub Releases, verifies its
//! SHA-256, and atomically replaces the on-disk binary. Mirrors
//! `website/public/install.sh` so users get the same release artifacts
//! whether they install fresh or upgrade.
//!
//! The CLI is now `thumbdesk`, but the plain archives keep their
//! `pocketshell` names and still hold the real binary as a regular file
//! called `pocketshell` (`pocketshell.exe`) at their root. Agents already in
//! the field (every release up to v1.1.0) update from exactly that and
//! nothing else: they look the binary up by that name and rename it over
//! themselves, so it must stay a file, not a link. Nothing else goes in the
//! plain archives: an old agent extracts all of it, and one entry its `tar`
//! cannot create (a link, on a staging dir that holds none) fails the whole
//! update. The other name is added on the host instead (`command_alias`).
//!
//! The macOS app archive (`….app.tar.gz`) is newer than every released
//! agent: no agent in the field reads it. It holds `Thumbdesk.app`, whose
//! executable is `Contents/MacOS/thumbdesk`. An app archive from before the
//! rename (`PocketShell.app/Contents/MacOS/pocketshell`, development builds
//! only) is still accepted, and either way the app is installed as
//! `Thumbdesk.app`; an install found under the old folder name is moved
//! (see [`download_and_install_with`]). The bundle identifier stays
//! `pocketshell`, which is what macOS ties the agent's permissions to.
//!
//! Asset layout (standard GitHub Releases):
//!
//! ```text
//! <base_url>/releases/latest                                            # 302 → /releases/tag/vX.Y.Z
//! <base_url>/releases/download/<tag>/pocketshell-<tag>-<triple>.tar.gz
//! <base_url>/releases/download/<tag>/pocketshell-<tag>-<triple>.tar.gz.sha256
//! ```
//!
//! `<base_url>` is the GitHub repo URL — forks/mirrors can point
//! `--base-url` at their own repo and the same logic works.

use crate::error::{HostError, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

/// Default release host. The public host-agent repo on GitHub — assets are
/// served as standard release downloads, no auth required. Keeps its old
/// name: every released agent updates from this repository, and the release
/// signatures are pinned to it (`COSIGN_IDENTITY_REGEXP`).
pub const DEFAULT_BASE_URL: &str = "https://github.com/yashagldit/PocketShell";

/// The macOS app's folder name.
pub const APP_BUNDLE_NAME: &str = "Thumbdesk.app";

/// The app's folder name before the rename: still accepted in an archive, and
/// moved to [`APP_BUNDLE_NAME`] where an install has it.
pub const LEGACY_APP_BUNDLE_NAME: &str = "PocketShell.app";

/// Apple Team ID stamped on every released macOS binary by the codesign step
/// in `.github/workflows/release-host-agent.yml`. Not a secret — visible via
/// `codesign -dv` on any shipped binary — so it lives in source rather than
/// as a build-time env var. If the Apple Developer account ever rotates and
/// produces a new Team ID, bump this constant in the same commit as the new
/// signing cert and ship a release; older clients will reject the new binary
/// until they pull the constant update via some out-of-band path (re-pair,
/// manual install). That's a feature, not a bug: it forces a deliberate
/// rotation event instead of silently accepting a foreign signer.
const EXPECTED_APPLE_TEAM_ID: &str = "UKH6DFA3B9";

/// Result of an update check — everything the caller needs to either show a
/// "you're up to date" message or proceed with [`download_and_install`].
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub current_version: String,
    /// Tag form (`vX.Y.Z`) — matches what the GitHub release is published under.
    pub target_version: String,
    /// Triple like `aarch64-apple-darwin` — must match the release artifact suffix.
    pub target_triple: String,
    /// `pocketshell-vX.Y.Z-<triple>.tar.gz` (the release asset names keep
    /// their old prefix: released agents fetch exactly these)
    pub archive_name: String,
    /// Direct URL to the tarball on GitHub releases.
    pub download_url: String,
    /// Sibling `.sha256` URL on GitHub releases.
    pub checksum_url: String,
    /// Sibling `.cosign-bundle.json` URL on GitHub releases — Sigstore keyless
    /// signature produced by `.github/workflows/release-host-agent.yml`. Empty
    /// for releases predating the cosign rollout.
    pub cosign_bundle_url: String,
    /// True when there is nothing to install: this is the target version,
    /// or, when no version was asked for by name, already newer than the
    /// latest release (a development build). Asking for a version by name
    /// installs it whichever way it lies.
    pub up_to_date: bool,
}

/// Detect the release-target triple matching this host. Mirrors the
/// `case "$os_kind/$arch_kind"` block in `install.sh`.
pub fn detect_target() -> Result<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let target = match (os, arch) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "x86_64") => {
            if is_musl() {
                "x86_64-unknown-linux-musl"
            } else {
                "x86_64-unknown-linux-gnu"
            }
        }
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => {
            return Err(HostError::Config(format!(
                "no prebuilt binary for {os}/{arch}"
            )))
        }
    };
    Ok(target.to_string())
}

/// Heuristic mirror of install.sh's musl detection. Only meaningful on Linux.
fn is_musl() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    Path::new("/lib/ld-musl-x86_64.so.1").exists()
        || Path::new("/lib/ld-musl-aarch64.so.1").exists()
        || Path::new("/etc/alpine-release").exists()
}

/// Resolve the latest release tag by following GitHub's `/releases/latest`
/// redirect. The final URL is `<base>/releases/tag/vX.Y.Z`; the tag is the
/// last path segment. No GitHub API call (anonymous quota would be a
/// problem for noisy update checks), no JSON parsing.
pub async fn resolve_latest_tag(base_url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| HostError::Config(format!("build http client: {e}")))?;

    let url = format!("{}/releases/latest", base_url.trim_end_matches('/'));
    let resp = client
        .head(&url)
        .send()
        .await
        .map_err(|e| HostError::Config(format!("fetch {url}: {e}")))?
        .error_for_status()
        .map_err(|e| HostError::Config(format!("fetch {url}: {e}")))?;

    let final_url = resp.url().clone();
    let tag = final_url
        .path()
        .rsplit('/')
        .find(|seg| !seg.is_empty())
        .unwrap_or("");
    if tag.is_empty() || tag == "latest" {
        return Err(HostError::Config(format!(
            "could not parse release tag from {final_url} — is {base_url} a GitHub repo with a published release?"
        )));
    }
    Ok(tag.to_string())
}

/// `app` selects the macOS app archive (`….app.tar.gz`, a whole
/// `Thumbdesk.app`) over the plain binary's. The `pocketshell-` prefix is the
/// release contract every released agent fetches by.
fn build_urls(
    base_url: &str,
    tag: &str,
    target: &str,
    app: bool,
) -> (String, String, String, String) {
    let base = base_url.trim_end_matches('/');
    let suffix = if app { "app.tar.gz" } else { "tar.gz" };
    let archive = format!("pocketshell-{tag}-{target}.{suffix}");
    let dl = format!("{base}/releases/download/{tag}/{archive}");
    let sha = format!("{dl}.sha256");
    let bundle = format!("{dl}.cosign-bundle.json");
    (archive, dl, sha, bundle)
}

/// The app bundle `exe` is the main executable of, if it is one:
/// `/Applications/Thumbdesk.app` for `…/Thumbdesk.app/Contents/MacOS/thumbdesk`.
fn app_bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    let is_bundle = macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app";
    is_bundle.then(|| bundle.to_path_buf())
}

/// Whether this process is the agent inside Thumbdesk.app. Such an install
/// updates by replacing the whole app: swapping only the binary would leave
/// a bundle whose signature no longer matches its contents, and macOS would
/// treat it as a different, unpermitted program.
fn running_from_app() -> bool {
    cfg!(target_os = "macos")
        && std::env::current_exe()
            .and_then(fs::canonicalize)
            .is_ok_and(|exe| app_bundle_of(&exe).is_some())
}

/// Whether the release carries the macOS app archive. Any failure counts as
/// "no": the caller then falls back to the binary archive.
async fn app_archive_exists(base_url: &str, tag: &str, target: &str) -> bool {
    let (_, url, _, _) = build_urls(base_url, tag, target, true);
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    else {
        return false;
    };
    client
        .head(&url)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

/// Where a first Thumbdesk.app goes: `/Applications`, or the user's own
/// `~/Applications` when that is not writable.
fn app_install_dir() -> Result<PathBuf> {
    let mut candidates = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join("Applications"));
    }
    for dir in candidates {
        let probe = dir.join(format!(".thumbdesk-probe-{}", std::process::id()));
        if fs::create_dir_all(&probe).is_ok() {
            let _ = fs::remove_dir(&probe);
            return Ok(dir);
        }
    }
    Err(HostError::Config(
        "no writable Applications folder to install Thumbdesk.app into".into(),
    ))
}

/// Make `link` a symlink to `target`, replacing whatever is there. Staged
/// beside it and renamed into place, so the command is never missing and a
/// process still running the old binary keeps its file.
fn replace_with_link(link: &Path, target: &Path) -> Result<()> {
    let staged = with_old_suffix(link).with_extension("new-link");
    let _ = fs::remove_file(&staged);
    #[cfg(unix)]
    let placed = std::os::unix::fs::symlink(target, &staged).and_then(|()| fs::rename(&staged, link));
    #[cfg(not(unix))]
    let placed: std::io::Result<()> = Err(std::io::Error::other("links are a macOS install detail"));
    placed.map_err(|e| {
        let _ = fs::remove_file(&staged);
        HostError::Config(format!(
            "link {} to {}: {e}",
            link.display(),
            target.display()
        ))
    })
}

fn normalize(v: &str) -> &str {
    v.trim_start_matches('v')
}

/// `version` as numbers to compare, when it is plain `major.minor.patch`.
fn numeric(version: &str) -> Option<Vec<u64>> {
    normalize(version.trim())
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

/// Whether `current` is a later version than `target`. False when either is
/// not plain numbers, which leaves the decision to equality.
fn is_newer(current: &str, target: &str) -> bool {
    matches!((numeric(current), numeric(target)), (Some(current), Some(target)) if current > target)
}

/// Resolve target version + URLs without downloading anything. Pass
/// `requested_version=None` to fall back on `<base_url>/releases/latest`.
pub async fn check(
    base_url: &str,
    current_version: &str,
    requested_version: Option<&str>,
) -> Result<UpdateInfo> {
    let latest = requested_version.is_none_or(|v| v.trim().is_empty());
    let target_version = match requested_version {
        Some(v) if !v.trim().is_empty() => {
            // Accept either `0.1.0` or `v0.1.0`; canonicalize to the tag form
            // because the artifact filenames embed the tag verbatim.
            let v = v.trim();
            if v.starts_with('v') {
                v.to_string()
            } else {
                format!("v{v}")
            }
        }
        _ => resolve_latest_tag(base_url).await?,
    };
    let target_triple = detect_target()?;
    // On a Mac the agent lives in Thumbdesk.app. An install already there
    // takes the app archive; a loose binary takes it too, and moves into the
    // app, when the release has one. Releases from before the app existed do
    // not, and update the binary in place as they always did.
    let app = running_from_app()
        || (cfg!(target_os = "macos")
            && app_archive_exists(base_url, &target_version, &target_triple).await);
    let (archive_name, download_url, checksum_url, cosign_bundle_url) =
        build_urls(base_url, &target_version, &target_triple, app);
    let up_to_date = normalize(&target_version) == normalize(current_version)
        || (latest && is_newer(current_version, &target_version));
    Ok(UpdateInfo {
        current_version: current_version.to_string(),
        target_version,
        target_triple,
        archive_name,
        download_url,
        checksum_url,
        cosign_bundle_url,
        up_to_date,
    })
}

/// Knobs the caller (CLI) can flip to relax authenticity checks. Every
/// non-default value here weakens the security posture; the corresponding CLI
/// flag must surface that to the user.
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Skip cosign keyless verification of the downloaded artifact. Only
    /// honored when the user explicitly passes `--insecure-skip-verify` (or
    /// equivalent). The SHA-256 + macOS codesign checks still run.
    pub skip_cosign: bool,
}

/// Download the archive + checksum + cosign bundle, verify SHA-256 and the
/// cosign keyless signature against our pinned workflow identity, then
/// atomically replace the currently-running binary on disk.
///
/// Returns the absolute path of the installed binary. The previous binary is
/// preserved at `<binary>.old` so an admin can roll back manually.
pub async fn download_and_install(info: &UpdateInfo) -> Result<PathBuf> {
    download_and_install_with(info, &InstallOptions::default()).await
}

/// Same as [`download_and_install`] but with explicit option control.
pub async fn download_and_install_with(
    info: &UpdateInfo,
    opts: &InstallOptions,
) -> Result<PathBuf> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| HostError::Config(format!("build http client: {e}")))?;

    info!("downloading {}", info.download_url);
    let archive_bytes = client
        .get(&info.download_url)
        .send()
        .await
        .map_err(|e| HostError::Config(format!("download archive: {e}")))?
        .error_for_status()
        .map_err(|e| HostError::Config(format!("download archive: {e}")))?
        .bytes()
        .await
        .map_err(|e| HostError::Config(format!("read archive body: {e}")))?;

    let sha_text = client
        .get(&info.checksum_url)
        .send()
        .await
        .map_err(|e| HostError::Config(format!("download checksum: {e}")))?
        .error_for_status()
        .map_err(|e| HostError::Config(format!("download checksum: {e}")))?
        .text()
        .await
        .map_err(|e| HostError::Config(format!("read checksum body: {e}")))?;

    info!("verifying sha-256");
    let expected = parse_sha256_line(&sha_text, &info.archive_name)?;
    let actual = {
        let mut h = Sha256::new();
        h.update(&archive_bytes);
        format!("{:x}", h.finalize())
    };
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err(HostError::Config(format!(
            "checksum mismatch — refusing to install (expected {expected}, got {actual})"
        )));
    }

    // Stage inside the install dir so the final `rename` is on the same
    // filesystem (rename across filesystems would EXDEV).
    let current_exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| HostError::Config(format!("resolve current exe: {e}")))?;
    // An app archive replaces the bundle, so it is staged beside the bundle;
    // a binary archive beside the binary. A loose binary handed an app
    // archive is moving into the app: the app is installed fresh and the
    // binary's path becomes a link to it. An app under its folder name from
    // before the rename is moving too: Thumbdesk.app goes in beside it.
    let is_app_archive = info.archive_name.ends_with(".app.tar.gz");
    let current_bundle = app_bundle_of(&current_exe);
    let converting = is_app_archive && current_bundle.is_none();
    let app_bundle = match (is_app_archive, &current_bundle) {
        (false, _) => None,
        (true, Some(bundle)) => Some(renamed_bundle(bundle)),
        (true, None) => Some(app_install_dir()?.join(APP_BUNDLE_NAME)),
    };
    let renaming = current_bundle
        .as_ref()
        .zip(app_bundle.as_ref())
        .filter(|(current, target)| current != target)
        .map(|(current, _)| current.clone());
    let install_dir = app_bundle
        .as_deref()
        .unwrap_or(&current_exe)
        .parent()
        .ok_or_else(|| HostError::Config("current exe has no parent dir".into()))?
        .to_path_buf();
    let staging = install_dir.join(format!(".thumbdesk-update-{}", std::process::id()));
    fs::create_dir_all(&staging).map_err(|e| {
        HostError::Config(format!(
            "create staging dir {} (need write access to install dir): {e}",
            staging.display()
        ))
    })?;
    let _cleanup = StagingGuard(staging.clone());

    let archive_path = staging.join(&info.archive_name);
    fs::write(&archive_path, &archive_bytes)
        .map_err(|e| HostError::Config(format!("write archive: {e}")))?;

    // Cosign keyless verification. The SHA-256 above proves the bytes match
    // what the release origin served — same origin, same trust. The cosign
    // signature is pinned to a specific GitHub workflow identity (the
    // release-host-agent.yml in this repo), so it proves the bytes were
    // produced by *that* workflow run. An attacker who owns GitHub Releases
    // publishing alone can no longer push a malicious update — they'd also
    // need an OIDC token from a workflow at this exact path.
    if opts.skip_cosign {
        warn!(
            "--insecure-skip-verify in effect: cosign keyless verification SKIPPED for {}. \
             Only the SHA-256 (same-origin as the artifact) was checked. \
             Do not use this flag against an untrusted release.",
            info.archive_name
        );
    } else if !cosign_available() {
        // Cosign not installed on this host. Rather than block the update,
        // continue with SHA-256 + (on macOS) codesign as the trust anchors and
        // surface a loud warning. The user can install cosign to re-enable
        // keyless-signature verification on subsequent updates.
        warn!(
            "cosign not installed on PATH — skipping keyless signature verification for {}. \
             SHA-256 (same-origin as the artifact){} was still checked. \
             Install cosign (`brew install cosign`, `apt install cosign`, or \
             https://github.com/sigstore/cosign/releases) to re-enable signature \
             verification on future updates.",
            info.archive_name,
            if cfg!(target_os = "macos") {
                " and Apple codesign"
            } else {
                ""
            }
        );
    } else {
        let bundle_path = staging.join(format!("{}.cosign-bundle.json", info.archive_name));
        let bundle_text = client
            .get(&info.cosign_bundle_url)
            .send()
            .await
            .map_err(|e| HostError::Config(format!("download cosign bundle: {e}")))?
            .error_for_status()
            .map_err(|e| {
                HostError::Config(format!(
                    "download cosign bundle from {}: {e} — release may predate the cosign \
                     rollout. Pass --insecure-skip-verify only if you have manually verified \
                     the SHA-256 out of band.",
                    info.cosign_bundle_url
                ))
            })?
            .text()
            .await
            .map_err(|e| HostError::Config(format!("read cosign bundle body: {e}")))?;
        fs::write(&bundle_path, bundle_text.as_bytes())
            .map_err(|e| HostError::Config(format!("write cosign bundle: {e}")))?;
        verify_cosign_bundle(&archive_path, &bundle_path)?;
    }

    info!("extracting {}", info.archive_name);
    let mut command = crate::platform::host_command("tar");
    let status = command
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&staging)
        .status()
        .map_err(|e| HostError::Config(format!("spawn tar: {e}")))?;
    if !status.success() {
        return Err(HostError::Config("tar extraction failed".into()));
    }

    if let Some(bundle) = app_bundle {
        let binary = install_app_bundle(&staging, &bundle).await?;
        info!(
            "installed {APP_BUNDLE_NAME} {} → {}",
            info.target_version,
            bundle.display()
        );
        if converting {
            // The app is in place and is now the only copy: the old binary's
            // path becomes a link into it, so the command and the running
            // service both lead there.
            replace_with_link(&current_exe, &binary)?;
            crate::service::repoint_launchd(&current_exe, &binary);
            info!("{} is now a link into {APP_BUNDLE_NAME}", current_exe.display());
            crate::command_alias::ensure_aliases_for(&binary);
            return Ok(binary);
        }
        // The app moved (PocketShell.app to Thumbdesk.app), or its executable
        // has another name than before (`pocketshell` to `thumbdesk`).
        if let (Some(old_bundle), true) = (&current_bundle, renaming.is_some() || binary != current_exe) {
            finish_bundle_move(old_bundle, renaming.is_some(), &current_exe, &binary);
        } else {
            crate::command_alias::ensure_aliases_for(&binary);
        }
        return Ok(binary);
    }

    let new_binary = extracted_binary(&staging).ok_or_else(|| {
        HostError::Config("archive did not contain a `thumbdesk` or `pocketshell` binary".into())
    })?;

    // On macOS, verify the new binary carries our Developer ID code signature
    // before we swap it in. The SHA-256 above only proves the bytes match what
    // was served from the release origin — same origin can publish both the
    // tarball and its checksum, so it's integrity, not authenticity. A valid
    // codesign chain anchored to Apple + our Team ID is authenticity: an
    // attacker who pushes a malicious release would have to steal our Apple
    // Developer ID cert in addition to the release publishing flow.
    if let Err(e) = verify_macos_codesign(&new_binary) {
        return Err(HostError::Config(format!(
            "refusing to install: codesign verification failed for {}: {e}",
            new_binary.display()
        )));
    }
    ensure_new_binary_runs(&new_binary, &staging).await?;

    // Atomically replace the on-disk binary. On Linux/macOS, `rename` over
    // a running executable is safe: the kernel keeps the old inode alive
    // for the duration of any process that already mapped it.
    let backup_path = with_old_suffix(&current_exe);
    let _ = fs::remove_file(&backup_path);
    fs::rename(&current_exe, &backup_path).map_err(|e| {
        HostError::Config(format!(
            "back up current binary to {}: {e}",
            backup_path.display(),
        ))
    })?;

    if let Err(e) = fs::rename(&new_binary, &current_exe) {
        // Roll back so the user isn't left without a working `thumbdesk`.
        let _ = fs::rename(&backup_path, &current_exe);
        return Err(HostError::Config(format!(
            "install new binary to {}: {e}",
            current_exe.display(),
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&current_exe)
            .map_err(|e| HostError::Config(format!("stat new binary: {e}")))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&current_exe, perms)
            .map_err(|e| HostError::Config(format!("chmod new binary: {e}")))?;
    }

    // tar-extracted binaries on macOS can inherit the quarantine xattr.
    // Strip it so the next exec doesn't get blocked by Gatekeeper, mirroring
    // the same step in install.sh. Best-effort.
    if cfg!(target_os = "macos") {
        let mut command = crate::platform::host_command("xattr");
        let _ = command
            .args(["-d", "com.apple.quarantine"])
            .arg(&current_exe)
            .status();
    }

    info!(
        "installed thumbdesk {} → {}",
        info.target_version,
        current_exe.display()
    );
    info!("previous binary saved at {}", backup_path.display());
    crate::command_alias::ensure_aliases_for(&current_exe);
    Ok(current_exe)
}

/// The binary an extracted archive holds: `thumbdesk` should a future
/// archive carry it as a file of its own, otherwise `pocketshell`, the name
/// every release so far carries it under. A link under either name is
/// skipped: renamed over the running binary, it would point into the deleted
/// staging dir.
fn extracted_binary(staging: &Path) -> Option<PathBuf> {
    crate::command_alias::COMMAND_NAMES
        .iter()
        .map(|name| {
            staging.join(if cfg!(windows) {
                format!("{name}.exe")
            } else {
                name.to_string()
            })
        })
        .find(|path| path.symlink_metadata().is_ok_and(|meta| meta.is_file()))
}

/// Where an app at `bundle` is installed by an update: the same folder, as
/// `Thumbdesk.app` (which it already is, unless it is an install from before
/// the rename). An app inside an npm package keeps its place: the package's
/// launcher looks it up there by name.
fn renamed_bundle(bundle: &Path) -> PathBuf {
    if bundle.components().any(|part| part.as_os_str() == "node_modules") {
        return bundle.to_path_buf();
    }
    bundle.with_file_name(APP_BUNDLE_NAME)
}

/// The agent executable inside `bundle`: `Contents/MacOS/thumbdesk`, or
/// `pocketshell` in an app built before the rename.
pub fn bundle_executable(bundle: &Path) -> Option<PathBuf> {
    crate::command_alias::COMMAND_NAMES
        .iter()
        .map(|name| bundle.join("Contents/MacOS").join(name))
        .find(|path| path.is_file())
}

/// The app an extracted archive holds: `Thumbdesk.app`, or `PocketShell.app`
/// from an archive made before the rename, with its executable.
fn extracted_app(staging: &Path) -> Option<(PathBuf, PathBuf)> {
    [APP_BUNDLE_NAME, LEGACY_APP_BUNDLE_NAME]
        .iter()
        .map(|name| staging.join(name))
        .find_map(|app| bundle_executable(&app).map(|exe| (app, exe)))
}

/// Replace the installed app `bundle` with the app extracted into `staging`,
/// and return the executable it now holds. The running process keeps its
/// already-mapped files, as with a renamed-over binary. No copy of the old
/// app is kept: the app is the only copy of the agent on a Mac, and a second
/// one would outlive it.
async fn install_app_bundle(staging: &Path, bundle: &Path) -> Result<PathBuf> {
    let Some((new_app, new_exe)) = extracted_app(staging) else {
        return Err(HostError::Config(format!(
            "archive did not contain {APP_BUNDLE_NAME}"
        )));
    };
    // The same authenticity check the binary gets, on the bundle as a whole:
    // codesign validates every file in it against the signature.
    if let Err(e) = verify_macos_codesign(&new_app) {
        return Err(HostError::Config(format!(
            "refusing to install: codesign verification failed for {}: {e}",
            new_app.display()
        )));
    }
    ensure_new_binary_runs(&new_exe, staging).await?;
    let relative = new_exe
        .strip_prefix(&new_app)
        .map_err(|_| HostError::Config("app executable outside its bundle".into()))?
        .to_path_buf();

    swap_app_bundle(&new_app, bundle)?;
    let mut command = crate::platform::host_command("xattr");
    let _ = command
        .args(["-dr", "com.apple.quarantine"])
        .arg(bundle)
        .status();
    Ok(bundle.join(relative))
}

/// After an update installed the app at `new_exe` where `old_exe`, inside
/// `old_bundle`, ran before (an app from before the rename, `PocketShell.app`
/// or an executable called `pocketshell`): point what led to the old path at
/// the new one, and with `remove_old`, remove the old app (a bundle beside
/// the new one), so the new app is again the only copy. The LaunchAgent is
/// rewritten, the commands on the PATH that led into the old app are
/// relinked, and the restart that follows the update loads the service again
/// from the new path (`service::restart`).
fn finish_bundle_move(old_bundle: &Path, remove_old: bool, old_exe: &Path, new_exe: &Path) {
    crate::service::repoint_launchd(old_exe, new_exe);
    #[cfg(unix)]
    for dir in crate::command_alias::command_dirs() {
        for name in crate::command_alias::COMMAND_NAMES {
            let link = dir.join(name);
            let into_old = fs::read_link(&link)
                .is_ok_and(|target| target.starts_with(old_bundle) && target != new_exe);
            if into_old {
                if let Err(e) = replace_with_link(&link, new_exe) {
                    warn!("could not relink {}: {e}", link.display());
                }
            }
        }
    }
    crate::command_alias::ensure_aliases_for(new_exe);
    if !remove_old {
        return;
    }
    match fs::remove_dir_all(old_bundle) {
        Ok(()) => info!(
            "moved the app from {} to {}",
            old_bundle.display(),
            new_exe.display()
        ),
        Err(e) => warn!("could not remove the old app at {}: {e}", old_bundle.display()),
    }
}

/// Remove a `PocketShell.app` left beside the running `Thumbdesk.app`.
///
/// `install.sh` installs the app under the archive's folder name, so a Mac
/// that had the app from before the rename ends up with both; only an update
/// run by the agent itself moves one to the other. The service code calls
/// this once it has installed or restarted the service for an agent running
/// from a `Thumbdesk.app` ([`crate::service`]), which is also when the
/// daemon under the old LaunchAgent label has just been replaced.
///
/// A candidate (in `/Applications` or `~/Applications`) goes only when it is
/// a real folder, not a link and not inside an npm package, its bundle
/// identifier is `pocketshell` (ours, not some other app of that name), it is
/// not the app this process runs from, and nothing runs from it any more
/// (the daemon it ran is given a moment to finish exiting). Commands on the
/// PATH that led into it are pointed at this app first, and a LaunchAgent
/// naming it is rewritten, as after an update that moved the app.
pub fn remove_leftover_legacy_app() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let Ok(exe) = std::env::current_exe().and_then(fs::canonicalize) else {
        return;
    };
    let Some(current) = app_bundle_of(&exe) else {
        return;
    };
    if current.file_name().is_none_or(|name| name != APP_BUNDLE_NAME) || in_npm_package(&current) {
        return;
    }
    let mut dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Applications"));
    }
    for old in leftover_legacy_apps(&current, &dirs) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while runs_from(&old) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        if runs_from(&old) {
            info!("leaving {}: a process still runs from it", old.display());
            continue;
        }
        let old_exe = bundle_executable(&old).unwrap_or_else(|| old.join("Contents/MacOS/pocketshell"));
        finish_bundle_move(&old, true, &old_exe, &exe);
    }
}

/// The `PocketShell.app` bundles in `dirs` that [`remove_leftover_legacy_app`]
/// may remove for an agent running from `current`: real folders, ours by
/// bundle identifier, not `current` itself, not in an npm package.
fn leftover_legacy_apps(current: &Path, dirs: &[PathBuf]) -> Vec<PathBuf> {
    let current = fs::canonicalize(current).unwrap_or_else(|_| current.to_path_buf());
    dirs.iter()
        .map(|dir| dir.join(LEGACY_APP_BUNDLE_NAME))
        .filter(|old| old.symlink_metadata().is_ok_and(|meta| meta.file_type().is_dir()))
        .filter(|old| !in_npm_package(old))
        .filter(|old| fs::canonicalize(old).is_ok_and(|real| real != current))
        .filter(|old| bundle_identifier(old).as_deref() == Some(OUR_BUNDLE_ID))
        .collect()
}

/// The bundle identifier the app has always had, from before the rename.
const OUR_BUNDLE_ID: &str = "pocketshell";

fn in_npm_package(path: &Path) -> bool {
    path.components().any(|part| part.as_os_str() == "node_modules")
}

/// `CFBundleIdentifier` from `bundle`'s Info.plist. Read as XML, which is how
/// `build-macos-app.sh` writes it; a binary plist is asked of `plutil`.
fn bundle_identifier(bundle: &Path) -> Option<String> {
    let plist = bundle.join("Contents/Info.plist");
    let bytes = fs::read(&plist).ok()?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Some(rest) = text.split("<key>CFBundleIdentifier</key>").nth(1) {
            let value = rest.trim_start().strip_prefix("<string>")?;
            return value.split("</string>").next().map(|id| id.trim().to_string());
        }
        if text.trim_start().starts_with("<?xml") {
            return None;
        }
    }
    let output = crate::platform::host_command("plutil")
        .args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
        .arg(&plist)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Whether any process runs an executable inside `bundle`.
fn runs_from(bundle: &Path) -> bool {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let bundle = fs::canonicalize(bundle).unwrap_or_else(|_| bundle.to_path_buf());
    system
        .processes()
        .values()
        .any(|process| process.exe().is_some_and(|exe| exe.starts_with(&bundle)))
}

/// Put `new_app` where `bundle` is, whole. Renames on one filesystem, so the
/// app is never half-written; a failed second rename puts the old one back.
fn swap_app_bundle(new_app: &Path, bundle: &Path) -> Result<()> {
    // A first install has nothing to move aside.
    if !bundle.exists() {
        return fs::rename(new_app, bundle).map_err(|e| {
            HostError::Config(format!(
                "install the new app to {}: {e}",
                bundle.display()
            ))
        });
    }
    let backup = with_old_suffix(bundle);
    let _ = fs::remove_dir_all(&backup);
    fs::rename(bundle, &backup).map_err(|e| {
        HostError::Config(format!("move the current app aside ({}): {e}", bundle.display()))
    })?;
    if let Err(e) = fs::rename(new_app, bundle) {
        // Roll back so the user isn't left without a working app.
        let _ = fs::rename(&backup, bundle);
        return Err(HostError::Config(format!(
            "install the new app to {}: {e}",
            bundle.display()
        )));
    }
    if let Err(e) = fs::remove_dir_all(&backup) {
        warn!("could not remove the previous app at {}: {e}", backup.display());
    }
    Ok(())
}

/// How long the staged binary gets to answer `--version`. The first exec of
/// a fresh macOS binary waits on its signature check, which can take seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Refuse an update whose binary cannot start on this machine, before it
/// replaces the one that can. dyld refuses a binary built for a newer macOS
/// (or missing a system library) before any of our code runs, so once such a
/// binary is swapped in the service crash-loops and the host never comes back
/// to take another update. Runs off the async workers: the probe can wait the
/// whole [`PROBE_TIMEOUT`].
async fn ensure_new_binary_runs(binary: &Path, staging: &Path) -> Result<()> {
    let (binary, staging) = (binary.to_path_buf(), staging.to_path_buf());
    tokio::task::spawn_blocking(move || probe_binary(&binary, &staging, PROBE_TIMEOUT))
        .await
        .map_err(|e| HostError::Config(format!("refusing to install: probe task failed: {e}")))?
}

/// Run `<binary> --version` and require it to exit 0 within `timeout`.
fn probe_binary(binary: &Path, staging: &Path, timeout: Duration) -> Result<()> {
    let log_path = staging.join("probe.log");
    let log = fs::File::create(&log_path)
        .map_err(|e| HostError::Config(format!("create probe log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| HostError::Config(format!("create probe log: {e}")))?;
    let mut command = crate::platform::host_command(binary);
    command
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(log_err);
    let status = crate::service::run_with_timeout(&mut command, timeout).map_err(|e| {
        HostError::Config(if e.kind() == std::io::ErrorKind::TimedOut {
            format!(
                "refusing to install: the new binary did not answer --version within {timeout:?}"
            )
        } else {
            format!("refusing to install: the new binary cannot be started: {e}")
        })
    })?;
    if status.success() {
        return Ok(());
    }
    let output = fs::read_to_string(&log_path).unwrap_or_default();
    let output = output.trim();
    let likely = if cfg!(target_os = "macos") {
        " — it may need a newer macOS than this Mac runs"
    } else {
        ""
    };
    Err(HostError::Config(format!(
        "refusing to install: the new binary does not run on this machine ({status}){likely}{}",
        if output.is_empty() {
            String::new()
        } else {
            format!(": {}", output.chars().take(500).collect::<String>())
        }
    )))
}

/// `current_exe.with_extension("old")` would mangle `thumbdesk` into
/// `thumbdesk.old` (correct), but on Windows-style paths with extensions
/// it would replace the extension. Keep both: `thumbdesk` → `thumbdesk.old`,
/// `thumbdesk.exe` → `thumbdesk.exe.old`.
fn with_old_suffix(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".old");
    PathBuf::from(s)
}

/// Cleans up the staging dir even on early-return / panic.
struct StagingGuard(PathBuf);
impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            warn!("failed to clean up staging dir {}: {e}", self.0.display());
        }
    }
}

/// Sigstore keyless certificate identity that our release workflow produces.
/// Matches `https://github.com/<owner>/<repo>/.github/workflows/release-host-agent.yml@refs/tags/v...`
/// for any version tag. Anchored with `^` and `$` so a workflow at a similar
/// path (e.g. a fork's `release-host-agent-test.yml`) cannot satisfy this.
///
/// Releases are signed in `yashagldit/PocketShell` (agents before this one
/// pin only that repo, so it keeps signing while they are around) and may
/// later be signed in `yashagldit/Thumbdesk`, which this agent accepts too.
const COSIGN_IDENTITY_REGEXP: &str = concat!(
    "^https://github\\.com/yashagldit/(PocketShell|Thumbdesk)/",
    "\\.github/workflows/release-host-agent\\.yml@refs/tags/v[0-9][0-9A-Za-z.\\-]*$",
);

/// The OIDC issuer GitHub Actions uses to mint tokens for the workflow's
/// keyless signing flow. This is the same string the cosign-installer action
/// expects on the signing side; if either rotates the verify will fail loudly.
const COSIGN_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Probe whether `cosign` is invokable on PATH. Used to decide between
/// running a real signature verification and falling back to the SHA-256 +
/// codesign trust anchors with a loud warning. We deliberately don't try to
/// auto-install cosign — silently fetching another binary to verify this
/// binary expands the trust surface in a non-obvious way.
fn cosign_available() -> bool {
    let mut command = crate::platform::host_command("cosign");
    command
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Shell out to `cosign verify-blob` to check the keyless signature bundle
/// produced by our release workflow. We require the cosign binary to be
/// installed on the host — there is no usable production-grade Rust verifier
/// in May 2026 (sigstore-rs is marked experimental; sigstore-verification was
/// archived 2026-05-18). When sigstore-rs stabilizes, replace this with an
/// in-process verifier and a baked-in TUF trust root.
fn verify_cosign_bundle(artifact: &Path, bundle: &Path) -> Result<()> {
    let mut command = crate::platform::host_command("cosign");
    let output = command
        .args(["verify-blob", "--new-bundle-format", "--bundle"])
        .arg(bundle)
        .args(["--certificate-identity-regexp", COSIGN_IDENTITY_REGEXP])
        .args(["--certificate-oidc-issuer", COSIGN_OIDC_ISSUER])
        .arg(artifact)
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostError::Config(
                "cosign is not installed on PATH — required to verify the release signature. \
                 Install it (`brew install cosign`, `apt install cosign`, or download from \
                 https://github.com/sigstore/cosign/releases) and re-run, or pass \
                 --insecure-skip-verify if you have manually verified the artifact out of band."
                    .to_string(),
            ));
        }
        Err(e) => {
            return Err(HostError::Config(format!("spawn cosign: {e}")));
        }
    };
    if output.status.success() {
        info!("cosign verified (identity pinned to release workflow)");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(HostError::Config(format!(
        "cosign verify-blob rejected the release artifact — refusing to install. \
         Identity required: {COSIGN_IDENTITY_REGEXP}. cosign stderr: {stderr}"
    )))
}

/// Build the `codesign` designated-requirement clause that proves a binary
/// was signed by us:
///   * `anchor apple generic` — chain ultimately rooted in Apple
///   * intermediate `1.2.840.113635.100.6.2.6` — Developer ID CA
///   * leaf `1.2.840.113635.100.6.1.13` — Developer ID Application cert
///   * leaf subject OU equals our Team ID
fn developer_id_requirement(team_id: &str) -> String {
    format!(
        "anchor apple generic \
         and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{team_id}\""
    )
}

/// Verify a downloaded binary carries our Apple Developer ID signature before
/// we let it replace the on-disk binary. No-op on non-macOS targets — the
/// Sigstore cosign verify (TODO) will cover Linux + macOS uniformly later.
fn verify_macos_codesign(binary: &Path) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    // codesign's `-R requirement` (two args) is a sign-time option; the
    // verify form requires the equals-sign syntax `-R=<requirement>` as a
    // single argv entry. Easy to get wrong — see `man codesign`.
    let req_arg = format!("-R={}", developer_id_requirement(EXPECTED_APPLE_TEAM_ID));
    let mut command = crate::platform::host_command("codesign");
    let output = command
        .args(["--verify", "--strict"])
        .arg(&req_arg)
        .arg(binary)
        .output()
        .map_err(|e| HostError::Config(format!("spawn codesign: {e}")))?;
    if output.status.success() {
        info!("codesign verified (Team ID {EXPECTED_APPLE_TEAM_ID})");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(HostError::Config(format!(
        "codesign --verify rejected binary (Team ID {EXPECTED_APPLE_TEAM_ID}): {stderr}"
    )))
}

/// `.sha256` files from our release pipeline look like:
///   `<hex>  <archive_name>\n`
/// Pull out the hex digest matching the expected archive name. Tolerates a
/// bare digest (no filename) for forward-compatibility with checksum tools
/// that emit only the hash.
fn parse_sha256_line(text: &str, archive_name: &str) -> Result<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex = parts.next().unwrap_or("").trim();
        // The leading `*` is the binary-mode marker emitted by some sha256
        // implementations (`sha256sum -b`).
        let file = parts.next().unwrap_or("").trim().trim_start_matches('*');
        if hex.is_empty() {
            continue;
        }
        if file.is_empty() || file == archive_name {
            return Ok(hex.to_string());
        }
    }
    Err(HostError::Config(format!(
        "no sha-256 entry found for {archive_name}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha256_accepts_standard_format() {
        let text = "abc123  pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz\n";
        let h = parse_sha256_line(text, "pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz").unwrap();
        assert_eq!(h, "abc123");
    }

    #[test]
    fn parse_sha256_accepts_binary_mode_marker() {
        let text = "abc123 *pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz\n";
        let h = parse_sha256_line(text, "pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz").unwrap();
        assert_eq!(h, "abc123");
    }

    #[test]
    fn parse_sha256_accepts_bare_digest() {
        let text = "deadbeef\n";
        let h = parse_sha256_line(text, "anything.tar.gz").unwrap();
        assert_eq!(h, "deadbeef");
    }

    #[test]
    fn parse_sha256_skips_comments_and_blanks() {
        let text = "\n# comment\nabc  archive.tar.gz\n";
        let h = parse_sha256_line(text, "archive.tar.gz").unwrap();
        assert_eq!(h, "abc");
    }

    #[test]
    fn parse_sha256_errors_when_filename_does_not_match() {
        let text = "abc  other.tar.gz\n";
        let err = parse_sha256_line(text, "wanted.tar.gz").err().unwrap();
        assert!(err.to_string().contains("no sha-256 entry"));
    }

    #[test]
    fn detect_target_returns_known_release_triple() {
        // Sanity-check we got one of the triples the release matrix actually ships.
        let t = detect_target().unwrap();
        assert!(
            matches!(
                t.as_str(),
                "aarch64-apple-darwin"
                    | "x86_64-apple-darwin"
                    | "aarch64-unknown-linux-gnu"
                    | "x86_64-unknown-linux-gnu"
                    | "x86_64-unknown-linux-musl"
                    | "x86_64-pc-windows-msvc"
            ),
            "unexpected target triple: {t}"
        );
    }

    #[test]
    fn build_urls_produces_expected_paths() {
        let (archive, dl, sha, bundle) = build_urls(
            "https://github.com/yashagldit/PocketShell",
            "v0.1.0",
            "aarch64-apple-darwin",
            false,
        );
        assert_eq!(archive, "pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            dl,
            "https://github.com/yashagldit/PocketShell/releases/download/v0.1.0/pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(sha, format!("{dl}.sha256"));
        assert_eq!(bundle, format!("{dl}.cosign-bundle.json"));
    }

    #[test]
    fn build_urls_tolerates_trailing_slash_on_base() {
        // Operator-friendly: don't double-slash if someone configures the
        // base with a trailing /.
        let (_, dl, _, _) = build_urls(
            "https://github.com/yashagldit/PocketShell/",
            "v0.1.0",
            "x86_64-unknown-linux-gnu",
            false,
        );
        assert_eq!(
            dl,
            "https://github.com/yashagldit/PocketShell/releases/download/v0.1.0/pocketshell-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn a_build_newer_than_the_release_is_not_behind_it() {
        assert!(is_newer("1.4.0", "v1.1.0"));
        assert!(is_newer("1.10.0", "1.9.9"), "compared as numbers, not text");
        assert!(!is_newer("1.1.0", "v1.1.0"));
        assert!(!is_newer("1.1.0", "v1.4.0"));
        assert!(!is_newer("1.4.0-dev", "v1.1.0"), "anything else is left to equality");

        // Asked for by name, an older version is still an install.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let info = rt
            .block_on(check("https://example.test/r", "1.4.0", Some("1.1.0")))
            .unwrap();
        assert!(!info.up_to_date);
    }

    #[test]
    fn check_treats_v_prefix_and_bare_version_as_equivalent() {
        // Caller may pass a version with or without `v`; `target_version`
        // must canonicalize to the tag form, but `up_to_date` must compare
        // numerically (i.e. "v0.1.0" == "0.1.0").
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let info = rt
            .block_on(check("https://example.test/r", "0.1.0", Some("0.1.0")))
            .unwrap();
        assert_eq!(info.target_version, "v0.1.0");
        assert!(info.up_to_date);

        let info2 = rt
            .block_on(check("https://example.test/r", "0.1.0", Some("v0.1.0")))
            .unwrap();
        assert_eq!(info2.target_version, "v0.1.0");
        assert!(info2.up_to_date);

        let info3 = rt
            .block_on(check("https://example.test/r", "0.1.0", Some("0.2.0")))
            .unwrap();
        assert!(!info3.up_to_date);
    }

    #[test]
    fn an_app_install_fetches_the_app_archive() {
        let (archive, dl, sha, bundle) = build_urls(
            "https://github.com/o/r",
            "v1.4.0",
            "aarch64-apple-darwin",
            true,
        );
        assert_eq!(archive, "pocketshell-v1.4.0-aarch64-apple-darwin.app.tar.gz");
        assert_eq!(
            dl,
            "https://github.com/o/r/releases/download/v1.4.0/pocketshell-v1.4.0-aarch64-apple-darwin.app.tar.gz"
        );
        assert_eq!(sha, format!("{dl}.sha256"));
        assert_eq!(bundle, format!("{dl}.cosign-bundle.json"));
    }

    #[test]
    fn only_a_bundles_main_executable_names_an_app() {
        assert_eq!(
            app_bundle_of(Path::new("/Applications/Thumbdesk.app/Contents/MacOS/thumbdesk")),
            Some(PathBuf::from("/Applications/Thumbdesk.app"))
        );
        assert_eq!(
            app_bundle_of(Path::new("/Applications/PocketShell.app/Contents/MacOS/pocketshell")),
            Some(PathBuf::from("/Applications/PocketShell.app"))
        );
        for loose in [
            "/usr/local/bin/thumbdesk",
            "/Users/me/.local/bin/pocketshell",
            "/Applications/Thumbdesk.app/Contents/Resources/thumbdesk",
            "/tmp/MacOS/thumbdesk",
            "/opt/thing.app/bin/MacOS/thumbdesk",
        ] {
            assert_eq!(app_bundle_of(Path::new(loose)), None, "{loose}");
        }
    }

    fn fake_app(dir: &Path, folder: &str, exe: &str, body: &[u8]) -> PathBuf {
        let app = dir.join(folder);
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(app.join("Contents/MacOS").join(exe), body).unwrap();
        app
    }

    #[test]
    fn an_archive_with_either_app_layout_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let current = fake_app(&dir.path().join("new"), "Thumbdesk.app", "thumbdesk", b"new");
        assert_eq!(
            extracted_app(&dir.path().join("new")),
            Some((current.clone(), current.join("Contents/MacOS/thumbdesk")))
        );
        // An app archive from before the rename.
        let legacy = fake_app(&dir.path().join("old"), "PocketShell.app", "pocketshell", b"old");
        assert_eq!(
            extracted_app(&dir.path().join("old")),
            Some((legacy.clone(), legacy.join("Contents/MacOS/pocketshell")))
        );
        // A folder with no executable in it is no app.
        fs::create_dir_all(dir.path().join("empty/Thumbdesk.app/Contents/MacOS")).unwrap();
        assert_eq!(extracted_app(&dir.path().join("empty")), None);
    }

    #[test]
    fn an_app_from_before_the_rename_is_installed_as_thumbdesk_app() {
        assert_eq!(
            renamed_bundle(Path::new("/Applications/PocketShell.app")),
            PathBuf::from("/Applications/Thumbdesk.app")
        );
        assert_eq!(
            renamed_bundle(Path::new("/Users/me/Applications/Thumbdesk.app")),
            PathBuf::from("/Users/me/Applications/Thumbdesk.app")
        );
        let npm = Path::new("/opt/lib/node_modules/@pocketshell/darwin-arm64/PocketShell.app");
        assert_eq!(renamed_bundle(npm), npm);
    }

    // The fake app's binary is a shell script, which Windows cannot run.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_old_layout_archive_lands_as_thumbdesk_app() {
        // codesign is a no-op off macOS and refuses unsigned fakes on it.
        if cfg!(target_os = "macos") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        let old_app = fake_app(&staging, "PocketShell.app", "pocketshell", b"#!/bin/sh\nexit 0\n");
        {
            use std::os::unix::fs::PermissionsExt;
            let exe = old_app.join("Contents/MacOS/pocketshell");
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let bundle = dir.path().join("Applications/Thumbdesk.app");
        fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        let exe = install_app_bundle(&staging, &bundle).await.unwrap();
        assert_eq!(exe, bundle.join("Contents/MacOS/pocketshell"));
        assert!(exe.is_file());
    }

    #[test]
    fn an_app_update_replaces_the_bundle_and_keeps_no_copy() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = fake_app(dir.path(), "Thumbdesk.app", "thumbdesk", b"old");
        fs::write(bundle.join("Contents/leftover"), b"stale").unwrap();
        let staging = dir.path().join("staging");
        let new_app = fake_app(&staging, "Thumbdesk.app", "thumbdesk", b"new");

        swap_app_bundle(&new_app, &bundle).unwrap();

        assert_eq!(fs::read(bundle.join("Contents/MacOS/thumbdesk")).unwrap(), b"new");
        assert!(!bundle.join("Contents/leftover").exists(), "replaced whole, not merged");
        assert!(!with_old_suffix(&bundle).exists(), "no second copy is kept");
    }

    #[test]
    fn a_first_app_install_needs_nothing_to_replace() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("Applications/Thumbdesk.app");
        fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        let new_app = fake_app(&dir.path().join("staging"), "Thumbdesk.app", "thumbdesk", b"new");

        swap_app_bundle(&new_app, &bundle).unwrap();

        assert_eq!(fs::read(bundle.join("Contents/MacOS/thumbdesk")).unwrap(), b"new");
    }

    /// An update from an app under its old name: the new app goes in beside
    /// it, the commands that led into the old one lead into the new one, and
    /// the old one is gone.
    #[cfg(unix)]
    #[test]
    fn a_moved_app_leaves_no_copy_and_no_link_into_the_old_one() {
        let _g = crate::test_support::HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let old_app = fake_app(dir.path(), "PocketShell.app", "pocketshell", b"old");
        let old_exe = old_app.join("Contents/MacOS/pocketshell");
        let new_app = fake_app(dir.path(), "Thumbdesk.app", "thumbdesk", b"new");
        let new_exe = new_app.join("Contents/MacOS/thumbdesk");
        let home = dir.path().join("home");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(&old_exe, bin.join("pocketshell")).unwrap();
        std::os::unix::fs::symlink(&old_exe, bin.join("thumbdesk")).unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &home) };

        finish_bundle_move(&old_app, true, &old_exe, &new_exe);

        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert!(!old_app.exists());
        assert_eq!(fs::read_link(bin.join("thumbdesk")).unwrap(), new_exe);
        assert_eq!(fs::read_link(bin.join("pocketshell")).unwrap(), new_exe);
        assert_eq!(fs::read(bin.join("pocketshell")).unwrap(), b"new");
    }

    fn info_plist(app: &Path, bundle_id: &str) {
        fs::write(
            app.join("Contents/Info.plist"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n  \
                 <key>CFBundleName</key>\n  <string>Thumbdesk</string>\n  \
                 <key>CFBundleIdentifier</key>\n  <string>{bundle_id}</string>\n</dict>\n</plist>\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn the_bundle_identifier_is_read_from_the_xml_plist() {
        let dir = tempfile::tempdir().unwrap();
        let app = fake_app(dir.path(), "PocketShell.app", "pocketshell", b"old");
        info_plist(&app, "pocketshell");
        assert_eq!(bundle_identifier(&app).as_deref(), Some("pocketshell"));
        info_plist(&app, "com.example.other");
        assert_eq!(bundle_identifier(&app).as_deref(), Some("com.example.other"));
        assert_eq!(bundle_identifier(&dir.path().join("missing.app")), None);
    }

    /// Only our own `PocketShell.app`, as a real folder, other than the app
    /// running, outside npm, is a leftover to remove.
    #[cfg(unix)]
    #[test]
    fn only_our_own_old_app_beside_the_new_one_is_a_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let apps = dir.path().join("Applications");
        let user_apps = dir.path().join("home/Applications");
        let current = fake_app(&apps, "Thumbdesk.app", "thumbdesk", b"new");
        let ours = fake_app(&apps, "PocketShell.app", "pocketshell", b"old");
        info_plist(&ours, "pocketshell");
        // Someone else's app that happens to have the name.
        let theirs = fake_app(&user_apps, "PocketShell.app", "pocketshell", b"other");
        info_plist(&theirs, "com.example.pocketshell");

        let found = leftover_legacy_apps(&current, &[apps.clone(), user_apps.clone()]);
        assert_eq!(found, [apps.join("PocketShell.app")]);

        // A link (to the new app, say) is not a folder to remove.
        fs::remove_dir_all(&ours).unwrap();
        std::os::unix::fs::symlink(&current, apps.join("PocketShell.app")).unwrap();
        assert!(leftover_legacy_apps(&current, &[apps.clone()]).is_empty());

        // The app running is never its own leftover.
        let running_old = fake_app(&user_apps.join("x"), "PocketShell.app", "pocketshell", b"o");
        info_plist(&running_old, "pocketshell");
        assert!(leftover_legacy_apps(&running_old, &[user_apps.join("x")]).is_empty());

        // Nor one inside an npm package.
        let npm = dir.path().join("lib/node_modules/@pocketshell/darwin-arm64");
        let npm_app = fake_app(&npm, "PocketShell.app", "pocketshell", b"npm");
        info_plist(&npm_app, "pocketshell");
        assert!(leftover_legacy_apps(&current, &[npm]).is_empty());
    }

    /// Removing a leftover relinks the commands that led into it, as an
    /// update that moved the app does.
    #[cfg(unix)]
    #[test]
    fn a_removed_leftover_leaves_the_commands_leading_to_the_new_app() {
        let _g = crate::test_support::HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let apps = dir.path().join("Applications");
        let current = fake_app(&apps, "Thumbdesk.app", "thumbdesk", b"new");
        let new_exe = current.join("Contents/MacOS/thumbdesk");
        let old = fake_app(&apps, "PocketShell.app", "pocketshell", b"old");
        info_plist(&old, "pocketshell");
        let home = dir.path().join("home");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(old.join("Contents/MacOS/pocketshell"), bin.join("pocketshell")).unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &home) };

        for leftover in leftover_legacy_apps(&current, &[apps.clone()]) {
            assert!(!runs_from(&leftover));
            let old_exe = bundle_executable(&leftover).unwrap();
            finish_bundle_move(&leftover, true, &old_exe, &new_exe);
        }

        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert!(!old.exists());
        assert!(current.exists());
        assert_eq!(fs::read_link(bin.join("pocketshell")).unwrap(), new_exe);
    }

    // App bundles are a macOS thing; on Windows `canonicalize` adds a `\\?\`
    // prefix the process list's paths lack.
    #[cfg(unix)]
    #[test]
    fn a_bundle_this_process_runs_from_is_in_use() {
        let exe = std::env::current_exe().unwrap();
        // The test binary's own directory stands in for a bundle.
        assert!(runs_from(&fs::canonicalize(exe.parent().unwrap()).unwrap()));
        let dir = tempfile::tempdir().unwrap();
        assert!(!runs_from(dir.path()));
    }

    /// What moving a loose install into the app leaves at the old path.
    #[cfg(unix)]
    #[test]
    fn a_loose_binary_becomes_a_link_into_the_app() {
        let dir = tempfile::tempdir().unwrap();
        let in_app = dir.path().join("Thumbdesk.app/Contents/MacOS/thumbdesk");
        fs::create_dir_all(in_app.parent().unwrap()).unwrap();
        fs::write(&in_app, b"app binary").unwrap();
        let loose = dir.path().join("bin/pocketshell");
        fs::create_dir_all(loose.parent().unwrap()).unwrap();
        fs::write(&loose, b"loose binary").unwrap();

        replace_with_link(&loose, &in_app).unwrap();

        assert_eq!(fs::read_link(&loose).unwrap(), in_app);
        assert_eq!(fs::read(&loose).unwrap(), b"app binary");
        let leftovers: Vec<_> = fs::read_dir(loose.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(leftovers, ["pocketshell"], "no second copy, no staging file");
    }

    #[tokio::test]
    async fn an_archive_without_the_app_is_refused_and_the_old_app_stays() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = fake_app(dir.path(), "Thumbdesk.app", "thumbdesk", b"old");
        let staging = dir.path().join("staging");
        fs::create_dir_all(&staging).unwrap();

        assert!(install_app_bundle(&staging, &bundle).await.is_err());
        assert_eq!(fs::read(bundle.join("Contents/MacOS/thumbdesk")).unwrap(), b"old");
    }

    #[cfg(unix)]
    fn fake_binary(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("pocketshell");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_answers_version_passes_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_binary(dir.path(), r#"[ "$1" = --version ] && echo "thumbdesk 9.9.9""#);
        probe_binary(&bin, dir.path(), Duration::from_secs(10)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_cannot_load_is_refused_with_its_error() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_binary(
            dir.path(),
            "echo 'dyld: Library not loaded: ScreenCaptureKit' >&2; exit 134",
        );
        let err = probe_binary(&bin, dir.path(), Duration::from_secs(10))
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing to install"), "{err}");
        assert!(err.contains("Library not loaded"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_hangs_is_refused_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_binary(dir.path(), "sleep 30");
        let started = std::time::Instant::now();
        let err = probe_binary(&bin, dir.path(), Duration::from_millis(300))
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not answer"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_binary_that_is_missing_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = probe_binary(&dir.path().join("nope"), dir.path(), Duration::from_secs(5))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be started"), "{err}");
    }

    #[cfg(unix)]
    fn file(path: &Path, body: &[u8]) {
        fs::write(path, body).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_extracted_binary_is_thumbdesk_when_it_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        file(&dir.path().join("pocketshell"), b"old name");
        file(&dir.path().join("thumbdesk"), b"new name");
        assert_eq!(extracted_binary(dir.path()), Some(dir.path().join("thumbdesk")));
    }

    #[cfg(unix)]
    #[test]
    fn a_thumbdesk_link_is_passed_over_for_the_file_it_names() {
        // No release carries one, but should one: renaming the link over the
        // running binary would leave it pointing into the staging dir.
        let dir = tempfile::tempdir().unwrap();
        file(&dir.path().join("pocketshell"), b"binary");
        std::os::unix::fs::symlink("pocketshell", dir.path().join("thumbdesk")).unwrap();
        assert_eq!(extracted_binary(dir.path()), Some(dir.path().join("pocketshell")));
    }

    #[cfg(unix)]
    #[test]
    fn an_archive_from_before_the_rename_still_installs() {
        let dir = tempfile::tempdir().unwrap();
        file(&dir.path().join("pocketshell"), b"binary");
        assert_eq!(extracted_binary(dir.path()), Some(dir.path().join("pocketshell")));
    }

    #[test]
    fn an_archive_without_either_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README"), b"no binary").unwrap();
        assert_eq!(extracted_binary(dir.path()), None);
    }

    /// The archive the release workflow packs (one entry, `pocketshell`, a
    /// regular file), extracted with the same `tar -xzf` the updater runs,
    /// reads right both to an old agent, which takes `pocketshell` by name,
    /// and to this one.
    #[cfg(unix)]
    #[test]
    fn the_release_archive_layout_suits_old_and_new_agents() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("pack");
        fs::create_dir_all(&pack).unwrap();
        file(&pack.join("pocketshell"), b"binary");
        let archive = dir.path().join("pocketshell-v9.9.9-test.tar.gz");
        let packed = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&pack)
            .arg("pocketshell")
            .status()
            .unwrap();
        assert!(packed.success());

        let staging = dir.path().join("staging");
        fs::create_dir_all(&staging).unwrap();
        let unpacked = std::process::Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&staging)
            .status()
            .unwrap();
        assert!(unpacked.success());

        // What an old agent checks and renames into place: a regular file,
        // and nothing beside it.
        let old_pick = staging.join("pocketshell");
        assert!(old_pick.symlink_metadata().unwrap().is_file());
        assert_eq!(extracted_binary(&staging), Some(old_pick));
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 1);
    }

    #[test]
    fn with_old_suffix_appends_dot_old() {
        assert_eq!(
            with_old_suffix(Path::new("/usr/local/bin/pocketshell")),
            PathBuf::from("/usr/local/bin/pocketshell.old")
        );
        assert_eq!(
            with_old_suffix(Path::new("/opt/pocketshell.exe")),
            PathBuf::from("/opt/pocketshell.exe.old")
        );
    }

    #[test]
    fn developer_id_requirement_pins_team_id_and_apple_anchor() {
        let req = developer_id_requirement("ABCDE12345");
        // Pin the exact requirement clause: changing any of these tokens is a
        // semantic change to what "we signed this" means, and should require
        // an explicit test update — not a silent edit.
        assert!(req.contains("anchor apple generic"));
        assert!(req.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
        assert!(req.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert!(req.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
    }

    #[test]
    fn verify_macos_codesign_is_noop_on_non_macos() {
        // Off-platform the verify must short-circuit so Linux/Windows builds
        // of `thumbdesk update` don't try to spawn a non-existent `codesign`.
        // We can't assert codesign behavior portably on macOS in unit tests
        // because it depends on a properly-signed binary at the given path.
        #[cfg(not(target_os = "macos"))]
        verify_macos_codesign(Path::new("/nonexistent")).unwrap();
    }

    #[test]
    fn cosign_identity_regexp_anchors_and_matches_expected_workflow_path() {
        // Pin the exact shape of the certificate-identity-regexp so a typo in
        // the workflow path (e.g. renaming release-host-agent.yml) is caught
        // here, not at update time on every user's machine.
        assert!(COSIGN_IDENTITY_REGEXP.starts_with("^https://github\\.com/"));
        assert!(COSIGN_IDENTITY_REGEXP.ends_with("$"));
        assert!(COSIGN_IDENTITY_REGEXP.contains("yashagldit/(PocketShell|Thumbdesk)/"));
        assert!(COSIGN_IDENTITY_REGEXP.contains("release-host-agent\\.yml"));
        assert!(COSIGN_IDENTITY_REGEXP.contains("refs/tags/v"));

        let re = regex::Regex::new(COSIGN_IDENTITY_REGEXP).expect("regexp must compile");
        assert!(re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent.yml@refs/tags/v0.1.0"
        ));
        assert!(re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent.yml@refs/tags/v1.2.3-beta.4"
        ));
        assert!(re.is_match(
            "https://github.com/yashagldit/Thumbdesk/.github/workflows/release-host-agent.yml@refs/tags/v1.4.0"
        ));
        // Negatives that must NOT satisfy the pin:
        assert!(!re.is_match(
            "https://github.com/somebodyelse/PocketShell/.github/workflows/release-host-agent.yml@refs/tags/v0.1.0"
        ));
        assert!(!re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent.yml@refs/heads/main"
        ));
        assert!(!re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent-test.yml@refs/tags/v0.1.0"
        ));
        // Only those two repos: not a look-alike, nor the private source repo.
        assert!(!re.is_match(
            "https://github.com/yashagldit/ThumbdeskX/.github/workflows/release-host-agent.yml@refs/tags/v1.4.0"
        ));
        assert!(!re.is_match(
            "https://github.com/yashagldit/PocketShellApp/.github/workflows/release-host-agent.yml@refs/tags/v1.4.0"
        ));
    }

    #[test]
    fn cosign_oidc_issuer_is_github_actions_token_endpoint() {
        // Anchored to GitHub Actions' OIDC issuer URL. If GitHub ever rotates
        // this we'll hit a runtime verify failure; pin it here so the symptom
        // is a failing unit test instead of users getting broken updates.
        assert_eq!(
            COSIGN_OIDC_ISSUER,
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn expected_team_id_is_set_and_well_formed() {
        // 10-char alphanumeric Team ID, per Apple's account format. If this
        // changes the codesign requirement clause changes too — the test
        // catches accidental edits that would break authenticity on update.
        assert_eq!(EXPECTED_APPLE_TEAM_ID.len(), 10);
        assert!(EXPECTED_APPLE_TEAM_ID
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_macos_codesign_rejects_unsigned_file() {
        // Live invocation of `codesign --verify` against a known-bad file.
        // Catches regressions in the requirement-clause syntax that wouldn't
        // surface in the string-builder test (e.g. forgetting the `-R=` form
        // vs. `-R ` two-arg form, which means very different things).
        let dir = tempfile::tempdir().unwrap();
        let unsigned = dir.path().join("not-a-macho");
        std::fs::write(&unsigned, b"definitely not a signed Mach-O").unwrap();
        let err = verify_macos_codesign(&unsigned).unwrap_err();
        // We don't pin the exact codesign stderr — Apple has changed wording
        // across macOS releases. We just need confirmation we hit the verify
        // path, not the spawn-failed path.
        assert!(
            err.to_string().contains("codesign --verify rejected"),
            "expected verify-rejection error, got: {err}"
        );
    }
}
