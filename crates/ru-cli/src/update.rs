use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
use tokio::task::JoinHandle;

use crate::config::Config;

const GITHUB_RELEASES_URL: &str = "https://api.github.com/repos/david-saint/ru.sh/releases/latest";

const CHECK_INTERVAL_SECS: i64 = 24 * 60 * 60; // 24 hours

// ---------------------------------------------------------------------------
// Persisted state
// ---------------------------------------------------------------------------

/// Manages the persistent state of the update checker.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateState {
    /// The timestamp of the last successful update check.
    pub last_check: Option<DateTime<Utc>>,
    /// The latest version string retrieved from GitHub.
    pub latest_version: Option<String>,
}

impl UpdateState {
    fn path() -> Option<PathBuf> {
        Config::dir().map(|dir| dir.join("update.toml"))
    }

    /// Loads the update state from the configuration directory.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        if !path.exists() {
            return Self::default();
        }
        fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Saves the current update state to the configuration directory.
    pub fn save(&self) {
        let Some(path) = Self::path() else { return };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(contents) = toml::to_string_pretty(self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                if let Ok(mut f) = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                {
                    let _ = f.write_all(contents.as_bytes());
                }
            }
            #[cfg(not(unix))]
            {
                let _ = fs::write(&path, contents);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub API types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

/// Parse a version string like "0.1.7" or "v0.1.7" into (major, minor, patch).
fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Returns true if `candidate` is strictly newer than `current`.
fn is_newer(current: &str, candidate: &str) -> bool {
    match (parse_version(current), parse_version(candidate)) {
        (Some(cur), Some(cand)) => cand > cur,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Platform detection (compile-time)
// ---------------------------------------------------------------------------

fn target_triple() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    {
        "x86_64-pc-windows-msvc"
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"),
    )))]
    {
        "unsupported"
    }
}

/// Returns the expected archive extension for the current platform.
fn archive_ext() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "zip"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "tar.gz"
    }
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

/// Fetch the latest release metadata from GitHub.
async fn fetch_latest_release() -> Result<GitHubRelease> {
    let client = crate::api::http_client();
    let resp = client
        .get(GITHUB_RELEASES_URL)
        .header(
            "User-Agent",
            format!("ru-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("Failed to reach GitHub API")?;

    if !resp.status().is_success() {
        bail!("GitHub API returned status {}", resp.status().as_u16());
    }

    resp.json::<GitHubRelease>()
        .await
        .context("Failed to parse GitHub release response")
}

// ---------------------------------------------------------------------------
// Check for update (used by both background check & `ru update`)
// ---------------------------------------------------------------------------

/// Check whether a newer version exists. Returns the newer version string if so.
async fn check_for_update() -> Result<Option<String>> {
    let current = env!("CARGO_PKG_VERSION");
    let release = fetch_latest_release().await?;
    let latest = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);

    let mut state = UpdateState::load();
    state.last_check = Some(Utc::now());
    state.latest_version = Some(latest.to_string());
    state.save();

    if is_newer(current, latest) {
        Ok(Some(latest.to_string()))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Background check (spawned from run_prompt)
// ---------------------------------------------------------------------------

/// Spawns a background task to check for updates.
///
/// The check is only performed if it has been more than 24 hours since the
/// last check. Returns `None` if the check was skipped.
pub fn spawn_background_check() -> Option<JoinHandle<Option<String>>> {
    let state = UpdateState::load();
    if let Some(last) = state.last_check {
        let elapsed = Utc::now().signed_duration_since(last).num_seconds();
        if elapsed < CHECK_INTERVAL_SECS {
            return None;
        }
    }

    Some(tokio::spawn(async {
        check_for_update().await.unwrap_or(None)
    }))
}

/// Prints a notification to stderr informing the user that a new version is available.
pub fn print_update_notification(new_version: &str) {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!(
        "{}",
        format!(
            "A new version of ru is available: {} -> {} (run `ru update` to upgrade)",
            current, new_version
        )
        .yellow()
    );
}

// ---------------------------------------------------------------------------
// Full update flow (`ru update`)
// ---------------------------------------------------------------------------

/// Executes the full self-update flow.
///
/// This function checks for the latest release on GitHub, downloads the
/// appropriate archive for the current platform, verifies its checksum,
/// and replaces the current binary with the new version.
///
/// # Errors
///
/// Returns an error if any step of the update process fails (network,
/// verification, or file system operations).
pub async fn perform_update() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("{}", format!("Current version: {}", current).dimmed());
    eprintln!("{}", "Checking for updates...".dimmed());

    let release = fetch_latest_release().await?;
    let latest = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);

    // Persist check timestamp
    let mut state = UpdateState::load();
    state.last_check = Some(Utc::now());
    state.latest_version = Some(latest.to_string());
    state.save();

    if !is_newer(current, latest) {
        println!("{}", format!("Already up to date (v{}).", current).green());
        return Ok(());
    }

    println!(
        "{}",
        format!("New version available: {} -> {}", current, latest).yellow()
    );

    // Find the right asset for this platform
    let triple = target_triple();
    if triple == "unsupported" {
        bail!(
            "Auto-update is not supported on this platform. Please download manually from:\nhttps://github.com/david-saint/ru.sh/releases/latest"
        );
    }
    let ext = archive_ext();
    let version = latest;
    let archive_name = format!("ru-{}-{}.{}", version, triple, ext);

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == archive_name)
        .with_context(|| {
            format!(
                "Could not find release asset '{}'. Available assets: {}",
                archive_name,
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    // Checksum verification is mandatory for updater integrity.
    let checksums_asset = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS")
        .with_context(|| {
            format!(
                "Release '{}' is missing SHA256SUMS; refusing to update without checksum metadata",
                release.tag_name
            )
        })?;

    // Download the archive
    eprintln!("{}", format!("Downloading {}...", archive_name).dimmed());
    let archive_bytes = download_asset(&asset.browser_download_url).await?;

    eprintln!("{}", "Verifying checksum...".dimmed());
    let sums_text = download_asset_text(&checksums_asset.browser_download_url).await?;
    verify_checksum(&archive_bytes, &archive_name, &sums_text)?;
    eprintln!("{}", "Checksum verified.".green());

    // Extract and self-replace
    let binary_path =
        std::env::current_exe().context("Could not determine current executable path")?;

    extract_and_replace(&archive_bytes, &binary_path, ext)?;

    println!(
        "{}",
        format!("Successfully updated to v{}!", version)
            .green()
            .bold()
    );

    Ok(())
}

/// Download an asset as raw bytes.
async fn download_asset(url: &str) -> Result<Vec<u8>> {
    let client = crate::api::http_client();
    let resp = client
        .get(url)
        .header(
            "User-Agent",
            format!("ru-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .context("Failed to download asset")?;

    if !resp.status().is_success() {
        bail!("Download failed with status {}", resp.status().as_u16());
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .context("Failed to read asset bytes")
}

/// Download an asset as text.
async fn download_asset_text(url: &str) -> Result<String> {
    let client = crate::api::http_client();
    let resp = client
        .get(url)
        .header(
            "User-Agent",
            format!("ru-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .context("Failed to download checksums")?;

    if !resp.status().is_success() {
        bail!(
            "Checksum download failed with status {}",
            resp.status().as_u16()
        );
    }

    resp.text().await.context("Failed to read checksum text")
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

/// Verify the SHA-256 checksum of `data` against an entry in `sums_text`
/// for `file_name`.  The sums file uses the `sha256sum` output format:
///   `<hex_hash>  <filename>`
fn verify_checksum(data: &[u8], file_name: &str, sums_text: &str) -> Result<()> {
    let expected = sums_text
        .lines()
        .find_map(|line| {
            // sha256sum format: "<hash>  <filename>" or "<hash> *<filename>"
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            let name = parts.next()?.trim_start_matches('*');
            if name == file_name {
                Some(hash.to_lowercase())
            } else {
                None
            }
        })
        .with_context(|| format!("No checksum entry found for '{}'", file_name))?;

    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual = format!("{:x}", hasher.finalize());

    if actual != expected {
        bail!(
            "Checksum mismatch for '{}'!\n  expected: {}\n  actual:   {}",
            file_name,
            expected,
            actual
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Extraction & self-replace
// ---------------------------------------------------------------------------

/// Create a secure temporary directory for update extraction.
fn make_temp_dir() -> Result<TempDir> {
    tempfile::Builder::new()
        .prefix("ru-update-")
        .tempdir()
        .context("Failed to create temporary directory for update")
}

/// Return true if an archive member path is safe to extract under `tmp_dir`.
fn is_safe_archive_member(member: &str) -> bool {
    if member.is_empty() || member.contains('\\') {
        return false;
    }

    let path = Path::new(member);
    if path.is_absolute() {
        return false;
    }

    let mut has_normal_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => has_normal_component = true,
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir => return false,
            _ => return false,
        }
    }

    has_normal_component
}

fn list_tar_members(archive_path: &Path) -> Result<Vec<String>> {
    let output = std::process::Command::new("tar")
        .arg("tzf")
        .arg(archive_path)
        .output()
        .context("Failed to list archive contents with tar")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to inspect update archive (tar list exited with {:?}): {}",
            output.status.code(),
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn select_binary_member(members: &[String], binary_name: &str) -> Option<String> {
    let root = members
        .iter()
        .find(|entry| {
            let trimmed = entry.trim_start_matches("./");
            trimmed == binary_name && is_safe_archive_member(trimmed)
        })
        .cloned();

    if root.is_some() {
        return root;
    }

    members
        .iter()
        .filter(|entry| is_safe_archive_member(entry))
        .filter(|entry| {
            Path::new(entry)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == binary_name)
        })
        .min_by_key(|entry| Path::new(entry).components().count())
        .cloned()
}

fn validate_extracted_binary(extracted: &Path, tmp_dir: &Path, binary_name: &str) -> Result<()> {
    let meta = fs::symlink_metadata(extracted).with_context(|| {
        format!(
            "Expected binary '{}' not found after extraction",
            extracted.display()
        )
    })?;

    if !meta.file_type().is_file() {
        bail!(
            "Extracted archive entry '{}' is not a regular file",
            extracted.display()
        );
    }

    let canonical_tmp = tmp_dir
        .canonicalize()
        .context("Failed to canonicalize extraction directory")?;
    let canonical_extracted = extracted
        .canonicalize()
        .context("Failed to canonicalize extracted binary path")?;
    if !canonical_extracted.starts_with(&canonical_tmp) {
        bail!("Archive extraction escaped the temporary directory");
    }

    let file_name = extracted
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if file_name != binary_name {
        bail!(
            "Unexpected extracted filename '{}', expected '{}'",
            file_name,
            binary_name
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn powershell_single_quote_escape(input: &str) -> String {
    input.replace('\'', "''")
}

/// Extract the binary from the archive and replace the current executable.
fn extract_and_replace(archive_bytes: &[u8], binary_path: &PathBuf, ext: &str) -> Result<()> {
    let tmp_dir = make_temp_dir()?;
    let archive_path = tmp_dir.path().join(format!("ru-archive.{}", ext));
    fs::write(&archive_path, archive_bytes).context("Failed to write archive to temp dir")?;

    let binary_name = if cfg!(target_os = "windows") {
        "ru.exe"
    } else {
        "ru"
    };

    // Extract
    if ext == "tar.gz" {
        let members = list_tar_members(&archive_path)?;
        let selected = select_binary_member(&members, binary_name).with_context(|| {
            format!(
                "Could not find binary '{}' in update archive contents",
                binary_name
            )
        })?;
        if !is_safe_archive_member(&selected) {
            bail!("Archive contained unsafe path '{}'", selected);
        }

        let status = std::process::Command::new("tar")
            .arg("xzf")
            .arg(&archive_path)
            .arg("-C")
            .arg(tmp_dir.path())
            .args(["--no-same-owner", "--no-same-permissions"])
            .arg("--")
            .arg(&selected)
            .status()
            .context("Failed to run tar. Is tar installed?")?;

        if !status.success() {
            bail!("tar extraction failed with exit code {:?}", status.code());
        }

        let extracted = tmp_dir.path().join(selected.trim_start_matches("./"));
        validate_extracted_binary(&extracted, tmp_dir.path(), binary_name)?;

        // Self-replace: write to temp file in the same directory, then atomic rename
        self_replace(&extracted, binary_path)?;
    } else {
        // zip on Windows — extract only the binary entry to avoid blind extraction.
        #[cfg(target_os = "windows")]
        {
            let extracted = tmp_dir.path().join(binary_name);
            let ps_script = format!(
                "$ErrorActionPreference='Stop'; \
                 Add-Type -AssemblyName System.IO.Compression.FileSystem; \
                 $zip=[System.IO.Compression.ZipFile]::OpenRead('{archive}'); \
                 try {{ \
                     $entry=$zip.Entries | Where-Object {{ \
                         -not $_.FullName.Contains('..') -and \
                         -not $_.FullName.StartsWith('/') -and \
                         -not $_.FullName.StartsWith('\\\\') -and \
                         $_.Name -eq '{binary}' \
                     }} | Sort-Object FullName | Select-Object -First 1; \
                     if (-not $entry) {{ exit 2 }}; \
                     [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, '{dest}', $true); \
                 }} finally {{ \
                     $zip.Dispose(); \
                 }}",
                archive = powershell_single_quote_escape(&archive_path.display().to_string()),
                binary = powershell_single_quote_escape(binary_name),
                dest = powershell_single_quote_escape(&extracted.display().to_string()),
            );

            let status = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_script])
                .status()
                .context("Failed to run PowerShell for extraction")?;

            if status.code() == Some(2) {
                bail!("Expected binary '{}' not found in zip archive", binary_name);
            }
            if !status.success() {
                bail!("zip extraction failed");
            }

            validate_extracted_binary(&extracted, tmp_dir.path(), binary_name)?;
            self_replace(&extracted, binary_path)?;
        }
        #[cfg(not(target_os = "windows"))]
        {
            bail!("zip extraction is only supported on Windows");
        }
    }

    Ok(())
}

/// Atomically replace the binary at `target` with `source`.
///
/// On Unix: copy new binary to a temp file in the same dir, rename current
/// binary to backup, rename new binary into place (same-fs rename = atomic).
///
/// On Windows: the OS locks running executables against deletion/overwrite,
/// but *does* allow renaming them.  So we rename the running binary to a
/// backup name first, then copy the new binary to the original path.
fn self_replace(source: &PathBuf, target: &PathBuf) -> Result<()> {
    let target_dir = target
        .parent()
        .context("Could not determine parent directory of current binary")?;

    let tmp_new = target_dir.join(".ru-update-new");
    let backup = target_dir.join(".ru-update-backup");

    // Clean up any leftover files from a previous failed update.
    // On Windows the backup may still be present from the previous run
    // (we can delete it now because it's no longer the running process).
    let _ = fs::remove_file(&tmp_new);
    let _ = fs::remove_file(&backup);

    // Copy new binary to temp location in the same directory
    fs::copy(source, &tmp_new).context("Failed to copy new binary")?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&tmp_new, perms).context("Failed to set executable permissions")?;
    }

    // Rename current (running) binary to backup.
    // Windows allows renaming a running executable; it just forbids
    // deleting or overwriting it in place.
    if let Err(e) = fs::rename(target, &backup) {
        let _ = fs::remove_file(&tmp_new);
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            #[cfg(unix)]
            bail!(
                "Permission denied when updating {}. Try: sudo ru update",
                target.display()
            );
            #[cfg(not(unix))]
            bail!(
                "Permission denied when updating {}. Try running your terminal as Administrator.",
                target.display()
            );
        }
        return Err(e).context("Failed to move current binary to backup");
    }

    // Move new binary into place
    if let Err(e) = fs::rename(&tmp_new, target) {
        // Attempt to restore backup
        let _ = fs::rename(&backup, target);
        let _ = fs::remove_file(&tmp_new);
        return Err(e).context("Failed to move new binary into place");
    }

    // Clean up backup.  On Windows this will fail because the backup *is*
    // the still-running executable — that's fine, we'll clean it up on the
    // next update invocation (see cleanup above).
    let _ = fs::remove_file(&backup);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_basic() {
        assert_eq!(parse_version("0.1.7"), Some((0, 1, 7)));
        assert_eq!(parse_version("v0.1.7"), Some((0, 1, 7)));
        assert_eq!(parse_version("1.0.0"), Some((1, 0, 0)));
        assert_eq!(parse_version("12.34.56"), Some((12, 34, 56)));
    }

    #[test]
    fn test_parse_version_invalid() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("0.1"), None);
        assert_eq!(parse_version("abc"), None);
        assert_eq!(parse_version("0.1.7.8"), None);
        assert_eq!(parse_version("v"), None);
        assert_eq!(parse_version("0.1.abc"), None);
    }

    #[test]
    fn test_is_newer() {
        assert!(is_newer("0.1.7", "0.1.8"));
        assert!(is_newer("0.1.7", "0.2.0"));
        assert!(is_newer("0.1.7", "1.0.0"));
        assert!(is_newer("0.1.7", "v0.1.8"));
    }

    #[test]
    fn test_is_not_newer() {
        assert!(!is_newer("0.1.7", "0.1.7")); // same
        assert!(!is_newer("0.1.8", "0.1.7")); // older
        assert!(!is_newer("1.0.0", "0.9.9")); // older
    }

    #[test]
    fn test_is_newer_with_v_prefix() {
        assert!(is_newer("v0.1.7", "v0.1.8"));
        assert!(is_newer("v0.1.7", "0.1.8"));
        assert!(is_newer("0.1.7", "v0.1.8"));
    }

    #[test]
    fn test_is_newer_invalid() {
        assert!(!is_newer("invalid", "0.1.8"));
        assert!(!is_newer("0.1.7", "invalid"));
        assert!(!is_newer("", ""));
    }

    #[test]
    fn test_target_triple_is_known() {
        let triple = target_triple();
        let known = [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ];
        assert!(
            known.contains(&triple) || triple == "unsupported",
            "unexpected triple: {}",
            triple
        );
    }

    #[test]
    fn test_archive_ext() {
        let ext = archive_ext();
        assert!(ext == "tar.gz" || ext == "zip");
    }

    #[test]
    fn test_is_safe_archive_member() {
        assert!(is_safe_archive_member("ru"));
        assert!(is_safe_archive_member("./ru"));
        assert!(is_safe_archive_member("bin/ru"));
        assert!(!is_safe_archive_member(""));
        assert!(!is_safe_archive_member("../ru"));
        assert!(!is_safe_archive_member("/tmp/ru"));
        assert!(!is_safe_archive_member("bin\\ru"));
    }

    #[test]
    fn test_select_binary_member_prefers_safe_path() {
        let members = vec![
            "../ru".to_string(),
            "nested/ru".to_string(),
            "ru".to_string(),
        ];
        assert_eq!(select_binary_member(&members, "ru"), Some("ru".to_string()));
    }

    #[test]
    fn test_select_binary_member_rejects_only_unsafe_entries() {
        let members = vec!["../ru".to_string(), "/etc/passwd".to_string()];
        assert_eq!(select_binary_member(&members, "ru"), None);
    }

    #[test]
    fn test_verify_checksum_success() {
        let data = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        let sums_text = format!("{}  test-file.tar.gz\n", hash);
        assert!(verify_checksum(data, "test-file.tar.gz", &sums_text).is_ok());
    }

    #[test]
    fn test_verify_checksum_mismatch() {
        let data = b"hello world";
        let sums_text =
            "0000000000000000000000000000000000000000000000000000000000000000  test-file.tar.gz\n";
        let result = verify_checksum(data, "test-file.tar.gz", sums_text);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Checksum mismatch")
        );
    }

    #[test]
    fn test_verify_checksum_missing_entry() {
        let data = b"hello world";
        let sums_text = "abcdef1234567890  other-file.tar.gz\n";
        let result = verify_checksum(data, "test-file.tar.gz", sums_text);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No checksum entry")
        );
    }

    #[test]
    fn test_update_state_serialization() {
        let state = UpdateState {
            last_check: Some(Utc::now()),
            latest_version: Some("0.2.0".to_string()),
        };
        let toml_str = toml::to_string_pretty(&state).unwrap();
        let loaded: UpdateState = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.latest_version, state.latest_version);
        assert!(loaded.last_check.is_some());
    }

    #[test]
    fn test_update_state_default() {
        let state = UpdateState::default();
        assert!(state.last_check.is_none());
        assert!(state.latest_version.is_none());
    }
}
