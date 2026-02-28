use anyhow::{Context, Result};
use chrono::{Datelike, NaiveDate, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::config::Config;

/// Default warning threshold for daily requests
pub const DEFAULT_DAILY_WARNING: u32 = 100;
/// Default warning threshold for monthly requests
pub const DEFAULT_MONTHLY_WARNING: u32 = 1000;

/// Tracks API usage statistics for rate limit warnings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageStats {
    /// Number of requests made on the current day.
    pub requests_today: u32,
    /// The date of the last successful API request.
    pub last_request_date: Option<NaiveDate>,
    /// Number of requests made in the current calendar month.
    pub requests_this_month: u32,
    /// Total number of successful requests made across all time.
    pub total_requests: u32,
}

/// Represents a warning triggered when usage approaches or exceeds limits.
#[derive(Debug, Clone)]
pub struct UsageWarning {
    /// A human-readable message describing the usage state.
    pub message: String,
    /// Whether the usage has strictly exceeded the configured hard limit.
    pub is_limit_exceeded: bool,
}

impl UsageStats {
    /// Returns the path to the usage statistics file (`usage.toml`).
    pub fn path() -> Option<PathBuf> {
        Config::dir().map(|dir| dir.join("usage.toml"))
    }

    /// Loads the usage statistics from the default file path.
    pub fn load() -> Result<Self> {
        let path = match Self::path() {
            Some(p) => p,
            None => return Ok(Self::default()),
        };
        Self::load_from(path)
    }

    /// Loads the usage statistics from a specific file path.
    ///
    /// If the file is corrupted, it is backed up and fresh statistics are returned.
    pub fn load_from(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read usage file: {}", path.display()))?;

        let mut stats: Self = match toml::from_str::<Self>(&contents) {
            Ok(s) => s,
            Err(e) => {
                let bak_path = PathBuf::from(format!("{}.bak", path.display()));
                match fs::rename(&path, &bak_path) {
                    Ok(_) => {
                        eprintln!(
                            "{} Usage file at {} is corrupted and has been backed up to {}. Usage stats have been reset.",
                            "Warning:".yellow().bold(),
                            path.display(),
                            bak_path.display()
                        );
                    }
                    Err(rename_err) => {
                        eprintln!(
                            "{} Usage file at {} is corrupted. Failed to create backup: {}. Usage stats have been reset.",
                            "Warning:".yellow().bold(),
                            path.display(),
                            rename_err
                        );
                    }
                }
                eprintln!("{} {}", "Error details:".dimmed(), e);
                Self::default()
            }
        };

        // Reset counters if date/month changed
        stats.reset_if_needed();

        Ok(stats)
    }

    /// Saves the current usage statistics to the default file path.
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine usage path")?;
        self.save_to(path)
    }

    /// Saves the current usage statistics to a specific file path.
    pub fn save_to(&self, path: PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create usage directory: {}", parent.display())
            })?;
        }

        let contents = toml::to_string_pretty(self).context("Failed to serialize usage stats")?;

        // Write with restricted permissions (0600 on Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("Failed to open usage file: {}", path.display()))?
                .write_all(contents.as_bytes())
                .with_context(|| format!("Failed to write usage file: {}", path.display()))?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&path, contents)
                .with_context(|| format!("Failed to write usage file: {}", path.display()))?;
        }

        Ok(())
    }

    /// Reset daily/monthly counters if the date has changed
    fn reset_if_needed(&mut self) {
        let now = Utc::now().date_naive();
        let today = now;
        let this_month = (now.year(), now.month());

        // Reset daily counter if date changed
        if self.last_request_date != Some(today) {
            self.requests_today = 0;
        }

        // Reset monthly counter if month changed or the last date is missing.
        let same_month = self
            .last_request_date
            .map(|last_date| (last_date.year(), last_date.month()) == this_month)
            .unwrap_or(false);
        if !same_month {
            self.requests_this_month = 0;
        }
    }

    /// Increments the usage counters and updates the last request date.
    ///
    /// This automatically calls `reset_if_needed` before incrementing.
    pub fn increment(&mut self) {
        let now = Utc::now().date_naive();

        // Reset if needed before incrementing
        self.reset_if_needed();

        self.requests_today += 1;
        self.last_request_date = Some(now);

        self.requests_this_month += 1;

        self.total_requests += 1;
    }

    /// Checks the current statistics against provided limits.
    ///
    /// If no explicit limits are provided, it uses the default warning thresholds.
    pub fn check_limits(
        &self,
        daily_limit: Option<u32>,
        monthly_limit: Option<u32>,
    ) -> Vec<UsageWarning> {
        let mut warnings = Vec::new();

        let daily_threshold = daily_limit.unwrap_or(DEFAULT_DAILY_WARNING);
        let monthly_threshold = monthly_limit.unwrap_or(DEFAULT_MONTHLY_WARNING);

        // Check daily limit
        if self.requests_today >= daily_threshold {
            let is_exceeded = daily_limit
                .map(|l| self.requests_today >= l)
                .unwrap_or(false);
            warnings.push(UsageWarning {
                message: format!(
                    "Daily usage: {}/{} requests{}",
                    self.requests_today,
                    daily_threshold,
                    if is_exceeded { " (LIMIT EXCEEDED)" } else { "" }
                ),
                is_limit_exceeded: is_exceeded,
            });
        }

        // Check monthly limit
        if self.requests_this_month >= monthly_threshold {
            let is_exceeded = monthly_limit
                .map(|l| self.requests_this_month >= l)
                .unwrap_or(false);
            warnings.push(UsageWarning {
                message: format!(
                    "Monthly usage: {}/{} requests{}",
                    self.requests_this_month,
                    monthly_threshold,
                    if is_exceeded { " (LIMIT EXCEEDED)" } else { "" }
                ),
                is_limit_exceeded: is_exceeded,
            });
        }

        warnings
    }
}

/// Checks API usage against limits without modifying the stored statistics.
///
/// This is typically called before making an API request to prevent
/// exceeding configured thresholds.
pub fn check_usage(
    daily_limit: Option<u32>,
    monthly_limit: Option<u32>,
) -> Result<Vec<UsageWarning>> {
    let stats = UsageStats::load()?;
    Ok(stats.check_limits(daily_limit, monthly_limit))
}

/// Increments the persistent usage statistics by one.
pub fn record_successful_request() -> Result<()> {
    let mut stats = UsageStats::load()?;
    stats.increment();
    stats.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage_stats_default() {
        let stats = UsageStats::default();
        assert_eq!(stats.requests_today, 0);
        assert_eq!(stats.requests_this_month, 0);
        assert_eq!(stats.total_requests, 0);
    }

    #[test]
    fn test_usage_stats_increment() {
        let mut stats = UsageStats::default();
        stats.increment();

        assert_eq!(stats.requests_today, 1);
        assert_eq!(stats.requests_this_month, 1);
        assert_eq!(stats.total_requests, 1);
        assert!(stats.last_request_date.is_some());
    }

    #[test]
    fn test_usage_stats_increment_multiple() {
        let mut stats = UsageStats::default();
        stats.increment();
        stats.increment();
        stats.increment();

        assert_eq!(stats.requests_today, 3);
        assert_eq!(stats.requests_this_month, 3);
        assert_eq!(stats.total_requests, 3);
    }

    #[test]
    fn test_check_limits_no_warnings() {
        let stats = UsageStats::default();
        let warnings = stats.check_limits(Some(100), Some(1000));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_limits_daily_warning() {
        let stats = UsageStats {
            requests_today: 100,
            last_request_date: Some(Utc::now().date_naive()),
            ..Default::default()
        };

        let warnings = stats.check_limits(Some(100), Some(1000));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("Daily usage"));
        assert!(warnings[0].is_limit_exceeded);
    }

    #[test]
    fn test_check_limits_monthly_warning() {
        let stats = UsageStats {
            requests_this_month: 1000,
            // Even if we don't set last_request_date, limits are checked against counters
            ..Default::default()
        };

        let warnings = stats.check_limits(Some(100), Some(1000));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("Monthly usage"));
        assert!(warnings[0].is_limit_exceeded);
    }

    #[test]
    fn test_check_limits_default_thresholds() {
        let stats = UsageStats {
            requests_today: DEFAULT_DAILY_WARNING,
            last_request_date: Some(Utc::now().date_naive()),
            ..Default::default()
        };

        // No limits set, use defaults
        let warnings = stats.check_limits(None, None);
        assert_eq!(warnings.len(), 1);
        assert!(!warnings[0].is_limit_exceeded); // Warnings but not exceeded (no hard limit)
    }

    #[test]
    fn test_reset_daily_counter() {
        let mut stats = UsageStats {
            requests_today: 50,
            last_request_date: NaiveDate::from_ymd_opt(2020, 1, 1), // Old date
            ..Default::default()
        };

        stats.reset_if_needed();
        assert_eq!(stats.requests_today, 0);
    }

    #[test]
    fn test_reset_monthly_counter() {
        let mut stats = UsageStats {
            requests_this_month: 500,
            // Use a date from a different month (Jan 2020)
            last_request_date: NaiveDate::from_ymd_opt(2020, 1, 1),
            ..Default::default()
        };

        stats.reset_if_needed();
        assert_eq!(stats.requests_this_month, 0);
    }

    #[test]
    fn test_no_reset_same_day() {
        let mut stats = UsageStats::default();
        let today = Utc::now().date_naive();
        stats.requests_today = 50;
        stats.last_request_date = Some(today);

        stats.reset_if_needed();
        assert_eq!(stats.requests_today, 50);
    }

    #[test]
    fn test_reset_monthly_counter_when_last_date_missing() {
        let mut stats = UsageStats {
            requests_this_month: 42,
            last_request_date: None,
            ..Default::default()
        };

        stats.reset_if_needed();
        assert_eq!(stats.requests_this_month, 0);
    }

    #[test]
    fn test_load_corrupted_usage_recovers() -> Result<()> {
        use tempfile::NamedTempFile;
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        // Write invalid TOML
        fs::write(&path, "invalid = toml = format")?;

        let stats = UsageStats::load_from(path.clone())?;
        assert_eq!(stats.total_requests, 0);

        let bak_path = PathBuf::from(format!("{}.bak", path.display()));
        assert!(bak_path.exists());
        assert!(!path.exists());

        Ok(())
    }

    #[test]
    fn test_serialize_deserialize() -> Result<()> {
        let mut stats = UsageStats::default();
        stats.increment();
        stats.increment();

        let toml_str = toml::to_string_pretty(&stats)?;
        let loaded: UsageStats = toml::from_str(&toml_str)?;

        assert_eq!(loaded.requests_today, stats.requests_today);
        assert_eq!(loaded.requests_this_month, stats.requests_this_month);
        assert_eq!(loaded.total_requests, stats.total_requests);

        Ok(())
    }
}
