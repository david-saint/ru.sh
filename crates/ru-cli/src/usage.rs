use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::config::Config;

/// Default warning threshold for daily requests
pub const DEFAULT_DAILY_WARNING: u32 = 100;
/// Default warning threshold for monthly requests
pub const DEFAULT_MONTHLY_WARNING: u32 = 1000;

/// Usage statistics tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageStats {
    /// Number of requests made today
    pub requests_today: u32,
    /// Date of last request (YYYY-MM-DD format)
    pub last_request_date: Option<String>,
    /// Number of requests this month
    pub requests_this_month: u32,
    /// Month of last request (YYYY-MM format)
    pub last_request_month: Option<String>,
    /// Total requests all time
    pub total_requests: u32,
}

/// Warning about usage limits
#[derive(Debug, Clone)]
pub struct UsageWarning {
    pub message: String,
    pub is_limit_exceeded: bool,
}

impl UsageStats {
    /// Get the usage file path
    pub fn path() -> Option<PathBuf> {
        Config::dir().map(|dir| dir.join("usage.toml"))
    }

    /// Load usage stats from file
    pub fn load() -> Result<Self> {
        let path = match Self::path() {
            Some(p) => p,
            None => return Ok(Self::default()),
        };

        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read usage file: {}", path.display()))?;

        let mut stats: Self = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse usage file: {}", path.display()))?;

        // Reset counters if date/month changed
        stats.reset_if_needed();

        Ok(stats)
    }

    /// Save usage stats to file
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine usage path")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create usage directory: {}", parent.display())
            })?;
        }

        let contents = toml::to_string_pretty(self).context("Failed to serialize usage stats")?;

        fs::write(&path, contents)
            .with_context(|| format!("Failed to write usage file: {}", path.display()))?;

        Ok(())
    }

    /// Reset daily/monthly counters if the date has changed
    fn reset_if_needed(&mut self) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let this_month = Utc::now().format("%Y-%m").to_string();

        // Reset daily counter if date changed
        if self.last_request_date.as_ref() != Some(&today) {
            self.requests_today = 0;
        }

        // Reset monthly counter if month changed
        if self.last_request_month.as_ref() != Some(&this_month) {
            self.requests_this_month = 0;
        }
    }

    /// Increment usage counters
    pub fn increment(&mut self) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let this_month = Utc::now().format("%Y-%m").to_string();

        // Reset if needed before incrementing
        self.reset_if_needed();

        self.requests_today += 1;
        self.last_request_date = Some(today);

        self.requests_this_month += 1;
        self.last_request_month = Some(this_month);

        self.total_requests += 1;
    }

    /// Check usage against limits and return any warnings
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

/// Increment usage and check limits, returning any warnings
pub fn track_usage(
    daily_limit: Option<u32>,
    monthly_limit: Option<u32>,
) -> Result<Vec<UsageWarning>> {
    let mut stats = UsageStats::load()?;
    stats.increment();
    stats.save()?;

    Ok(stats.check_limits(daily_limit, monthly_limit))
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
        assert!(stats.last_request_month.is_some());
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
            last_request_date: Some(Utc::now().format("%Y-%m-%d").to_string()),
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
            last_request_month: Some(Utc::now().format("%Y-%m").to_string()),
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
            last_request_date: Some(Utc::now().format("%Y-%m-%d").to_string()),
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
            last_request_date: Some("2020-01-01".to_string()), // Old date
            ..Default::default()
        };

        stats.reset_if_needed();
        assert_eq!(stats.requests_today, 0);
    }

    #[test]
    fn test_reset_monthly_counter() {
        let mut stats = UsageStats {
            requests_this_month: 500,
            last_request_month: Some("2020-01".to_string()), // Old month
            ..Default::default()
        };

        stats.reset_if_needed();
        assert_eq!(stats.requests_this_month, 0);
    }

    #[test]
    fn test_no_reset_same_day() {
        let mut stats = UsageStats::default();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        stats.requests_today = 50;
        stats.last_request_date = Some(today);

        stats.reset_if_needed();
        assert_eq!(stats.requests_today, 50);
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
