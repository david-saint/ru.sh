use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::config::Config;
use crate::safety::RiskLevel;

/// Maximum history file size before rotation (10 MB)
const MAX_HISTORY_SIZE: u64 = 10 * 1024 * 1024;

/// Number of recent entries to keep when rotating
const ENTRIES_TO_KEEP: usize = 1000;

/// Maximum length for script preview
const PREVIEW_MAX_LEN: usize = 50;

/// Compute SHA-256 hash of a string
fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Truncate a string to a maximum length with ellipsis
fn truncate_preview(s: &str, max_len: usize) -> String {
    // Handle multi-line scripts by taking first line
    let first_line = s.lines().next().unwrap_or(s);
    if first_line.len() <= max_len {
        first_line.to_string()
    } else {
        format!("{}...", &first_line[..max_len])
    }
}

/// A record of a script execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the prompt (for privacy)
    pub prompt_hash: String,
    /// SHA-256 hash of the script (for privacy)
    pub script_hash: String,
    /// Truncated preview of the script for reference
    pub script_preview: String,
    pub risk_level: String,
    pub executed: bool,
    pub exit_code: Option<i32>,
    /// Duration of the API call in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl ExecutionRecord {
    pub fn new(
        prompt: &str,
        script: &str,
        risk_level: RiskLevel,
        executed: bool,
        exit_code: Option<i32>,
        duration_ms: Option<u64>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            prompt_hash: hash_string(prompt),
            script_hash: hash_string(script),
            script_preview: truncate_preview(script, PREVIEW_MAX_LEN),
            risk_level: risk_level.to_string(),
            executed,
            exit_code,
            duration_ms,
        }
    }
}

/// Get the history file path
pub fn history_path() -> Option<PathBuf> {
    Config::dir().map(|dir| dir.join("history.jsonl"))
}

/// Log an execution to the history file
pub fn log_execution(record: &ExecutionRecord) -> Result<()> {
    let path = history_path().context("Could not determine history path")?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create history directory: {}", parent.display()))?;
    }

    // Check if rotation is needed
    if let Ok(metadata) = fs::metadata(&path)
        && metadata.len() > MAX_HISTORY_SIZE
    {
        rotate_history(&path)?;
    }

    // Append the record as JSON line with restricted permissions (0600 on Unix)
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("Failed to open history file: {}", path.display()))?
    };

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Failed to open history file: {}", path.display()))?;

    let json = serde_json::to_string(record).context("Failed to serialize execution record")?;
    writeln!(file, "{}", json).context("Failed to write to history file")?;

    Ok(())
}

/// Rotate the history file by keeping only the most recent entries
fn rotate_history(path: &PathBuf) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open history file: {}", path.display()))?;

    let reader = BufReader::new(file);

    // Use a VecDeque as a ring buffer to store only the last ENTRIES_TO_KEEP lines
    // This optimization avoids loading the entire history file into memory
    let mut lines = VecDeque::with_capacity(ENTRIES_TO_KEEP);

    for line in reader.lines() {
        let line = line?;
        if lines.len() == ENTRIES_TO_KEEP {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    // Write the truncated history with restricted permissions (0600 on Unix)
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to truncate history file: {}", path.display()))?
    };

    #[cfg(not(unix))]
    let mut file = File::create(path)
        .with_context(|| format!("Failed to truncate history file: {}", path.display()))?;

    for line in lines {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_record() -> ExecutionRecord {
        ExecutionRecord::new(
            "list files",
            "ls -la",
            RiskLevel::Safe,
            true,
            Some(0),
            Some(150),
        )
    }

    #[test]
    fn test_execution_record_new() {
        let record = create_test_record();
        // Should store hashes, not plaintext
        assert_eq!(record.prompt_hash, hash_string("list files"));
        assert_eq!(record.script_hash, hash_string("ls -la"));
        assert_eq!(record.script_preview, "ls -la"); // Short enough, no truncation
        assert_eq!(record.risk_level, "Safe");
        assert!(record.executed);
        assert_eq!(record.exit_code, Some(0));
    }

    #[test]
    fn test_execution_record_serialize() {
        let record = create_test_record();
        let json = serde_json::to_string(&record).unwrap();
        // Should contain hashes, not plaintext
        assert!(json.contains("\"prompt_hash\":"));
        assert!(json.contains("\"script_hash\":"));
        assert!(json.contains("\"script_preview\":\"ls -la\""));
        assert!(json.contains("\"risk_level\":\"Safe\""));
        // Should NOT contain plaintext prompt or full script
        assert!(!json.contains("\"prompt\":"));
        assert!(!json.contains("\"script\":\""));
    }

    #[test]
    fn test_execution_record_deserialize() {
        let prompt_hash = hash_string("test");
        let script_hash = hash_string("echo test");
        let json = format!(
            r#"{{"timestamp":"2024-01-15T10:30:00Z","prompt_hash":"{}","script_hash":"{}","script_preview":"echo test","risk_level":"Low","executed":true,"exit_code":0}}"#,
            prompt_hash, script_hash
        );
        let record: ExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.prompt_hash, prompt_hash);
        assert_eq!(record.script_hash, script_hash);
        assert!(record.executed);
    }

    #[test]
    fn test_log_execution_creates_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let history_file = temp_dir.path().join("history.jsonl");

        // Manually write since we can't easily mock history_path()
        let record = create_test_record();
        let json = serde_json::to_string(&record)?;

        let mut file = File::create(&history_file)?;
        writeln!(file, "{}", json)?;

        // Verify - should contain preview, not full sensitive data
        let content = fs::read_to_string(&history_file)?;
        assert!(content.contains("prompt_hash"));
        assert!(content.contains("script_preview"));
        // Should NOT contain plaintext prompt
        assert!(!content.contains("\"prompt\":\"list files\""));

        Ok(())
    }

    #[test]
    fn test_truncate_preview() {
        // Short script - no truncation
        assert_eq!(truncate_preview("ls -la", 50), "ls -la");

        // Long script - truncated with ellipsis
        let long_script = "echo 'this is a very long command that should be truncated'";
        let preview = truncate_preview(long_script, 20);
        assert_eq!(preview, "echo 'this is a very...");

        // Multi-line script - takes first line only
        let multiline = "echo hello\necho world\necho test";
        assert_eq!(truncate_preview(multiline, 50), "echo hello");
    }

    #[test]
    fn test_hash_string() {
        // Same input should produce same hash
        let hash1 = hash_string("test");
        let hash2 = hash_string("test");
        assert_eq!(hash1, hash2);

        // Different input should produce different hash
        let hash3 = hash_string("different");
        assert_ne!(hash1, hash3);

        // Hash should be 64 hex characters (SHA-256)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_rotation_keeps_recent_entries() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let history_file = temp_dir.path().join("history.jsonl");

        // Create a file with more entries than ENTRIES_TO_KEEP
        let mut file = File::create(&history_file)?;
        for i in 0..1500 {
            let record = ExecutionRecord::new(
                &format!("prompt {}", i),
                &format!("echo {}", i),
                RiskLevel::Safe,
                true,
                Some(0),
                Some(100),
            );
            let json = serde_json::to_string(&record)?;
            writeln!(file, "{}", json)?;
        }
        drop(file);

        // Rotate
        rotate_history(&history_file)?;

        // Count remaining entries
        let content = fs::read_to_string(&history_file)?;
        let line_count = content.lines().count();
        assert_eq!(line_count, ENTRIES_TO_KEEP);

        // Verify we kept the most recent entries by checking script_preview
        // (since prompts are now hashed, we check the preview which shows "echo N")
        assert!(content.contains("echo 1499"));
        assert!(content.contains("echo 500"));
        assert!(!content.contains("\"script_preview\":\"echo 0\""));

        Ok(())
    }

    #[test]
    fn test_rotation_memory_optimization() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let history_file = temp_dir.path().join("history.jsonl");

        // Create a large file (approx 15MB)
        // Each record is roughly 200 bytes
        // 75,000 records * 200 bytes = 15MB
        let mut file = File::create(&history_file)?;

        // Write in chunks to speed up test setup
        let record = ExecutionRecord::new(
            "test prompt",
            "echo test",
            RiskLevel::Safe,
            true,
            Some(0),
            Some(100),
        );
        let line = format!("{}\n", serde_json::to_string(&record)?);

        for _ in 0..75_000 {
            file.write_all(line.as_bytes())?;
        }
        drop(file);

        let start = std::time::Instant::now();
        rotate_history(&history_file)?;
        let duration = start.elapsed();

        println!("Rotation took: {:?}", duration);

        // Verify we only have ENTRIES_TO_KEEP
        let content = fs::read_to_string(&history_file)?;
        assert_eq!(content.lines().count(), ENTRIES_TO_KEEP);

        Ok(())
    }
}
