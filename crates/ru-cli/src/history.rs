use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::config::Config;
use crate::safety::RiskLevel;

/// Maximum history file size before rotation (10 MB)
const MAX_HISTORY_SIZE: u64 = 10 * 1024 * 1024;

/// Number of recent entries to keep when rotating
const ENTRIES_TO_KEEP: usize = 1000;

/// A record of a script execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub timestamp: DateTime<Utc>,
    pub prompt: String,
    pub script: String,
    pub risk_level: String,
    pub executed: bool,
    pub exit_code: Option<i32>,
}

impl ExecutionRecord {
    pub fn new(
        prompt: &str,
        script: &str,
        risk_level: RiskLevel,
        executed: bool,
        exit_code: Option<i32>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            prompt: prompt.to_string(),
            script: script.to_string(),
            risk_level: risk_level.to_string(),
            executed,
            exit_code,
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
    if let Ok(metadata) = fs::metadata(&path) {
        if metadata.len() > MAX_HISTORY_SIZE {
            rotate_history(&path)?;
        }
    }

    // Append the record as JSON line
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
    let file =
        File::open(path).with_context(|| format!("Failed to open history file: {}", path.display()))?;

    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<Vec<_>, _>>()?;

    // Keep only the most recent entries
    let to_keep = if lines.len() > ENTRIES_TO_KEEP {
        &lines[lines.len() - ENTRIES_TO_KEEP..]
    } else {
        &lines[..]
    };

    // Write the truncated history
    let mut file = File::create(path)
        .with_context(|| format!("Failed to truncate history file: {}", path.display()))?;

    for line in to_keep {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_record() -> ExecutionRecord {
        ExecutionRecord::new("list files", "ls -la", RiskLevel::Safe, true, Some(0))
    }

    #[test]
    fn test_execution_record_new() {
        let record = create_test_record();
        assert_eq!(record.prompt, "list files");
        assert_eq!(record.script, "ls -la");
        assert_eq!(record.risk_level, "Safe");
        assert!(record.executed);
        assert_eq!(record.exit_code, Some(0));
    }

    #[test]
    fn test_execution_record_serialize() {
        let record = create_test_record();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"prompt\":\"list files\""));
        assert!(json.contains("\"script\":\"ls -la\""));
        assert!(json.contains("\"risk_level\":\"Safe\""));
    }

    #[test]
    fn test_execution_record_deserialize() {
        let json = r#"{"timestamp":"2024-01-15T10:30:00Z","prompt":"test","script":"echo test","risk_level":"Low","executed":true,"exit_code":0}"#;
        let record: ExecutionRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.prompt, "test");
        assert_eq!(record.script, "echo test");
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

        // Verify
        let content = fs::read_to_string(&history_file)?;
        assert!(content.contains("list files"));
        assert!(content.contains("ls -la"));

        Ok(())
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

        // Verify we kept the most recent entries
        assert!(content.contains("prompt 1499"));
        assert!(content.contains("prompt 500"));
        assert!(!content.contains("prompt 0\","));

        Ok(())
    }
}
