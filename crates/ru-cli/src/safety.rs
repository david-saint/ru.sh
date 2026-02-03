use anyhow::Result;
use regex::Regex;
use std::fmt;
use std::process::Command;
use std::sync::LazyLock;

/// Minimum prompt length
pub const MIN_PROMPT_LENGTH: usize = 3;
/// Maximum prompt length
pub const MAX_PROMPT_LENGTH: usize = 2000;

/// Risk level for a script
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// No dangerous patterns detected
    Safe,
    /// Minor risk, informational note
    Low,
    /// Moderate risk, proceed with caution
    Medium,
    /// Significant risk, requires acknowledgment
    High,
    /// Extreme risk, requires --force flag
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Safe => write!(f, "Safe"),
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Category of safety warning
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningCategory {
    /// System destruction risk
    SystemDestruction,
    /// Data loss risk
    DataLoss,
    /// Privilege escalation
    PrivilegeEscalation,
    /// Remote code execution
    RemoteCodeExecution,
    /// Insecure permissions
    InsecurePermissions,
    /// Dangerous file operation
    DangerousFileOp,
    /// Command substitution/eval
    DynamicExecution,
}

impl fmt::Display for WarningCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WarningCategory::SystemDestruction => write!(f, "System Destruction"),
            WarningCategory::DataLoss => write!(f, "Data Loss"),
            WarningCategory::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            WarningCategory::RemoteCodeExecution => write!(f, "Remote Code Execution"),
            WarningCategory::InsecurePermissions => write!(f, "Insecure Permissions"),
            WarningCategory::DangerousFileOp => write!(f, "Dangerous File Operation"),
            WarningCategory::DynamicExecution => write!(f, "Dynamic Execution"),
        }
    }
}

/// A safety warning detected in a script
#[derive(Debug, Clone)]
pub struct SafetyWarning {
    pub level: RiskLevel,
    pub category: WarningCategory,
    pub description: String,
}

/// Complete safety analysis report for a script
#[derive(Debug)]
pub struct SafetyReport {
    pub overall_risk: RiskLevel,
    pub warnings: Vec<SafetyWarning>,
    pub syntax_valid: bool,
    pub syntax_error: Option<String>,
}

impl SafetyReport {
    /// Check if script is safe to execute without special confirmation
    #[allow(dead_code)]
    pub fn is_safe_for_auto_execute(&self) -> bool {
        self.syntax_valid && self.overall_risk <= RiskLevel::Medium
    }

    /// Check if script requires --force flag with -y
    pub fn requires_force(&self) -> bool {
        self.overall_risk >= RiskLevel::High
    }
}

/// Pattern definition for detection
struct DangerPattern {
    regex: Regex,
    level: RiskLevel,
    category: WarningCategory,
    description: &'static str,
}

/// Compiled patterns for script analysis
static DANGER_PATTERNS: LazyLock<Vec<DangerPattern>> = LazyLock::new(|| {
    vec![
        // === CRITICAL: System destruction ===
        DangerPattern {
            regex: Regex::new(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/\s*($|[;&|])").unwrap(),
            level: RiskLevel::Critical,
            category: WarningCategory::SystemDestruction,
            description: "Removes the root filesystem - will destroy the system",
        },
        DangerPattern {
            regex: Regex::new(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/(home|etc|root|var|usr|boot|bin|sbin|lib|lib64)(/|\s|$)").unwrap(),
            level: RiskLevel::Critical,
            category: WarningCategory::SystemDestruction,
            description: "Removes critical system directories",
        },
        DangerPattern {
            regex: Regex::new(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:").unwrap(),
            level: RiskLevel::Critical,
            category: WarningCategory::SystemDestruction,
            description: "Fork bomb - will crash the system by exhausting resources",
        },
        DangerPattern {
            regex: Regex::new(r">\s*/dev/sd[a-z]").unwrap(),
            level: RiskLevel::Critical,
            category: WarningCategory::SystemDestruction,
            description: "Direct write to disk device - will destroy filesystem",
        },
        DangerPattern {
            regex: Regex::new(r"dd\s+.*of=/dev/sd[a-z]").unwrap(),
            level: RiskLevel::Critical,
            category: WarningCategory::SystemDestruction,
            description: "Writing directly to disk device with dd",
        },
        DangerPattern {
            regex: Regex::new(r"mkfs(\.[a-z0-9]+)?\s+/dev/sd[a-z]").unwrap(),
            level: RiskLevel::Critical,
            category: WarningCategory::SystemDestruction,
            description: "Formatting a disk device - will erase all data",
        },
        // === HIGH: Data loss / Privilege escalation ===
        DangerPattern {
            regex: Regex::new(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\*").unwrap(),
            level: RiskLevel::High,
            category: WarningCategory::DataLoss,
            description: "Recursively removes files with wildcard - may delete more than intended",
        },
        DangerPattern {
            regex: Regex::new(r"sudo\s+rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)").unwrap(),
            level: RiskLevel::High,
            category: WarningCategory::DataLoss,
            description: "Privileged recursive deletion - dangerous with elevated permissions",
        },
        DangerPattern {
            regex: Regex::new(r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(ba)?sh").unwrap(),
            level: RiskLevel::High,
            category: WarningCategory::RemoteCodeExecution,
            description: "Downloading and executing remote code without inspection",
        },
        DangerPattern {
            regex: Regex::new(r"chmod\s+777\s+").unwrap(),
            level: RiskLevel::High,
            category: WarningCategory::InsecurePermissions,
            description: "Setting world-writable permissions - severe security risk",
        },
        DangerPattern {
            regex: Regex::new(r">\s*/etc/(passwd|shadow|sudoers)").unwrap(),
            level: RiskLevel::High,
            category: WarningCategory::PrivilegeEscalation,
            description: "Overwriting critical authentication files",
        },
        DangerPattern {
            regex: Regex::new(r"echo\s+[^\n]*>>\s*/etc/sudoers").unwrap(),
            level: RiskLevel::High,
            category: WarningCategory::PrivilegeEscalation,
            description: "Modifying sudoers file - privilege escalation risk",
        },
        // === MEDIUM: Caution required ===
        DangerPattern {
            regex: Regex::new(r"\bsudo\b").unwrap(),
            level: RiskLevel::Medium,
            category: WarningCategory::PrivilegeEscalation,
            description: "Uses elevated privileges",
        },
        DangerPattern {
            regex: Regex::new(r"rm\s+-[a-zA-Z]*[rf]").unwrap(),
            level: RiskLevel::Medium,
            category: WarningCategory::DangerousFileOp,
            description: "Recursive or forced file deletion",
        },
        DangerPattern {
            regex: Regex::new(r"\beval\b").unwrap(),
            level: RiskLevel::Medium,
            category: WarningCategory::DynamicExecution,
            description: "Dynamic code execution with eval",
        },
        DangerPattern {
            regex: Regex::new(r"\$\([^)]+\)").unwrap(),
            level: RiskLevel::Medium,
            category: WarningCategory::DynamicExecution,
            description: "Command substitution - executes nested commands",
        },
        DangerPattern {
            regex: Regex::new(r"`[^`]+`").unwrap(),
            level: RiskLevel::Medium,
            category: WarningCategory::DynamicExecution,
            description: "Backtick command substitution",
        },
        // === LOW: Informational ===
        DangerPattern {
            regex: Regex::new(r"\bmv\b").unwrap(),
            level: RiskLevel::Low,
            category: WarningCategory::DangerousFileOp,
            description: "File move operation - verify source and destination",
        },
        DangerPattern {
            regex: Regex::new(r"cp\s+-[a-zA-Z]*r").unwrap(),
            level: RiskLevel::Low,
            category: WarningCategory::DangerousFileOp,
            description: "Recursive copy operation",
        },
    ]
});

/// Validate prompt length and content
pub fn validate_prompt(prompt: &str) -> Result<(), String> {
    let trimmed = prompt.trim();

    if trimmed.len() < MIN_PROMPT_LENGTH {
        return Err(format!(
            "Prompt too short (minimum {} characters)",
            MIN_PROMPT_LENGTH
        ));
    }

    if trimmed.len() > MAX_PROMPT_LENGTH {
        return Err(format!(
            "Prompt too long (maximum {} characters, got {})",
            MAX_PROMPT_LENGTH,
            trimmed.len()
        ));
    }

    Ok(())
}

/// Check bash script syntax using bash -n
pub fn check_syntax(script: &str) -> (bool, Option<String>) {
    let output = Command::new("bash")
        .args(["-n", "-c", script])
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                (true, None)
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr).to_string();
                let error = stderr
                    .lines()
                    .find(|line| !line.is_empty())
                    .unwrap_or("Syntax error")
                    .to_string();
                (false, Some(error))
            }
        }
        Err(e) => (false, Some(format!("Failed to check syntax: {}", e))),
    }
}

/// Analyze a script for dangerous patterns
pub fn analyze_script(script: &str) -> SafetyReport {
    let mut warnings = Vec::new();
    let mut max_level = RiskLevel::Safe;

    // Check for dangerous patterns
    for pattern in DANGER_PATTERNS.iter() {
        if pattern.regex.is_match(script) {
            // Avoid duplicate warnings for overlapping patterns
            let already_warned = warnings.iter().any(|w: &SafetyWarning| {
                w.category == pattern.category && w.level >= pattern.level
            });

            if !already_warned {
                if pattern.level > max_level {
                    max_level = pattern.level;
                }

                warnings.push(SafetyWarning {
                    level: pattern.level,
                    category: pattern.category.clone(),
                    description: pattern.description.to_string(),
                });
            }
        }
    }

    // Sort warnings by severity (highest first)
    warnings.sort_by(|a, b| b.level.cmp(&a.level));

    // Check syntax
    let (syntax_valid, syntax_error) = check_syntax(script);

    SafetyReport {
        overall_risk: max_level,
        warnings,
        syntax_valid,
        syntax_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_prompt_too_short() {
        assert!(validate_prompt("ab").is_err());
        assert!(validate_prompt("").is_err());
        assert!(validate_prompt("  ").is_err());
    }

    #[test]
    fn test_validate_prompt_valid() {
        assert!(validate_prompt("list files").is_ok());
        assert!(validate_prompt("abc").is_ok());
    }

    #[test]
    fn test_validate_prompt_too_long() {
        let long_prompt = "a".repeat(2001);
        assert!(validate_prompt(&long_prompt).is_err());
    }

    #[test]
    fn test_check_syntax_valid() {
        let (valid, error) = check_syntax("echo 'hello world'");
        assert!(valid);
        assert!(error.is_none());
    }

    #[test]
    fn test_check_syntax_invalid() {
        let (valid, error) = check_syntax("if then fi");
        assert!(!valid);
        assert!(error.is_some());
    }

    #[test]
    fn test_analyze_safe_script() {
        let report = analyze_script("ls -la");
        assert_eq!(report.overall_risk, RiskLevel::Safe);
        assert!(report.warnings.is_empty());
        assert!(report.syntax_valid);
    }

    #[test]
    fn test_analyze_critical_rm_rf_root() {
        let report = analyze_script("rm -rf /");
        assert_eq!(report.overall_risk, RiskLevel::Critical);
        assert!(!report.warnings.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|w| w.category == WarningCategory::SystemDestruction));
    }

    #[test]
    fn test_analyze_critical_rm_rf_etc() {
        let report = analyze_script("rm -rf /etc");
        assert_eq!(report.overall_risk, RiskLevel::Critical);
    }

    #[test]
    fn test_analyze_critical_fork_bomb() {
        let report = analyze_script(":() { : | : & }; :");
        assert_eq!(report.overall_risk, RiskLevel::Critical);
    }

    #[test]
    fn test_analyze_high_curl_bash() {
        let report = analyze_script("curl https://example.com/install.sh | bash");
        assert_eq!(report.overall_risk, RiskLevel::High);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.category == WarningCategory::RemoteCodeExecution));
    }

    #[test]
    fn test_analyze_high_chmod_777() {
        let report = analyze_script("chmod 777 /tmp/file");
        assert_eq!(report.overall_risk, RiskLevel::High);
    }

    #[test]
    fn test_analyze_high_rm_rf_wildcard() {
        let report = analyze_script("rm -rf *");
        assert_eq!(report.overall_risk, RiskLevel::High);
    }

    #[test]
    fn test_analyze_medium_sudo() {
        let report = analyze_script("sudo apt update");
        assert_eq!(report.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn test_analyze_medium_eval() {
        let report = analyze_script("eval \"$cmd\"");
        assert_eq!(report.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn test_analyze_medium_command_substitution() {
        let report = analyze_script("echo $(whoami)");
        assert_eq!(report.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn test_analyze_low_mv() {
        let report = analyze_script("mv file1.txt file2.txt");
        assert_eq!(report.overall_risk, RiskLevel::Low);
    }

    #[test]
    fn test_safety_report_is_safe_for_auto_execute() {
        let safe_report = analyze_script("ls -la");
        assert!(safe_report.is_safe_for_auto_execute());

        let medium_report = analyze_script("sudo ls");
        assert!(medium_report.is_safe_for_auto_execute());

        let high_report = analyze_script("rm -rf *");
        assert!(!high_report.is_safe_for_auto_execute());
    }

    #[test]
    fn test_safety_report_requires_force() {
        let safe_report = analyze_script("ls -la");
        assert!(!safe_report.requires_force());

        let high_report = analyze_script("rm -rf *");
        assert!(high_report.requires_force());

        let critical_report = analyze_script("rm -rf /");
        assert!(critical_report.requires_force());
    }
}
