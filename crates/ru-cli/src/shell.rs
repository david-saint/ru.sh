use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported shell types for script generation and execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    Bash,
    Zsh,
    Sh,
    Fish,
    #[serde(alias = "pwsh")]
    PowerShell,
    Cmd,
}

impl Shell {
    /// Detect the current shell from the environment
    #[cfg(unix)]
    pub fn detect() -> Self {
        if let Ok(shell_env) = std::env::var("SHELL") {
            let shell_name = shell_env.rsplit('/').next().unwrap_or("").to_lowercase();
            match shell_name.as_str() {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "sh" | "dash" | "ash" => Shell::Sh,
                _ => Shell::Bash,
            }
        } else {
            Shell::Bash
        }
    }

    /// Detect the current shell from the environment
    #[cfg(windows)]
    pub fn detect() -> Self {
        // If PSModulePath is set, likely running in PowerShell
        if std::env::var("PSModulePath").is_ok() {
            return Shell::PowerShell;
        }
        // Fall back to COMSPEC
        if let Ok(comspec) = std::env::var("COMSPEC") {
            if comspec.to_lowercase().contains("cmd") {
                return Shell::Cmd;
            }
        }
        Shell::PowerShell
    }

    /// Detect the current shell from the environment (fallback for other platforms)
    #[cfg(not(any(unix, windows)))]
    pub fn detect() -> Self {
        Shell::Bash
    }

    /// Get the shell binary name
    pub fn binary(&self) -> &str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Sh => "sh",
            Shell::Fish => "fish",
            Shell::PowerShell => {
                // Prefer "pwsh" (PowerShell Core, cross-platform) over "powershell.exe"
                if cfg!(windows) {
                    "powershell.exe"
                } else {
                    "pwsh"
                }
            }
            Shell::Cmd => "cmd.exe",
        }
    }

    /// Get the arguments needed to execute a script string
    pub fn exec_args(&self) -> &[&str] {
        match self {
            Shell::Bash | Shell::Zsh | Shell::Sh => &["-c"],
            Shell::Fish => &["-c"],
            Shell::PowerShell => &["-NoProfile", "-Command"],
            Shell::Cmd => &["/c"],
        }
    }

    /// Check if this is a Unix-family shell
    pub fn is_unix(&self) -> bool {
        matches!(self, Shell::Bash | Shell::Zsh | Shell::Sh | Shell::Fish)
    }

    /// Check if this is a Windows-family shell
    #[allow(dead_code)]
    pub fn is_windows(&self) -> bool {
        matches!(self, Shell::PowerShell | Shell::Cmd)
    }

    /// Get a human-friendly display name for prompts and messages
    pub fn display_name(&self) -> &str {
        match self {
            Shell::Bash => "Bash",
            Shell::Zsh => "Zsh",
            Shell::Sh => "POSIX sh",
            Shell::Fish => "Fish",
            Shell::PowerShell => "PowerShell",
            Shell::Cmd => "cmd.exe",
        }
    }
}

impl fmt::Display for Shell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shell::Bash => write!(f, "bash"),
            Shell::Zsh => write!(f, "zsh"),
            Shell::Sh => write!(f, "sh"),
            Shell::Fish => write!(f, "fish"),
            Shell::PowerShell => write!(f, "powershell"),
            Shell::Cmd => write!(f, "cmd"),
        }
    }
}

impl FromStr for Shell {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bash" => Ok(Shell::Bash),
            "zsh" => Ok(Shell::Zsh),
            "sh" | "posix" => Ok(Shell::Sh),
            "fish" => Ok(Shell::Fish),
            "powershell" | "pwsh" => Ok(Shell::PowerShell),
            "cmd" | "cmd.exe" => Ok(Shell::Cmd),
            _ => Err(format!(
                "Invalid shell: '{}'. Valid options: bash, zsh, sh, fish, powershell, cmd",
                s
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_from_str() {
        assert_eq!(Shell::from_str("bash").unwrap(), Shell::Bash);
        assert_eq!(Shell::from_str("BASH").unwrap(), Shell::Bash);
        assert_eq!(Shell::from_str("zsh").unwrap(), Shell::Zsh);
        assert_eq!(Shell::from_str("sh").unwrap(), Shell::Sh);
        assert_eq!(Shell::from_str("posix").unwrap(), Shell::Sh);
        assert_eq!(Shell::from_str("fish").unwrap(), Shell::Fish);
        assert_eq!(Shell::from_str("powershell").unwrap(), Shell::PowerShell);
        assert_eq!(Shell::from_str("pwsh").unwrap(), Shell::PowerShell);
        assert_eq!(Shell::from_str("cmd").unwrap(), Shell::Cmd);
        assert_eq!(Shell::from_str("cmd.exe").unwrap(), Shell::Cmd);
        assert!(Shell::from_str("invalid").is_err());
    }

    #[test]
    fn test_shell_display() {
        assert_eq!(Shell::Bash.to_string(), "bash");
        assert_eq!(Shell::Zsh.to_string(), "zsh");
        assert_eq!(Shell::Sh.to_string(), "sh");
        assert_eq!(Shell::Fish.to_string(), "fish");
        assert_eq!(Shell::PowerShell.to_string(), "powershell");
        assert_eq!(Shell::Cmd.to_string(), "cmd");
    }

    #[test]
    fn test_shell_binary() {
        assert_eq!(Shell::Bash.binary(), "bash");
        assert_eq!(Shell::Zsh.binary(), "zsh");
        assert_eq!(Shell::Sh.binary(), "sh");
        assert_eq!(Shell::Fish.binary(), "fish");
        assert_eq!(Shell::Cmd.binary(), "cmd.exe");
        // PowerShell binary depends on platform
        let ps_binary = Shell::PowerShell.binary();
        assert!(ps_binary == "pwsh" || ps_binary == "powershell.exe");
    }

    #[test]
    fn test_shell_exec_args() {
        assert_eq!(Shell::Bash.exec_args(), &["-c"]);
        assert_eq!(Shell::Zsh.exec_args(), &["-c"]);
        assert_eq!(Shell::Sh.exec_args(), &["-c"]);
        assert_eq!(Shell::Fish.exec_args(), &["-c"]);
        assert_eq!(Shell::PowerShell.exec_args(), &["-NoProfile", "-Command"]);
        assert_eq!(Shell::Cmd.exec_args(), &["/c"]);
    }

    #[test]
    fn test_shell_is_unix() {
        assert!(Shell::Bash.is_unix());
        assert!(Shell::Zsh.is_unix());
        assert!(Shell::Sh.is_unix());
        assert!(Shell::Fish.is_unix());
        assert!(!Shell::PowerShell.is_unix());
        assert!(!Shell::Cmd.is_unix());
    }

    #[test]
    fn test_shell_is_windows() {
        assert!(!Shell::Bash.is_windows());
        assert!(!Shell::Zsh.is_windows());
        assert!(Shell::PowerShell.is_windows());
        assert!(Shell::Cmd.is_windows());
    }

    #[test]
    fn test_shell_display_name() {
        assert_eq!(Shell::Bash.display_name(), "Bash");
        assert_eq!(Shell::Zsh.display_name(), "Zsh");
        assert_eq!(Shell::Sh.display_name(), "POSIX sh");
        assert_eq!(Shell::Fish.display_name(), "Fish");
        assert_eq!(Shell::PowerShell.display_name(), "PowerShell");
        assert_eq!(Shell::Cmd.display_name(), "cmd.exe");
    }

    #[test]
    fn test_shell_detect() {
        // Just verify detect() returns a valid Shell variant without panicking
        let shell = Shell::detect();
        // On any platform, detect should return a valid shell
        assert!(!shell.binary().is_empty());
    }

    #[test]
    fn test_shell_roundtrip_display_fromstr() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Sh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Cmd,
        ] {
            let s = shell.to_string();
            let parsed = Shell::from_str(&s).unwrap();
            assert_eq!(parsed, shell);
        }
    }

    #[test]
    fn test_shell_serde_roundtrip() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Sh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Cmd,
        ] {
            let json = serde_json::to_string(&shell).unwrap();
            let parsed: Shell = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, shell);
        }
    }
}
