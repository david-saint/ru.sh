use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

/// Default model for Fast preset
pub const DEFAULT_MODEL_FAST: &str = "google/gemini-2.5-flash:nitro";
/// Default model for Standard preset
pub const DEFAULT_MODEL_STANDARD: &str = "google/gemini-3-flash-preview:nitro";
/// Default model for Quality preset
pub const DEFAULT_MODEL_QUALITY: &str = "anthropic/claude-opus-4.5:nitro";
/// Default model for Explainer
pub const DEFAULT_MODEL_EXPLAINER: &str = "nvidia/nemotron-3-nano-30b-a3b:nitro";
/// Default script execution timeout in seconds (5 minutes)
pub const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 300;

/// Model preset for quick selection
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelPreset {
    /// Fastest response time
    Fast,
    /// Best balance of quality, speed, and cost
    #[default]
    Standard,
    /// Highest quality output
    Quality,
}

impl std::fmt::Display for ModelPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelPreset::Fast => write!(f, "fast"),
            ModelPreset::Standard => write!(f, "standard"),
            ModelPreset::Quality => write!(f, "quality"),
        }
    }
}

impl FromStr for ModelPreset {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fast" => Ok(ModelPreset::Fast),
            "standard" => Ok(ModelPreset::Standard),
            "quality" => Ok(ModelPreset::Quality),
            // Backward compatibility: map "cheap" to "fast"
            "cheap" => Ok(ModelPreset::Fast),
            _ => Err(format!(
                "Invalid model preset: '{}'. Valid options: fast, standard, quality",
                s
            )),
        }
    }
}

/// Custom model overrides for each preset
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PresetModels {
    /// Custom model for the "fast" preset
    pub fast: Option<String>,
    /// Custom model for the "standard" preset
    pub standard: Option<String>,
    /// Custom model for the "quality" preset
    pub quality: Option<String>,
}

/// Verbosity level for script explanations
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExplainVerbosity {
    /// Concise 2-3 sentence summary
    #[default]
    Concise,
    /// Detailed step-by-step explanation
    Verbose,
}

impl std::fmt::Display for ExplainVerbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExplainVerbosity::Concise => write!(f, "concise"),
            ExplainVerbosity::Verbose => write!(f, "verbose"),
        }
    }
}

impl FromStr for ExplainVerbosity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "concise" | "summary" => Ok(ExplainVerbosity::Concise),
            "verbose" | "detailed" => Ok(ExplainVerbosity::Verbose),
            _ => Err(format!(
                "Invalid explain verbosity: '{}'. Valid options: concise, verbose",
                s
            )),
        }
    }
}

impl PresetModels {
    /// Get custom model for a preset
    pub fn get(&self, preset: &ModelPreset) -> Option<&str> {
        match preset {
            ModelPreset::Fast => self.fast.as_deref(),
            ModelPreset::Standard => self.standard.as_deref(),
            ModelPreset::Quality => self.quality.as_deref(),
        }
    }

    /// Set custom model for a preset
    pub fn set(&mut self, preset: &ModelPreset, model_id: String) {
        match preset {
            ModelPreset::Fast => self.fast = Some(model_id),
            ModelPreset::Standard => self.standard = Some(model_id),
            ModelPreset::Quality => self.quality = Some(model_id),
        }
    }

    /// Clear custom model for a preset
    pub fn clear(&mut self, preset: &ModelPreset) {
        match preset {
            ModelPreset::Fast => self.fast = None,
            ModelPreset::Standard => self.standard = None,
            ModelPreset::Quality => self.quality = None,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub api_key: Option<String>,
    /// Model preset (fast, standard, quality)
    pub model_preset: Option<ModelPreset>,
    /// Custom model ID (overrides preset for one-time use via CLI)
    pub custom_model: Option<String>,
    /// Custom model overrides per preset (persisted in config)
    #[serde(default)]
    pub preset_models: PresetModels,
    /// Custom model for the explainer feature
    pub explainer_model: Option<String>,
    /// Verbosity level for script explanations (concise or verbose)
    pub explain_verbosity: Option<ExplainVerbosity>,
    /// Target shell (bash, zsh, sh, fish, powershell, cmd)
    pub shell: Option<String>,
    /// Daily request limit (warning threshold)
    pub daily_limit: Option<u32>,
    /// Monthly request limit (warning threshold)
    pub monthly_limit: Option<u32>,
    /// Script execution timeout in seconds
    pub script_timeout: Option<u64>,
}

impl Config {
    /// Get the config directory path (~/.config/ru.sh)
    pub fn dir() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".config").join("ru.sh"))
    }

    /// Get the config file path (~/.config/ru/config.toml)
    pub fn path() -> Option<PathBuf> {
        Self::dir().map(|dir| dir.join("config.toml"))
    }

    /// Load config from file, returning default if file doesn't exist
    pub fn load() -> Result<Self> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        Self::load_from(path)
    }

    /// Load config from a specific path
    pub fn load_from(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        match toml::from_str::<Self>(&contents) {
            Ok(config) => Ok(config),
            Err(e) => {
                let bak_path = PathBuf::from(format!("{}.bak", path.display()));
                match fs::rename(&path, &bak_path) {
                    Ok(_) => {
                        eprintln!(
                            "{} Config file at {} is corrupted and has been backed up to {}. Using default settings.",
                            "Warning:".yellow().bold(),
                            path.display(),
                            bak_path.display()
                        );
                    }
                    Err(rename_err) => {
                        eprintln!(
                            "{} Config file at {} is corrupted. Failed to create backup: {}. Using default settings.",
                            "Warning:".yellow().bold(),
                            path.display(),
                            rename_err
                        );
                    }
                }
                eprintln!("{} {}", "Error details:".dimmed(), e);
                Ok(Self::default())
            }
        }
    }

    /// Save config to file, creating directory if needed
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine config path")?;
        self.save_to(path)
    }

    /// Save config to a specific path
    pub fn save_to(&self, path: PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let contents = toml::to_string_pretty(self).context("Failed to serialize config")?;

        // Write with restricted permissions (0600 on Unix) to protect API key
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("Failed to open config file: {}", path.display()))?;

            file.write_all(contents.as_bytes())
                .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&path, contents)
                .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        }

        Ok(())
    }

    /// Get the API key from config
    pub fn get_api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    /// Set the API key in config
    pub fn set_api_key(&mut self, key: String) {
        self.api_key = Some(key);
    }

    /// Clear the API key from config
    pub fn clear_api_key(&mut self) {
        self.api_key = None;
    }

    /// Get the model preset from config
    pub fn get_model_preset(&self) -> ModelPreset {
        self.model_preset.clone().unwrap_or_default()
    }

    /// Set the model preset in config
    pub fn set_model_preset(&mut self, preset: ModelPreset) {
        self.model_preset = Some(preset);
        // Clear custom model when setting a preset
        self.custom_model = None;
    }

    /// Get the custom model ID from config
    pub fn get_custom_model(&self) -> Option<&str> {
        self.custom_model.as_deref()
    }

    /// Set a custom model ID in config
    pub fn set_custom_model(&mut self, model_id: String) {
        self.custom_model = Some(model_id);
    }

    /// Clear model settings from config
    pub fn clear_model(&mut self) {
        self.model_preset = None;
        self.custom_model = None;
    }

    /// Set a custom model for a specific preset
    pub fn set_preset_model(&mut self, preset: &ModelPreset, model_id: String) {
        self.preset_models.set(preset, model_id);
    }

    /// Clear custom model for a specific preset (revert to default)
    pub fn clear_preset_model(&mut self, preset: &ModelPreset) {
        self.preset_models.clear(preset);
    }

    /// Get the custom model for a preset (if any)
    pub fn get_preset_model(&self, preset: &ModelPreset) -> Option<&str> {
        self.preset_models.get(preset)
    }

    /// Get the default model ID for a preset (ignoring custom overrides)
    pub fn get_default_model_id(preset: &ModelPreset) -> &'static str {
        match preset {
            ModelPreset::Fast => DEFAULT_MODEL_FAST,
            ModelPreset::Standard => DEFAULT_MODEL_STANDARD,
            ModelPreset::Quality => DEFAULT_MODEL_QUALITY,
        }
    }

    /// Get the effective model ID based on config
    /// Priority: custom_model > preset custom override > preset default
    pub fn get_model_id(&self) -> &str {
        // 1. CLI custom_model takes highest priority
        if let Some(custom) = &self.custom_model {
            return custom;
        }

        let preset = self.get_model_preset();

        // 2. Check for user-configured preset override
        if let Some(custom_preset_model) = self.preset_models.get(&preset) {
            return custom_preset_model;
        }

        // 3. Fall back to built-in defaults
        Self::get_default_model_id(&preset)
    }

    /// Set the explainer model
    pub fn set_explainer_model(&mut self, model_id: String) {
        self.explainer_model = Some(model_id);
    }

    /// Clear the explainer model (revert to default)
    pub fn clear_explainer_model(&mut self) {
        self.explainer_model = None;
    }

    /// Get the effective explainer model ID
    /// Returns custom override if set, otherwise default
    pub fn get_explainer_model(&self) -> &str {
        self.explainer_model
            .as_deref()
            .unwrap_or(DEFAULT_MODEL_EXPLAINER)
    }

    /// Get the explain verbosity level
    /// Returns Concise by default if not set
    pub fn get_explain_verbosity(&self) -> ExplainVerbosity {
        self.explain_verbosity.clone().unwrap_or_default()
    }

    /// Set the explain verbosity level
    pub fn set_explain_verbosity(&mut self, verbosity: ExplainVerbosity) {
        self.explain_verbosity = Some(verbosity);
    }

    /// Clear the explain verbosity (revert to default: concise)
    pub fn clear_explain_verbosity(&mut self) {
        self.explain_verbosity = None;
    }

    /// Get the daily request limit
    pub fn get_daily_limit(&self) -> Option<u32> {
        self.daily_limit
    }

    /// Set the daily request limit
    pub fn set_daily_limit(&mut self, limit: u32) {
        self.daily_limit = Some(limit);
    }

    /// Clear the daily request limit
    pub fn clear_daily_limit(&mut self) {
        self.daily_limit = None;
    }

    /// Get the monthly request limit
    pub fn get_monthly_limit(&self) -> Option<u32> {
        self.monthly_limit
    }

    /// Set the monthly request limit
    pub fn set_monthly_limit(&mut self, limit: u32) {
        self.monthly_limit = Some(limit);
    }

    /// Clear the monthly request limit
    pub fn clear_monthly_limit(&mut self) {
        self.monthly_limit = None;
    }

    /// Get the script execution timeout in seconds
    pub fn get_script_timeout(&self) -> u64 {
        self.script_timeout.unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS)
    }

    /// Set the script execution timeout in seconds
    pub fn set_script_timeout(&mut self, timeout: u64) {
        self.script_timeout = Some(timeout);
    }

    /// Clear the script execution timeout (revert to default)
    pub fn clear_script_timeout(&mut self) {
        self.script_timeout = None;
    }

    /// Get the shell setting
    pub fn get_shell(&self) -> Option<&str> {
        self.shell.as_deref()
    }

    /// Set the shell
    pub fn set_shell(&mut self, shell: String) {
        self.shell = Some(shell);
    }

    /// Clear the shell (revert to auto-detect)
    pub fn clear_shell(&mut self) {
        self.shell = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.api_key, None);
        assert_eq!(config.model_preset, None);
        assert_eq!(config.custom_model, None);
    }

    #[test]
    fn test_set_and_get_api_key() {
        let mut config = Config::default();
        config.set_api_key("test-key".to_string());
        assert_eq!(config.get_api_key(), Some("test-key"));
    }

    #[test]
    fn test_clear_api_key() {
        let mut config = Config::default();
        config.set_api_key("test-key".to_string());
        config.clear_api_key();
        assert_eq!(config.api_key, None);
    }

    #[test]
    fn test_model_preset() {
        let mut config = Config::default();

        // Default preset is Standard
        assert_eq!(config.get_model_preset(), ModelPreset::Standard);

        // Set preset
        config.set_model_preset(ModelPreset::Fast);
        assert_eq!(config.get_model_preset(), ModelPreset::Fast);

        // Setting preset clears custom model
        config.set_custom_model("custom/model".to_string());
        config.set_model_preset(ModelPreset::Quality);
        assert_eq!(config.custom_model, None);
    }

    #[test]
    fn test_custom_model() {
        let mut config = Config::default();

        config.set_custom_model("openai/gpt-4o".to_string());
        assert_eq!(config.get_custom_model(), Some("openai/gpt-4o"));

        // Custom model takes priority in get_model_id
        assert_eq!(config.get_model_id(), "openai/gpt-4o");
    }

    #[test]
    fn test_model_preset_from_str() {
        assert_eq!(ModelPreset::from_str("fast").unwrap(), ModelPreset::Fast);
        assert_eq!(
            ModelPreset::from_str("STANDARD").unwrap(),
            ModelPreset::Standard
        );
        assert_eq!(
            ModelPreset::from_str("Quality").unwrap(),
            ModelPreset::Quality
        );
        assert!(ModelPreset::from_str("invalid").is_err());
    }

    #[test]
    fn test_cheap_maps_to_fast() {
        // Backward compatibility: "cheap" should parse to Fast
        let preset = ModelPreset::from_str("cheap").unwrap();
        assert_eq!(preset, ModelPreset::Fast);
        let preset = ModelPreset::from_str("CHEAP").unwrap();
        assert_eq!(preset, ModelPreset::Fast);
    }

    #[test]
    fn test_get_model_id_priority() {
        let mut config = Config::default();

        // Default returns standard preset model
        assert_eq!(config.get_model_id(), DEFAULT_MODEL_STANDARD);

        // Custom model overrides preset
        config.set_custom_model("my/custom-model".to_string());
        assert_eq!(config.get_model_id(), "my/custom-model");
    }

    #[test]
    fn test_preset_model_override() {
        let mut config = Config::default();

        // Default fast model
        config.set_model_preset(ModelPreset::Fast);
        assert_eq!(config.get_model_id(), DEFAULT_MODEL_FAST);

        // Override fast preset with custom model
        config.set_preset_model(&ModelPreset::Fast, "my/custom-fast".to_string());
        assert_eq!(config.get_model_id(), "my/custom-fast");

        // Clear override, back to default
        config.clear_preset_model(&ModelPreset::Fast);
        assert_eq!(config.get_model_id(), DEFAULT_MODEL_FAST);
    }

    #[test]
    fn test_custom_model_overrides_preset_override() {
        let mut config = Config::default();
        config.set_model_preset(ModelPreset::Fast);
        config.set_preset_model(&ModelPreset::Fast, "my/preset-override".to_string());
        config.set_custom_model("my/cli-override".to_string());

        // CLI custom_model should take precedence
        assert_eq!(config.get_model_id(), "my/cli-override");
    }

    #[test]
    fn test_quality_preset() {
        let mut config = Config::default();
        config.set_model_preset(ModelPreset::Quality);
        assert_eq!(config.get_model_id(), DEFAULT_MODEL_QUALITY);
    }

    #[test]
    fn test_explainer_model() {
        let mut config = Config::default();

        // Default explainer model
        assert_eq!(config.get_explainer_model(), DEFAULT_MODEL_EXPLAINER);

        // Set custom explainer model
        config.set_explainer_model("my/custom-explainer".to_string());
        assert_eq!(config.get_explainer_model(), "my/custom-explainer");

        // Clear explainer model, back to default
        config.clear_explainer_model();
        assert_eq!(config.get_explainer_model(), DEFAULT_MODEL_EXPLAINER);
    }

    #[test]
    fn test_save_and_load() -> Result<()> {
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        // Save
        let mut config = Config::default();
        config.set_api_key("persistent-key".to_string());
        config.set_model_preset(ModelPreset::Fast);
        config.save_to(path.clone())?;

        // Load
        let loaded = Config::load_from(path)?;
        assert_eq!(loaded.get_api_key(), Some("persistent-key"));
        assert_eq!(loaded.model_preset, Some(ModelPreset::Fast));

        Ok(())
    }

    #[test]
    fn test_save_and_load_with_preset_models() -> Result<()> {
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        let mut config = Config::default();
        config.set_api_key("test-key".to_string());
        config.set_model_preset(ModelPreset::Standard);
        config.set_preset_model(&ModelPreset::Fast, "custom/fast-model".to_string());
        config.set_explainer_model("custom/explainer".to_string());
        config.save_to(path.clone())?;

        let loaded = Config::load_from(path)?;
        assert_eq!(loaded.get_api_key(), Some("test-key"));
        assert_eq!(
            loaded.get_preset_model(&ModelPreset::Fast),
            Some("custom/fast-model")
        );
        assert_eq!(loaded.get_preset_model(&ModelPreset::Standard), None);
        assert_eq!(loaded.get_explainer_model(), "custom/explainer");

        Ok(())
    }

    #[test]
    fn test_explain_verbosity_default() {
        let config = Config::default();
        assert_eq!(config.get_explain_verbosity(), ExplainVerbosity::Concise);
    }

    #[test]
    fn test_explain_verbosity_set_get() {
        let mut config = Config::default();
        config.set_explain_verbosity(ExplainVerbosity::Verbose);
        assert_eq!(config.get_explain_verbosity(), ExplainVerbosity::Verbose);
    }

    #[test]
    fn test_explain_verbosity_clear() {
        let mut config = Config::default();
        config.set_explain_verbosity(ExplainVerbosity::Verbose);
        config.clear_explain_verbosity();
        assert_eq!(config.get_explain_verbosity(), ExplainVerbosity::Concise);
    }

    #[test]
    fn test_explain_verbosity_from_str() {
        assert_eq!(
            ExplainVerbosity::from_str("concise").unwrap(),
            ExplainVerbosity::Concise
        );
        assert_eq!(
            ExplainVerbosity::from_str("verbose").unwrap(),
            ExplainVerbosity::Verbose
        );
        assert_eq!(
            ExplainVerbosity::from_str("summary").unwrap(),
            ExplainVerbosity::Concise
        );
        assert_eq!(
            ExplainVerbosity::from_str("detailed").unwrap(),
            ExplainVerbosity::Verbose
        );
        assert_eq!(
            ExplainVerbosity::from_str("CONCISE").unwrap(),
            ExplainVerbosity::Concise
        );
        assert!(ExplainVerbosity::from_str("invalid").is_err());
    }

    #[test]
    fn test_explain_verbosity_save_load() -> Result<()> {
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        let mut config = Config::default();
        config.set_explain_verbosity(ExplainVerbosity::Verbose);
        config.save_to(path.clone())?;

        let loaded = Config::load_from(path)?;
        assert_eq!(loaded.get_explain_verbosity(), ExplainVerbosity::Verbose);

        Ok(())
    }

    #[test]
    fn test_load_corrupted_config_recovers() -> Result<()> {
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        // Write invalid TOML
        fs::write(&path, "invalid = toml = format")?;

        let config = Config::load_from(path.clone())?;
        assert_eq!(config.api_key, None); // Should return default config

        // Original file should be renamed to .bak
        let bak_path = PathBuf::from(format!("{}.bak", path.display()));
        assert!(bak_path.exists());
        assert!(!path.exists());

        Ok(())
    }

    #[test]
    fn test_load_nonexistent_file() -> Result<()> {
        let path = PathBuf::from("/tmp/nonexistent-config-file-xyz.toml");
        // Ensure it doesn't exist
        if path.exists() {
            let _ = fs::remove_file(&path);
        }

        let config = Config::load_from(path)?;
        assert_eq!(config.api_key, None);
        Ok(())
    }
}
