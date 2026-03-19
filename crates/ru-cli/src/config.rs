use anyhow::{Context, Result};
use colored::Colorize;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

pub mod secret_string_opt {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<SecretString>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(secret) => serializer.serialize_some(secret.expose_secret()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Let the outer Option deserialization handle missing fields if `#[serde(default)]` is used
        let opt: Option<String> = Option::deserialize(deserializer)?;
        Ok(opt.map(SecretString::from))
    }
}

/// Default model used for the "fast" model preset.
pub const DEFAULT_MODEL_FAST: &str = "google/gemini-2.5-flash:nitro";
/// Default model used for the "standard" model preset.
pub const DEFAULT_MODEL_STANDARD: &str = "google/gemini-3-flash-preview:nitro";
/// Default model used for the "quality" model preset.
pub const DEFAULT_MODEL_QUALITY: &str = "anthropic/claude-opus-4.5:nitro";
/// Default model used for the explainer feature.
pub const DEFAULT_MODEL_EXPLAINER: &str = "nvidia/nemotron-3-nano-30b-a3b:nitro";
/// Default timeout for script execution in seconds (5 minutes).
pub const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 300;
/// Environment variable name for overriding the configuration directory path.
pub const CONFIG_DIR_ENV_VAR: &str = "RU_CONFIG_DIR";

/// Ensure that a directory exists with restricted permissions (`0o700` on Unix).
///
/// If the directory already exists, its permissions are corrected to `0o700`.
/// If it does not exist, it is created (along with any missing parent directories).
///
/// **Note:** On Unix, only the *target* directory receives `0o700` permissions.
/// Intermediate parent directories (e.g. `~/.config`) are created with the
/// process's default umask-derived permissions, since they may be shared with
/// other applications and should not be locked down.
pub fn ensure_secure_dir(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        // Fix permissions on an already-existing directory that may have been
        // created with a permissive umask (e.g. 0o755) by a prior version.
        // Only attempt the change if the current mode differs from 0o700 and
        // we own the directory, to avoid EPERM on system-managed directories.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;

            let metadata = fs::metadata(path).with_context(|| {
                format!(
                    "Failed to read metadata for existing directory: {}",
                    path.display()
                )
            })?;

            let current_mode = metadata.permissions().mode() & 0o777;
            let uid = unsafe { libc::getuid() };

            if current_mode != 0o700 && metadata.uid() == uid {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o700);

                fs::set_permissions(path, permissions).with_context(|| {
                    format!(
                        "Failed to update permissions for existing directory: {}",
                        path.display()
                    )
                })?;
            }
        }

        return Ok(());
    }

    // Create the directory tree. On Unix, DirBuilder with recursive(true) only
    // applies the explicit mode to the final path component; intermediate
    // directories receive umask-derived permissions. This is intentional —
    // shared parents like ~/.config should not be restricted to 0o700.
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    builder
        .create(path)
        .with_context(|| format!("Failed to create secure directory: {}", path.display()))?;

    Ok(())
}

/// Model preset for quick selection of LLM balance between speed and quality.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelPreset {
    /// Optimized for the fastest response time.
    Fast,
    /// The default preset, providing a balance of quality, speed, and cost.
    #[default]
    Standard,
    /// Optimized for the highest quality and accuracy of generated scripts.
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

/// Persistent custom model overrides for each of the available presets.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PresetModels {
    /// Optional custom model ID to use for the "fast" preset.
    pub fast: Option<String>,
    /// Optional custom model ID to use for the "standard" preset.
    pub standard: Option<String>,
    /// Optional custom model ID to use for the "quality" preset.
    pub quality: Option<String>,
}

/// Defines the level of detail provided in script explanations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExplainVerbosity {
    /// Provides a concise 2-3 sentence summary of what the script does.
    #[default]
    Concise,
    /// Provides a detailed, step-by-step breakdown of the script's logic and risks.
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
    /// Returns the custom model ID for a specific preset, if one is configured.
    pub fn get(&self, preset: &ModelPreset) -> Option<&str> {
        match preset {
            ModelPreset::Fast => self.fast.as_deref(),
            ModelPreset::Standard => self.standard.as_deref(),
            ModelPreset::Quality => self.quality.as_deref(),
        }
    }

    /// Sets a custom model ID for a specific preset.
    pub fn set(&mut self, preset: &ModelPreset, model_id: String) {
        match preset {
            ModelPreset::Fast => self.fast = Some(model_id),
            ModelPreset::Standard => self.standard = Some(model_id),
            ModelPreset::Quality => self.quality = Some(model_id),
        }
    }

    /// Clears the custom model ID for a specific preset, reverting it to the default.
    pub fn clear(&mut self, preset: &ModelPreset) {
        match preset {
            ModelPreset::Fast => self.fast = None,
            ModelPreset::Standard => self.standard = None,
            ModelPreset::Quality => self.quality = None,
        }
    }
}

/// Application configuration settings for `ru-cli`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// OpenRouter API key for authentication.
    #[serde(default, with = "secret_string_opt")]
    pub api_key: Option<SecretString>,
    /// The currently active model preset.
    pub model_preset: Option<ModelPreset>,
    /// A custom model ID that overrides the preset for a single execution.
    pub custom_model: Option<String>,
    /// User-configured persistent model overrides for each preset.
    #[serde(default)]
    pub preset_models: PresetModels,
    /// Custom model ID to use for explaining scripts.
    pub explainer_model: Option<String>,
    /// The verbosity level for the explainer feature.
    pub explain_verbosity: Option<ExplainVerbosity>,
    /// The target shell for script generation and execution.
    pub shell: Option<String>,
    /// Daily request limit threshold for warnings.
    pub daily_limit: Option<u32>,
    /// Monthly request limit threshold for warnings.
    pub monthly_limit: Option<u32>,
    /// Maximum time in seconds a generated script is allowed to run.
    pub script_timeout: Option<u64>,
}

impl Config {
    /// Returns the path to the configuration directory (defaults to `~/.config/ru.sh`).
    pub fn dir() -> Option<PathBuf> {
        // Allow overriding config directory for tests and controlled environments.
        if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV_VAR) {
            let path = PathBuf::from(dir);
            if !path.as_os_str().is_empty() {
                return Some(path);
            }
        }

        dirs::home_dir().map(|home| home.join(".config").join("ru.sh"))
    }

    /// Returns the full path to the configuration file (`config.toml`).
    pub fn path() -> Option<PathBuf> {
        Self::dir().map(|dir| dir.join("config.toml"))
    }

    /// Loads the configuration from the default file path.
    ///
    /// If the file does not exist, a default configuration is returned.
    pub fn load() -> Result<Self> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        Self::load_from(path)
    }

    /// Loads the configuration from a specific file path.
    ///
    /// If parsing fails, the corrupted file is backed up and a default configuration is returned.
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

    /// Saves the current configuration to the default file path.
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine config path")?;
        self.save_to(path)
    }

    /// Saves the current configuration to a specific file path.
    pub fn save_to(&self, path: PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            ensure_secure_dir(parent)?;
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

    /// Returns the configured API key, if any.
    #[allow(clippy::useless_asref)]
    pub fn get_api_key(&self) -> Option<&str> {
        self.api_key.as_ref().map(|s| s.expose_secret().as_ref())
    }

    /// Sets the API key in the configuration.
    pub fn set_api_key(&mut self, key: String) {
        self.api_key = Some(SecretString::from(key));
    }

    /// Clears the API key from the configuration.
    pub fn clear_api_key(&mut self) {
        self.api_key = None;
    }

    /// Returns the active model preset, falling back to the default if not set.
    pub fn get_model_preset(&self) -> ModelPreset {
        self.model_preset.unwrap_or_default()
    }

    /// Sets the active model preset. This clears any existing one-time custom model.
    pub fn set_model_preset(&mut self, preset: ModelPreset) {
        self.model_preset = Some(preset);
        // Clear custom model when setting a preset
        self.custom_model = None;
    }

    /// Returns the one-time custom model ID, if set.
    pub fn get_custom_model(&self) -> Option<&str> {
        self.custom_model.as_deref()
    }

    /// Sets a one-time custom model ID.
    pub fn set_custom_model(&mut self, model_id: String) {
        self.custom_model = Some(model_id);
    }

    /// Clears both the preset and any custom model settings.
    pub fn clear_model(&mut self) {
        self.model_preset = None;
        self.custom_model = None;
    }

    /// Configures a persistent custom model for a specific preset.
    pub fn set_preset_model(&mut self, preset: &ModelPreset, model_id: String) {
        self.preset_models.set(preset, model_id);
    }

    /// Clears the persistent custom model for a specific preset.
    pub fn clear_preset_model(&mut self, preset: &ModelPreset) {
        self.preset_models.clear(preset);
    }

    /// Returns the persistent custom model configured for a specific preset.
    pub fn get_preset_model(&self, preset: &ModelPreset) -> Option<&str> {
        self.preset_models.get(preset)
    }

    /// Returns the default model ID for the given preset.
    pub fn get_default_model_id(preset: &ModelPreset) -> &'static str {
        match preset {
            ModelPreset::Fast => DEFAULT_MODEL_FAST,
            ModelPreset::Standard => DEFAULT_MODEL_STANDARD,
            ModelPreset::Quality => DEFAULT_MODEL_QUALITY,
        }
    }

    /// Returns the effective model ID based on configuration precedence.
    ///
    /// Priority: `custom_model` (one-time) > preset custom override > preset default.
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

    /// Sets a custom model ID for the explainer feature.
    pub fn set_explainer_model(&mut self, model_id: String) {
        self.explainer_model = Some(model_id);
    }

    /// Clears the custom explainer model, reverting it to the default.
    pub fn clear_explainer_model(&mut self) {
        self.explainer_model = None;
    }

    /// Returns the effective model ID to be used for script explanations.
    pub fn get_explainer_model(&self) -> &str {
        self.explainer_model
            .as_deref()
            .unwrap_or(DEFAULT_MODEL_EXPLAINER)
    }

    /// Returns the configured explain verbosity level.
    pub fn get_explain_verbosity(&self) -> ExplainVerbosity {
        self.explain_verbosity.unwrap_or_default()
    }

    /// Sets the verbosity level for script explanations.
    pub fn set_explain_verbosity(&mut self, verbosity: ExplainVerbosity) {
        self.explain_verbosity = Some(verbosity);
    }

    /// Clears the explain verbosity setting, reverting it to the default.
    pub fn clear_explain_verbosity(&mut self) {
        self.explain_verbosity = None;
    }

    /// Returns the daily request limit threshold.
    pub fn get_daily_limit(&self) -> Option<u32> {
        self.daily_limit
    }

    /// Sets the daily request limit threshold.
    pub fn set_daily_limit(&mut self, limit: u32) {
        self.daily_limit = Some(limit);
    }

    /// Clears the daily request limit threshold.
    pub fn clear_daily_limit(&mut self) {
        self.daily_limit = None;
    }

    /// Returns the monthly request limit threshold.
    pub fn get_monthly_limit(&self) -> Option<u32> {
        self.monthly_limit
    }

    /// Sets the monthly request limit threshold.
    pub fn set_monthly_limit(&mut self, limit: u32) {
        self.monthly_limit = Some(limit);
    }

    /// Clears the monthly request limit threshold.
    pub fn clear_monthly_limit(&mut self) {
        self.monthly_limit = None;
    }

    /// Returns the script execution timeout in seconds.
    pub fn get_script_timeout(&self) -> u64 {
        self.script_timeout.unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS)
    }

    /// Sets the script execution timeout in seconds.
    pub fn set_script_timeout(&mut self, timeout: u64) {
        self.script_timeout = Some(timeout);
    }

    /// Clears the script execution timeout, reverting it to the default.
    pub fn clear_script_timeout(&mut self) {
        self.script_timeout = None;
    }

    /// Returns the manually configured target shell, if any.
    pub fn get_shell(&self) -> Option<&str> {
        self.shell.as_deref()
    }

    /// Sets the target shell.
    pub fn set_shell(&mut self, shell: String) {
        self.shell = Some(shell);
    }

    /// Clears the target shell configuration, reverting to auto-detection.
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
        assert!(config.api_key.is_none());
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
        assert!(config.api_key.is_none());
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
        assert!(config.api_key.is_none()); // Should return default config

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
        assert!(config.api_key.is_none());
        Ok(())
    }

    #[test]
    fn test_ensure_secure_dir_creates_new_directory() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("new_secure_dir");

        assert!(!dir.exists());
        ensure_secure_dir(&dir)?;
        assert!(dir.exists());
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "New directory should have 0700 permissions");
        }

        Ok(())
    }

    #[test]
    fn test_ensure_secure_dir_idempotent_on_existing() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("existing_dir");

        // Create the directory first
        fs::create_dir(&dir)?;
        assert!(dir.exists());

        // Calling ensure_secure_dir on an existing directory should succeed
        ensure_secure_dir(&dir)?;
        assert!(dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "Existing directory should be corrected to 0700 permissions"
            );
        }

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_secure_dir_corrects_permissive_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("permissive_dir");

        // Create directory with overly permissive permissions (0755)
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
        let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "Directory should start with 0755 permissions");

        // ensure_secure_dir should correct to 0700
        ensure_secure_dir(&dir)?;
        let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "Directory with 0755 should be corrected to 0700"
        );

        Ok(())
    }

    #[test]
    fn test_ensure_secure_dir_creates_nested_path() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("parent").join("child").join("target");

        assert!(!dir.exists());
        ensure_secure_dir(&dir)?;
        assert!(dir.exists());
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "Target directory in nested path should have 0700 permissions"
            );
        }

        Ok(())
    }
}
