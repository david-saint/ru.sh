use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

/// Model preset for quick selection
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelPreset {
    /// Fastest response time
    Fast,
    /// Lowest cost per request
    Cheap,
    /// Best balance of quality, speed, and cost
    #[default]
    Standard,
}

impl std::fmt::Display for ModelPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelPreset::Fast => write!(f, "fast"),
            ModelPreset::Cheap => write!(f, "cheap"),
            ModelPreset::Standard => write!(f, "standard"),
        }
    }
}

impl FromStr for ModelPreset {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fast" => Ok(ModelPreset::Fast),
            "cheap" => Ok(ModelPreset::Cheap),
            "standard" => Ok(ModelPreset::Standard),
            _ => Err(format!(
                "Invalid model preset: '{}'. Valid options: fast, cheap, standard",
                s
            )),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub api_key: Option<String>,
    /// Model preset (fast, cheap, standard)
    pub model_preset: Option<ModelPreset>,
    /// Custom model ID (overrides preset)
    pub custom_model: Option<String>,
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

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Save config to file, creating directory if needed
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine config path")?;
        self.save_to(path)
    }

    /// Save config to a specific path
    pub fn save_to(&self, path: PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }

        let contents = toml::to_string_pretty(self).context("Failed to serialize config")?;

        fs::write(&path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

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

    /// Get the effective model ID based on config
    /// Priority: custom_model > preset mapping
    pub fn get_model_id(&self) -> &str {
        if let Some(custom) = &self.custom_model {
            return custom;
        }

        // Map presets to model IDs based on benchmark results
        // Benchmark on NL2SH-ALFA dataset (30 examples):
        // - gpt-4o-mini: 76.67% accuracy, 604ms latency, $0.12/1K
        // - gemini-2.5-flash: 60% accuracy, 967ms latency, $0.11/1K
        // - claude-sonnet-4.5: 63.33% accuracy, 1947ms latency, $0.14/1K
        match self.get_model_preset() {
            ModelPreset::Fast => "google/gemini-2.5-flash",
            ModelPreset::Cheap => "google/gemini-2.5-flash",
            ModelPreset::Standard => "openai/gpt-4o-mini",
        }
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
        config.set_model_preset(ModelPreset::Cheap);
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
        assert_eq!(ModelPreset::from_str("CHEAP").unwrap(), ModelPreset::Cheap);
        assert_eq!(
            ModelPreset::from_str("Standard").unwrap(),
            ModelPreset::Standard
        );
        assert!(ModelPreset::from_str("invalid").is_err());
    }

    #[test]
    fn test_get_model_id_priority() {
        let mut config = Config::default();

        // Default returns standard preset model
        let default_model = config.get_model_id();
        assert!(!default_model.is_empty());

        // Custom model overrides preset
        config.set_custom_model("my/custom-model".to_string());
        assert_eq!(config.get_model_id(), "my/custom-model");
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
