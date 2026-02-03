use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub api_key: Option<String>,
}

impl Config {
    /// Get the config directory path (~/.config/ru)
    pub fn dir() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".config").join("ru"))
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
        let dir = Self::dir().context("Could not determine config directory")?;
        let path = Self::path().context("Could not determine config path")?;

        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create config directory: {}", dir.display()))?;

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
}
