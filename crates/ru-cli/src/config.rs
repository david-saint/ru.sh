use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub api_key: Option<String>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.api_key, None);
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
    fn test_save_and_load() -> Result<()> {
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();
        
        // Save
        let mut config = Config::default();
        config.set_api_key("persistent-key".to_string());
        config.save_to(path.clone())?;

        // Load
        let loaded = Config::load_from(path)?;
        assert_eq!(loaded.get_api_key(), Some("persistent-key"));

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
