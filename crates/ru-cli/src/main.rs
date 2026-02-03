mod api;
mod config;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use config::{Config, ModelPreset};
use dialoguer::Select;
use std::env;

#[derive(Parser, Debug)]
#[command(name = "ru")]
#[command(author, version, about = "Convert natural language to bash scripts")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// The prompt describing what you want to do
    #[arg(short, long, global = true)]
    prompt: Option<String>,

    /// OpenRouter API key (overrides env var and config file)
    #[arg(long, global = true, hide_env_values = true)]
    api_key: Option<String>,

    /// Model preset: fast, cheap, or standard (default)
    #[arg(short, long, global = true)]
    model: Option<String>,

    /// Custom model ID (overrides preset)
    #[arg(long, global = true)]
    model_id: Option<String>,

    /// Skip confirmation and execute immediately (use with caution)
    #[arg(short = 'y', long, global = true)]
    yes: bool,

    /// Show the generated script without executing
    #[arg(long, global = true)]
    dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Set a configuration value
    Set {
        /// The key to set (api-key, model, model-id)
        key: String,
        /// The value to set
        value: String,
    },
    /// Get a configuration value
    Get {
        /// The key to get (api-key, model, model-id)
        key: String,
    },
    /// Show the config file path
    Path,
    /// Clear a configuration value
    Clear {
        /// The key to clear (api-key, model)
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Config { action }) => handle_config(action),
        None => run_prompt(cli).await,
    }
}

fn handle_config(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Set { key, value } => {
            let mut config = Config::load()?;
            match key.as_str() {
                "api-key" | "api_key" => {
                    config.set_api_key(value);
                    config.save()?;
                    println!("{}", "API key saved successfully.".green());
                }
                "model" => {
                    let preset: ModelPreset = value
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    config.set_model_preset(preset.clone());
                    config.save()?;
                    println!(
                        "{}",
                        format!("Model preset set to: {} ({})", preset, config.get_model_id()).green()
                    );
                }
                "model-id" | "model_id" => {
                    config.set_custom_model(value.clone());
                    config.save()?;
                    println!(
                        "{}",
                        format!("Custom model set to: {}", value).green()
                    );
                }
                _ => bail!(
                    "Unknown config key: {}. Available keys: api-key, model, model-id",
                    key
                ),
            }
        }
        ConfigAction::Get { key } => {
            let config = Config::load()?;
            match key.as_str() {
                "api-key" | "api_key" => {
                    if let Some(api_key) = config.get_api_key() {
                        // Show only first/last few chars for security
                        let masked = if api_key.len() > 12 {
                            format!(
                                "{}...{}",
                                &api_key[..6],
                                &api_key[api_key.len() - 4..]
                            )
                        } else {
                            "[set]".to_string()
                        };
                        println!("api-key: {}", masked);
                    } else {
                        println!("{}", "api-key: not set".dimmed());
                    }
                }
                "model" => {
                    if let Some(custom) = config.get_custom_model() {
                        println!("model: custom ({})", custom);
                    } else {
                        let preset = config.get_model_preset();
                        println!("model: {} ({})", preset, config.get_model_id());
                    }
                }
                "model-id" | "model_id" => {
                    println!("model-id: {}", config.get_model_id());
                }
                _ => bail!(
                    "Unknown config key: {}. Available keys: api-key, model, model-id",
                    key
                ),
            }
        }
        ConfigAction::Path => {
            if let Some(path) = Config::path() {
                println!("{}", path.display());
            } else {
                bail!("Could not determine config path");
            }
        }
        ConfigAction::Clear { key } => {
            let mut config = Config::load()?;
            match key.as_str() {
                "api-key" | "api_key" => {
                    config.clear_api_key();
                    config.save()?;
                    println!("{}", "API key cleared.".green());
                }
                "model" => {
                    config.clear_model();
                    config.save()?;
                    println!("{}", "Model settings cleared (using default: standard).".green());
                }
                _ => bail!(
                    "Unknown config key: {}. Available keys: api-key, model",
                    key
                ),
            }
        }
    }
    Ok(())
}

async fn run_prompt(cli: Cli) -> Result<()> {
    let Some(prompt) = cli.prompt else {
        bail!("Missing prompt. Usage: ru -p \"your prompt here\"");
    };

    // Resolve API key: CLI flag > env var > config file
    let api_key = resolve_api_key(cli.api_key)?;

    // Resolve model: CLI flag > config file > default
    let model_id = resolve_model(cli.model_id, cli.model)?;

    println!("{}", "ru.sh - Natural Language to Bash".bold());
    println!("{}", format!("Using model: {}", model_id).dimmed());
    println!();

    let generated_script = api::generate_script(&prompt, &api_key, &model_id).await?;

    println!("{}", "Generated script:".cyan().bold());
    println!("{}", "-".repeat(40).dimmed());
    println!("{}", generated_script.yellow());
    println!("{}", "-".repeat(40).dimmed());
    println!();

    if cli.dry_run {
        println!("{}", "Dry run mode - script not executed.".dimmed());
        return Ok(());
    }

    if cli.yes {
        execute_script(&generated_script)?;
        return Ok(());
    }

    // Interactive confirmation
    let options = vec!["Execute", "Explain", "Cancel"];
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(&options)
        .default(0)
        .interact()?;

    match selection {
        0 => execute_script(&generated_script)?,
        1 => {
            // TODO: Ask LLM to explain the script
            println!("{}", "Explanation feature coming soon...".dimmed());
        }
        2 => {
            println!("{}", "Cancelled.".red());
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Resolve API key from: CLI flag > env var > config file
fn resolve_api_key(cli_key: Option<String>) -> Result<String> {
    let env_key = env::var("OPENROUTER_API_KEY").ok();
    let config = Config::load()?;
    let config_key = config.api_key;

    if let Some(key) = determine_api_key(cli_key, env_key, config_key) {
        return Ok(key);
    }

    // No API key found - show helpful error
    let config_path = Config::path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.config/ru.sh/config.toml".to_string());

    bail!(
        "No API key found. Set it using one of:\n\n\
         1. ru config set api-key <your-key>\n\
         2. export OPENROUTER_API_KEY=<your-key>\n\
         3. ru --api-key <your-key>\n\n\
         Config file location: {}",
        config_path
    );
}

/// Pure logic to determine API key precedence
fn determine_api_key(
    cli_key: Option<String>,
    env_key: Option<String>,
    config_key: Option<String>,
) -> Option<String> {
    cli_key
        .or(env_key.filter(|k| !k.is_empty()))
        .or(config_key)
}

/// Resolve model from: CLI model-id > CLI preset > config
fn resolve_model(cli_model_id: Option<String>, cli_preset: Option<String>) -> Result<String> {
    // CLI model-id takes highest priority
    if let Some(model_id) = cli_model_id {
        return Ok(model_id);
    }

    // CLI preset takes next priority
    if let Some(preset_str) = cli_preset {
        let preset: ModelPreset = preset_str
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        let mut temp_config = Config::default();
        temp_config.set_model_preset(preset);
        return Ok(temp_config.get_model_id().to_string());
    }

    // Fall back to config file
    let config = Config::load()?;
    Ok(config.get_model_id().to_string())
}

fn execute_script(script: &str) -> Result<()> {
    println!("{}", "Executing...".green().bold());

    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()?;

    if !output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr).red());
    }

    if output.status.success() {
        println!("{}", "Script executed successfully.".green());
    } else {
        println!(
            "{}",
            format!("Script exited with code: {:?}", output.status.code()).red()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_api_key_precedence() {
        let cli = Some("cli-key".to_string());
        let env = Some("env-key".to_string());
        let config = Some("config-key".to_string());

        // CLI > Env > Config
        assert_eq!(
            determine_api_key(cli.clone(), env.clone(), config.clone()),
            Some("cli-key".to_string())
        );

        // Env > Config
        assert_eq!(
            determine_api_key(None, env.clone(), config.clone()),
            Some("env-key".to_string())
        );

        // Config only
        assert_eq!(
            determine_api_key(None, None, config.clone()),
            Some("config-key".to_string())
        );

        // Env empty string should be ignored
        assert_eq!(
            determine_api_key(None, Some("".to_string()), config.clone()),
            Some("config-key".to_string())
        );

        // None
        assert_eq!(determine_api_key(None, None, None), None);
    }

    #[test]
    fn test_resolve_model_cli_model_id() {
        // CLI model-id takes priority
        let result = resolve_model(
            Some("custom/model".to_string()),
            Some("fast".to_string()),
        );
        assert_eq!(result.unwrap(), "custom/model");
    }

    #[test]
    fn test_resolve_model_cli_preset() {
        // CLI preset when no model-id
        let result = resolve_model(None, Some("fast".to_string()));
        assert!(result.is_ok());
        // Should return the fast preset model
        let model = result.unwrap();
        assert!(!model.is_empty());
    }

    #[test]
    fn test_resolve_model_default() {
        // Default when nothing specified
        let result = resolve_model(None, None);
        assert!(result.is_ok());
        // Should return standard preset model
        let model = result.unwrap();
        assert!(!model.is_empty());
    }

    #[test]
    fn test_resolve_model_invalid_preset() {
        let result = resolve_model(None, Some("invalid".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_script_success() {
        // We use a simple echo command that should always succeed
        let result = execute_script("echo 'hello world'");
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_script_failure() {
        // We use a command that is guaranteed to fail
        // Note: execute_script currently returns Ok(()) even on script failure (exit code != 0),
        // because the *execution* itself (spawning process) succeeded.
        // It prints the error. If we want to test that it ran, we check is_ok().
        let result = execute_script("exit 1");
        assert!(result.is_ok());
    }
}
