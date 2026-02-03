mod config;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use config::Config;
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
        /// The key to set (api-key)
        key: String,
        /// The value to set
        value: String,
    },
    /// Get a configuration value
    Get {
        /// The key to get (api-key)
        key: String,
    },
    /// Show the config file path
    Path,
    /// Clear a configuration value
    Clear {
        /// The key to clear (api-key)
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
                _ => bail!("Unknown config key: {}. Available keys: api-key", key),
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
                _ => bail!("Unknown config key: {}. Available keys: api-key", key),
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
                _ => bail!("Unknown config key: {}. Available keys: api-key", key),
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

    println!("{}", "ru.sh - Natural Language to Bash".bold());
    println!();

    let generated_script = generate_script(&prompt, &api_key).await?;

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
    // 1. CLI flag (highest priority)
    if let Some(key) = cli_key {
        return Ok(key);
    }

    // 2. Environment variable
    if let Ok(key) = env::var("OPENROUTER_API_KEY") {
        if !key.is_empty() {
            return Ok(key);
        }
    }

    // 3. Config file
    let config = Config::load()?;
    if let Some(key) = config.api_key {
        return Ok(key);
    }

    // No API key found - show helpful error
    let config_path = Config::path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.config/ru/config.toml".to_string());

    bail!(
        "No API key found. Set it using one of:\n\n\
         1. ru config set api-key <your-key>\n\
         2. export OPENROUTER_API_KEY=<your-key>\n\
         3. ru --api-key <your-key>\n\n\
         Config file location: {}",
        config_path
    );
}

async fn generate_script(prompt: &str, _api_key: &str) -> Result<String> {
    // TODO: Implement actual OpenRouter API call
    Ok(format!(
        "# Generated from: {}\necho \"Script generation not yet implemented\"",
        prompt
    ))
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
