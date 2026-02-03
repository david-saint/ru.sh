mod api;
mod config;
mod history;
mod safety;
mod sanitize;
mod usage;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use colored::Colorize;
use config::{Config, ModelPreset};
use dialoguer::Select;
use history::ExecutionRecord;
use safety::{RiskLevel, SafetyReport};
use std::env;
use std::io::{self, Write};
use std::time::Instant;

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

    /// Model preset: fast, standard (default), or quality
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

    /// Force execution of high-risk scripts (requires -y)
    #[arg(long, global = true)]
    force: bool,
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
        /// The key to set (api-key, model, model-id, model.fast, model.standard, model.quality, model.explainer, daily-limit, monthly-limit)
        key: String,
        /// The value to set
        value: String,
    },
    /// Get a configuration value
    Get {
        /// The key to get (api-key, model, model-id, model.fast, model.standard, model.quality, model.explainer, daily-limit, monthly-limit)
        key: String,
    },
    /// Show the config file path
    Path,
    /// Clear a configuration value
    Clear {
        /// The key to clear (api-key, model, model.fast, model.standard, model.quality, model.explainer, daily-limit, monthly-limit)
        key: String,
    },
    /// List all model presets and their current models
    Models,
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
                    let preset: ModelPreset =
                        value.parse().map_err(|e: String| anyhow::anyhow!(e))?;
                    config.set_model_preset(preset.clone());
                    config.save()?;
                    println!(
                        "{}",
                        format!(
                            "Model preset set to: {} ({})",
                            preset,
                            config.get_model_id()
                        )
                        .green()
                    );
                }
                "model-id" | "model_id" => {
                    config.set_custom_model(value.clone());
                    config.save()?;
                    println!("{}", format!("Custom model set to: {}", value).green());
                }
                "model.fast" => {
                    config.set_preset_model(&ModelPreset::Fast, value.clone());
                    config.save()?;
                    println!(
                        "{}",
                        format!("Custom model for 'fast' preset set to: {}", value).green()
                    );
                }
                "model.standard" => {
                    config.set_preset_model(&ModelPreset::Standard, value.clone());
                    config.save()?;
                    println!(
                        "{}",
                        format!("Custom model for 'standard' preset set to: {}", value).green()
                    );
                }
                "model.quality" => {
                    config.set_preset_model(&ModelPreset::Quality, value.clone());
                    config.save()?;
                    println!(
                        "{}",
                        format!("Custom model for 'quality' preset set to: {}", value).green()
                    );
                }
                "model.explainer" => {
                    config.set_explainer_model(value.clone());
                    config.save()?;
                    println!("{}", format!("Explainer model set to: {}", value).green());
                }
                "daily-limit" | "daily_limit" => {
                    let limit: u32 = value.parse().map_err(|_| {
                        anyhow::anyhow!("Invalid daily limit: must be a positive integer")
                    })?;
                    config.set_daily_limit(limit);
                    config.save()?;
                    println!(
                        "{}",
                        format!("Daily limit set to: {} requests", limit).green()
                    );
                }
                "monthly-limit" | "monthly_limit" => {
                    let limit: u32 = value.parse().map_err(|_| {
                        anyhow::anyhow!("Invalid monthly limit: must be a positive integer")
                    })?;
                    config.set_monthly_limit(limit);
                    config.save()?;
                    println!(
                        "{}",
                        format!("Monthly limit set to: {} requests", limit).green()
                    );
                }
                _ => bail!(
                    "Unknown config key: {}. Available keys: api-key, model, model-id, model.fast, model.standard, model.quality, model.explainer, daily-limit, monthly-limit",
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
                            format!("{}...{}", &api_key[..6], &api_key[api_key.len() - 4..])
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
                "model.fast" => {
                    let default = Config::get_default_model_id(&ModelPreset::Fast);
                    if let Some(custom) = config.get_preset_model(&ModelPreset::Fast) {
                        println!("model.fast: {} (default: {})", custom, default);
                    } else {
                        println!("model.fast: {} (default)", default);
                    }
                }
                "model.standard" => {
                    let default = Config::get_default_model_id(&ModelPreset::Standard);
                    if let Some(custom) = config.get_preset_model(&ModelPreset::Standard) {
                        println!("model.standard: {} (default: {})", custom, default);
                    } else {
                        println!("model.standard: {} (default)", default);
                    }
                }
                "model.quality" => {
                    let default = Config::get_default_model_id(&ModelPreset::Quality);
                    if let Some(custom) = config.get_preset_model(&ModelPreset::Quality) {
                        println!("model.quality: {} (default: {})", custom, default);
                    } else {
                        println!("model.quality: {} (default)", default);
                    }
                }
                "model.explainer" => {
                    let default = config::DEFAULT_MODEL_EXPLAINER;
                    if config.explainer_model.is_some() {
                        println!(
                            "model.explainer: {} (default: {})",
                            config.get_explainer_model(),
                            default
                        );
                    } else {
                        println!("model.explainer: {} (default)", default);
                    }
                }
                "daily-limit" | "daily_limit" => {
                    if let Some(limit) = config.get_daily_limit() {
                        println!("daily-limit: {} requests", limit);
                    } else {
                        println!(
                            "{}",
                            "daily-limit: not set (default warning at 100)".dimmed()
                        );
                    }
                }
                "monthly-limit" | "monthly_limit" => {
                    if let Some(limit) = config.get_monthly_limit() {
                        println!("monthly-limit: {} requests", limit);
                    } else {
                        println!(
                            "{}",
                            "monthly-limit: not set (default warning at 1000)".dimmed()
                        );
                    }
                }
                _ => bail!(
                    "Unknown config key: {}. Available keys: api-key, model, model-id, model.fast, model.standard, model.quality, model.explainer, daily-limit, monthly-limit",
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
                    println!(
                        "{}",
                        "Model settings cleared (using default: standard).".green()
                    );
                }
                "model.fast" => {
                    config.clear_preset_model(&ModelPreset::Fast);
                    config.save()?;
                    let default = Config::get_default_model_id(&ModelPreset::Fast);
                    println!(
                        "{}",
                        format!("Custom 'fast' model cleared. Using default: {}", default).green()
                    );
                }
                "model.standard" => {
                    config.clear_preset_model(&ModelPreset::Standard);
                    config.save()?;
                    let default = Config::get_default_model_id(&ModelPreset::Standard);
                    println!(
                        "{}",
                        format!(
                            "Custom 'standard' model cleared. Using default: {}",
                            default
                        )
                        .green()
                    );
                }
                "model.quality" => {
                    config.clear_preset_model(&ModelPreset::Quality);
                    config.save()?;
                    let default = Config::get_default_model_id(&ModelPreset::Quality);
                    println!(
                        "{}",
                        format!("Custom 'quality' model cleared. Using default: {}", default)
                            .green()
                    );
                }
                "model.explainer" => {
                    config.clear_explainer_model();
                    config.save()?;
                    let default = config::DEFAULT_MODEL_EXPLAINER;
                    println!(
                        "{}",
                        format!("Explainer model cleared. Using default: {}", default).green()
                    );
                }
                "daily-limit" | "daily_limit" => {
                    config.clear_daily_limit();
                    config.save()?;
                    println!(
                        "{}",
                        "Daily limit cleared. Using default warning threshold (100).".green()
                    );
                }
                "monthly-limit" | "monthly_limit" => {
                    config.clear_monthly_limit();
                    config.save()?;
                    println!(
                        "{}",
                        "Monthly limit cleared. Using default warning threshold (1000).".green()
                    );
                }
                _ => bail!(
                    "Unknown config key: {}. Available keys: api-key, model, model.fast, model.standard, model.quality, model.explainer, daily-limit, monthly-limit",
                    key
                ),
            }
        }
        ConfigAction::Models => {
            let config = Config::load()?;
            println!("{}", "Model Presets:".bold());
            println!();

            let current_preset = config.get_model_preset();
            for preset in [
                ModelPreset::Fast,
                ModelPreset::Standard,
                ModelPreset::Quality,
            ] {
                let default = Config::get_default_model_id(&preset);
                let custom = config.get_preset_model(&preset);
                let is_current = current_preset == preset;

                let marker = if is_current { " (current)" } else { "" };

                if let Some(custom_model) = custom {
                    println!("  {}{}: {}", preset, marker, custom_model.cyan());
                    println!("    {} {}", "default:".dimmed(), default.dimmed());
                } else {
                    println!("  {}{}: {}", preset, marker, default.cyan());
                }
            }

            println!();
            println!("{}", "Explainer:".bold());
            let default_explainer = config::DEFAULT_MODEL_EXPLAINER;
            if config.explainer_model.is_some() {
                println!("  explainer: {}", config.get_explainer_model().cyan());
                println!("    {} {}", "default:".dimmed(), default_explainer.dimmed());
            } else {
                println!("  explainer: {}", default_explainer.cyan());
            }
        }
    }
    Ok(())
}

async fn run_prompt(cli: Cli) -> Result<()> {
    let Some(prompt) = cli.prompt else {
        bail!("Missing prompt. Usage: ru -p \"your prompt here\"");
    };

    // Validate prompt
    if let Err(e) = safety::validate_prompt(&prompt) {
        bail!("Invalid prompt: {}", e);
    }

    // Resolve API key: CLI flag > env var > config file
    let api_key = resolve_api_key(cli.api_key)?;

    // Resolve model: CLI flag > config file > default
    let model_id = resolve_model(cli.model_id, cli.model)?;

    // Load config for limits
    let config = Config::load()?;

    // Track usage and check limits
    let usage_warnings = usage::track_usage(config.get_daily_limit(), config.get_monthly_limit())?;
    for warning in &usage_warnings {
        if warning.is_limit_exceeded {
            println!(
                "{}",
                format!("Warning: {}", warning.message).yellow().bold()
            );
        } else {
            println!("{}", format!("Note: {}", warning.message).yellow());
        }
    }

    println!("{}", "ru.sh - Natural Language to Bash".bold());
    println!("{}", format!("Using model: {}", model_id).dimmed());
    println!();

    let start = Instant::now();
    let generated_script = api::generate_script(&prompt, &api_key, &model_id).await?;
    let api_duration_ms = start.elapsed().as_millis() as u64;

    // Analyze script for safety
    let report = safety::analyze_script(&generated_script);

    // Display script with safety information
    display_script_with_safety(&generated_script, &report);

    if cli.dry_run {
        println!("{}", "Dry run mode - script not executed.".dimmed());
        log_execution(
            &prompt,
            &generated_script,
            &report,
            false,
            None,
            Some(api_duration_ms),
        );
        return Ok(());
    }

    // Handle --yes flag (auto-execute)
    if cli.yes {
        // Block execution if syntax is invalid
        if !report.syntax_valid {
            println!(
                "{}",
                "Cannot auto-execute: script has syntax errors."
                    .red()
                    .bold()
            );
            log_execution(
                &prompt,
                &generated_script,
                &report,
                false,
                None,
                Some(api_duration_ms),
            );
            return Ok(());
        }

        // Block high-risk scripts without --force
        if report.requires_force() && !cli.force {
            println!(
                "{}",
                format!(
                    "Cannot auto-execute {} risk script without --force flag.",
                    report.overall_risk
                )
                .red()
                .bold()
            );
            println!(
                "{}",
                "Use: ru -y --force -p \"...\" to execute dangerous scripts.".dimmed()
            );
            log_execution(
                &prompt,
                &generated_script,
                &report,
                false,
                None,
                Some(api_duration_ms),
            );
            return Ok(());
        }

        let exit_code = execute_script(&generated_script)?;
        log_execution(
            &prompt,
            &generated_script,
            &report,
            true,
            exit_code,
            Some(api_duration_ms),
        );
        return Ok(());
    }

    // Interactive confirmation
    if !report.syntax_valid {
        println!(
            "{}",
            "Script has syntax errors. Execution blocked.".red().bold()
        );
        log_execution(
            &prompt,
            &generated_script,
            &report,
            false,
            None,
            Some(api_duration_ms),
        );
        return Ok(());
    }

    // For high/critical risk, require explicit confirmation
    if report.requires_force() {
        let exit_code = prompt_high_risk_execution(&generated_script, &report, &api_key).await?;
        log_execution(
            &prompt,
            &generated_script,
            &report,
            exit_code.is_some(),
            exit_code,
            Some(api_duration_ms),
        );
    } else {
        let exit_code =
            prompt_normal_execution(&generated_script, &report, &prompt, &api_key).await?;
        log_execution(
            &prompt,
            &generated_script,
            &report,
            exit_code.is_some(),
            exit_code,
            Some(api_duration_ms),
        );
    }

    Ok(())
}

/// Display the script with safety warnings
fn display_script_with_safety(script: &str, report: &SafetyReport) {
    // Show risk header
    match report.overall_risk {
        RiskLevel::Critical => {
            println!("{}", "!!! CRITICAL RISK !!!".on_red().white().bold());
        }
        RiskLevel::High => {
            println!("{}", "!! HIGH RISK !!".red().bold());
        }
        RiskLevel::Medium => {
            println!("{}", "! Caution".yellow().bold());
        }
        RiskLevel::Low => {
            println!("{}", "Info".cyan());
        }
        RiskLevel::Safe => {}
    }

    // Show warnings
    for warning in &report.warnings {
        let icon = match warning.level {
            RiskLevel::Critical => "!!!",
            RiskLevel::High => "!!",
            RiskLevel::Medium => "!",
            RiskLevel::Low => "i",
            RiskLevel::Safe => "",
        };
        let color_msg = format!("[{}] {}: {}", icon, warning.category, warning.description);
        match warning.level {
            RiskLevel::Critical => println!("  {}", color_msg.red().bold()),
            RiskLevel::High => println!("  {}", color_msg.red()),
            RiskLevel::Medium => println!("  {}", color_msg.yellow()),
            RiskLevel::Low => println!("  {}", color_msg.dimmed()),
            RiskLevel::Safe => {}
        }
    }

    if !report.warnings.is_empty() {
        println!();
    }

    println!("{}", "Generated script:".cyan().bold());
    println!("{}", "-".repeat(40).dimmed());
    // Sanitize script to prevent terminal injection attacks
    println!("{}", sanitize::for_display(script).yellow());
    println!("{}", "-".repeat(40).dimmed());

    // Show syntax error if present
    if !report.syntax_valid
        && let Some(ref error) = report.syntax_error
    {
        println!();
        println!("{}", "Syntax Error:".red().bold());
        println!("  {}", error.red());
    }

    println!();
}

/// Prompt for execution of high-risk scripts (requires typing "yes")
async fn prompt_high_risk_execution(
    script: &str,
    report: &SafetyReport,
    api_key: &str,
) -> Result<Option<i32>> {
    println!(
        "{}",
        format!(
            "This script has {} risk. You must type 'yes' to confirm execution.",
            report.overall_risk
        )
        .yellow()
        .bold()
    );
    println!();

    let options = vec!["Confirm (type 'yes')", "Explain", "Cancel"];
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(&options)
        .default(2) // Default to Cancel for safety
        .interact()?;

    match selection {
        0 => {
            // Require typing "yes"
            print!("{}", "Type 'yes' to confirm: ".yellow());
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().to_lowercase() == "yes" {
                let exit_code = execute_script(script)?;
                Ok(exit_code)
            } else {
                println!("{}", "Cancelled - confirmation not received.".red());
                Ok(None)
            }
        }
        1 => {
            explain_script_only(script, api_key).await?;
            // After explaining, ask again
            Box::pin(prompt_high_risk_execution(script, report, api_key)).await
        }
        2 => {
            println!("{}", "Cancelled.".red());
            Ok(None)
        }
        _ => unreachable!(),
    }
}

/// Prompt for normal execution (safe to medium risk)
async fn prompt_normal_execution(
    script: &str,
    _report: &SafetyReport,
    _prompt: &str,
    api_key: &str,
) -> Result<Option<i32>> {
    let options = vec!["Execute", "Explain", "Cancel"];
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(&options)
        .default(0)
        .interact()?;

    match selection {
        0 => execute_script(script),
        1 => explain_and_prompt(script, api_key).await,
        2 => {
            println!("{}", "Cancelled.".red());
            Ok(None)
        }
        _ => unreachable!(),
    }
}

/// Explain script without follow-up prompt
async fn explain_script_only(script: &str, api_key: &str) -> Result<()> {
    let config = Config::load()?;
    let explainer_model = config.get_explainer_model();

    println!(
        "{}",
        format!("Explaining with: {}", explainer_model).dimmed()
    );
    println!();

    let explanation = api::explain_script(script, api_key, explainer_model).await?;

    println!("{}", "Explanation:".cyan().bold());
    println!("{}", "-".repeat(40).dimmed());
    println!("{}", explanation);
    println!("{}", "-".repeat(40).dimmed());
    println!();

    Ok(())
}

/// Log execution to history
fn log_execution(
    prompt: &str,
    script: &str,
    report: &SafetyReport,
    executed: bool,
    exit_code: Option<i32>,
    duration_ms: Option<u64>,
) {
    let record = ExecutionRecord::new(
        prompt,
        script,
        report.overall_risk,
        executed,
        exit_code,
        duration_ms,
    );
    if let Err(e) = history::log_execution(&record) {
        eprintln!(
            "{}",
            format!("Warning: Failed to log execution: {}", e).dimmed()
        );
    }
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
    cli_key.or(env_key.filter(|k| !k.is_empty())).or(config_key)
}

/// Resolve model from: CLI model-id > CLI preset > config
fn resolve_model(cli_model_id: Option<String>, cli_preset: Option<String>) -> Result<String> {
    // CLI model-id takes highest priority
    if let Some(model_id) = cli_model_id {
        return Ok(model_id);
    }

    // Load config for both preset lookup and custom overrides
    let mut config = Config::load()?;

    // CLI preset takes next priority (but still respects user's custom model for that preset)
    if let Some(preset_str) = cli_preset {
        let preset: ModelPreset = preset_str.parse().map_err(|e: String| anyhow::anyhow!(e))?;
        config.set_model_preset(preset);
        return Ok(config.get_model_id().to_string());
    }

    // Fall back to config file settings
    Ok(config.get_model_id().to_string())
}

async fn explain_and_prompt(script: &str, api_key: &str) -> Result<Option<i32>> {
    let config = Config::load()?;
    let explainer_model = config.get_explainer_model();

    println!(
        "{}",
        format!("Explaining with: {}", explainer_model).dimmed()
    );
    println!();

    let explanation = api::explain_script(script, api_key, explainer_model).await?;

    println!("{}", "Explanation:".cyan().bold());
    println!("{}", "-".repeat(40).dimmed());
    println!("{}", explanation);
    println!("{}", "-".repeat(40).dimmed());
    println!();

    // Ask what to do next
    let options = vec!["Execute", "Cancel"];
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(&options)
        .default(0)
        .interact()?;

    match selection {
        0 => execute_script(script),
        1 => {
            println!("{}", "Cancelled.".red());
            Ok(None)
        }
        _ => unreachable!(),
    }
}

fn execute_script(script: &str) -> Result<Option<i32>> {
    println!("{}", "Executing...".green().bold());

    let start = Instant::now();
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()?;
    let duration = start.elapsed();

    if !output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr).red());
    }

    let exit_code = output.status.code();

    if output.status.success() {
        println!(
            "{}",
            format!(
                "Script executed successfully in {:.2}s.",
                duration.as_secs_f64()
            )
            .green()
        );
    } else {
        println!(
            "{}",
            format!("Script exited with code: {:?}", exit_code).red()
        );
    }

    Ok(exit_code)
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
        let result = resolve_model(Some("custom/model".to_string()), Some("fast".to_string()));
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
        assert_eq!(result.unwrap(), Some(0));
    }

    #[test]
    fn test_execute_script_failure() {
        // We use a command that is guaranteed to fail
        let result = execute_script("exit 1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(1));
    }
}
