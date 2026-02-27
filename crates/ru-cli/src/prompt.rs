use anyhow::{Context, Result};
use console::style;
use dialoguer::{Select, theme::ColorfulTheme};
use std::io::{self, Write};

/// A trait for interacting with the user via terminal prompts.
pub trait Prompter {
    /// Displays a selection menu and returns the index of the chosen item.
    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize>;
    /// Prompts the user for a text input and returns the resulting string.
    fn input(&self, prompt: &str) -> Result<String>;
}

/// The standard implementation of `Prompter` using `dialoguer` for interactive menus.
pub struct RealPrompter;

impl Prompter for RealPrompter {
    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize> {
        Select::with_theme(&select_theme())
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .interact()
            .context("Failed to interact with select prompt")
    }

    fn input(&self, prompt: &str) -> Result<String> {
        print!("{}", prompt);
        io::stdout().flush().context("Failed to flush stdout")?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("Failed to read from stdin")?;
        Ok(input)
    }
}

/// A mock implementation of `Prompter` for use in automated tests.
pub struct TestPrompter {
    select_responses: std::sync::Mutex<Vec<usize>>,
    input_responses: std::sync::Mutex<Vec<String>>,
}

impl TestPrompter {
    /// Creates a new `TestPrompter` with predefined responses from CSV strings.
    pub fn new(select_csv: &str, input_csv: &str) -> Self {
        let select_responses = select_csv
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect::<Vec<_>>();

        let input_responses = input_csv
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect::<Vec<_>>();

        Self {
            select_responses: std::sync::Mutex::new(select_responses),
            input_responses: std::sync::Mutex::new(input_responses),
        }
    }
}

impl Prompter for TestPrompter {
    fn select(&self, prompt: &str, items: &[&str], _default: usize) -> Result<usize> {
        let mut responses = self.select_responses.lock().unwrap();
        if responses.is_empty() {
            anyhow::bail!("No more mock select responses for prompt: {}", prompt);
        }
        let response = responses.remove(0);
        if response >= items.len() {
            anyhow::bail!(
                "Mock select response {} out of bounds for prompt: {}",
                response,
                prompt
            );
        }
        Ok(response)
    }

    fn input(&self, prompt: &str) -> Result<String> {
        let mut responses = self.input_responses.lock().unwrap();
        if responses.is_empty() {
            anyhow::bail!("No more mock input responses for prompt: {}", prompt);
        }
        Ok(responses.remove(0))
    }
}

fn select_theme() -> ColorfulTheme {
    ColorfulTheme {
        active_item_style: console::Style::new().bold(),
        active_item_prefix: style("▸ ".to_string()).bold(),
        inactive_item_prefix: style("  ".to_string()),
        ..ColorfulTheme::default()
    }
}
