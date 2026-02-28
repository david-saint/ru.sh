# ru.sh

> **Natural Language to Bash Scripts** 🚀

[![CI](https://github.com/david-saint/ru.sh/actions/workflows/ci.yml/badge.svg)](https://github.com/david-saint/ru.sh/actions/workflows/ci.yml)
[![Release](https://github.com/david-saint/ru.sh/actions/workflows/release.yml/badge.svg)](https://github.com/david-saint/ru.sh/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**ru.sh** is a powerful command-line tool that turns your plain English requests into executable bash scripts using AI. Stop memorizing obscure flags and complex syntax—just say what you want, review the generated script, and run it.

## ✨ Features

- **🗣️ Natural Language Interface**: Describe your task in plain English (e.g., "Find all files larger than 100MB and delete them").
- **🛡️ Safety & Risk Analysis**: Scripts are analyzed for risk levels (Safe to Critical) and syntax errors before execution.
- **🐚 Multi-Shell Support**: Works with Bash, Zsh, Fish, PowerShell, and Cmd with automatic detection.
- **📚 Script Explanation**: Get a detailed breakdown of what a generated command does with the "Explain" feature.
- **🔒 Prompt Injection Protection**: Built-in detection of malicious prompts and instruction overrides.
- **📜 Execution History**: Automatic logging of all prompts and generated scripts for auditing.
- **🎭 Model Presets**: Choose between `fast`, `standard`, and `quality` models via OpenRouter.
- **🔌 API Architecture**: [Documented integration architecture](API_INTEGRATION.md) for developers.
- **🛠️ Troubleshooting**: Need help? See the [Troubleshooting Guide](TROUBLESHOOTING.md).
- **⚙️ Flexible Configuration**: Manage API keys, models, usage limits, and timeouts via the CLI.
- **📊 Usage Tracking**: Monitor and set limits for your daily and monthly API usage to avoid surprises.

## 📦 Installation

### Quick Install (macOS & Linux)

```bash
curl -sL https://ru.sh/install | bash
```

### From Source

Ensure you have [Rust installed](https://rustup.rs/).

```bash
git clone https://github.com/saint/ru.sh.git
cd ru.sh
cargo install --path crates/ru-cli
```

## 🚀 Usage

### 1. Setup API Key

You need an [OpenRouter](https://openrouter.ai/) API key.

```bash
# Recommended: Interactive Config
ru config set api-key sk-or-v1-your-key-here

# Alternative: Environment Variable
export OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 2. Generate & Run Scripts

Basic usage:

```bash
ru -p "Git commit all changes with the message 'wip'"
```

**Advanced Model Selection:**

```bash
# Use a preset (fast, standard, quality)
ru -p "list files" --model fast

# Use a specific OpenRouter model ID
ru -p "refactor this script" --model-id anthropic/claude-3.5-sonnet
```

### 3. Safety Options

**Dry Run**: Review script and safety analysis without execution prompt.

```bash
ru -p "Delete all node_modules recursively" --dry-run
```

**Skip Confirmation (Use with Caution)**:

```bash
# Auto-execute Safe scripts only
ru -p "echo hello" -y

# Non-safe scripts require interactive confirmation (even with --force)
ru -p "rm -rf /" -y --force
```

## 🐚 Shell Support

ru.sh automatically detects your current shell but can be configured for others:

| Shell          | Binary | Platform                     |
| -------------- | ------ | ---------------------------- |
| **Bash**       | `bash` | Unix / macOS / Windows (WSL) |
| **Zsh**        | `zsh`  | Unix / macOS                 |
| **Fish**       | `fish` | Unix / macOS                 |
| **Sh**         | `sh`   | Unix / macOS                 |
| **PowerShell** | `pwsh` | Windows / Unix / macOS       |
| **Cmd**        | `cmd`  | Windows                      |

**Override shell detection:**

```bash
# Per-request
ru -p "list files" --shell zsh

# Persistent default
ru config set shell fish
```

## 🛡️ Security

### Risk Levels

| Level        | Description                                | Confirmation Required       |
| ------------ | ------------------------------------------ | --------------------------- |
| **Safe**     | Read-only or trivial commands              | Optional (with `-y`)        |
| **Low**      | Minimal impact operations                  | Yes                         |
| **Medium**   | Standard file/system changes               | Yes                         |
| **High**     | Potentially dangerous (e.g. `rm`, `chmod`) | Yes (Requires typing "yes") |
| **Critical** | Highly destructive (e.g. `rm -rf /`)       | Yes (Requires typing "yes") |

### Prompt Injection Protection

ru.sh includes filters to detect and reject prompts that attempt to:

- Override system instructions
- Manipulate AI roles
- Inject malicious delimiters

## 📜 Execution History

All attempts and executions are logged to `~/.config/ru.sh/history.jsonl` (Unix) or `%AppData%\ru.sh\history.jsonl` (Windows). Each record contains:

- The original prompt
- Generated script and its SHA-256 hash
- Safety analysis report
- Execution exit code and duration

## 🔧 Configuration

Manage settings via the `config` subcommand:

| Key                 | Description                              | Default                         |
| ------------------- | ---------------------------------------- | ------------------------------- |
| `api-key`           | OpenRouter API Key                       | None                            |
| `shell`             | Default target shell                     | Auto-detected                   |
| `model`             | Default preset (fast, standard, quality) | `standard`                      |
| `model-id`          | Global custom model ID                   | None                            |
| `model.fast`        | Custom model for fast preset             | `google/gemini-2.5-flash:nitro` |
| `explain-verbosity` | Detail level (concise, verbose)          | `concise`                       |
| `script-timeout`    | Max execution time in seconds            | `300`                           |
| `daily-limit`       | Max daily API requests                   | `100` (warning)                 |
| `monthly-limit`     | Max monthly API requests                 | `1000` (warning)                |

**Examples:**

```bash
# Set explain verbosity to detailed
ru config set explain-verbosity verbose

# Change script timeout to 1 minute
ru config set script-timeout 60

# View all model presets
ru config models
```

## 💻 Development

This project is a Rust workspace:

- **`crates/ru-cli`**: The CLI tool binary (`ru`).
- **`crates/ru-web`**: The [Leptos](https://leptos.dev/) web landing page.

### Build & Test

```bash
# Build release binaries
cargo build --release

# Run unit tests
cargo test

# Start Web Dev Server (requires 'trunk')
cd crates/ru-web && trunk serve
```

## 📄 License

Apache-2.0 License. See `LICENSE` for details.
