# ru.sh

> **Natural Language to Bash Scripts** 🚀

**ru.sh** is a powerful command-line tool that turns your plain English requests into executable bash scripts using AI. Stop memorizing obscure flags and complex syntax—just say what you want, review the generated script, and run it.

## ✨ Features

- **🗣️ Natural Language Interface**: Describe your task in plain English (e.g., "Find all files larger than 100MB and delete them").
- **🛡️ Safety & Risk Analysis**: Scripts are analyzed for risk levels (Safe to Critical) and syntax errors before execution.
- **📚 Script Explanation**: Not sure what a generated command does? Get a detailed breakdown with the "Explain" feature.
- **🎭 Model Presets**: Choose between `fast` (optimized for speed), `standard` (balanced), and `quality` (optimized for complex tasks) models.
- **⚙️ Flexible Configuration**: Manage API keys, model presets, and usage limits via the CLI.
- **📊 Usage Tracking**: Monitor and set limits for your daily and monthly API usage to avoid surprises.
- **🦀 Built with Rust**: Blazing fast, memory safe, and reliable.

## 📦 Installation

Ensure you have [Rust installed](https://rustup.rs/).

```bash
git clone https://github.com/saint/ru.sh.git
cd ru.sh
cargo install --path crates/ru-cli
```

## 🚀 Usage

### 1. Setup API Key

You need an [OpenRouter](https://openrouter.ai/) API key to generate scripts.

**Option A: Interactive Config (Recommended)**

```bash
ru config set api-key sk-or-v1-your-key-here
```

**Option B: Environment Variable**

```bash
export OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 2. Generate & Run Scripts

Basic usage:

```bash
ru -p "Git commit all changes with the message 'wip'"
```

**Advanced Model Selection:**

```bash
# Use the fast model preset
ru -p "list files" --model fast

# Use a specific OpenRouter model ID
ru -p "refactor this bash script" --model-id anthropic/claude-3.5-sonnet
```

**What happens next?**

1.  **AI Generation**: The script is generated using your selected model.
2.  **Safety Check**: The script is analyzed for syntax errors and risk levels.
3.  **Review**: You choose to **Execute**, **Explain**, or **Cancel**.

### 3. Safety Options

**Dry Run**: See the script and safety analysis without being prompted to execute it.

```bash
ru -p "Delete all node_modules recursively" --dry-run
```

**Skip Confirmation (Use with Caution)**:

```bash
# Auto-execute safe scripts
ru -p "echo hello" -y

# Force execution of high-risk scripts (requires typing 'yes' or using --force)
ru -p "rm -rf /" -y --force
```

## 🔧 Configuration

Manage your settings via the `config` subcommand:

```bash
# View all available model presets and their current models
ru config models

# Set model preset (fast, standard, quality)
ru config set model quality

# Set custom model for a specific preset
ru config set model.fast google/gemini-2.0-flash-exp:nitro

# Set API usage limits
ru config set daily-limit 50
ru config set monthly-limit 500

# View current config path
ru config path
```

## 💻 Development

This project is a Rust workspace containing:

- **`crates/ru-cli`**: The CLI tool binary.
- **`crates/ru-web`**: A [Leptos](https://leptos.dev/) web landing page.

### Build & Run

```bash
# Run CLI from source
cargo run -p ru-cli -- -p "your prompt"

# Run Tests
cargo test

# Start Web Dev Server
cd crates/ru-web
trunk serve
```

## 📄 License

Apache-2.0 License. See `LICENSE` for details.
