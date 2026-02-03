# ru.sh

> **Natural Language to Bash Scripts** 🚀

**ru.sh** is a powerful command-line tool that turns your plain English requests into executable bash scripts using AI. Stop memorizing obscure flags and complex syntax—just say what you want, review the generated script, and run it.

## ✨ Features

- **🗣️ Natural Language Interface**: Describe your task in plain English (e.g., "Find all files larger than 100MB and delete them").
- **🛡️ Safety First**: Scripts are **never** executed without your explicit confirmation. You can always review (or dry-run) the code first.
- **⚡ Fast & Smart**: Powered by the OpenRouter API to leverage the best available coding models.
- **⚙️ Flexible Configuration**: Manage API keys via config files, environment variables, or CLI flags.
- **🦀 Built with Rust**: Blazing fast, memory safe, and reliable.

## 📦 Installation

### From Source

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

**Option C: One-off Flag**
```bash
ru -p "list files" --api-key sk-or-v1-your-key-here
```

### 2. Generate & Run Scripts

Basic usage:
```bash
ru -p "Git commit all changes with the message 'wip'"
```

**What happens next?**
1.  The AI generates a script.
2.  The script is displayed for your review.
3.  You choose to **Execute**, **Explain** (coming soon), or **Cancel**.

### 3. Dry Run

Want to see the script without being prompted to execute it?
```bash
ru -p "Delete all node_modules recursively" --dry-run
```

### 4. Skip Confirmation (Use with Caution)

Trust the AI implicitly? (Not recommended for destructive commands)
```bash
ru -p "echo hello" -y
```

## 🔧 Configuration

Manage your settings via the `config` subcommand:

```bash
# View current config path
ru config path

# Check if API key is set (masked)
ru config get api-key

# Clear API key
ru config clear api-key
```

## 💻 Development

This project is a Rust workspace containing:
- **`crates/ru-cli`**: The CLI tool binary.
- **`crates/ru-web`**: A [Leptos](https://leptos.dev/) web landing page.

### Prerequisites
- Rust (latest stable)
- `trunk` (for web development): `cargo install trunk`

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

MIT License. See `Cargo.toml` for details.
