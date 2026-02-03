# ru.sh

Natural language to bash script converter powered by AI.

## Project Structure

```
ru.sh/
├── Cargo.toml              # Workspace root
└── crates/
    ├── ru-cli/             # CLI tool (binary: "ru")
    └── ru-web/             # Leptos landing page
```

## Quick Reference

```bash
# Build everything
cargo build

# Run CLI
cargo run -p ru-cli -- -p "your prompt" --api-key <key>

# Run web dev server (requires: cargo install trunk)
cd crates/ru-web && trunk serve --open

# Check all packages
cargo check

# Run tests
cargo test
```

## Architecture

### ru-cli
- **Purpose**: Convert natural language prompts to bash scripts via OpenRouter API
- **Binary name**: `ru`
- **Key deps**: clap (CLI), reqwest (HTTP), dialoguer (interactive prompts), tokio (async)
- **Flow**: prompt → OpenRouter API → generated script → user confirmation → execute

### ru-web
- **Purpose**: Landing page explaining the tool
- **Framework**: Leptos (CSR mode)
- **Build tool**: Trunk

## Environment Variables

- `OPENROUTER_API_KEY` - Required for CLI to call OpenRouter API

## Design Principles

1. **Security first** - Never execute scripts without explicit user approval
2. **Speed** - Use fastest available model via OpenRouter
3. **Simplicity** - Minimal flags, sensible defaults
