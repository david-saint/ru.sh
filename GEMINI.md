# ru.sh - Natural Language to Bash Converter

## Project Overview

**ru.sh** is a developer tool that converts natural language prompts into executable bash scripts using AI. It is built with Rust and organized as a workspace containing a CLI tool and a web-based landing page.

### Key Components

*   **`crates/ru-cli` (Binary: `ru`)**: The core command-line interface. It handles user input, communicates with the OpenRouter API (planned), and executes generated scripts after user confirmation.
*   **`crates/ru-web`**: A frontend landing page built with the Leptos framework (CSR), explaining the tool's features and installation.

## Architecture & Tech Stack

*   **Language:** Rust (2024 Edition)
*   **Workspace:** Managed via a root `Cargo.toml`.
*   **CLI Stack:**
    *   `clap`: Command-line argument parsing.
    *   `tokio`: Asynchronous runtime.
    *   `dialoguer`: Interactive terminal prompts.
    *   `reqwest`: HTTP client (for API calls).
    *   `config`: Configuration management via TOML.
*   **Web Stack:**
    *   `leptos`: Reactive web framework (Client-Side Rendering).
    *   `trunk`: WASM web application bundler and server.

## Getting Started

### Prerequisites

*   **Rust Toolchain:** Ensure `cargo` and `rustc` are installed.
*   **Trunk:** Required for the web project (`cargo install trunk`).
*   **OpenRouter API Key:** Required for the CLI to function fully.

### Key Commands

| Action | Command | Description |
| :--- | :--- | :--- |
| **Build All** | `cargo build` | Builds the entire workspace. |
| **Run CLI** | `cargo run -p ru-cli -- -p "your prompt"` | Runs the CLI from the source. |
| **Run Web** | `cd crates/ru-web && trunk serve` | Serves the landing page locally. |
| **Test** | `cargo test` | Runs unit tests across the workspace. |
| **Check** | `cargo check` | Fast type checking. |

### Configuration

The CLI looks for an API key in the following order:
1.  **CLI Flag:** `--api-key <key>`
2.  **Environment Variable:** `OPENROUTER_API_KEY`
3.  **Config File:** `~/.config/ru/config.toml` (managed via `ru config set api-key <key>`)

## Development Status & Conventions

*   **Current State:**
    *   CLI argument parsing and configuration management are implemented.
    *   **The core AI generation logic (`generate_script`) is currently MOCKED and needs implementation.**
    *   Script execution logic is implemented.
    *   Web landing page is implemented.
*   **Security:**
    *   **Never execute without confirmation:** The user must explicitly approve any generated script.
    *   **Dry Run:** `dry_run` mode is supported to preview scripts.
*   **Coding Style:** Follow standard Rust conventions (`rustfmt`, `clippy`).
*   **Error Handling:** Use `anyhow` for top-level error handling and `thiserror` for library errors.

## Directory Structure

```text
ru.sh/
├── Cargo.toml              # Workspace configuration
├── CLAUDE.md               # Project reference & cheat sheet
├── crates/
│   ├── ru-cli/             # CLI application source
│   │   ├── src/main.rs     # Entry point & command handling
│   │   └── src/config.rs   # Configuration logic
│   └── ru-web/             # Web application source
│       ├── src/app.rs      # Main UI component
│       └── index.html      # Web entry point
└── target/                 # Build artifacts
```
