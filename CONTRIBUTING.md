# Contributing to ru.sh

Thank you for your interest in contributing to **ru.sh**! We welcome contributions of all kinds, from bug fixes and feature implementations to documentation improvements.

## 🛠️ Getting Started

### Prerequisites

To build and run the project, you'll need:
- [Rust](https://rustup.rs/) (2024 edition)
- [Trunk](https://trunkrs.dev/) (for building the web project)

### Setup

1. Fork the repository.
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/ru.sh.git
   cd ru.sh
   ```
3. Verify that everything builds:
   ```bash
   cargo build
   ```

## 💻 Development Workflow

### Standard Commands

Before submitting a Pull Request, please ensure your changes pass all checks:

```bash
# Format code
cargo fmt --all

# Run lints
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test --all-features
```

### Working with `ru-cli`

The CLI tool is located in `crates/ru-cli`.

```bash
# Run the CLI in development
cargo run -p ru-cli -- -p "your prompt"
```

### Working with `ru-web`

The landing page is located in `crates/ru-web`.

```bash
cd crates/ru-web
trunk serve
```

## 🛡️ Best Practices

### Security First
Since `ru.sh` generates and executes shell scripts, security is paramount.
- **Strict Parsing**: Always strictly parse LLM outputs. Never assume the LLM will follow formatting instructions perfectly. Discard everything outside of expected code blocks.
- **Regex Robustness**: When writing regex for security checks, account for shell separators (`;`, `|`, `&`, `#`), whitespace, and flexible argument ordering.
- **No Execution without Confirmation**: Never bypass the user confirmation step for potentially dangerous actions.
- **Modern Standards**: Ensure security checks account for modern hardware (e.g., NVMe/MMC device names) and modern shell behaviors.

### Performance
- **Minimize Allocations**: Use `Cow`, borrowed slices (`&str`), and pre-allocated buffers where possible in performance-critical paths (like history rotation or safety analysis).
- **Efficient I/O**: Use buffered I/O (`BufReader`/`BufWriter`) for file operations.
- **Zero-Copy**: Favor zero-copy deserialization and comparisons where appropriate.

### API Integration
For details on how we integrate with LLM APIs, see the [API Integration Architecture](API_INTEGRATION.md) document.

## 🤝 Pull Request Process

1. Create a new branch for your changes: `git checkout -b feature/your-feature-name`.
2. Follow the [Rust style guide](https://github.com/rust-lang/rust/blob/master/src/doc/style-guide/src/README.md).
3. Ensure all tests pass and there are no Clippy warnings.
4. Add tests for any new functionality.
5. Update documentation if necessary.
6. Submit your PR with a clear description of the changes.

## 📄 License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).
