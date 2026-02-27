# API Integration Architecture

This document describes how `ru.sh` integrates with external LLM APIs (primarily OpenRouter) to provide natural language to shell script translation and script explanation.

## Overview

The core value of `ru.sh` is its ability to bridge the gap between human intent and executable shell code. It uses Large Language Models (LLMs) to perform two primary tasks:
1. **Script Generation**: Translating a natural language prompt into a specific, executable shell command.
2. **Script Explanation**: Breaking down a shell command into human-readable steps to ensure the user understands what they are about to execute.

## Component Architecture

The API integration is distributed across several modules in `crates/ru-cli/src/`:

- **`api.rs`**: The core integration layer. It defines request/response structures, manages the HTTP client, implements retry logic, and handles prompt engineering (system prompts).
- **`config.rs`**: Manages API-related configuration, including API keys, model presets (`fast`, `standard`, `quality`), and custom model overrides.
- **`usage.rs`**: Tracks API usage locally to enforce daily and monthly quotas before making network requests.
- **`main.rs`**: Orchestrates the high-level flow, resolving configuration, checking usage, calling the API, and handling the resulting script or explanation.

## Authentication

`ru.sh` supports multiple ways to provide an OpenRouter API key, resolved in the following order of precedence:
1. **CLI Flag**: `--api-key <KEY>`
2. **Environment Variable**: `OPENROUTER_API_KEY`
3. **Configuration File**: Stored in `~/.config/ru.sh/config.toml` (managed via `ru config set api-key <KEY>`)

For security, API keys are masked when displayed via `ru config get api-key`.

## Request Lifecycle

1. **Prompt Validation**: Before any request, the user prompt is validated for length and basic sanity.
2. **Quota Check**: Local usage stats are checked against configured daily/monthly limits.
3. **System Prompt Selection**: A system prompt is tailored based on the target shell (Bash, Zsh, Fish, etc.) to ensure compatible syntax and safety rules.
4. **Execution**:
   - Uses `reqwest` with a shared, persistent `Client`.
   - **Timeouts**: 10s connection timeout, 30s total request timeout.
   - **Retries**: Up to 3 attempts with exponential backoff and jitter.
   - **429 Handling**: Respects the `Retry-After` header for rate limiting.
5. **Response Sanitization**: LLM output is parsed to extract executable code blocks and reject ambiguous or malformed prose.

## Security

Security is integrated into every step of the API lifecycle:
- **System Prompts**: Include strict "NEVER" rules for destructive commands (e.g., `rm -rf /`).
- **Input Filtering**: Detection of prompt injection attempts that try to override system instructions.
- **Response Validation**: Rejection of multi-line unfenced responses to prevent "prose injection" where a command might be hidden in text.
- **Post-API Analysis**: Even after generation, the `safety.rs` module performs a local regex-based risk analysis before execution.

## Performance

- **Zero-Copy**: Extensive use of `Cow<'a, str>` and borrowed slices to minimize memory allocations during prompt building and response parsing.
- **Lazy Evaluation**: Configuration and environment variables are only resolved when needed.
- **Connection Pooling**: Uses a `LazyLock<reqwest::Client>` to reuse TCP connections across multiple calls (e.g., generation followed by explanation).

## Multi-Shell Support

The integration is shell-aware. The `api.rs` module generates unique system prompts for:
- **Bash/Zsh**: Standard Unix utilities and syntax.
- **POSIX sh**: Restricted syntax (no bashisms).
- **Fish**: Fish-specific syntax (e.g., `set` instead of `export`).
- **PowerShell**: Windows-specific cmdlets and syntax.
- **Cmd**: Windows Command Prompt built-ins.

## Usage Tracking

To prevent unexpected costs or API abuse, `ru.sh` maintains a local history of successful requests.
- **Location**: `~/.config/ru.sh/usage.json`
- **Granularity**: Daily and monthly counters.
- **Action**: Warns or blocks requests when user-defined thresholds are reached.
