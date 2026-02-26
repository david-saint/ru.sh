# API Integration Architecture

This document describes the architecture and design of the API integration in `ru.sh`.

## Overview

`ru.sh` integrates with the [OpenRouter API](https://openrouter.ai/) to provide natural language to shell script translation and script explanation capabilities. The integration is designed to be resilient, secure, and highly performant.

## Components

The primary component for API integration is the `api` module located in `crates/ru-cli/src/api.rs`.

### `api.rs`

This module contains:
- **System Prompt Construction**: Shell-specific instructions that guide the LLM to produce only valid, safe, and unfenced/fenced code based on the target shell.
- **Client Configuration**: A shared `reqwest::Client` with optimized timeouts (`30s` request, `10s` connect).
- **Retry Mechanism**: Implements exponential backoff with jitter for transient failures (5xx) and rate limiting (429).
- **Response Sanitization**: Strict parsing of LLM output to extract only executable code blocks and reject ambiguous mixed-prose responses.

## Request Lifecycle

1.  **Resolution**: The CLI resolves the API key and model ID from multiple sources (CLI flags, environment variables, or config file).
2.  **Usage Check**: Before the request, the `usage` module checks if the user has exceeded their daily or monthly limits.
3.  **Prompt Building**: The `build_system_prompt` function generates a detailed set of instructions tailored to the user's current shell.
4.  **Execution**: The request is sent to OpenRouter via the shared `HTTP_CLIENT`.
5.  **Retry Strategy**:
    - **429 (Too Many Requests)**: Retries using the `Retry-After` header or exponential backoff.
    - **5xx (Server Error)**: Retries with exponential backoff and jitter.
    - **4xx (Client Error)**: Fails immediately with a user-friendly error message.
6.  **Sanitization**: The response is processed by `sanitize_generated_script_response`, which extracts code blocks and validates the format.

## Security Measures

- **Prompt Injection Protection**: The system prompt includes specific instructions to ignore attempts to override rules or inject malicious instructions.
- **Strict Response Parsing**: `ru.sh` only accepts responses that are either single-line unfenced or contained within markdown code blocks. Multi-line unfenced responses are rejected as ambiguous.
- **Display Sanitization**: Before displaying a script to the user, it is sanitized in `sanitize.rs` to prevent terminal injection attacks (e.g., hidden escape sequences).

## Resilience & Performance

- **Zero-Copy Optimization**: The integration uses `Cow<'a, str>` and efficient string slicing where possible to minimize allocations.
- **Request Cloning**: Uses `try_clone()` on `reqwest::RequestBuilder` to efficiently retry requests without re-serializing JSON payloads.
- **Jitter**: Jitter is added to retry delays to prevent the "thundering herd" problem during API outages.

## Error Handling

Errors are classified into:
- **User Errors**: Authentication failure, rate limits, payment required.
- **System Errors**: Network issues, OpenRouter downtime.
- **Model Errors**: Malformed responses, ambiguous output.

The `classify_api_error` function maps HTTP status codes to actionable, human-readable messages.
