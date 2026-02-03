use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;

const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";

// Timeout configuration
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// Retry configuration
const MAX_RETRIES: u32 = 3;
const BASE_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

const SYSTEM_PROMPT: &str = r#"You are an expert bash script generator. Convert natural language descriptions to valid bash commands.

Rules:
1. Output ONLY the bash command/script, nothing else
2. Do not include explanations, comments, or markdown formatting
3. Do not wrap output in code blocks
4. Produce a single command or pipeline when possible
5. Use common Unix utilities (ls, grep, find, awk, sed, etc.)
6. Handle edge cases appropriately (spaces in filenames, etc.)"#;

const EXPLAINER_SYSTEM_PROMPT: &str = r#"You are an expert at explaining bash scripts and commands. Given a bash script, explain what it does in clear, simple terms.

Guidelines:
1. Break down the command/script into logical steps
2. Explain what each part does
3. Highlight any potential risks or side effects
4. Keep the explanation concise but thorough
5. Use plain language that a non-expert can understand"#;

/// Shared HTTP client with timeout configuration
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .expect("Failed to create HTTP client")
});

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessageResponse,
}

#[derive(Debug, Deserialize)]
struct ChatMessageResponse {
    content: String,
}

/// Send HTTP request with retry logic and exponential backoff
async fn send_with_retry(
    request_builder: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let mut attempts = 0;
    let mut delay = BASE_RETRY_DELAY;

    loop {
        attempts += 1;

        let result = request_builder().send().await;

        match result {
            Ok(response) => {
                let status = response.status();

                // Success - return response
                if status.is_success() {
                    return Ok(response);
                }

                // Rate limited (429) - retry with Retry-After header
                if status == StatusCode::TOO_MANY_REQUESTS {
                    if attempts >= MAX_RETRIES {
                        let error_text = response.text().await.unwrap_or_default();
                        bail!("Rate limited after {} attempts: {}", attempts, error_text);
                    }

                    let retry_after = parse_retry_after(&response);
                    let wait_time = retry_after.unwrap_or(delay);
                    tokio::time::sleep(wait_time).await;
                    delay = (delay * 2).min(MAX_RETRY_DELAY);
                    continue;
                }

                // Server error (5xx) - retry with backoff
                if status.is_server_error() {
                    if attempts >= MAX_RETRIES {
                        let error_text = response.text().await.unwrap_or_default();
                        bail!(
                            "Server error after {} attempts ({}): {}",
                            attempts,
                            status,
                            error_text
                        );
                    }

                    let jittered_delay = add_jitter(delay);
                    tokio::time::sleep(jittered_delay).await;
                    delay = (delay * 2).min(MAX_RETRY_DELAY);
                    continue;
                }

                // Client error (4xx except 429) - fail immediately
                let error_text = response.text().await.unwrap_or_default();
                bail!("OpenRouter API error ({}): {}", status, error_text);
            }

            Err(e) => {
                // Network errors are retryable
                if attempts >= MAX_RETRIES {
                    bail!("Network error after {} attempts: {}", attempts, e);
                }

                let jittered_delay = add_jitter(delay);
                tokio::time::sleep(jittered_delay).await;
                delay = (delay * 2).min(MAX_RETRY_DELAY);
            }
        }
    }
}

/// Parse the Retry-After header value (in seconds)
fn parse_retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Add jitter to delay to prevent thundering herd
fn add_jitter(duration: Duration) -> Duration {
    // Use system time as entropy source to avoid rand dependency
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();

    // +/- 10% jitter
    let jitter_percent = ((nanos % 21) as i32 - 10) as f64 / 100.0;
    let jittered = duration.as_secs_f64() * (1.0 + jitter_percent);
    Duration::from_secs_f64(jittered.max(0.1))
}

/// Generate a bash script from a natural language prompt using OpenRouter API
pub async fn generate_script(prompt: &str, api_key: &str, model_id: &str) -> Result<String> {
    let request = ChatRequest {
        model: model_id.to_string(),
        messages: vec![
            ChatMessage {
                role: "system",
                content: SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user",
                content: prompt.to_string(),
            },
        ],
        temperature: 0.0,
        max_tokens: 512,
    };

    let api_key = api_key.to_string();
    let response = send_with_retry(|| {
        HTTP_CLIENT
            .post(OPENROUTER_API_URL)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .header("HTTP-Referer", "https://github.com/ru-sh/ru-cli")
            .header("X-Title", "ru.sh CLI")
            .json(&request)
    })
    .await
    .context("Failed to call OpenRouter API")?;

    let chat_response: ChatResponse = response
        .json()
        .await
        .context("Failed to parse OpenRouter API response")?;

    let content = chat_response
        .choices
        .first()
        .map(|c| c.message.content.clone())
        .unwrap_or_default();

    // Clean up the response - remove markdown code blocks if present
    let script = strip_code_blocks(&content);

    Ok(script)
}

/// Explain a bash script using the explainer model
pub async fn explain_script(script: &str, api_key: &str, model_id: &str) -> Result<String> {
    let request = ChatRequest {
        model: model_id.to_string(),
        messages: vec![
            ChatMessage {
                role: "system",
                content: EXPLAINER_SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user",
                content: format!("Explain this bash script:\n\n```bash\n{}\n```", script),
            },
        ],
        temperature: 0.0,
        max_tokens: 1024,
    };

    let api_key = api_key.to_string();
    let response = send_with_retry(|| {
        HTTP_CLIENT
            .post(OPENROUTER_API_URL)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .header("HTTP-Referer", "https://github.com/ru-sh/ru-cli")
            .header("X-Title", "ru.sh CLI")
            .json(&request)
    })
    .await
    .context("Failed to call OpenRouter API")?;

    let chat_response: ChatResponse = response
        .json()
        .await
        .context("Failed to parse OpenRouter API response")?;

    let content = chat_response
        .choices
        .first()
        .map(|c| c.message.content.clone())
        .unwrap_or_default();

    Ok(content.trim().to_string())
}

/// Strip markdown code blocks from the response
fn strip_code_blocks(content: &str) -> String {
    let content = content.trim();

    // Check for ```bash or ```sh or just ```
    if content.starts_with("```") {
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() >= 2 {
            // Skip first line (```bash) and last line (```)
            let end = if lines.last() == Some(&"```") {
                lines.len() - 1
            } else {
                lines.len()
            };

            return lines[1..end].join("\n").trim().to_string();
        }
    }

    content.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_code_blocks_bash() {
        let input = "```bash\nls -la\n```";
        assert_eq!(strip_code_blocks(input), "ls -la");
    }

    #[test]
    fn test_strip_code_blocks_sh() {
        let input = "```sh\necho hello\n```";
        assert_eq!(strip_code_blocks(input), "echo hello");
    }

    #[test]
    fn test_strip_code_blocks_plain() {
        let input = "```\nfind . -name '*.rs'\n```";
        assert_eq!(strip_code_blocks(input), "find . -name '*.rs'");
    }

    #[test]
    fn test_strip_code_blocks_none() {
        let input = "ls -la";
        assert_eq!(strip_code_blocks(input), "ls -la");
    }

    #[test]
    fn test_strip_code_blocks_multiline() {
        let input = "```bash\necho one\necho two\necho three\n```";
        assert_eq!(strip_code_blocks(input), "echo one\necho two\necho three");
    }

    #[test]
    fn test_add_jitter_in_range() {
        let base = Duration::from_secs(1);
        // Run multiple times to check jitter is applied
        for _ in 0..10 {
            let jittered = add_jitter(base);
            // Should be within +/- 10% of base (0.9 to 1.1 seconds)
            assert!(jittered >= Duration::from_millis(900));
            assert!(jittered <= Duration::from_millis(1100));
        }
    }

    #[test]
    fn test_add_jitter_min_value() {
        // Very small duration should be clamped to minimum
        let tiny = Duration::from_millis(1);
        let jittered = add_jitter(tiny);
        assert!(jittered >= Duration::from_millis(100));
    }
}
