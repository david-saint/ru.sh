use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";

const SYSTEM_PROMPT: &str = r#"You are an expert bash script generator. Convert natural language descriptions to valid bash commands.

Rules:
1. Output ONLY the bash command/script, nothing else
2. Do not include explanations, comments, or markdown formatting
3. Do not wrap output in code blocks
4. Produce a single command or pipeline when possible
5. Use common Unix utilities (ls, grep, find, awk, sed, etc.)
6. Handle edge cases appropriately (spaces in filenames, etc.)"#;

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

/// Generate a bash script from a natural language prompt using OpenRouter API
pub async fn generate_script(prompt: &str, api_key: &str, model_id: &str) -> Result<String> {
    let client = reqwest::Client::new();

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

    let response = client
        .post(OPENROUTER_API_URL)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", "https://github.com/ru-sh/ru-cli")
        .header("X-Title", "ru.sh CLI")
        .json(&request)
        .send()
        .await
        .context("Failed to send request to OpenRouter API")?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        bail!(
            "OpenRouter API error ({}): {}",
            status,
            error_text
        );
    }

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
}
