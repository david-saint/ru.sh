use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_e2e_execution_flow() -> Result<(), Box<dyn std::error::Error>> {
    let mock_server = MockServer::start().await;
    let tmp_dir = tempdir()?;
    let test_file = tmp_dir.path().join("e2e_test.txt");
    let test_file_str = test_file.to_str().unwrap();

    // Mock response from OpenRouter
    let response_body = serde_json::json!({
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": format!("echo 'success' > '{}'", test_file_str)
                }
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/chat/completions"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&mock_server)
        .await;

    let mut cmd = Command::cargo_bin("ru")?;
    cmd.env("RU_API_URL", format!("{}/api/v1/chat/completions", mock_server.uri()))
       .env("OPENROUTER_API_KEY", "test-api-key")
       .env("RU_TEST_MODE", "1")
       .arg("--prompt")
       .arg("write success to a file")
       .arg("--yes")
       .arg("--shell")
       .arg("bash");

    cmd.assert()
       .success()
       .stdout(predicate::str::contains("Script executed successfully"));

    // Verify side effect
    let content = fs::read_to_string(&test_file)?;
    assert_eq!(content.trim(), "success");

    Ok(())
}
