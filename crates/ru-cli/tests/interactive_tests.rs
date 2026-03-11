#![allow(deprecated)]
use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn_mock_api(responses: Vec<serde_json::Value>) -> (MockServer, String) {
    let mock_server = MockServer::start().await;
    let n = responses.len();
    for (i, response) in responses.into_iter().enumerate().rev() {
        let mock = Mock::given(method("POST"))
            .and(path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));

        if i < n - 1 {
            mock.up_to_n_times(1).mount(&mock_server).await;
        } else {
            mock.mount(&mock_server).await;
        }
    }

    let url = format!("{}/api/v1/chat/completions", mock_server.uri());
    (mock_server, url)
}

fn chat_response(content: &str) -> serde_json::Value {
    serde_json::json!({
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": content
                }
            }
        ]
    })
}

#[tokio::test]
async fn test_execute_flow() {
    let api_response = chat_response("ls -la");
    let (_mock_server, url) = spawn_mock_api(vec![api_response]).await;

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("--test-select")
        .arg("0") // Select "Execute"
        .arg("-p")
        .arg("list files");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Executing..."))
        .stdout(predicate::str::contains("Script executed successfully"));
}

#[tokio::test]
async fn test_explain_then_execute_flow() {
    let gen_response = chat_response("ls -la");
    let explain_response = chat_response("This command lists all files in long format.");
    let (_mock_server, url) = spawn_mock_api(vec![gen_response, explain_response]).await;

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("--test-select")
        .arg("1,0") // Select "Explain", then "Execute"
        .arg("-p")
        .arg("list files");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Explaining with:"))
        .stdout(predicate::str::contains("Explanation:"))
        .stdout(predicate::str::contains(
            "This command lists all files in long format.",
        ))
        .stdout(predicate::str::contains("Executing..."));
}

#[tokio::test]
async fn test_cancel_flow() {
    let api_response = chat_response("ls -la");
    let (_mock_server, url) = spawn_mock_api(vec![api_response]).await;

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("--test-select")
        .arg("2") // Select "Cancel"
        .arg("-p")
        .arg("list files");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Cancelled."))
        .stdout(predicate::str::contains("Executing...").not());
}

#[tokio::test]
async fn test_high_risk_confirmation_flow() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let test_file = tmp_dir.path().join("ru-test-file");
    std::fs::File::create(&test_file).unwrap();

    // chmod 777 is High risk
    let api_response = chat_response(&format!("chmod 777 {}", test_file.display()));
    let (_mock_server, url) = spawn_mock_api(vec![api_response]).await;

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("--test-select")
        .arg("0") // Select "Confirm (type 'yes')"
        .arg("--test-input")
        .arg("yes") // Type "yes"
        .arg("-p")
        .arg("make world writable");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Executing..."))
        .stdout(predicate::str::contains("Script executed successfully"));
}

#[tokio::test]
async fn test_high_risk_rejection_flow() {
    let api_response = chat_response("rm -rf /");
    let (_mock_server, url) = spawn_mock_api(vec![api_response]).await;

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("--test-select")
        .arg("0") // Select "Confirm"
        .arg("--test-input")
        .arg("no") // Type "no"
        .arg("-p")
        .arg("delete everything");

    cmd.assert().success().stdout(predicate::str::contains(
        "Cancelled - confirmation not received.",
    ));
}

#[tokio::test]
async fn test_high_risk_explain_then_confirm_flow() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let test_file = tmp_dir.path().join("ru-test-file-2");
    std::fs::File::create(&test_file).unwrap();

    let gen_response = chat_response(&format!("chmod 777 {}", test_file.display()));
    let explain_response = chat_response("This makes the file world-writable.");
    let (_mock_server, url) = spawn_mock_api(vec![gen_response, explain_response]).await;

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("--test-select")
        .arg("1,0") // Select "Explain", then "Confirm"
        .arg("--test-input")
        .arg("yes")
        .arg("-p")
        .arg("make world writable");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Explaining with:"))
        .stdout(predicate::str::contains(
            "This makes the file world-writable.",
        ))
        .stdout(predicate::str::contains("Executing..."));
}
