#![allow(deprecated)]
use assert_cmd::Command;
use predicates::prelude::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn spawn_mock_api(responses: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for body in responses {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0; 2048];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });
    format!("http://127.0.0.1:{}", port)
}

fn chat_response(content: &str) -> String {
    format!(
        r#"{{"choices": [{{"message": {{"role": "assistant", "content": {:?}}}}}]}}"#,
        content
    )
}

#[test]
fn test_execute_flow() {
    let api_response = chat_response("ls -la");
    let url = spawn_mock_api(vec![api_response]);

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("RU_TEST_MODE", "1")
        .env("RU_MOCK_SELECT", "0") // Select "Execute"
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("-p")
        .arg("list files");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Executing..."))
        .stdout(predicate::str::contains("Script executed successfully"));
}

#[test]
fn test_explain_then_execute_flow() {
    let gen_response = chat_response("ls -la");
    let explain_response = chat_response("This command lists all files in long format.");
    let url = spawn_mock_api(vec![gen_response, explain_response]);

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("RU_TEST_MODE", "1")
        .env("RU_MOCK_SELECT", "1,0") // Select "Explain", then "Execute"
        .env("OPENROUTER_API_KEY", "test-key")
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

#[test]
fn test_cancel_flow() {
    let api_response = chat_response("ls -la");
    let url = spawn_mock_api(vec![api_response]);

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("RU_TEST_MODE", "1")
        .env("RU_MOCK_SELECT", "2") // Select "Cancel"
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("-p")
        .arg("list files");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Cancelled."))
        .stdout(predicate::str::contains("Executing...").not());
}

#[test]
fn test_high_risk_confirmation_flow() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let test_file = tmp_dir.path().join("ru-test-file");
    std::fs::File::create(&test_file).unwrap();

    // chmod 777 is High risk
    let api_response = chat_response(&format!("chmod 777 {}", test_file.display()));
    let url = spawn_mock_api(vec![api_response]);

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("RU_TEST_MODE", "1")
        .env("RU_MOCK_SELECT", "0") // Select "Confirm (type 'yes')"
        .env("RU_MOCK_INPUT", "yes") // Type "yes"
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("-p")
        .arg("make world writable");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Executing..."))
        .stdout(predicate::str::contains("Script executed successfully"));
}

#[test]
fn test_high_risk_rejection_flow() {
    let api_response = chat_response("rm -rf /");
    let url = spawn_mock_api(vec![api_response]);

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("RU_TEST_MODE", "1")
        .env("RU_MOCK_SELECT", "0") // Select "Confirm"
        .env("RU_MOCK_INPUT", "no") // Type "no"
        .env("OPENROUTER_API_KEY", "test-key")
        .arg("-p")
        .arg("delete everything");

    cmd.assert().success().stdout(predicate::str::contains(
        "Cancelled - confirmation not received.",
    ));
}

#[test]
fn test_high_risk_explain_then_confirm_flow() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let test_file = tmp_dir.path().join("ru-test-file-2");
    std::fs::File::create(&test_file).unwrap();

    let gen_response = chat_response(&format!("chmod 777 {}", test_file.display()));
    let explain_response = chat_response("This makes the file world-writable.");
    let url = spawn_mock_api(vec![gen_response, explain_response]);

    let mut cmd = Command::cargo_bin("ru").unwrap();
    cmd.env("RU_API_URL", &url)
        .env("RU_TEST_MODE", "1")
        .env("RU_MOCK_SELECT", "1,0") // Select "Explain", then "Confirm"
        .env("RU_MOCK_INPUT", "yes")
        .env("OPENROUTER_API_KEY", "test-key")
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
