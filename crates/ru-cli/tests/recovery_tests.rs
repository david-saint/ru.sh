use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_config_corruption_recovery_integration() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let config_dir = tmp_dir.path().join(".config").join("ru.sh");
    fs::create_dir_all(&config_dir).expect("failed to create config dir");

    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "invalid toml content").expect("failed to write corrupted config");

    // Run the binary with HOME set to our temp dir
    let output = Command::new("cargo")
        .args(["run", "--package", "ru-cli", "--", "config", "path"])
        .env("HOME", tmp_dir.path())
        .output()
        .expect("failed to execute process");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stderr.contains("Warning:") || stdout.contains("Warning:"), "stderr: {}\nstdout: {}", stderr, stdout);
    assert!(stderr.contains("corrupted") || stdout.contains("corrupted"));
    assert!(stderr.contains("config.toml.bak") || stdout.contains("config.toml.bak"));

    // Verify backup exists
    let bak_path = config_dir.join("config.toml.bak");
    assert!(bak_path.exists());

    // Verify original is gone (it might have been recreated if the command saves,
    // but 'config path' shouldn't save unless it's a 'set' command)
    // Actually, Config::load_from renames it, so it should be gone unless recreated.
    assert!(!config_path.exists());
}

#[test]
fn test_usage_corruption_recovery_integration() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let config_dir = tmp_dir.path().join(".config").join("ru.sh");
    fs::create_dir_all(&config_dir).expect("failed to create config dir");

    let usage_path = config_dir.join("usage.toml");
    fs::write(&usage_path, "invalid toml content").expect("failed to write corrupted usage");

    // We need a command that loads usage. 'ru --help' or 'ru config path' might not.
    // 'ru -p "test" --dry-run' will definitely load usage to check limits.
    // We need to provide an API key to avoid that error.
    let output = Command::new("cargo")
        .args(["run", "--package", "ru-cli", "--", "-p", "hello", "--dry-run", "--api-key", "test-key"])
        .env("HOME", tmp_dir.path())
        .output()
        .expect("failed to execute process");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stderr.contains("Warning:") || stdout.contains("Warning:"), "stderr: {}\nstdout: {}", stderr, stdout);
    assert!(stderr.contains("usage.toml is corrupted") || stdout.contains("usage.toml is corrupted"));
    assert!(stderr.contains("usage.toml.bak") || stdout.contains("usage.toml.bak"));

    // Verify backup exists
    let bak_path = config_dir.join("usage.toml.bak");
    assert!(bak_path.exists());
}
