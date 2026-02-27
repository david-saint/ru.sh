use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn run_ru(args: &[&str], config_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ru"))
        .args(args)
        .env("RU_CONFIG_DIR", config_dir)
        .output()
        .expect("failed to execute process")
}

#[test]
fn test_config_corruption_recovery_integration() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let config_dir = tmp_dir.path().join("ru-config");
    fs::create_dir_all(&config_dir).expect("failed to create config dir");

    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "invalid toml content").expect("failed to write corrupted config");

    // config get loads and parses the config file.
    let output = run_ru(&["config", "get", "model"], &config_dir);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "status: {:?}\nstderr: {}\nstdout: {}",
        output.status.code(),
        stderr,
        stdout
    );
    assert!(
        stderr.contains("Warning:") || stdout.contains("Warning:"),
        "stderr: {}\nstdout: {}",
        stderr,
        stdout
    );
    assert!(stderr.contains("corrupted") || stdout.contains("corrupted"));
    assert!(stderr.contains("config.toml.bak") || stdout.contains("config.toml.bak"));

    // Verify backup exists
    let bak_path = config_dir.join("config.toml.bak");
    assert!(bak_path.exists());

    // Config::load_from renames corrupted config to .bak.
    assert!(!config_path.exists());
}

#[test]
fn test_usage_corruption_recovery_integration() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let config_dir = tmp_dir.path().join("ru-config");
    fs::create_dir_all(&config_dir).expect("failed to create config dir");

    let usage_path = config_dir.join("usage.toml");
    fs::write(&usage_path, "invalid toml content").expect("failed to write corrupted usage");

    // This path exercises usage loading during request handling.
    let output = run_ru(
        &["-p", "hello", "--dry-run", "--api-key", "test-key"],
        &config_dir,
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("Warning:") || stdout.contains("Warning:"),
        "stderr: {}\nstdout: {}",
        stderr,
        stdout
    );
    assert!(
        stderr.contains("usage.toml is corrupted") || stdout.contains("usage.toml is corrupted")
    );
    assert!(stderr.contains("usage.toml.bak") || stdout.contains("usage.toml.bak"));

    // Verify backup exists
    let bak_path = config_dir.join("usage.toml.bak");
    assert!(bak_path.exists());
}

#[cfg(unix)]
#[test]
fn test_config_path_succeeds_with_unreadable_config() {
    use std::os::unix::fs::PermissionsExt;

    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let config_dir = tmp_dir.path().join("ru-config");
    fs::create_dir_all(&config_dir).expect("failed to create config dir");

    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "api_key = \"x\"").expect("failed to write config");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o000))
        .expect("failed to chmod config unreadable");

    let output = run_ru(&["config", "path"], &config_dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("failed to restore config permissions");

    assert!(
        output.status.success(),
        "status: {:?}\nstderr: {}\nstdout: {}",
        output.status.code(),
        stderr,
        stdout
    );
    assert_eq!(stdout.trim(), config_path.display().to_string());
}
