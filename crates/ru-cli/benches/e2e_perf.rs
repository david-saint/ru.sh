use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, Clone)]
struct Scenario {
    name: &'static str,
    args: Vec<&'static str>,
    needs_mock_api: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    version: String,
    git_sha: String,
    date: String,
    rust_version: String,
    os: String,
    cpu: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct E2eMetric {
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    stddev_ms: f64,
    min_ms: f64,
    max_ms: f64,
    iterations: usize,
}

#[derive(Debug, Clone)]
struct BenchResult {
    name: String,
    samples_ms: Vec<f64>,
    min_ms: f64,
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    stddev_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkFile {
    meta: Meta,
    micro: BTreeMap<String, serde_json::Value>,
    e2e: BTreeMap<String, E2eMetric>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("e2e benchmark failed: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let iterations = env::var("RU_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50);

    let workspace_root = workspace_root()?;
    build_release_binary(&workspace_root)?;
    let ru_bin = release_binary_path(&workspace_root);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    let mock_server = runtime.block_on(MockServer::start());
    runtime.block_on(configure_mocks(&mock_server));

    let temp_dir = tempfile::tempdir().context("failed to create benchmark tempdir")?;
    let config_dir = temp_dir.path().join("ru-bench-config");
    std::fs::create_dir_all(&config_dir).context("failed to create benchmark config dir")?;

    let mock_url = format!("{}/api/v1/chat/completions", mock_server.uri());

    let scenarios = vec![
        Scenario {
            name: "startup",
            args: vec!["--version"],
            needs_mock_api: false,
        },
        Scenario {
            name: "config_read",
            args: vec!["config", "get", "model"],
            needs_mock_api: false,
        },
        Scenario {
            name: "dry_run_safe",
            args: vec!["-p", "list files", "--dry-run", "--shell", "bash"],
            needs_mock_api: true,
        },
        Scenario {
            name: "dry_run_complex",
            args: vec!["-p", "deploy application", "--dry-run", "--shell", "bash"],
            needs_mock_api: true,
        },
        Scenario {
            name: "dry_run_echo",
            args: vec!["-p", "echo hello", "--dry-run", "--shell", "bash"],
            needs_mock_api: true,
        },
    ];

    let mut results = Vec::new();
    for scenario in &scenarios {
        let mut samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let mut cmd = Command::new(&ru_bin);
            cmd.args(&scenario.args);
            cmd.env("RU_CONFIG_DIR", &config_dir);
            if scenario.needs_mock_api {
                cmd.env("RU_API_URL", &mock_url);
                cmd.env("OPENROUTER_API_KEY", "test-key");
            }

            let start = Instant::now();
            let output = cmd
                .output()
                .with_context(|| format!("failed to run scenario {}", scenario.name))?;
            let elapsed = start.elapsed();

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                bail!("scenario '{}' failed: {}", scenario.name, stderr.trim());
            }

            samples.push(elapsed);
        }
        if scenario.name == "startup" {
            samples.sort();
            let drop = samples.len() / 20;
            if drop > 0 && samples.len() > drop * 2 {
                samples = samples[drop..(samples.len() - drop)].to_vec();
            }
        }
        results.push(compute_stats(scenario.name, samples));
    }

    print_table(&results);

    let benchmark_file = BenchmarkFile {
        meta: collect_meta(&workspace_root),
        micro: BTreeMap::new(),
        e2e: results
            .iter()
            .map(|r| {
                (
                    r.name.clone(),
                    E2eMetric {
                        mean_ms: r.mean_ms,
                        median_ms: r.median_ms,
                        p95_ms: r.p95_ms,
                        p99_ms: r.p99_ms,
                        stddev_ms: r.stddev_ms,
                        min_ms: r.min_ms,
                        max_ms: r.max_ms,
                        iterations: r.samples_ms.len(),
                    },
                )
            })
            .collect(),
    };

    let results_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("latest-e2e.json");
    write_json(&results_path, &benchmark_file)?;
    println!("Saved e2e results to {}", results_path.display());

    let baseline_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("baseline.json");
    print_baseline_comparison(&baseline_path, &results)?;

    Ok(())
}

async fn configure_mocks(server: &MockServer) {
    let safe_body = serde_json::json!({
        "choices": [{ "message": { "content": "ls -la" } }]
    });
    let complex_script = [
        "```bash",
        "set -euo pipefail",
        "git fetch origin",
        "git checkout main",
        "git pull --ff-only",
        "cargo build --release",
        "systemctl restart app.service",
        "systemctl status app.service --no-pager",
        "```",
    ]
    .join("\n");
    let complex_body = serde_json::json!({
        "choices": [{ "message": { "content": complex_script } }]
    });
    let exec_body = serde_json::json!({
        "choices": [{ "message": { "content": "echo hello" } }]
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/chat/completions"))
        .and(header("authorization", "Bearer test-key"))
        .and(body_string_contains("list files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(safe_body))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/chat/completions"))
        .and(header("authorization", "Bearer test-key"))
        .and(body_string_contains("deploy application"))
        .respond_with(ResponseTemplate::new(200).set_body_json(complex_body))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/chat/completions"))
        .and(header("authorization", "Bearer test-key"))
        .and(body_string_contains("echo hello"))
        .respond_with(ResponseTemplate::new(200).set_body_json(exec_body))
        .mount(server)
        .await;
}

fn compute_stats(name: &str, samples: Vec<Duration>) -> BenchResult {
    let mut values: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    values.sort_by(|a, b| a.total_cmp(b));

    let min_ms = *values.first().unwrap_or(&0.0);
    let max_ms = *values.last().unwrap_or(&0.0);
    let mean_ms = if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    };

    let median_ms = percentile(&values, 0.50);
    let p95_ms = percentile(&values, 0.95);
    let p99_ms = percentile(&values, 0.99);

    let variance = if values.len() <= 1 {
        0.0
    } else {
        values
            .iter()
            .map(|v| {
                let diff = *v - mean_ms;
                diff * diff
            })
            .sum::<f64>()
            / (values.len() - 1) as f64
    };
    let stddev_ms = variance.sqrt();

    BenchResult {
        name: name.to_string(),
        samples_ms: values,
        min_ms,
        mean_ms,
        median_ms,
        p95_ms,
        p99_ms,
        max_ms,
        stddev_ms,
    }
}

fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let n = values.len();
    let rank = ((n as f64 - 1.0) * p).round() as usize;
    values[rank.min(n - 1)]
}

fn print_table(results: &[BenchResult]) {
    println!("CLI End-to-End Benchmarks");
    println!("================================================");
    println!(
        "{:<20} | {:>6} | {:>8} | {:>8} | {:>8} | {:>8}",
        "Scenario", "N", "Mean", "Median", "P95", "Stddev"
    );
    println!("---------------------|--------|----------|----------|----------|----------");

    for r in results {
        println!(
            "{:<20} | {:>6} | {:>7.1}ms | {:>7.1}ms | {:>7.1}ms | {:>7.1}ms",
            r.name,
            r.samples_ms.len(),
            r.mean_ms,
            r.median_ms,
            r.p95_ms,
            r.stddev_ms
        );
    }
}

fn print_baseline_comparison(baseline_path: &Path, current: &[BenchResult]) -> Result<()> {
    if !baseline_path.exists() {
        println!("No baseline found at {}", baseline_path.display());
        return Ok(());
    }

    let baseline_raw = std::fs::read_to_string(baseline_path)
        .with_context(|| format!("failed to read baseline file {}", baseline_path.display()))?;
    let baseline: BenchmarkFile = serde_json::from_str(&baseline_raw)
        .with_context(|| format!("failed to parse baseline file {}", baseline_path.display()))?;

    println!();
    println!(
        "Comparison vs baseline ({}, {}):",
        baseline.meta.git_sha,
        baseline
            .meta
            .date
            .split('T')
            .next()
            .unwrap_or(&baseline.meta.date)
    );

    for result in current {
        let Some(previous) = baseline.e2e.get(&result.name) else {
            continue;
        };
        let delta_pct = if previous.mean_ms <= f64::EPSILON {
            0.0
        } else {
            ((result.mean_ms - previous.mean_ms) / previous.mean_ms) * 100.0
        };

        let marker = if delta_pct > 10.0 {
            "REGRESSION"
        } else if delta_pct < -10.0 {
            "IMPROVED"
        } else {
            ""
        };

        println!(
            "  {:<18} {:>7.1}ms -> {:>7.1}ms ({:+5.1}%) {}",
            format!("{}:", result.name),
            previous.mean_ms,
            result.mean_ms,
            delta_pct,
            marker
        );
    }

    Ok(())
}

fn write_json(path: &Path, value: &BenchmarkFile) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("failed to serialize benchmark JSON")?;
    std::fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
}

fn build_release_binary(workspace_root: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "ru-cli"])
        .current_dir(workspace_root)
        .status()
        .context("failed to launch cargo build")?;
    if !status.success() {
        bail!("cargo build --release -p ru-cli failed");
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|p| p.to_path_buf())
        .context("failed to determine workspace root")
}

fn release_binary_path(workspace_root: &Path) -> PathBuf {
    let exe = if cfg!(windows) { "ru.exe" } else { "ru" };
    workspace_root.join("target").join("release").join(exe)
}

fn collect_meta(workspace_root: &Path) -> Meta {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let git_sha = command_output("git", &["rev-parse", "--short", "HEAD"], workspace_root)
        .unwrap_or_else(|| "unknown".to_string());
    let date = chrono::Utc::now().to_rfc3339();
    let rust_version = command_output("rustc", &["--version"], workspace_root)
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let os = format!("{}-{}", env::consts::OS, env::consts::ARCH);
    let cpu = env::var("PROCESSOR_IDENTIFIER")
        .or_else(|_| env::var("HOSTTYPE"))
        .unwrap_or_else(|_| "unknown".to_string());

    Meta {
        version,
        git_sha,
        date,
        rust_version,
        os,
        cpu,
    }
}

fn command_output(command: &str, args: &[&str], cwd: &Path) -> Option<String> {
    let mut cmd = Command::new(command);
    let output = cmd.args(args).current_dir(cwd).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.trim().to_string())
}
