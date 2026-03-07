#!/usr/bin/env bash
set -euo pipefail

echo "=== Building release binary ==="
cargo build --release -p ru-cli

echo ""
echo "=== Running Criterion micro-benchmarks ==="
cargo bench -p ru-cli --bench cli_perf

echo ""
echo "=== Running end-to-end benchmarks ==="
cargo bench -p ru-cli --bench e2e_perf

echo ""
echo "Results saved. Criterion HTML reports: target/criterion/"
