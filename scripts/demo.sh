#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== SentinelClarity demo =="
echo

echo "1. Validate configuration"
cargo run --package sentinel-cli -- init --validate --config sentinel.toml
echo

echo "2. Scan handcrafted vulnerable corpus with markdown triage"
cargo run --package sentinel-cli -- scan sentinel-test-corpus/contracts \
  --format markdown \
  --triage \
  --fail-on critical
echo

echo "3. Generate SARIF for GitHub code scanning"
cargo run --package sentinel-cli -- scan sentinel-test-corpus/contracts \
  --format sarif \
  --output sentinel-results.sarif \
  --fail-on critical || true

echo
echo "SARIF written to sentinel-results.sarif"
