#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEMO_CONTRACT="sentinel-test-corpus/contracts/demo/vulnerable-dao.clar"
REPORT="artifacts/demo-output.md"
SARIF="artifacts/sentinel-results.sarif"

mkdir -p artifacts

echo "== SentinelClarity Judge Demo =="
echo

echo "1. Running workspace tests"
cargo test --workspace
echo

echo "2. Validating scanner configuration"
cargo run --package sentinel-cli -- init --validate --config sentinel.toml
echo

echo "3. Generating AI triage markdown"
set +e
cargo run --package sentinel-cli -- scan "$DEMO_CONTRACT" \
  --format markdown \
  --triage \
  --fail-on critical > "$REPORT"
TRIAGE_STATUS=$?
set -e
echo "Wrote $REPORT"
echo

echo "4. Generating SARIF"
set +e
cargo run --package sentinel-cli -- scan "$DEMO_CONTRACT" \
  --format sarif \
  --output "$SARIF" \
  --fail-on critical
SARIF_STATUS=$?
set -e
echo "Wrote $SARIF"
echo

echo "5. Demo result"
echo "Findings are expected for the vulnerable DAO."
echo "Triage exit code: $TRIAGE_STATUS"
echo "SARIF exit code: $SARIF_STATUS"
echo
echo "Open artifacts/demo-output.md and artifacts/fix-plan.md for the judge-facing story."
