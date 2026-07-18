#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-sentinel-test-corpus/contracts/handcrafted/reentrancy/fixed.clar}"
CONFIG="${2:-sentinel.toml}"
SARIF_OUTPUT="${3:-artifacts/audit-results.sarif}"
EVIDENCE_OUTPUT="${4:-artifacts/audit-evidence.json}"

if ! command -v clarinet >/dev/null 2>&1; then
  echo "Clarinet is required for an audit-grade run. Install it from https://docs.hiro.so/clarinet."
  exit 2
fi

mkdir -p "$(dirname "$SARIF_OUTPUT")" "$(dirname "$EVIDENCE_OUTPUT")"

cargo run --locked --package sentinel-cli -- scan "$TARGET" \
  --config "$CONFIG" \
  --clarinet \
  --format sarif \
  --output "$SARIF_OUTPUT" \
  --evidence "$EVIDENCE_OUTPUT"

echo "Audit passed."
echo "SARIF: $SARIF_OUTPUT"
echo "Evidence: $EVIDENCE_OUTPUT"
