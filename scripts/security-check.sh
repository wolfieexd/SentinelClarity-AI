#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SECRET_PATTERNS=(
  'api[_-]?''key'
  'pass''word[[:space:]]*[:=]'
  'private[_-]?''key'
  'BEGIN (RSA|OPENSSH|PRIVATE)'
  's''k-[A-Za-z0-9]'
  'g''hp_[A-Za-z0-9]'
  'github_''pat_'
  'A''KIA[0-9A-Z]{16}'
  'OPENAI_API_''KEY'
)

echo "== SentinelClarity Security Check =="
echo

echo "1. Scanning tracked files for high-risk secret patterns"
found_secret=0
for pattern in "${SECRET_PATTERNS[@]}"; do
  if git grep -n -I -E "$pattern" -- . ':!Cargo.lock'; then
    found_secret=1
  fi
done

if [[ "$found_secret" -ne 0 ]]; then
  echo "Potential secret-like material found in tracked files."
  exit 1
fi
echo "No high-risk secret patterns found."
echo

echo "2. Running smart-contract security regression tests"
cargo test -p sentinel-test-corpus security_
echo

echo "3. Verifying fixed contract clears targeted finding"
cargo run --package sentinel-cli -- verify-fix \
  --before sentinel-test-corpus/contracts/handcrafted/reentrancy/vulnerable.clar \
  --after sentinel-test-corpus/contracts/handcrafted/reentrancy/fixed.clar \
  --clears SC-REENTRANCY
echo

echo "4. Checking dependency advisories when cargo-audit is available"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "cargo-audit is not installed; skipping dependency advisory audit."
  echo "Install with: cargo install cargo-audit --locked"
fi
