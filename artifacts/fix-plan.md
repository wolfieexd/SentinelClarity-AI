# SentinelClarity Fix Plan

## Demo Target

`sentinel-test-corpus/contracts/demo/vulnerable-dao.clar`

## Summary

The demo DAO contract intentionally combines multiple common Clarity security risks:

- Missing owner guard on privileged state mutation
- Arithmetic that needs boundary validation
- External call before treasury accounting update
- External call response not handled explicitly
- State mutation inside a read-only function

## Proposed Pull Request

Title: `fix: harden demo DAO treasury flows`

### Changes

- Add an `assert-owner` helper and call it from privileged public functions.
- Move treasury accounting updates before external calls.
- Wrap external calls with `try!` so failures propagate.
- Add arithmetic boundary checks before treasury updates.
- Remove write operations from read-only query paths.

### Regression Tests

- Unauthorized caller cannot change owner.
- Treasury withdrawal updates internal accounting before transfer.
- Bridge notification returns an error when the bridge call fails.
- Vote query stays read-only.
- Boundary-value minting rejects overflow-like states.

### Verification

```bash
cargo run --package sentinel-cli -- scan sentinel-test-corpus/contracts/demo/vulnerable-dao.clar --format markdown --triage --fail-on critical
cargo run --package sentinel-cli -- scan sentinel-test-corpus/contracts/demo/fixed-dao.clar --format markdown --triage --fail-on critical
```
