# Contributing

## Rule Development

Security rules implement `sentinel_core::SecurityRule`.

Each rule should include:

- A stable `SC-*` rule ID
- Severity and confidence metadata
- Focused unit tests with vulnerable and fixed fixtures
- A documentation page in `docs/rules/`
- SARIF output coverage for locations and messages

## Local Checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
