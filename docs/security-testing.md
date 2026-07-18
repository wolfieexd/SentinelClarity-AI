# Security Testing

SentinelClarity includes cybersecurity-oriented tests for both the scanner and the repository itself.

## What Runs in CI

The `Security` workflow runs on every push to `main` and every pull request.

| Check | Purpose |
| --- | --- |
| Secret pattern scan | Fails if tracked files contain high-risk patterns such as private keys, GitHub tokens, OpenAI keys, AWS access keys, or password-like fields. |
| Dependency advisory audit | Checks `Cargo.lock` against the RustSec advisory database. |
| CodeQL | Runs scheduled and pull-request static analysis of the Rust workspace. |
| Smart-contract security regressions | Runs targeted Clarity corpus tests that verify vulnerable fixtures emit expected findings and fixed fixtures clear targeted risks. |
| Fix verification | The CLI can compare before/after contracts and fail if selected risks remain. |

## Runtime Boundary Tests

The local `serve` API is deliberately constrained to reduce its attack surface:

- It binds only to `127.0.0.1`, not to external network interfaces.
- It enforces a five-second read/write timeout.
- It caps headers at 16 KiB, request bodies at 512 KiB, and scanned files at 2 MiB.
- Recursive filesystem scans are capped at 10,000 `.clar` files and fail instead of silently skipping traversal errors.
- It accepts only `GET /health`, `GET /version`, and `POST /scan` with raw UTF-8 Clarity source.
- It rejects duplicate `Content-Length`, transfer encodings, incomplete bodies, unsupported query strings, and invalid UTF-8.
- Error responses are JSON-escaped and include `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Policy and Parser Checks

- Explicit `--config` files are parsed as TOML and fail closed for missing required sections, unknown rules/settings, invalid rule severities, or invalid output policy severity.
- Rule enablement and severity overrides are applied by the registry itself, so SARIF, markdown, JSON, fix verification, and exit status share the same security policy.
- The Clarity adapter rejects unbalanced parentheses and unterminated strings before rule execution.
- Rule matching uses sanitized code, preventing comments and string literals from fabricating apparent dangerous operations.
- `scan --clarinet` optionally invokes the installed Clarinet compiler with direct process arguments, requiring its syntax validation before SentinelClarity analysis proceeds.

## Local Command

```bash
./scripts/security-check.sh
```

The script performs the same secret scan and targeted security regression tests. If `cargo-audit` is installed locally, it also runs a dependency advisory audit.

## Security Regression Coverage

The corpus validates these vulnerability classes:

- `SC-REENTRANCY` external-call ordering risk
- `SC-ACCESS` missing authorization on privileged mutation
- `SC-OVERFLOW` arithmetic requiring boundary review
- `SC-UNCHECKED` unhandled external call responses
- `SC-TRAIT` trait implementation mismatch patterns
- `SC-READONLY` state mutation from read-only functions

Additional regression tests verify that fixed handcrafted fixtures clear targeted access-control, reentrancy, unchecked-call, trait, and read-only findings. The fixed DAO demo intentionally retains conservative access-control and arithmetic review signals because the MVP rule engine does not yet follow delegated private authorization helpers or prove arithmetic guards.

## Not Yet Covered

- Fuzzing and property-based tests
- Compiler-grade Clarity semantic validation
- Mainnet-scale labeled corpus evaluation
- Live OpenAI API integration testing
- Automated PR remediation security review
- Authenticated multi-user API deployment and rate-limiting
