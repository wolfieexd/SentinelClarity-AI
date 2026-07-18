# Security Testing

SentinelClarity includes cybersecurity-oriented tests for both the scanner and the repository itself.

## What Runs in CI

The `Security` workflow runs on every push to `main` and every pull request.

| Check | Purpose |
| --- | --- |
| Secret pattern scan | Fails if tracked files contain high-risk patterns such as private keys, GitHub tokens, OpenAI keys, AWS access keys, or password-like fields. |
| Smart-contract security regressions | Runs targeted Clarity corpus tests that verify vulnerable fixtures emit expected findings and fixed fixtures clear targeted risks. |
| Fix verification | The CLI can compare before/after contracts and fail if selected risks remain. |

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
