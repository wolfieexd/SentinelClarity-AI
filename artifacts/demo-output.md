# SentinelClarity AI Triage

Path: `sentinel-test-corpus/contracts/demo/vulnerable-dao.clar`
Config: `sentinel.toml`
Fail on: `critical`
Findings: 5

| Rule | Exploitability | Blast Radius | Strategy | Confidence |
| --- | --- | --- | --- | --- |
| `SC-ACCESS` | Confirmed | Governance | AddAccessControl | 88% |
| `SC-OVERFLOW` | Possible | StateCorruption | UseCheckedMath | 68% |
| `SC-REENTRANCY` | Probable | UserFunds | ChecksEffectsInteractions | 82% |
| `SC-UNCHECKED` | Probable | ContractBalance | HandleErrors | 78% |
| `SC-READONLY` | Confirmed | StateCorruption | MoveStateChange | 86% |

## Fix Packages

### `SC-ACCESS`

Codex should insert the smallest owner or role check that matches local contract conventions.

- Patch plan: Add an `asserts!` authorization guard before the first state write.
- Test plan: Add a regression test proving unauthorized callers receive an error.

### `SC-OVERFLOW`

Codex should preserve the existing return type and error style.

- Patch plan: Add a boundary assertion or checked arithmetic helper around the flagged operation.
- Test plan: Add boundary-value tests for max uint and expected overflow rejection.

### `SC-UNCHECKED`

Codex should make response handling explicit without changing successful behavior.

- Patch plan: Wrap the external call with `try!` or a `match` expression.
- Test plan: Add a mock failing callee path and assert the error propagates.

### `SC-READONLY`

Codex should split read and write behavior while keeping the query API stable.

- Patch plan: Move the state-changing operation out of the read-only function.
- Test plan: Add a regression test showing the read-only function is query-only.
