# Threat Model

SentinelClarity focuses on security risks that appear repeatedly in Clarity smart contract development and that benefit from fast feedback during pull requests.

## Assets

- User funds held or transferred by Clarity contracts.
- DAO governance authority and privileged state.
- Token balances, treasury values, and accounting invariants.
- Contract upgrade, pause, mint, burn, and ownership controls.
- Developer confidence in CI and code review workflows.

## Adversaries

- External users who call public functions with unexpected inputs.
- Malicious or compromised contracts reached through `contract-call?`.
- Governance participants attempting unauthorized privilege changes.
- Integrators relying on incorrect trait or response-handling assumptions.
- Honest developers accidentally introducing state mutation or accounting bugs.
- Local malware or untrusted tools attempting to flood the developer-only HTTP endpoint.
- Corrupted repositories containing unreadable paths or oversized contract-like files that could hide scan coverage gaps.

## Covered Risk Classes

| Rule | Risk | Example Impact |
| --- | --- | --- |
| `SC-REENTRANCY` | External calls before state updates | Treasury accounting can be observed or manipulated before effects are finalized. |
| `SC-ACCESS` | Missing owner/caller authorization | Public callers can mutate privileged state. |
| `SC-OVERFLOW` | Arithmetic requiring boundary review | Balances, fees, or supply values can become incorrect. |
| `SC-UNCHECKED` | Unhandled `contract-call?` responses | Failed external calls can be ignored, leaving inconsistent state. |
| `SC-TRAIT` | Trait implementation mismatch patterns | Integrations can rely on incomplete or misleading interfaces. |
| `SC-READONLY` | State mutation in read-only flows | Query paths can violate expected read-only behavior. |
| `SC-TX-SENDER` | Authorization trusts `tx-sender` alone | A malicious intermediary can induce a signer to reach a privileged state-changing path. |

## Out of Scope for MVP

- Full Clarity type checking and symbolic execution.
- Economic/game-theoretic attacks that require protocol simulation.
- Cross-chain bridge security beyond simple external-call patterns.
- Oracle manipulation analysis beyond local call and response handling.
- Formal verification or mathematical proof of contract invariants.

## Safety Posture

SentinelClarity should be used as fast review assistance, not as the sole audit gate. The MVP intentionally favors explainable, deterministic findings over opaque automation. The local API binds to loopback, uses strict request limits and timeouts, and is not a network service boundary. Filesystem scanning fails closed rather than silently skipping traversal errors. Future production hardening should add typed parsing, dataflow analysis, larger labeled corpora, authenticated/rate-limited service deployment, and human approval gates for automated fixes.
