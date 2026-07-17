# SC-REENTRANCY

Detects functions that perform an external call, such as `contract-call?` or `as-contract`, before mutating contract state with `map-set`, `var-set`, or `stx-transfer?`.

## Risk

External calls before state updates can expose inconsistent state to another contract and make the function vulnerable to reentrancy-style control flow.

## Fix Guidance

Move state changes before external calls, use explicit response handling with `try!` or `match`, and keep the checks-effects-interactions pattern visible in the function body.

## False Positives

This heuristic may flag safe calls when the callee is fully trusted or when transaction rollback semantics make the state transition safe. Triage should verify exploitability.
