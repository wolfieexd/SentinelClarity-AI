# SC-UNCHECKED

Detects external `contract-call?` usage without an explicit response handling path such as `try!`, `match`, `unwrap!`, or `unwrap-err!`.

## Risk

Ignoring contract call responses can make transfers, mints, burns, or protocol interactions appear successful when the callee returned an error.

## Fix Guidance

Handle responses explicitly and return or map errors in a way callers can understand.

## False Positives

Some responses may be intentionally ignored in best-effort workflows. Those cases should include clear comments and tests.
