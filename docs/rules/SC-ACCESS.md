# SC-ACCESS

Detects admin-like public functions that mutate state without an obvious `tx-sender`, owner, or `contract-caller` authorization check.

## Risk

Missing access control can allow arbitrary users to change owners, mint or burn assets, pause protocols, or upgrade critical configuration.

## Fix Guidance

Add an explicit authorization guard before state changes, preferably using a single owner or role helper that returns a clear error code.

## False Positives

Functions may be intentionally permissionless, or authorization may be delegated to a helper this heuristic does not yet understand.
