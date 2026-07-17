# SC-READONLY

Detects state-changing operations inside `define-read-only` functions.

## Risk

Read-only functions should not mutate state or perform write-capable calls. Violations can mislead callers and break assumptions made by tooling and integrations.

## Fix Guidance

Move state changes into public functions and keep read-only functions limited to deterministic queries.

## False Positives

Calls to helper functions may need deeper interprocedural analysis to determine whether they are truly state-changing.
