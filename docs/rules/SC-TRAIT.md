# SC-TRAIT

Detects incomplete or suspicious trait implementation declarations.

## Risk

Trait mismatches can break composability, cause integrations to fail, or hide missing protocol-required behavior.

## Fix Guidance

Ensure every implemented trait function exists with the expected name, visibility, parameters, and response type.

## False Positives

The Sprint 1 heuristic only detects clearly empty trait implementations. Full signature comparison is planned once parser-backed trait extraction is complete.
