# SC-OVERFLOW

Detects arithmetic operations that should be reviewed for checked overflow behavior.

## Risk

Unchecked arithmetic can corrupt supply, accounting, voting weight, or collateral calculations.

## Fix Guidance

Prefer checked arithmetic patterns, assert postconditions, and add regression tests around boundary values.

## False Positives

Some Clarity versions and arithmetic forms are checked by the runtime. The rule intentionally keeps early coverage broad until parser-backed type analysis lands.
