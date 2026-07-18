# SC-TX-SENDER: `tx-sender` Authorization Without Caller Constraint

## Detection

Flags public state-changing functions that compare `tx-sender` for authorization without also constraining `contract-caller`.

## Risk

`tx-sender` remains the original transaction signer across nested contract calls. A malicious intermediary contract can therefore induce a user to call it and reach a privileged target that trusts only `tx-sender`. This can create a phishing-style authorization path.

## Remediation

Use `contract-caller` for authorization when the immediate caller must be trusted, or otherwise document and test the intended composability of `tx-sender`. Review delegated-call designs individually; this rule is a high-signal review prompt, not a proof of exploitability.
