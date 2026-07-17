# ADR 0001: SentinelClarity Architecture

## Status

Proposed

## Context

SentinelClarity needs a fast, CI-friendly security engine for Clarity smart contracts that can later support additional smart-contract languages.

## Decision

- Use Rust for performance, reliable binaries, and a strong security tooling ecosystem.
- Start with a custom Universal AST that can represent Clarity contracts and future language adapters.
- Use a trait-based `LanguageAdapter` and `SecurityRule` model.
- Emit SARIF 2.1.0 as the primary machine-readable output.
- Add GPT structured triage and Codex fix generation behind explicit configuration gates.
- Ship as a CLI and GitHub Action first.
- Use TOML configuration with future environment-variable overrides.
- Keep telemetry opt-in and local-only.

## Consequences

The initial codebase stays small and testable while preserving a clean path to Sprint 1 parser and rule implementation work.

## Alternatives Considered

- Language-specific AST only: simpler now, but weaker for Solidity and Move expansion.
- WASM IR: powerful, but too much complexity for the Build Week timeline.
- SaaS-first service: easier AI orchestration, but weaker local security posture.
