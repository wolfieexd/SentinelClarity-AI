# Changelog

All notable changes to SentinelClarity will be documented in this file.

The format is based on Keep a Changelog.

## [Unreleased]

### Added

- Sprint 0 Rust workspace scaffold.
- Core AST, trait, SARIF, CLI, action, config, and documentation skeletons.
- Sprint 1 lightweight Clarity function extractor.
- Six heuristic security rules for reentrancy, access control, overflow, unchecked calls, trait declarations, and read-only mutation.
- CLI scanning for `.clar` files and directories with SARIF, JSON, and markdown output.
- Handcrafted vulnerable and fixed corpus fixtures for each rule.
- Rule documentation pages under `docs/rules/`.
- Sprint 2 offline triage engine with exploitability, blast radius, root cause, fix strategy, confidence, and references.
- Fix-package templates for access control, overflow, unchecked calls, and read-only violations.
- `sentinel-clarity scan --triage --format markdown` output.
- Sprint 3 config validation via `sentinel-clarity init --validate --config sentinel.toml`.
- Shell completion generation via `sentinel-clarity completions <shell>`.
- Demo script for config validation, triage markdown, and SARIF generation.
- Demo DAO vulnerable/fixed contract pair with sample triage report, SARIF, and mock fix-plan artifacts.
