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
