# SentinelClarity - OpenAI Build Week Submission

## Inspiration

Clarity smart contracts secure Bitcoin-layer applications, but most security feedback still arrives too late: after a large review cycle, after a protocol integration, or after code is already close to deployment. SentinelClarity was built around a simple question: what if every Clarity repository had an AI-native security engineer watching every pull request?

## What It Does

SentinelClarity scans Clarity smart contracts, detects security risks, produces SARIF for code-scanning workflows, and generates AI-style triage reports that explain exploitability, blast radius, root cause, fix strategy, and remediation confidence.

The current demo focuses on a vulnerable DAO treasury contract with multiple findings:

- Missing access control on owner mutation
- Arithmetic that needs boundary validation
- External call before treasury accounting update
- Unhandled external contract response
- State mutation inside a read-only function

## How We Built It

The project is a Rust workspace with separate crates for:

- Universal AST and shared security types
- Clarity source adaptation
- Rule registry and scanner orchestration
- AI triage and Codex fix-package planning
- CLI and GitHub Action entrypoints
- Test corpus fixtures

The scanner emits deterministic findings, then the triage layer enriches those findings with structured reasoning. CI remains deterministic by using an offline `HeuristicTriageClient`, while the `TriageClient` trait keeps a clean path for live OpenAI-backed triage.

## What Makes It AI-Native

SentinelClarity does not treat AI as a chat box bolted onto a linter. Findings are normalized first, context is assembled around each finding, and triage returns structured fields that can drive fix planning, PR summaries, and future workflow automation.

The AI-facing shape includes:

- Exploitability
- Blast radius
- Root cause
- Fix strategy
- Confidence
- Developer-facing explanation
- References
- Optional fix package plan

## Challenges

The main challenge was balancing an ambitious end-to-end product vision with a reliable Build Week implementation. A full Clarity parser, live OpenAI integration, and GitHub PR bot are larger than a single sprint. The project therefore emphasizes a stable architecture, deterministic CI, realistic fixtures, rich SARIF, and clear extension points.

## Accomplishments

- Rust workspace with clean crate boundaries
- CI passing on Ubuntu, macOS, and Windows
- Six security rule categories
- Handcrafted vulnerable and fixed Clarity fixtures
- Demo DAO contract with multi-finding security story
- AI-style triage and fix-package output
- SARIF 2.1.0 output with source locations
- Judge quickstart and one-command demo script

## What We Learned

The most useful AI security workflows start with structured static context. When findings, spans, metadata, and rule docs are normalized before AI triage, the model-facing workflow becomes more auditable and easier to automate.

## What's Next

- Replace lightweight parsing with parser-backed Clarity AST conversion.
- Add live OpenAI triage behind the existing `TriageClient` trait.
- Generate minimal patches and regression tests for fixable findings.
- Open annotated GitHub pull requests from CI.
- Expand the corpus with real Stacks ecosystem contracts.
- Add language adapters for Solidity and Move.

## Demo Commands

```bash
./scripts/judge-demo.sh
```

Manual equivalent:

```bash
cargo test --workspace
cargo run --package sentinel-cli -- init --validate --config sentinel.toml
cargo run --package sentinel-cli -- scan sentinel-test-corpus/contracts/demo/vulnerable-dao.clar --format markdown --triage --fail-on critical
```

## Links

- Repository: https://github.com/wolfieexd/SentinelClarity-AI
- Track: Developer Tools
- License: MIT
- Demo video: TBD
