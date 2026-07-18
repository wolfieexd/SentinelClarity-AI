# SentinelClarity Architecture

SentinelClarity is organized as a pipeline: source code is adapted into a shared representation, deterministic rules emit findings, AI triage enriches those findings, and delivery layers publish results to developers.

## System Flow

```mermaid
flowchart LR
    Source["Clarity source files"] --> Adapter["Clarity adapter"]
    Adapter --> AST["Universal AST"]
    AST --> Rules["Security rule registry"]
    Rules --> Findings["Normalized findings"]
    Findings --> SARIF["SARIF / JSON / Markdown"]
    Findings --> Context["Triage context builder"]
    Context --> Triage["TriageClient"]
    Triage --> FixPlan["Codex fix package"]
    FixPlan --> PR["Future GitHub PR automation"]
```

## Crate Responsibilities

```mermaid
flowchart TB
    Core["sentinel-core\nAST, traits, findings, SARIF"]
    Clarity["sentinel-clarity\nClarity source adapter"]
    Engine["sentinel-engine\nRules and scanner"]
    AI["sentinel-ai\nTriage and fix packages"]
    CLI["sentinel-cli\nUser-facing commands"]
    Action["sentinel-action\nGitHub Action wrapper"]
    Corpus["sentinel-test-corpus\nFixtures and regression checks"]

    Clarity --> Core
    Engine --> Core
    AI --> Core
    CLI --> Clarity
    CLI --> Engine
    CLI --> AI
    Action --> CLI
    Corpus --> Engine
```

## Triage Contract

```mermaid
sequenceDiagram
    participant Scanner
    participant ContextBuilder
    participant TriageClient
    participant FixGenerator

    Scanner->>ContextBuilder: Finding + source
    ContextBuilder-->>Scanner: TriageContext
    Scanner->>TriageClient: Finding + TriageContext
    TriageClient-->>Scanner: TriageResult
    Scanner->>FixGenerator: Finding + FixContext
    FixGenerator-->>Scanner: FixPackage
```

## Design Principles

- Keep static analysis deterministic and CI-safe.
- Keep AI output structured and reviewable.
- Prefer small fix packages over broad rewrites.
- Make SARIF useful for GitHub code scanning.
- Preserve a language-agnostic core for future adapters.

## Current Implementation Boundaries

The current Clarity adapter is intentionally lightweight. It extracts function boundaries, visibility, external calls, state operations, arithmetic markers, and read-only functions well enough for the Build Week demo.

Future parser-backed work should replace the heuristic extraction while keeping the `LanguageAdapter`, `SecurityRule`, and `TriageClient` contracts stable.
