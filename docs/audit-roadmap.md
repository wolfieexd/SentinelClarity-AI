# Audit-Grade Roadmap

SentinelClarity can become a strong, independent audit **assistant**. It must not claim to replace accountable professional review for high-value or irreversible deployments: an audit includes threat-model judgment, protocol economics, deployment context, and a reviewer who accepts responsibility for conclusions.

## What Is Implemented

- Bounded, fail-closed static scanning with deterministic output.
- Six documented Clarity risk rules and vulnerable/fixed regression fixtures.
- Rule policy enforcement from `sentinel.toml`.
- Structural source validation that ignores comments and strings during rule matching.
- Optional official-toolchain validation through `sentinel-clarity scan --clarinet`.
- SHA-256 audit evidence bundles covering the source, policy, compiler version, findings, and gate result.
- SHA-256 checksums attached to every release artifact.
- SARIF, JSON, markdown, fix verification, dependency advisory checks, secret scanning, and CodeQL.

## Audit-Grade Milestones

| Milestone | Evidence Produced | Required Capability |
| --- | --- | --- |
| Semantic model | Typed call graph, storage inventory, privilege graph | Parse Clarity using compiler-compatible AST/type information |
| Interprocedural analysis | Taint, authority, and external-call paths | Dataflow across public/private functions and contracts |
| Invariant testing | Reproducible counterexamples | Property tests against Clarinet Simnet with adversarial principals and values |
| Differential checks | Before/after behavioral proof | Compare fixed and vulnerable contracts across the same test vectors |
| Supply-chain review | Locked dependencies and reproducible release evidence | SBOM, signed artifacts, provenance, and dependency policy |
| Audit report | Finding confidence, assumptions, coverage, and residual risk | A reviewable evidence bundle, not a severity-only scanner output |

## Operating Standard

An audit run should fail when compiler validation fails, relevant tests are missing, a configured invariant is violated, or a critical/high finding remains unresolved. A release should include the exact source revision, `Cargo.lock`, scanner configuration, compiler version, test vectors, SARIF, and a signed evidence bundle.

## Next Core Build

The highest-value next implementation is a Clarinet Simnet test harness that executes contract-specific invariants against generated adversarial inputs. That turns detected patterns into demonstrated exploitability or documented non-exploitability.
