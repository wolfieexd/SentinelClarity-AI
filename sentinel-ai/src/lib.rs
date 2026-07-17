use sentinel_core::{Finding, FixContext, FixError, FixGenerator, FixPackage, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub exploitability: Exploitability,
    pub blast_radius: BlastRadius,
    pub root_cause: String,
    pub fix_strategy: FixStrategy,
    pub fix_confidence: f32,
    pub explanation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Exploitability {
    Confirmed,
    Probable,
    Possible,
    Unlikely,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlastRadius {
    ContractBalance,
    UserFunds,
    Governance,
    StateCorruption,
    DenialOfService,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FixStrategy {
    ChecksEffectsInteractions,
    AddAccessControl,
    UseCheckedMath,
    HandleErrors,
    FixTraitImpl,
    MoveStateChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageContext {
    pub finding_hash: String,
    pub contract_snippet: String,
    pub rule_summary: String,
    pub related_state: Vec<String>,
    pub call_graph: Vec<String>,
    pub contract_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagedFinding {
    pub finding: Finding,
    pub context: TriageContext,
    pub triage: TriageResult,
    pub fix: Option<FixPackage>,
}

#[derive(Debug, Error)]
pub enum TriageError {
    #[error("triage failed for {rule_id}: {message}")]
    Client { rule_id: String, message: String },
}

pub trait TriageClient {
    fn triage(
        &self,
        finding: &Finding,
        context: &TriageContext,
    ) -> Result<TriageResult, TriageError>;
}

#[derive(Debug, Default)]
pub struct ContextBuilder {
    rule_docs: BTreeMap<String, String>,
}

impl ContextBuilder {
    pub fn new(rule_docs: BTreeMap<String, String>) -> Self {
        Self { rule_docs }
    }

    pub fn build(&self, finding: &Finding, source: &str) -> TriageContext {
        let contract_snippet = snippet_around(source, finding.location.start_line, 30);
        let mut contract_metadata = BTreeMap::new();
        contract_metadata.insert("line".to_string(), finding.location.start_line.to_string());
        contract_metadata.insert("severity".to_string(), format!("{:?}", finding.severity));

        TriageContext {
            finding_hash: finding_hash(finding),
            contract_snippet,
            rule_summary: self
                .rule_docs
                .get(&finding.rule_id)
                .cloned()
                .unwrap_or_else(|| "No rule documentation loaded.".to_string()),
            related_state: related_state(source),
            call_graph: related_calls(source),
            contract_metadata,
        }
    }
}

pub struct TriageEngine<C> {
    client: C,
    context_builder: ContextBuilder,
}

impl<C> TriageEngine<C>
where
    C: TriageClient,
{
    pub fn new(client: C, context_builder: ContextBuilder) -> Self {
        Self {
            client,
            context_builder,
        }
    }

    pub fn run(
        &self,
        findings: Vec<Finding>,
        source: &str,
    ) -> Result<Vec<TriagedFinding>, TriageError> {
        findings
            .into_iter()
            .map(|finding| {
                let context = self.context_builder.build(&finding, source);
                let triage = self.client.triage(&finding, &context)?;
                let fix = CodexFixGenerator.generate(
                    &finding,
                    &FixContext {
                        source_path: "inline.clar".to_string(),
                        coding_standards: vec![
                            "Keep fixes minimal".to_string(),
                            "Add regression tests for changed behavior".to_string(),
                        ],
                    },
                );

                Ok(TriagedFinding {
                    finding,
                    context,
                    triage,
                    fix: fix.ok().filter(|package| !package.patch.is_empty()),
                })
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct HeuristicTriageClient;

impl TriageClient for HeuristicTriageClient {
    fn triage(
        &self,
        finding: &Finding,
        _context: &TriageContext,
    ) -> Result<TriageResult, TriageError> {
        Ok(match finding.rule_id.as_str() {
            "SC-REENTRANCY" => TriageResult {
                exploitability: Exploitability::Probable,
                blast_radius: BlastRadius::UserFunds,
                root_cause: "The function performs an external call before contract state is updated.".to_string(),
                fix_strategy: FixStrategy::ChecksEffectsInteractions,
                fix_confidence: 0.82,
                explanation:
                    "External calls should not observe stale accounting state. Move state updates before the call and keep response handling explicit."
                        .to_string(),
                references: vec!["CWE-841".to_string(), "SWC-107".to_string()],
            },
            "SC-ACCESS" => TriageResult {
                exploitability: Exploitability::Confirmed,
                blast_radius: BlastRadius::Governance,
                root_cause: "A public state-changing function appears to lack an authorization guard."
                    .to_string(),
                fix_strategy: FixStrategy::AddAccessControl,
                fix_confidence: 0.88,
                explanation:
                    "Admin-like functions should prove caller authority before mutating privileged state."
                        .to_string(),
                references: vec!["CWE-284".to_string(), "CWE-862".to_string()],
            },
            "SC-OVERFLOW" => TriageResult {
                exploitability: Exploitability::Possible,
                blast_radius: BlastRadius::StateCorruption,
                root_cause: "Arithmetic lacks an obvious boundary assertion or checked-operation wrapper."
                    .to_string(),
                fix_strategy: FixStrategy::UseCheckedMath,
                fix_confidence: 0.68,
                explanation:
                    "Arithmetic findings need type-aware confirmation, but boundary assertions are a low-risk mitigation."
                        .to_string(),
                references: vec!["CWE-190".to_string()],
            },
            "SC-UNCHECKED" => TriageResult {
                exploitability: Exploitability::Probable,
                blast_radius: BlastRadius::ContractBalance,
                root_cause: "An external contract call response is not explicitly handled.".to_string(),
                fix_strategy: FixStrategy::HandleErrors,
                fix_confidence: 0.78,
                explanation:
                    "Unchecked responses can let failed downstream operations look successful to callers."
                        .to_string(),
                references: vec!["CWE-252".to_string()],
            },
            "SC-TRAIT" => TriageResult {
                exploitability: Exploitability::Possible,
                blast_radius: BlastRadius::Low,
                root_cause: "The contract declares trait usage without enough visible implementation surface."
                    .to_string(),
                fix_strategy: FixStrategy::FixTraitImpl,
                fix_confidence: 0.58,
                explanation:
                    "Trait findings should be confirmed against the trait definition before a patch is generated."
                        .to_string(),
                references: vec!["CWE-573".to_string()],
            },
            "SC-READONLY" => TriageResult {
                exploitability: Exploitability::Confirmed,
                blast_radius: BlastRadius::StateCorruption,
                root_cause: "A read-only function contains a state-changing operation.".to_string(),
                fix_strategy: FixStrategy::MoveStateChange,
                fix_confidence: 0.86,
                explanation:
                    "Read-only query paths should remain side-effect free. Move writes to public functions."
                        .to_string(),
                references: vec!["CWE-664".to_string()],
            },
            _ => TriageResult {
                exploitability: match finding.severity {
                    Severity::Critical | Severity::High => Exploitability::Possible,
                    Severity::Medium | Severity::Low => Exploitability::Unlikely,
                },
                blast_radius: BlastRadius::Low,
                root_cause: "The rule reported a finding that requires manual confirmation.".to_string(),
                fix_strategy: FixStrategy::HandleErrors,
                fix_confidence: 0.4,
                explanation: finding.message.clone(),
                references: Vec::new(),
            },
        })
    }
}

#[derive(Debug, Default)]
pub struct CodexFixGenerator;

impl FixGenerator for CodexFixGenerator {
    fn generate(&self, finding: &Finding, _ctx: &FixContext) -> Result<FixPackage, FixError> {
        let (patch, test_patch, explanation) = match finding.rule_id.as_str() {
            "SC-ACCESS" => (
                "Add an `asserts!` authorization guard before the first state write.".to_string(),
                "Add a regression test proving unauthorized callers receive an error.".to_string(),
                "Codex should insert the smallest owner or role check that matches local contract conventions."
                    .to_string(),
            ),
            "SC-OVERFLOW" => (
                "Add a boundary assertion or checked arithmetic helper around the flagged operation.".to_string(),
                "Add boundary-value tests for max uint and expected overflow rejection.".to_string(),
                "Codex should preserve the existing return type and error style.".to_string(),
            ),
            "SC-UNCHECKED" => (
                "Wrap the external call with `try!` or a `match` expression.".to_string(),
                "Add a mock failing callee path and assert the error propagates.".to_string(),
                "Codex should make response handling explicit without changing successful behavior.".to_string(),
            ),
            "SC-READONLY" => (
                "Move the state-changing operation out of the read-only function.".to_string(),
                "Add a regression test showing the read-only function is query-only.".to_string(),
                "Codex should split read and write behavior while keeping the query API stable.".to_string(),
            ),
            _ => (String::new(), String::new(), "No safe automatic fix template is available for this rule yet.".to_string()),
        };

        Ok(FixPackage {
            patch,
            test_patch,
            explanation,
        })
    }
}

fn snippet_around(source: &str, line: u32, context_lines: u32) -> String {
    let start = line.saturating_sub(context_lines).max(1);
    let end = line.saturating_add(context_lines);

    source
        .lines()
        .enumerate()
        .filter_map(|(index, text)| {
            let current = (index + 1) as u32;
            (current >= start && current <= end).then(|| format!("{current}: {text}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn related_state(source: &str) -> Vec<String> {
    ["define-map", "define-data-var", "map-set", "var-set"]
        .into_iter()
        .filter(|needle| source.contains(needle))
        .map(str::to_string)
        .collect()
}

fn related_calls(source: &str) -> Vec<String> {
    ["contract-call?", "as-contract", "try!", "match"]
        .into_iter()
        .filter(|needle| source.contains(needle))
        .map(str::to_string)
        .collect()
}

fn finding_hash(finding: &Finding) -> String {
    format!(
        "{}:{}:{}:{}",
        finding.rule_id, finding.location.start_line, finding.location.start_col, finding.message
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::Span;

    fn finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            location: Span::default(),
            message: "test finding".to_string(),
            code_snippet: None,
            related_locations: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn heuristic_client_maps_access_control() {
        let client = HeuristicTriageClient;
        let context = ContextBuilder::default().build(&finding("SC-ACCESS"), "");
        let triage = client.triage(&finding("SC-ACCESS"), &context).unwrap();

        assert!(matches!(triage.fix_strategy, FixStrategy::AddAccessControl));
        assert!(triage.fix_confidence > 0.8);
    }

    #[test]
    fn engine_attaches_fix_package_for_fixable_rule() {
        let engine = TriageEngine::new(HeuristicTriageClient, ContextBuilder::default());
        let triaged = engine
            .run(vec![finding("SC-UNCHECKED")], "(contract-call? .x y)")
            .unwrap();

        assert_eq!(triaged.len(), 1);
        assert!(triaged[0].fix.is_some());
    }
}
