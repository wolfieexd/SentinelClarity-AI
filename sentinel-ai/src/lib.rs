use serde::{Deserialize, Serialize};
use sentinel_core::{Finding, FixContext, FixError, FixGenerator, FixPackage};

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

#[derive(Debug, Default)]
pub struct CodexFixGenerator;

impl FixGenerator for CodexFixGenerator {
    fn generate(&self, finding: &Finding, _ctx: &FixContext) -> Result<FixPackage, FixError> {
        Ok(FixPackage {
            patch: String::new(),
            test_patch: String::new(),
            explanation: format!(
                "Fix generation prompt scaffolded for finding {}.",
                finding.rule_id
            ),
        })
    }
}
