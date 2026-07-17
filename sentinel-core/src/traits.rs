use crate::{SarifReport, UniversalAST};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub type RuleId = String;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse source: {0}")]
    InvalidSource(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub location: crate::Span,
    pub message: String,
    pub code_snippet: Option<String>,
    pub related_locations: Vec<crate::Span>,
    pub metadata: BTreeMap<String, String>,
}

pub trait LanguageAdapter {
    fn parse(&self, source: &str) -> Result<UniversalAST, ParseError>;

    fn to_sarif(&self, findings: Vec<Finding>) -> SarifReport {
        SarifReport::from_findings(findings)
    }
}

pub trait SecurityRule: Send + Sync {
    fn id(&self) -> RuleId;
    fn severity(&self) -> Severity;
    fn visit(&self, ast: &UniversalAST) -> Vec<Finding>;
}

pub trait FixGenerator {
    fn generate(&self, finding: &Finding, ctx: &FixContext) -> Result<FixPackage, FixError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixContext {
    pub source_path: String,
    pub coding_standards: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPackage {
    pub patch: String,
    pub test_patch: String,
    pub explanation: String,
}

#[derive(Debug, Error)]
pub enum FixError {
    #[error("fix generation failed: {0}")]
    GenerationFailed(String),
}
