use crate::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<SarifArtifact>,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifDefaultConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDefaultConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifact {
    pub location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn")]
    pub start_column: u32,
    #[serde(rename = "endLine")]
    pub end_line: u32,
    #[serde(rename = "endColumn")]
    pub end_column: u32,
}

impl SarifReport {
    pub fn empty() -> Self {
        Self {
            version: "2.1.0".to_string(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "SentinelClarity".to_string(),
                        rules: Vec::new(),
                    },
                },
                artifacts: Vec::new(),
                results: Vec::new(),
            }],
        }
    }

    pub fn from_findings(findings: Vec<Finding>) -> Self {
        let mut report = Self::empty();
        let run = &mut report.runs[0];

        for finding in findings {
            if !run
                .tool
                .driver
                .rules
                .iter()
                .any(|rule| rule.id == finding.rule_id)
            {
                let rule_details = rule_details(&finding.rule_id);
                run.tool.driver.rules.push(SarifRule {
                    id: finding.rule_id.clone(),
                    name: finding.rule_id.clone(),
                    short_description: SarifMessage {
                        text: rule_details.0.to_string(),
                    },
                    full_description: SarifMessage {
                        text: rule_details.1.to_string(),
                    },
                    default_configuration: SarifDefaultConfiguration {
                        level: severity_to_level(finding.severity).to_string(),
                    },
                });
            }

            let source_path = finding
                .metadata
                .get("source_path")
                .cloned()
                .unwrap_or_else(|| "inline.clar".to_string());

            if !run
                .artifacts
                .iter()
                .any(|artifact| artifact.location.uri == source_path)
            {
                run.artifacts.push(SarifArtifact {
                    location: SarifArtifactLocation {
                        uri: source_path.clone(),
                    },
                });
            }

            run.results.push(SarifResult {
                rule_id: finding.rule_id.clone(),
                level: severity_to_level(finding.severity).to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: source_path },
                        region: SarifRegion {
                            start_line: finding.location.start_line,
                            start_column: finding.location.start_col,
                            end_line: finding.location.end_line,
                            end_column: finding.location.end_col,
                        },
                    },
                }],
                properties: finding.metadata,
            });
        }

        report
    }
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn rule_details(rule_id: &str) -> (&'static str, &'static str) {
    match rule_id {
        "SC-REENTRANCY" => (
            "External call before state update",
            "Detects external calls that occur before state-changing operations in the same function.",
        ),
        "SC-ACCESS" => (
            "Missing access control",
            "Detects admin-like public functions that mutate state without an obvious authorization guard.",
        ),
        "SC-OVERFLOW" => (
            "Unchecked arithmetic",
            "Detects arithmetic that should be reviewed for checked overflow behavior.",
        ),
        "SC-UNCHECKED" => (
            "Unchecked external call",
            "Detects external contract calls without explicit response handling.",
        ),
        "SC-TRAIT" => (
            "Trait implementation mismatch",
            "Detects suspicious or incomplete trait implementation declarations.",
        ),
        "SC-READONLY" => (
            "Read-only state mutation",
            "Detects state-changing operations inside read-only functions.",
        ),
        "SC-TX-SENDER" => (
            "tx-sender authorization risk",
            "Detects state-changing public functions that authorize with tx-sender without constraining contract-caller.",
        ),
        _ => (
            "SentinelClarity finding",
            "Security finding emitted by SentinelClarity.",
        ),
    }
}
