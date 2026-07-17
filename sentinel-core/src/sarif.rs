use crate::Finding;
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
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
                run.tool.driver.rules.push(SarifRule {
                    id: finding.rule_id.clone(),
                    name: finding.rule_id.clone(),
                });
            }

            run.results.push(SarifResult {
                rule_id: finding.rule_id,
                level: match finding.severity {
                    crate::Severity::Low => "note",
                    crate::Severity::Medium => "warning",
                    crate::Severity::High | crate::Severity::Critical => "error",
                }
                .to_string(),
                message: SarifMessage {
                    text: finding.message,
                },
            });
        }

        report
    }
}
