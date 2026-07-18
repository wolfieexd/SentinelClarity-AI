pub mod rules;

use sentinel_core::{Finding, LanguageAdapter, SarifReport, SecurityRule, Severity};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub struct RuleRegistry {
    rules: Vec<Box<dyn SecurityRule>>,
    disabled_rules: BTreeSet<String>,
    severity_overrides: BTreeMap<String, Severity>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            disabled_rules: BTreeSet::new(),
            severity_overrides: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, rule: impl SecurityRule + 'static) {
        self.rules.push(Box::new(rule));
    }

    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) {
        if enabled {
            self.disabled_rules.remove(rule_id);
        } else {
            self.disabled_rules.insert(rule_id.to_string());
        }
    }

    pub fn set_rule_severity(&mut self, rule_id: &str, severity: Severity) {
        self.severity_overrides
            .insert(rule_id.to_string(), severity);
    }

    pub fn visit_all(&self, ast: &sentinel_core::UniversalAST) -> Vec<Finding> {
        self.rules
            .iter()
            .filter(|rule| !self.disabled_rules.contains(&rule.id()))
            .flat_map(|rule| {
                let rule_id = rule.id();
                let severity_override = self.severity_overrides.get(&rule_id).copied();
                rule.visit(ast).into_iter().map(move |mut finding| {
                    if let Some(severity) = severity_override {
                        finding.severity = severity;
                    }
                    finding
                })
            })
            .collect()
    }
}

pub fn default_registry() -> RuleRegistry {
    let mut registry = RuleRegistry::new();
    registry.register(rules::ReentrancyRule);
    registry.register(rules::AccessControlRule);
    registry.register(rules::OverflowRule);
    registry.register(rules::UncheckedCallRule);
    registry.register(rules::TraitRule);
    registry.register(rules::ReadOnlyRule);
    registry.register(rules::TxSenderRule);
    registry
}

pub struct Scanner<A> {
    adapter: A,
    registry: RuleRegistry,
}

impl<A> Scanner<A>
where
    A: LanguageAdapter,
{
    pub fn new(adapter: A, registry: RuleRegistry) -> Self {
        Self { adapter, registry }
    }

    pub fn scan_source(&self, source: &str) -> Result<SarifReport, sentinel_core::ParseError> {
        let ast = self.adapter.parse(source)?;
        let findings = self.registry.visit_all(&ast);
        Ok(self.adapter.to_sarif(findings))
    }

    pub fn scan_findings(&self, source: &str) -> Result<Vec<Finding>, sentinel_core::ParseError> {
        let ast = self.adapter.parse(source)?;
        Ok(self.registry.visit_all(&ast))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_clarity::ClarityAdapter;
    use sentinel_core::LanguageAdapter;

    #[test]
    fn registry_policy_can_disable_and_reclassify_findings() {
        let source =
            "(define-public (set-owner (new principal)) (begin (var-set owner new) (ok true)))";
        let ast = ClarityAdapter.parse(source).expect("source parses");
        let mut registry = default_registry();

        registry.set_rule_severity("SC-ACCESS", Severity::Critical);
        let findings = registry.visit_all(&ast);
        assert!(findings.iter().any(|finding| {
            finding.rule_id == "SC-ACCESS" && finding.severity == Severity::Critical
        }));

        registry.set_rule_enabled("SC-ACCESS", false);
        assert!(!registry
            .visit_all(&ast)
            .iter()
            .any(|finding| finding.rule_id == "SC-ACCESS"));
    }
}
