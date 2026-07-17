pub mod rules;

use sentinel_core::{Finding, LanguageAdapter, SarifReport, SecurityRule};

#[derive(Default)]
pub struct RuleRegistry {
    rules: Vec<Box<dyn SecurityRule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register(&mut self, rule: impl SecurityRule + 'static) {
        self.rules.push(Box::new(rule));
    }

    pub fn visit_all(&self, ast: &sentinel_core::UniversalAST) -> Vec<Finding> {
        self.rules.iter().flat_map(|rule| rule.visit(ast)).collect()
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
