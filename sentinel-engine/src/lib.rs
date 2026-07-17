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
}
