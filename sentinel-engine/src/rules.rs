use sentinel_core::{
    Finding, Function, SecurityRule, Severity, Span, Stmt, UniversalAST, Visibility,
};
use std::collections::BTreeMap;

pub struct ReentrancyRule;
pub struct AccessControlRule;
pub struct OverflowRule;
pub struct UncheckedCallRule;
pub struct TraitRule;
pub struct ReadOnlyRule;

impl SecurityRule for ReentrancyRule {
    fn id(&self) -> String {
        "SC-REENTRANCY".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, ast: &UniversalAST) -> Vec<Finding> {
        ast.functions()
            .into_iter()
            .filter(|function| {
                let body = body_text(function);
                let external_call = first_index(&body, &["contract-call?", "as-contract"]);
                let state_write = first_index(&body, &["map-set", "var-set", "stx-transfer?"]);
                matches!((external_call, state_write), (Some(call), Some(write)) if call < write)
            })
            .map(|function| {
                finding(
                    self.id(),
                    self.severity(),
                    function.span,
                    format!(
                        "Function `{}` performs an external call before a state-changing operation.",
                        function.name
                    ),
                )
            })
            .collect()
    }
}

impl SecurityRule for AccessControlRule {
    fn id(&self) -> String {
        "SC-ACCESS".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn visit(&self, ast: &UniversalAST) -> Vec<Finding> {
        ast.functions()
            .into_iter()
            .filter(|function| matches!(function.visibility, Visibility::Public))
            .filter(|function| is_admin_like(&function.name))
            .filter(|function| contains_state_write(&body_text(function)))
            .filter(|function| {
                let body = body_text(function);
                !(body.contains("tx-sender")
                    && (body.contains("contract-owner")
                        || body.contains("owner")
                        || body.contains("contract-caller")))
            })
            .map(|function| {
                finding(
                    self.id(),
                    self.severity(),
                    function.span,
                    format!(
                        "Admin-like public function `{}` mutates state without an owner or caller authorization check.",
                        function.name
                    ),
                )
            })
            .collect()
    }
}

impl SecurityRule for OverflowRule {
    fn id(&self) -> String {
        "SC-OVERFLOW".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn visit(&self, ast: &UniversalAST) -> Vec<Finding> {
        ast.functions()
            .into_iter()
            .filter(|function| {
                let body = body_text(function);
                body.contains("(+")
                    || body.contains("(-")
                    || body.contains("(*")
                    || body.contains("unchecked-+")
                    || body.contains("unchecked--")
                    || body.contains("unchecked-*")
            })
            .map(|function| {
                finding(
                    self.id(),
                    self.severity(),
                    function.span,
                    format!(
                        "Function `{}` uses arithmetic that should be reviewed for checked overflow behavior.",
                        function.name
                    ),
                )
            })
            .collect()
    }
}

impl SecurityRule for UncheckedCallRule {
    fn id(&self) -> String {
        "SC-UNCHECKED".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn visit(&self, ast: &UniversalAST) -> Vec<Finding> {
        ast.functions()
            .into_iter()
            .filter(|function| {
                let body = body_text(function);
                body.contains("contract-call?")
                    && !(body.contains("try!")
                        || body.contains("match")
                        || body.contains("unwrap!")
                        || body.contains("unwrap-err!"))
            })
            .map(|function| {
                finding(
                    self.id(),
                    self.severity(),
                    function.span,
                    format!(
                        "Function `{}` makes an external contract call without an explicit response handling path.",
                        function.name
                    ),
                )
            })
            .collect()
    }
}

impl SecurityRule for TraitRule {
    fn id(&self) -> String {
        "SC-TRAIT".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn visit(&self, ast: &UniversalAST) -> Vec<Finding> {
        if ast.source.contains("(impl-trait")
            && !ast.source.contains("(define-public")
            && !ast.source.contains("(define-read-only")
        {
            vec![finding(
                self.id(),
                self.severity(),
                Span::default(),
                "Contract declares a trait implementation but exposes no public or read-only functions to satisfy it."
                    .to_string(),
            )]
        } else {
            Vec::new()
        }
    }
}

impl SecurityRule for ReadOnlyRule {
    fn id(&self) -> String {
        "SC-READONLY".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn visit(&self, ast: &UniversalAST) -> Vec<Finding> {
        ast.functions()
            .into_iter()
            .filter(|function| matches!(function.visibility, Visibility::ReadOnly))
            .filter(|function| contains_state_write(&body_text(function)))
            .map(|function| {
                finding(
                    self.id(),
                    self.severity(),
                    function.span,
                    format!(
                        "Read-only function `{}` contains a state-changing operation.",
                        function.name
                    ),
                )
            })
            .collect()
    }
}

fn body_text(function: &Function) -> String {
    function
        .body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Expr(sentinel_core::Expr::Literal(text)) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn contains_state_write(body: &str) -> bool {
    ["map-set", "var-set", "stx-transfer?", "contract-call?"]
        .iter()
        .any(|needle| body.contains(needle))
}

fn first_index(body: &str, needles: &[&str]) -> Option<usize> {
    needles.iter().filter_map(|needle| body.find(needle)).min()
}

fn is_admin_like(name: &str) -> bool {
    ["set-", "mint", "burn", "pause", "upgrade", "rename"]
        .iter()
        .any(|needle| name.contains(needle))
}

fn finding(rule_id: String, severity: Severity, location: Span, message: String) -> Finding {
    Finding {
        rule_id,
        severity,
        location,
        message,
        code_snippet: None,
        related_locations: Vec::new(),
        metadata: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_clarity::ClarityAdapter;
    use sentinel_core::LanguageAdapter;

    fn findings(source: &str) -> Vec<Finding> {
        let ast = ClarityAdapter.parse(source).expect("source parses");
        crate::default_registry().visit_all(&ast)
    }

    #[test]
    fn detects_access_control() {
        let results = findings(
            "(define-public (set-owner (new principal)) (begin (var-set owner new) (ok true)))",
        );
        assert!(results.iter().any(|finding| finding.rule_id == "SC-ACCESS"));
    }

    #[test]
    fn detects_read_only_mutation() {
        let results = findings("(define-read-only (balance) (begin (var-set total u1) (ok u1)))");
        assert!(results
            .iter()
            .any(|finding| finding.rule_id == "SC-READONLY"));
    }

    #[test]
    fn detects_unchecked_call() {
        let results = findings(
            "(define-public (pay) (contract-call? .token transfer u1 tx-sender contract-caller))",
        );
        assert!(results
            .iter()
            .any(|finding| finding.rule_id == "SC-UNCHECKED"));
    }
}
