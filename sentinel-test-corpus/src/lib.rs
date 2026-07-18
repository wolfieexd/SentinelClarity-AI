pub const CORPUS_ROOT: &str = "contracts";

#[cfg(test)]
mod tests {
    use sentinel_clarity::ClarityAdapter;
    use sentinel_engine::{default_registry, Scanner};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use walkdir::WalkDir;

    #[test]
    fn corpus_crate_is_wired() {
        assert_eq!(super::CORPUS_ROOT, "contracts");
    }

    #[test]
    fn handcrafted_vulnerable_contracts_emit_all_rule_categories() {
        let scanner = Scanner::new(ClarityAdapter, default_registry());
        let mut rule_ids = BTreeSet::new();

        for path in vulnerable_contracts() {
            let source = fs::read_to_string(&path).expect("fixture is readable");
            let findings = scanner.scan_findings(&source).expect("fixture parses");
            rule_ids.extend(findings.into_iter().map(|finding| finding.rule_id));
        }

        for expected in [
            "SC-REENTRANCY",
            "SC-ACCESS",
            "SC-OVERFLOW",
            "SC-UNCHECKED",
            "SC-TRAIT",
            "SC-READONLY",
        ] {
            assert!(
                rule_ids.contains(expected),
                "missing finding for {expected}"
            );
        }
    }

    #[test]
    fn demo_dao_emits_story_findings() {
        let scanner = Scanner::new(ClarityAdapter, default_registry());
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(super::CORPUS_ROOT)
            .join("demo")
            .join("vulnerable-dao.clar");
        let source = fs::read_to_string(path).expect("demo fixture is readable");
        let findings = scanner.scan_findings(&source).expect("demo parses");
        let rule_ids = findings
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect::<BTreeSet<_>>();

        for expected in [
            "SC-ACCESS",
            "SC-OVERFLOW",
            "SC-REENTRANCY",
            "SC-UNCHECKED",
            "SC-READONLY",
        ] {
            assert!(
                rule_ids.contains(expected),
                "missing finding for {expected}"
            );
        }
    }

    #[test]
    fn regression_marketplace_escrow_emits_expected_findings() {
        let scanner = Scanner::new(ClarityAdapter, default_registry());
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(super::CORPUS_ROOT)
            .join("regression")
            .join("marketplace-escrow.clar");
        let source = fs::read_to_string(path).expect("regression fixture is readable");
        let findings = scanner
            .scan_findings(&source)
            .expect("regression fixture parses");
        let rule_ids = findings
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect::<BTreeSet<_>>();

        for expected in ["SC-ACCESS", "SC-OVERFLOW", "SC-REENTRANCY", "SC-READONLY"] {
            assert!(
                rule_ids.contains(expected),
                "missing finding for {expected}"
            );
        }
    }

    #[test]
    fn security_fixed_contracts_clear_targeted_findings() {
        let scanner = Scanner::new(ClarityAdapter, default_registry());

        for (fixture, cleared_rule) in [
            ("handcrafted/access/fixed.clar", "SC-ACCESS"),
            ("handcrafted/reentrancy/fixed.clar", "SC-REENTRANCY"),
            ("handcrafted/unchecked/fixed.clar", "SC-UNCHECKED"),
            ("handcrafted/readonly/fixed.clar", "SC-READONLY"),
            ("handcrafted/trait/fixed.clar", "SC-TRAIT"),
        ] {
            let rule_ids = scan_rule_ids(&scanner, fixture);
            assert!(
                !rule_ids.contains(cleared_rule),
                "{fixture} should clear {cleared_rule}, got {rule_ids:?}"
            );
        }
    }

    #[test]
    fn security_fixed_demo_reduces_critical_and_control_flow_risks() {
        let scanner = Scanner::new(ClarityAdapter, default_registry());
        let vulnerable = scan_rule_ids(&scanner, "demo/vulnerable-dao.clar");
        let fixed = scan_rule_ids(&scanner, "demo/fixed-dao.clar");

        for expected_vulnerable_rule in
            ["SC-ACCESS", "SC-REENTRANCY", "SC-UNCHECKED", "SC-READONLY"]
        {
            assert!(
                vulnerable.contains(expected_vulnerable_rule),
                "vulnerable demo should emit {expected_vulnerable_rule}"
            );
            assert!(
                !fixed.contains(expected_vulnerable_rule),
                "fixed demo should clear {expected_vulnerable_rule}, got {fixed:?}"
            );
        }

        assert!(
            fixed.contains("SC-OVERFLOW"),
            "fixed demo should retain conservative arithmetic review signal"
        );
    }

    #[test]
    fn security_expected_metadata_covers_demo_and_regression_corpus() {
        for expected_file in [
            "demo-dao.json",
            "marketplace-escrow.json",
            "handcrafted.json",
        ] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("expected")
                .join(expected_file);
            let content = fs::read_to_string(path).expect("expected metadata is readable");

            assert!(
                content.contains("expected_findings") || content.contains("\"contracts\""),
                "{expected_file} should describe expected security findings"
            );
        }
    }

    fn vulnerable_contracts() -> Vec<PathBuf> {
        let corpus_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(super::CORPUS_ROOT)
            .join("handcrafted");

        WalkDir::new(corpus_root)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .filter(|path| {
                path.file_name().and_then(|name| name.to_str()) == Some("vulnerable.clar")
            })
            .collect()
    }

    fn scan_rule_ids(scanner: &Scanner<ClarityAdapter>, fixture: &str) -> BTreeSet<String> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(super::CORPUS_ROOT)
            .join(fixture);
        let source = fs::read_to_string(path).expect("fixture is readable");
        scanner
            .scan_findings(&source)
            .expect("fixture parses")
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }
}
