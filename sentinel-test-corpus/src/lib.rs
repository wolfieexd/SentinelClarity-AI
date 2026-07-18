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
}
