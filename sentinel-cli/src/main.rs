use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use sentinel_ai::{ContextBuilder, HeuristicTriageClient, TriageEngine, TriagedFinding};
use sentinel_clarity::ClarityAdapter;
use sentinel_core::{Finding, SarifReport, Severity};
use sentinel_engine::{default_registry, Scanner};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Parser)]
#[command(name = "sentinel-clarity")]
#[command(about = "AI-native security scanner for Clarity smart contracts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value = "sarif")]
        format: OutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "HIGH")]
        fail_on: String,
        #[arg(long)]
        triage: bool,
    },
    Serve {
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    VerifyFix {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long)]
        clears: Vec<String>,
    },
    Init {
        #[arg(long)]
        validate: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    TestCorpus {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        rule: Option<String>,
    },
    Version,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Sarif,
    Markdown,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            format,
            output,
            config,
            fail_on,
            triage,
        } => {
            let scan_results = scan_path(&path)?;
            let findings = scan_results
                .iter()
                .flat_map(|result| result.findings.clone())
                .collect::<Vec<_>>();
            let report = SarifReport::from_findings(findings.clone());
            let rendered = match format {
                OutputFormat::Sarif | OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Markdown if triage => {
                    let triaged = triage_results(&scan_results)?;
                    render_triage_markdown(&path, config.as_deref(), &fail_on, &triaged)
                }
                OutputFormat::Markdown => {
                    render_markdown(&path, config.as_deref(), &fail_on, &findings)
                }
            };

            if let Some(output) = output {
                std::fs::write(output, rendered)?;
            } else {
                println!("{rendered}");
            }

            if has_blocking_findings(&findings, &fail_on) {
                std::process::exit(1);
            }
        }
        Command::Serve { port } => {
            serve(port)?;
        }
        Command::VerifyFix {
            before,
            after,
            clears,
        } => {
            let report = verify_fix(&before, &after, &clears)?;
            println!("{report}");
        }
        Command::Init { validate, config } => {
            if validate {
                let config_path = config.unwrap_or_else(|| PathBuf::from("sentinel.toml"));
                let config_text = std::fs::read_to_string(&config_path)
                    .with_context(|| format!("failed to read {}", config_path.display()))?;
                let warnings = validate_config(&config_text);

                if warnings.is_empty() {
                    println!("{} is valid.", config_path.display());
                } else {
                    for warning in warnings {
                        eprintln!("config warning: {warning}");
                    }
                    std::process::exit(2);
                }
            } else {
                println!("{}", include_str!("../../sentinel.toml"));
            }
        }
        Command::Completions { shell } => {
            let mut command = Cli::command();
            generate(
                shell,
                &mut command,
                "sentinel-clarity",
                &mut std::io::stdout(),
            );
        }
        Command::TestCorpus { all, rule } => {
            let report = test_corpus(all, rule.as_deref())?;
            println!("{report}");
        }
        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct FileScanResult {
    source: String,
    findings: Vec<Finding>,
}

fn scan_path(path: &Path) -> Result<Vec<FileScanResult>> {
    let scanner = Scanner::new(ClarityAdapter, default_registry());
    let mut results = Vec::new();

    for file in clarity_files(path)? {
        let source = std::fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let mut findings = scanner
            .scan_findings(&source)
            .with_context(|| format!("failed to parse {}", file.display()))?;
        let display_path = file.to_string_lossy().replace('\\', "/");

        for finding in &mut findings {
            finding
                .metadata
                .insert("source_path".to_string(), display_path.clone());
        }

        results.push(FileScanResult { source, findings });
    }

    Ok(results)
}

fn serve(port: u16) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("failed to bind HTTP API to 127.0.0.1:{port}"))?;
    println!("SentinelClarity HTTP API listening on http://127.0.0.1:{port}");
    println!("Endpoints: GET /health, GET /version, POST /scan");

    for stream in listener.incoming() {
        let stream = stream.context("failed to accept HTTP connection")?;
        handle_connection(stream)?;
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream) -> Result<()> {
    let mut buffer = [0; 65536];
    let bytes_read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let (method, path) = request_line_parts(&request);
    let request_body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();

    let (status, body) = match (method, path) {
        ("GET", "/health") => (
            "200 OK",
            r#"{"status":"ok","service":"sentinel-clarity"}"#.to_string(),
        ),
        ("GET", "/version") => (
            "200 OK",
            format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION")),
        ),
        ("POST", "/scan") => scan_http_body(request_body),
        _ => (
            "404 Not Found",
            r#"{"error":"not found","endpoints":["GET /health","GET /version","POST /scan"]}"#
                .to_string(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn request_line_parts(request: &str) -> (&str, &str) {
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/");
    (method, path)
}

fn scan_http_body(source: &str) -> (&'static str, String) {
    if source.trim().is_empty() {
        return (
            "400 Bad Request",
            r#"{"error":"POST /scan requires raw Clarity source in the request body"}"#.to_string(),
        );
    }

    let scanner = Scanner::new(ClarityAdapter, default_registry());
    match scanner.scan_findings(source) {
        Ok(findings) => {
            let report = SarifReport::from_findings(findings);
            (
                "200 OK",
                serde_json::to_string(&report)
                    .unwrap_or_else(|error| format!(r#"{{"error":"{error}"}}"#)),
            )
        }
        Err(error) => (
            "422 Unprocessable Entity",
            format!(r#"{{"error":"failed to parse source","detail":"{error}"}}"#),
        ),
    }
}

fn test_corpus(all: bool, rule: Option<&str>) -> Result<String> {
    if !all && rule.is_none() {
        return Ok("Select `--all` or `--rule <RULE_ID>` to run corpus expectations.".to_string());
    }

    let root = corpus_contract_root();
    let scanner = Scanner::new(ClarityAdapter, default_registry());
    let mut checked = 0usize;
    let mut failures = Vec::new();

    for (fixture, expected_rule) in handcrafted_expectations() {
        if rule.is_some_and(|selected| selected != expected_rule) {
            continue;
        }

        let source = std::fs::read_to_string(root.join(fixture))
            .with_context(|| format!("failed to read corpus fixture {fixture}"))?;
        let rule_ids = scanner
            .scan_findings(&source)
            .with_context(|| format!("failed to scan corpus fixture {fixture}"))?
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect::<BTreeSet<_>>();

        checked += 1;
        if !rule_ids.contains(expected_rule) {
            failures.push(format!(
                "{fixture} expected {expected_rule}, got {:?}",
                rule_ids
            ));
        }
    }

    let mut output = format!("# SentinelClarity Corpus Check\n\nFixtures checked: {checked}\n");
    if failures.is_empty() {
        output.push_str("Result: passed\n");
    } else {
        output.push_str("Result: failed\n\n");
        for failure in &failures {
            output.push_str(&format!("- {failure}\n"));
        }
    }

    if !failures.is_empty() {
        println!("{output}");
        std::process::exit(1);
    }

    Ok(output)
}

fn verify_fix(before: &Path, after: &Path, clears: &[String]) -> Result<String> {
    let before_results = scan_path(before)?;
    let after_results = scan_path(after)?;
    let before_rules = collect_rule_ids(&before_results);
    let after_rules = collect_rule_ids(&after_results);
    let rules_to_check = if clears.is_empty() {
        before_rules.iter().cloned().collect::<Vec<_>>()
    } else {
        clears.to_vec()
    };

    let mut failures = Vec::new();
    for rule in &rules_to_check {
        if !before_rules.contains(rule) {
            failures.push(format!("before scan did not contain `{rule}`"));
        }
        if after_rules.contains(rule) {
            failures.push(format!("after scan still contains `{rule}`"));
        }
    }

    let mut output = format!(
        "# SentinelClarity Fix Verification\n\nBefore: `{}`\nAfter: `{}`\nRules checked: {}\n\n",
        before.display(),
        after.display(),
        rules_to_check.len()
    );

    if failures.is_empty() {
        output.push_str("Result: passed\n");
    } else {
        output.push_str("Result: failed\n\n");
        for failure in &failures {
            output.push_str(&format!("- {failure}\n"));
        }
    }

    if !failures.is_empty() {
        println!("{output}");
        std::process::exit(1);
    }

    Ok(output)
}

fn collect_rule_ids(results: &[FileScanResult]) -> BTreeSet<String> {
    results
        .iter()
        .flat_map(|result| {
            result
                .findings
                .iter()
                .map(|finding| finding.rule_id.clone())
        })
        .collect()
}

fn handcrafted_expectations() -> [(&'static str, &'static str); 6] {
    [
        ("handcrafted/reentrancy/vulnerable.clar", "SC-REENTRANCY"),
        ("handcrafted/access/vulnerable.clar", "SC-ACCESS"),
        ("handcrafted/overflow/vulnerable.clar", "SC-OVERFLOW"),
        ("handcrafted/unchecked/vulnerable.clar", "SC-UNCHECKED"),
        ("handcrafted/trait/vulnerable.clar", "SC-TRAIT"),
        ("handcrafted/readonly/vulnerable.clar", "SC-READONLY"),
    ]
}

fn corpus_contract_root() -> PathBuf {
    let runtime_root = PathBuf::from("sentinel-test-corpus").join("contracts");
    if runtime_root.exists() {
        return runtime_root;
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("sentinel-test-corpus")
        .join("contracts")
}

fn clarity_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(
            if path.extension().and_then(|ext| ext.to_str()) == Some("clar") {
                vec![path.to_path_buf()]
            } else {
                Vec::new()
            },
        );
    }

    let files = WalkDir::new(path)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("clar"))
        .collect();

    Ok(files)
}

fn render_markdown(
    path: &Path,
    config: Option<&Path>,
    fail_on: &str,
    findings: &[Finding],
) -> String {
    let mut output = format!(
        "# SentinelClarity Scan\n\nPath: `{}`\nConfig: `{}`\nFail on: `{}`\nFindings: {}\n\n",
        path.display(),
        config
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "sentinel.toml".to_string()),
        fail_on,
        findings.len()
    );

    if findings.is_empty() {
        output.push_str("No findings detected.\n");
        return output;
    }

    output.push_str("| Rule | Severity | Location | Message |\n");
    output.push_str("| --- | --- | --- | --- |\n");

    for finding in findings {
        output.push_str(&format!(
            "| `{}` | {:?} | {}:{} | {} |\n",
            finding.rule_id,
            finding.severity,
            finding.location.start_line,
            finding.location.start_col,
            finding.message.replace('|', "\\|")
        ));
    }

    output
}

fn triage_results(scan_results: &[FileScanResult]) -> Result<Vec<TriagedFinding>> {
    let engine = TriageEngine::new(
        HeuristicTriageClient,
        ContextBuilder::new(default_rule_docs()),
    );
    let mut triaged = Vec::new();

    for result in scan_results {
        triaged.extend(engine.run(result.findings.clone(), &result.source)?);
    }

    Ok(triaged)
}

fn render_triage_markdown(
    path: &Path,
    config: Option<&Path>,
    fail_on: &str,
    findings: &[TriagedFinding],
) -> String {
    let mut output = format!(
        "# SentinelClarity AI Triage\n\nPath: `{}`\nConfig: `{}`\nFail on: `{}`\nFindings: {}\n\n",
        path.display(),
        config
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "sentinel.toml".to_string()),
        fail_on,
        findings.len()
    );

    if findings.is_empty() {
        output.push_str("No findings detected.\n");
        return output;
    }

    output.push_str("| Rule | Exploitability | Blast Radius | Strategy | Confidence |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");

    for triaged in findings {
        output.push_str(&format!(
            "| `{}` | {:?} | {:?} | {:?} | {:.0}% |\n",
            triaged.finding.rule_id,
            triaged.triage.exploitability,
            triaged.triage.blast_radius,
            triaged.triage.fix_strategy,
            triaged.triage.fix_confidence * 100.0
        ));
    }

    output.push_str("\n## Fix Packages\n\n");

    for triaged in findings.iter().filter(|triaged| triaged.fix.is_some()) {
        let fix = triaged.fix.as_ref().expect("filtered to Some");
        output.push_str(&format!(
            "### `{}`\n\n{}\n\n- Patch plan: {}\n- Test plan: {}\n\n",
            triaged.finding.rule_id, fix.explanation, fix.patch, fix.test_patch
        ));
    }

    output
}

fn default_rule_docs() -> BTreeMap<String, String> {
    [
        (
            "SC-REENTRANCY",
            include_str!("../../docs/rules/SC-REENTRANCY.md"),
        ),
        ("SC-ACCESS", include_str!("../../docs/rules/SC-ACCESS.md")),
        (
            "SC-OVERFLOW",
            include_str!("../../docs/rules/SC-OVERFLOW.md"),
        ),
        (
            "SC-UNCHECKED",
            include_str!("../../docs/rules/SC-UNCHECKED.md"),
        ),
        ("SC-TRAIT", include_str!("../../docs/rules/SC-TRAIT.md")),
        (
            "SC-READONLY",
            include_str!("../../docs/rules/SC-READONLY.md"),
        ),
    ]
    .into_iter()
    .map(|(rule_id, doc)| (rule_id.to_string(), doc.to_string()))
    .collect()
}

fn has_blocking_findings(findings: &[Finding], fail_on: &str) -> bool {
    let threshold = parse_severity(fail_on);
    findings.iter().any(|finding| finding.severity >= threshold)
}

fn parse_severity(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::High,
    }
}

fn validate_config(config_text: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    for section in ["[rules]", "[ai]", "[output]"] {
        if !config_text.contains(section) {
            warnings.push(format!("missing required section `{section}`"));
        }
    }

    for rule_id in [
        "SC-REENTRANCY",
        "SC-ACCESS",
        "SC-OVERFLOW",
        "SC-UNCHECKED",
        "SC-TRAIT",
        "SC-READONLY",
    ] {
        if !config_text.contains(rule_id) {
            warnings.push(format!("missing rule configuration for `{rule_id}`"));
        }
    }

    if !config_text.contains("model =") {
        warnings.push("missing `[ai] model` setting".to_string());
    }

    if !config_text.contains("formats =") {
        warnings.push("missing `[output] formats` setting".to_string());
    }

    for line in config_text
        .lines()
        .filter(|line| line.contains("severity ="))
    {
        let normalized = line.to_ascii_lowercase();
        if !["critical", "high", "medium", "low"]
            .iter()
            .any(|severity| normalized.contains(severity))
        {
            warnings.push(format!("unknown severity in `{}`", line.trim()));
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let warnings = validate_config(include_str!("../../sentinel.toml"));
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn missing_sections_are_reported() {
        let warnings = validate_config("[rules]\n");
        assert!(warnings.iter().any(|warning| warning.contains("[ai]")));
        assert!(warnings.iter().any(|warning| warning.contains("[output]")));
    }

    #[test]
    fn corpus_expectations_cover_all_rules() {
        let rules = handcrafted_expectations()
            .into_iter()
            .map(|(_, rule)| rule)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            rules,
            BTreeSet::from([
                "SC-ACCESS",
                "SC-OVERFLOW",
                "SC-READONLY",
                "SC-REENTRANCY",
                "SC-TRAIT",
                "SC-UNCHECKED",
            ])
        );
    }

    #[test]
    fn request_line_parts_extract_method_and_path() {
        let (method, path) = request_line_parts("POST /scan HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(method, "POST");
        assert_eq!(path, "/scan");
    }

    #[test]
    fn scan_http_body_returns_sarif_json() {
        let (status, body) = scan_http_body(
            "(define-public (pay) (contract-call? .token transfer u1 tx-sender contract-caller))",
        );

        assert_eq!(status, "200 OK");
        assert!(body.contains("SC-UNCHECKED"));
    }

    #[test]
    fn scan_http_body_rejects_empty_body() {
        let (status, body) = scan_http_body("");

        assert_eq!(status, "400 Bad Request");
        assert!(body.contains("requires raw Clarity source"));
    }
}
