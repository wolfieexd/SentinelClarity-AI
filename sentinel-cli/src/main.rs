use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use sentinel_ai::{ContextBuilder, HeuristicTriageClient, TriageEngine, TriagedFinding};
use sentinel_clarity::ClarityAdapter;
use sentinel_core::{Finding, SarifReport, Severity};
use sentinel_engine::{default_registry, Scanner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;
use walkdir::WalkDir;

const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SCAN_FILES: usize = 10_000;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(5);

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
        #[arg(long, help = "Write a cryptographically hashed audit evidence bundle")]
        evidence: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum)]
        fail_on: Option<FailSeverity>,
        #[arg(long)]
        triage: bool,
        #[arg(
            long,
            help = "Validate each contract with the installed Clarinet toolchain"
        )]
        clarinet: bool,
        #[arg(
            long,
            requires = "clarinet",
            help = "Clarinet.toml manifest for compiler-backed project validation"
        )]
        clarinet_manifest: Option<PathBuf>,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl FailSeverity {
    fn as_severity(self) -> Severity {
        match self {
            Self::Critical => Severity::Critical,
            Self::High => Severity::High,
            Self::Medium => Severity::Medium,
            Self::Low => Severity::Low,
        }
    }
}

#[derive(Debug)]
struct ScanPolicy {
    rules: BTreeMap<String, RulePolicy>,
    fail_on: Severity,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            rules: BTreeMap::new(),
            fail_on: Severity::High,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RulePolicy {
    enabled: bool,
    severity: Severity,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    rules: BTreeMap<String, ConfigRule>,
    output: ConfigOutput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigRule {
    enabled: bool,
    severity: String,
}

#[derive(Debug, Deserialize)]
struct ConfigOutput {
    fail_on_severity: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            format,
            output,
            evidence,
            config,
            fail_on,
            triage,
            clarinet,
            clarinet_manifest,
        } => {
            let policy = load_scan_policy(config.as_deref())?;
            let fail_on = fail_on
                .map(FailSeverity::as_severity)
                .unwrap_or(policy.fail_on);
            if let Some(manifest) = clarinet_manifest.as_deref() {
                clarinet_manifest_check(manifest)?;
            }
            let scan_results = scan_path(&path, &policy, clarinet)?;
            let findings = scan_results
                .iter()
                .flat_map(|result| result.findings.clone())
                .collect::<Vec<_>>();
            let report = SarifReport::from_findings(findings.clone());
            let rendered = match format {
                OutputFormat::Sarif | OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Markdown if triage => {
                    let triaged = triage_results(&scan_results)?;
                    render_triage_markdown(
                        &path,
                        config.as_deref(),
                        severity_label(fail_on),
                        &triaged,
                    )
                }
                OutputFormat::Markdown => {
                    render_markdown(&path, config.as_deref(), severity_label(fail_on), &findings)
                }
            };

            if let Some(evidence_path) = evidence {
                write_audit_evidence(
                    &evidence_path,
                    &path,
                    config.as_deref(),
                    fail_on,
                    clarinet,
                    &scan_results,
                    &findings,
                )?;
            }

            if let Some(output) = output {
                std::fs::write(output, rendered)?;
            } else {
                println!("{rendered}");
            }

            if has_blocking_findings(&findings, fail_on) {
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
    path: PathBuf,
    source: String,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct AuditEvidence {
    schema_version: String,
    scanner_version: String,
    source_root: String,
    config_sha256: Option<String>,
    clarinet_version: Option<String>,
    fail_on: String,
    passed: bool,
    contracts: Vec<AuditedContract>,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct AuditedContract {
    path: String,
    sha256: String,
    findings: usize,
}

const KNOWN_RULE_IDS: [&str; 7] = [
    "SC-REENTRANCY",
    "SC-ACCESS",
    "SC-OVERFLOW",
    "SC-UNCHECKED",
    "SC-TRAIT",
    "SC-READONLY",
    "SC-TX-SENDER",
];

fn load_scan_policy(config_path: Option<&Path>) -> Result<ScanPolicy> {
    let Some(config_path) = config_path else {
        return Ok(ScanPolicy::default());
    };
    let config_text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let warnings = validate_config(&config_text);
    if !warnings.is_empty() {
        anyhow::bail!(
            "invalid configuration in {}: {}",
            config_path.display(),
            warnings.join("; ")
        );
    }
    let config: ConfigFile = toml::from_str(&config_text)
        .with_context(|| format!("failed to parse {} as TOML", config_path.display()))?;
    let mut policy = ScanPolicy {
        fail_on: parse_config_severity(&config.output.fail_on_severity)
            .context("invalid `[output] fail_on_severity`")?,
        ..ScanPolicy::default()
    };

    for (rule_id, rule_config) in config.rules {
        if !KNOWN_RULE_IDS.contains(&rule_id.as_str()) {
            anyhow::bail!("unknown rule `{rule_id}` in {}", config_path.display());
        }
        let severity = parse_config_severity(&rule_config.severity)
            .with_context(|| format!("invalid severity for `{rule_id}`"))?;
        policy.rules.insert(
            rule_id,
            RulePolicy {
                enabled: rule_config.enabled,
                severity,
            },
        );
    }

    Ok(policy)
}

fn parse_config_severity(value: &str) -> Result<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        _ => anyhow::bail!("expected critical, high, medium, or low"),
    }
}

fn scanner_with_policy(policy: &ScanPolicy) -> Scanner<ClarityAdapter> {
    let mut registry = default_registry();
    for (rule_id, rule_policy) in &policy.rules {
        registry.set_rule_enabled(rule_id, rule_policy.enabled);
        registry.set_rule_severity(rule_id, rule_policy.severity);
    }
    Scanner::new(ClarityAdapter, registry)
}

fn scan_path(path: &Path, policy: &ScanPolicy, use_clarinet: bool) -> Result<Vec<FileScanResult>> {
    let scanner = scanner_with_policy(policy);
    let mut results = Vec::new();

    for file in clarity_files(path)? {
        let metadata = std::fs::metadata(&file)
            .with_context(|| format!("failed to inspect {}", file.display()))?;
        if metadata.len() > MAX_SCAN_FILE_BYTES {
            anyhow::bail!(
                "refusing to scan {}: file is {} bytes, exceeding the {} byte limit",
                file.display(),
                metadata.len(),
                MAX_SCAN_FILE_BYTES
            );
        }
        if use_clarinet {
            clarinet_check(&file)?;
        }
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

        results.push(FileScanResult {
            path: file,
            source,
            findings,
        });
    }

    Ok(results)
}

fn clarinet_check(file: &Path) -> Result<()> {
    let output = ProcessCommand::new("clarinet")
        .arg("check")
        .arg(file)
        .output()
        .context("failed to launch Clarinet; install it or omit `--clarinet`")?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let diagnostics = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    let detail = if diagnostics.is_empty() {
        "Clarinet returned a non-zero status without diagnostics".to_string()
    } else {
        diagnostics.chars().take(4_096).collect()
    };
    anyhow::bail!("Clarinet rejected {}: {detail}", file.display());
}

fn clarinet_manifest_check(manifest: &Path) -> Result<()> {
    let output = ProcessCommand::new("clarinet")
        .arg("check")
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .context("failed to launch Clarinet; install it or omit `--clarinet`")?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let diagnostics = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    let detail = if diagnostics.is_empty() {
        "Clarinet returned a non-zero status without diagnostics".to_string()
    } else {
        diagnostics.chars().take(4_096).collect()
    };
    anyhow::bail!(
        "Clarinet manifest validation failed for {}: {detail}",
        manifest.display()
    );
}

fn write_audit_evidence(
    output: &Path,
    source_root: &Path,
    config_path: Option<&Path>,
    fail_on: Severity,
    clarinet_checked: bool,
    scan_results: &[FileScanResult],
    findings: &[Finding],
) -> Result<()> {
    let config_sha256 = config_path
        .map(hash_file)
        .transpose()?
        .map(|hash| hash.to_string());
    let clarinet_version = if clarinet_checked {
        Some(clarinet_version()?)
    } else {
        None
    };
    let contracts = scan_results
        .iter()
        .map(|result| AuditedContract {
            path: result.path.to_string_lossy().replace('\\', "/"),
            sha256: sha256_hex(result.source.as_bytes()),
            findings: result.findings.len(),
        })
        .collect();
    let evidence = AuditEvidence {
        schema_version: "1.0".to_string(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        source_root: source_root.to_string_lossy().replace('\\', "/"),
        config_sha256,
        clarinet_version,
        fail_on: severity_label(fail_on).to_string(),
        passed: !has_blocking_findings(findings, fail_on),
        contracts,
        findings: findings.to_vec(),
    };
    let serialized = serde_json::to_string_pretty(&evidence)?;
    std::fs::write(output, serialized)
        .with_context(|| format!("failed to write audit evidence to {}", output.display()))?;
    Ok(())
}

fn clarinet_version() -> Result<String> {
    let output = ProcessCommand::new("clarinet")
        .arg("--version")
        .output()
        .context("failed to query Clarinet version")?;
    if !output.status.success() {
        anyhow::bail!("Clarinet version command failed")
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read {} for hashing", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
    stream.set_read_timeout(Some(HTTP_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(HTTP_READ_TIMEOUT))?;

    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(_) => {
            write_http_response(
                &mut stream,
                "400 Bad Request",
                &json_error("invalid HTTP request"),
                None,
            )?;
            return Ok(());
        }
    };

    let (status, body, extra_headers) = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/health") => (
            "200 OK",
            r#"{"status":"ok","service":"sentinel-clarity"}"#.to_string(),
            None,
        ),
        ("GET", "/version") => (
            "200 OK",
            format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION")),
            None,
        ),
        ("POST", "/scan") => {
            let (status, body) = scan_http_body(&request.body);
            (status, body, None)
        }
        ("GET", "/scan") | ("POST", "/health") | ("POST", "/version") => (
            "405 Method Not Allowed",
            json_error("method not allowed"),
            Some("Allow: GET, POST\r\n"),
        ),
        _ => (
            "404 Not Found",
            r#"{"error":"not found","endpoints":["GET /health","GET /version","POST /scan"]}"#
                .to_string(),
            None,
        ),
    };

    write_http_response(&mut stream, status, &body, extra_headers)
}

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => anyhow::bail!("connection closed before request headers were complete"),
            Ok(bytes_read) => {
                request.extend_from_slice(&chunk[..bytes_read]);
                if request.len() > MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES {
                    anyhow::bail!("request exceeds the {} byte limit", MAX_HTTP_BODY_BYTES);
                }
                if let Some(header_end) = find_header_end(&request) {
                    break header_end;
                }
                if request.len() > MAX_HTTP_HEADER_BYTES {
                    anyhow::bail!(
                        "request headers exceed the {} byte limit",
                        MAX_HTTP_HEADER_BYTES
                    );
                }
            }
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut =>
            {
                anyhow::bail!("request timed out")
            }
            Err(error) => return Err(error.into()),
        }
    };

    let header_text = std::str::from_utf8(&request[..header_end])
        .context("request headers must be valid UTF-8")?;
    let (method, path, content_length) = parse_http_headers(header_text)?;
    if content_length > MAX_HTTP_BODY_BYTES {
        anyhow::bail!(
            "request body exceeds the {} byte limit",
            MAX_HTTP_BODY_BYTES
        );
    }

    let expected_length = header_end + content_length;
    if request.len() > expected_length {
        anyhow::bail!("request contains data beyond its declared Content-Length")
    }
    while request.len() < expected_length {
        let bytes_read = match stream.read(&mut chunk) {
            Ok(0) => anyhow::bail!("connection closed before request body was complete"),
            Ok(bytes_read) => bytes_read,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut =>
            {
                anyhow::bail!("request timed out")
            }
            Err(error) => return Err(error.into()),
        };
        request.extend_from_slice(&chunk[..bytes_read]);
        if request.len() > expected_length {
            anyhow::bail!("request contains data beyond its declared Content-Length")
        }
    }

    Ok(HttpRequest {
        method,
        path,
        body: request[header_end..].to_vec(),
    })
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_http_headers(headers: &str) -> Result<(String, String, usize)> {
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().context("missing HTTP method")?;
    let path = request_parts.next().context("missing request path")?;
    let version = request_parts.next().context("missing HTTP version")?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        anyhow::bail!("malformed HTTP request line")
    }
    if !matches!(method, "GET" | "POST") || !path.starts_with('/') || path.contains('?') {
        anyhow::bail!("unsupported HTTP method or path")
    }

    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').context("malformed HTTP header")?;
        if name.eq_ignore_ascii_case("transfer-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            anyhow::bail!("Transfer-Encoding is not supported")
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                anyhow::bail!("multiple Content-Length headers are not allowed")
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("invalid Content-Length header")?,
            );
        }
    }

    Ok((
        method.to_string(),
        path.to_string(),
        content_length.unwrap_or(0),
    ))
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
    extra_headers: Option<&str>,
) -> Result<()> {
    let extra_headers = extra_headers.unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn json_error(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

fn scan_http_body(body: &[u8]) -> (&'static str, String) {
    let source = match std::str::from_utf8(body) {
        Ok(source) => source,
        Err(_) => {
            return (
                "400 Bad Request",
                json_error("request body must be UTF-8 Clarity source"),
            )
        }
    };
    if source.trim().is_empty() {
        return (
            "400 Bad Request",
            json_error("POST /scan requires raw Clarity source in the request body"),
        );
    }

    let scanner = scanner_with_policy(&ScanPolicy::default());
    match scanner.scan_findings(source) {
        Ok(findings) => {
            let report = SarifReport::from_findings(findings);
            (
                "200 OK",
                serde_json::to_string(&report)
                    .unwrap_or_else(|_| json_error("failed to serialize scan result")),
            )
        }
        Err(_) => (
            "422 Unprocessable Entity",
            json_error("failed to parse source"),
        ),
    }
}

fn test_corpus(all: bool, rule: Option<&str>) -> Result<String> {
    if !all && rule.is_none() {
        return Ok("Select `--all` or `--rule <RULE_ID>` to run corpus expectations.".to_string());
    }

    let root = corpus_contract_root();
    let scanner = scanner_with_policy(&ScanPolicy::default());
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
    let policy = ScanPolicy::default();
    let before_results = scan_path(before, &policy, false)?;
    let after_results = scan_path(after, &policy, false)?;
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

fn handcrafted_expectations() -> [(&'static str, &'static str); 7] {
    [
        ("handcrafted/reentrancy/vulnerable.clar", "SC-REENTRANCY"),
        ("handcrafted/access/vulnerable.clar", "SC-ACCESS"),
        ("handcrafted/overflow/vulnerable.clar", "SC-OVERFLOW"),
        ("handcrafted/unchecked/vulnerable.clar", "SC-UNCHECKED"),
        ("handcrafted/trait/vulnerable.clar", "SC-TRAIT"),
        ("handcrafted/readonly/vulnerable.clar", "SC-READONLY"),
        ("handcrafted/tx-sender/vulnerable.clar", "SC-TX-SENDER"),
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

    let mut files = WalkDir::new(path)
        .into_iter()
        .map(|entry| entry.context("failed while walking scan path"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("clar"))
        .collect::<Vec<_>>();
    files.sort();
    if files.len() > MAX_SCAN_FILES {
        anyhow::bail!(
            "refusing to scan {} files: limit is {MAX_SCAN_FILES}",
            files.len()
        );
    }

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
        (
            "SC-TX-SENDER",
            include_str!("../../docs/rules/SC-TX-SENDER.md"),
        ),
    ]
    .into_iter()
    .map(|(rule_id, doc)| (rule_id.to_string(), doc.to_string()))
    .collect()
}

fn has_blocking_findings(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|finding| finding.severity >= threshold)
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn validate_config(config_text: &str) -> Vec<String> {
    let parsed = match config_text.parse::<toml::Value>() {
        Ok(value) => value,
        Err(error) => return vec![format!("invalid TOML: {error}")],
    };
    let Some(root) = parsed.as_table() else {
        return vec!["configuration must be a TOML table".to_string()];
    };
    let mut warnings = Vec::new();

    for section in ["rules", "ai", "output"] {
        if !root.contains_key(section) {
            warnings.push(format!("missing required section `[{section}]`"));
        }
    }

    for key in root.keys() {
        if !matches!(key.as_str(), "rules" | "ai" | "output") {
            warnings.push(format!("unknown top-level section `[{key}]`"));
        }
    }

    if let Some(rules) = root.get("rules").and_then(toml::Value::as_table) {
        for rule_id in KNOWN_RULE_IDS {
            let Some(rule) = rules.get(rule_id).and_then(toml::Value::as_table) else {
                warnings.push(format!("missing rule configuration for `{rule_id}`"));
                continue;
            };
            if !rule.get("enabled").is_some_and(toml::Value::is_bool) {
                warnings.push(format!("`{rule_id}` requires boolean `enabled`"));
            }
            match rule.get("severity").and_then(toml::Value::as_str) {
                Some(value) if parse_config_severity(value).is_ok() => {}
                _ => warnings.push(format!("`{rule_id}` requires a valid `severity`")),
            }
            for key in rule.keys() {
                if !matches!(key.as_str(), "enabled" | "severity") {
                    warnings.push(format!("unknown `{rule_id}` setting `{key}`"));
                }
            }
        }
        for rule_id in rules.keys() {
            if !KNOWN_RULE_IDS.contains(&rule_id.as_str()) {
                warnings.push(format!("unknown rule `{rule_id}`"));
            }
        }
    } else if root.contains_key("rules") {
        warnings.push("`[rules]` must be a table".to_string());
    }

    validate_config_section(
        root,
        "ai",
        &[
            "model",
            "triage_enabled",
            "fix_enabled",
            "context_lines",
            "max_context_tokens",
        ],
        &mut warnings,
    );
    validate_config_section(
        root,
        "output",
        &["formats", "annotate_pr", "fail_on_severity"],
        &mut warnings,
    );

    if !root
        .get("ai")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("model"))
        .is_some_and(toml::Value::is_str)
    {
        warnings.push("`[ai] model` must be a string".to_string());
    }
    if let Some(output) = root.get("output").and_then(toml::Value::as_table) {
        if !output.get("formats").is_some_and(toml::Value::is_array) {
            warnings.push("`[output] formats` must be an array".to_string());
        }
        match output.get("fail_on_severity").and_then(toml::Value::as_str) {
            Some(value) if parse_config_severity(value).is_ok() => {}
            _ => warnings.push("`[output] fail_on_severity` must be valid".to_string()),
        }
    }

    warnings
}

fn validate_config_section(
    root: &toml::map::Map<String, toml::Value>,
    name: &str,
    required_keys: &[&str],
    warnings: &mut Vec<String>,
) {
    let Some(section) = root.get(name).and_then(toml::Value::as_table) else {
        return;
    };
    for key in required_keys {
        if !section.contains_key(*key) {
            warnings.push(format!("missing `[{name}] {key}` setting"));
        }
    }
    for key in section.keys() {
        if !required_keys.contains(&key.as_str()) {
            warnings.push(format!("unknown `[{name}]` setting `{key}`"));
        }
    }
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
    fn config_validation_rejects_unknown_rules_and_invalid_types() {
        let config = r#"
            [rules]
            SC-REENTRANCY = { enabled = "yes", severity = "urgent" }
            SC-ACCESS = { enabled = true, severity = "high" }
            SC-OVERFLOW = { enabled = true, severity = "high" }
            SC-UNCHECKED = { enabled = true, severity = "medium" }
            SC-TRAIT = { enabled = true, severity = "medium" }
            SC-READONLY = { enabled = true, severity = "high" }
            SC-TYPO = { enabled = true, severity = "high" }

            [ai]
            model = "test"
            triage_enabled = true
            fix_enabled = false
            context_lines = 1
            max_context_tokens = 1

            [output]
            formats = ["sarif"]
            annotate_pr = false
            fail_on_severity = "high"
        "#;
        let warnings = validate_config(config);

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("SC-REENTRANCY")));
        assert!(warnings.iter().any(|warning| warning.contains("SC-TYPO")));
    }

    #[test]
    fn scan_policy_applies_rule_and_exit_threshold_settings() {
        let config_path = std::env::temp_dir().join(format!(
            "sentinel-clarity-policy-{}.toml",
            std::process::id()
        ));
        std::fs::write(&config_path, include_str!("../../sentinel.toml"))
            .expect("temporary config is written");
        let policy = load_scan_policy(Some(&config_path)).expect("policy loads");
        std::fs::remove_file(&config_path).expect("temporary config is removed");

        assert_eq!(policy.fail_on, Severity::High);
        assert_eq!(
            policy.rules.get("SC-REENTRANCY").map(|rule| rule.severity),
            Some(Severity::Critical)
        );
        assert!(policy
            .rules
            .get("SC-READONLY")
            .is_some_and(|rule| rule.enabled));
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
                "SC-TX-SENDER",
                "SC-REENTRANCY",
                "SC-TRAIT",
                "SC-UNCHECKED",
            ])
        );
    }

    #[test]
    fn parses_safe_http_headers() {
        let (method, path, content_length) = parse_http_headers(
            "POST /scan HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n",
        )
        .expect("request should parse");
        assert_eq!(method, "POST");
        assert_eq!(path, "/scan");
        assert_eq!(content_length, 4);
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_http_headers() {
        assert!(parse_http_headers(
            "POST /scan HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"
        )
        .is_err());
        assert!(
            parse_http_headers("POST /scan HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
                .is_err()
        );
        assert!(parse_http_headers("POST /scan?mode=fast HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn scan_http_body_returns_sarif_json() {
        let (status, body) = scan_http_body(
            b"(define-public (pay) (contract-call? .token transfer u1 tx-sender contract-caller))",
        );

        assert_eq!(status, "200 OK");
        assert!(body.contains("SC-UNCHECKED"));
    }

    #[test]
    fn scan_http_body_rejects_empty_body() {
        let (status, body) = scan_http_body(b"");

        assert_eq!(status, "400 Bad Request");
        assert!(body.contains("requires raw Clarity source"));
    }

    #[test]
    fn scan_http_body_rejects_non_utf8_source() {
        let (status, body) = scan_http_body(&[0xff]);

        assert_eq!(status, "400 Bad Request");
        assert!(body.contains("UTF-8"));
    }

    #[test]
    fn sha256_evidence_hash_is_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
