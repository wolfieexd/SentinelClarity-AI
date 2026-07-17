use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sentinel_clarity::ClarityAdapter;
use sentinel_core::{Finding, SarifReport, Severity};
use sentinel_engine::{default_registry, Scanner};
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
    },
    Serve {
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    Init,
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
        } => {
            let findings = scan_path(&path)?;
            let report = SarifReport::from_findings(findings.clone());
            let rendered = match format {
                OutputFormat::Sarif | OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Markdown => render_markdown(
                    &path,
                    config.as_ref().map(PathBuf::as_path),
                    &fail_on,
                    &findings,
                ),
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
            println!("SentinelClarity HTTP API scaffold listening target: {port}");
        }
        Command::Init => {
            println!("{}", include_str!("../../sentinel.toml"));
        }
        Command::TestCorpus { all, rule } => {
            println!("Test corpus scaffold selected: all={all}, rule={rule:?}");
        }
        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

fn scan_path(path: &Path) -> Result<Vec<Finding>> {
    let scanner = Scanner::new(ClarityAdapter, default_registry());
    let mut findings = Vec::new();

    for file in clarity_files(path)? {
        let source = std::fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        findings.extend(
            scanner
                .scan_findings(&source)
                .with_context(|| format!("failed to parse {}", file.display()))?,
        );
    }

    Ok(findings)
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
