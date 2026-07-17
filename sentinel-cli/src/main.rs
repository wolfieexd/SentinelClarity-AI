use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sentinel_clarity::ClarityAdapter;
use sentinel_engine::{RuleRegistry, Scanner};
use std::path::PathBuf;

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
        #[arg(long, value_enum, default_value_t = OutputFormat::Sarif)]
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
            let registry = RuleRegistry::new();
            let scanner = Scanner::new(ClarityAdapter, registry);
            let report = scanner.scan_source("(define-public (noop) (ok true))")?;
            let rendered = match format {
                OutputFormat::Sarif | OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Markdown => format!(
                    "# SentinelClarity Scan\n\nPath: `{}`\nConfig: `{}`\nFail on: `{}`\nFindings: 0\n",
                    path.display(),
                    config
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "sentinel.toml".to_string()),
                    fail_on
                ),
            };

            if let Some(output) = output {
                std::fs::write(output, rendered)?;
            } else {
                println!("{rendered}");
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
