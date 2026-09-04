mod baseline;
mod config;
mod engine;
mod serve;
mod state;
mod watch;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

/// Keys accepted in the piped-stdin JSON object: CLI overrides (interval /
/// host / port / token) and config overrides (watch / process / ports / alert).
const KNOWN_STDIN_KEYS: &[&str] = &[
    "watch", "process", "ports", "alert", "interval", "host", "port", "token",
];

#[derive(Parser)]
#[command(
    name = "adonword",
    version,
    about = "Active-defense sentinel for AI agents around the BIT ecosystem",
    long_about = "ADONWORD gives AI agents (especially BIT) local security posture awareness: \
file-integrity baselines, suspicious process monitoring and listening-port alerts. \
Observation + alerting only — it never kills processes."
)]
struct Cli {
    /// Path to the TOML config file (default: <data_dir>/adonword.toml)
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Emit machine-readable JSON on stdout
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build or rebuild the file-integrity baseline
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Run one full inspection: file integrity + processes + listening ports
    Scan,
    /// Daemon mode: scan on an interval, alert on stderr + webhook
    Watch {
        /// Seconds between scan rounds
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        interval: u64,
    },
    /// Print the most recent scan result (from state.json)
    Report,
    /// Run the HTTP API (BIT Remote tool compatible), default port 8754
    Serve {
        /// Bind host
        #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
        host: String,
        /// Bind port
        #[arg(long, value_name = "PORT", default_value_t = 8754)]
        port: u16,
        /// Require 'Authorization: Bearer <token>' on /report and /invoke
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Recompute the sha256 baseline for [watch].paths (relative path -> hash -> mtime)
    Update,
    /// Compare current files against the baseline.
    /// Exit codes: 0 = no change, 1 = changes found, 2 = baseline missing
    Check,
}

fn main() {
    let mut cli = Cli::parse();
    let stdin_overrides = read_stdin_overrides();
    if let Some(value) = &stdin_overrides {
        apply_cli_overrides(&mut cli, value);
    }
    match run(cli, stdin_overrides) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli, stdin_overrides: Option<Value>) -> Result<i32> {
    let (cfg, data_dir) = config::load_effective(cli.config.as_deref(), stdin_overrides.as_ref())?;
    match cli.command {
        Command::Baseline { action } => match action {
            BaselineAction::Update => {
                let (baseline, warnings) = baseline::update(&cfg, &data_dir)?;
                for warning in &warnings {
                    eprintln!("warning: {warning}");
                }
                let path = baseline::baseline_path(&data_dir);
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "status": "updated",
                            "files": baseline.entries.len(),
                            "path": path.display().to_string(),
                            "generated_at": baseline.generated_at,
                        }))?
                    );
                } else {
                    println!(
                        "baseline updated: {} files -> {}",
                        baseline.entries.len(),
                        path.display()
                    );
                }
                Ok(0)
            }
            BaselineAction::Check => {
                let baseline = baseline::load(&data_dir)?;
                let Some(baseline) = baseline else {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "status": "missing",
                                "added": [],
                                "removed": [],
                                "modified": [],
                            }))?
                        );
                    } else {
                        eprintln!("error: no baseline found; run `adonword baseline update` first");
                    }
                    return Ok(2);
                };
                let report = baseline::check(&cfg, &baseline);
                for warning in &report.warnings {
                    eprintln!("warning: {warning}");
                }
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("status: {}", report.status);
                    for path in &report.added {
                        println!("added: {path}");
                    }
                    for path in &report.removed {
                        println!("removed: {path}");
                    }
                    for path in &report.modified {
                        println!("modified: {path}");
                    }
                }
                Ok(if report.status == "clean" { 0 } else { 1 })
            }
        },
        Command::Scan => {
            let result = watch::scan_once(&cfg, &data_dir)?;
            print_scan(&result, cli.json);
            Ok(0)
        }
        Command::Watch { interval } => {
            watch::run(cfg, &data_dir, interval, cli.json)?;
            Ok(0)
        }
        Command::Report => {
            let stored = state::load_scan(&data_dir)?;
            match stored {
                Some(result) => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "status": "ok",
                                "report": result,
                            }))?
                        );
                    } else {
                        print_scan(&result, false);
                    }
                }
                None => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "status": "no_report",
                                "report": Value::Null,
                            }))?
                        );
                    } else {
                        println!("no scan report available; run `adonword scan` first");
                    }
                }
            }
            Ok(0)
        }
        Command::Serve { host, port, token } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to build tokio runtime")?;
            runtime.block_on(serve::run(cfg, data_dir, host, port, token))?;
            Ok(0)
        }
    }
}

fn print_scan(result: &engine::ScanResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    } else {
        println!("scan at {}:", result.scanned_at);
        for finding in &result.findings {
            println!("[{}] {} {}", finding.severity, finding.kind, finding.detail);
        }
        println!(
            "{} findings ({} crit, {} warn)",
            result.summary.total, result.summary.crit, result.summary.warn
        );
    }
}

/// Read the BIT exec-mode contract: when stdin is piped (not a TTY), treat its
/// contents as a JSON object that merges over CLI args and config (stdin wins).
fn read_stdin_overrides() -> Option<Value> {
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut buffer = String::new();
    if std::io::stdin().read_to_string(&mut buffer).is_err() {
        return None;
    }
    let trimmed = buffer.trim();
    if trimmed.is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) if value.is_object() => {
            if let Some(map) = value.as_object() {
                for key in map.keys() {
                    if !KNOWN_STDIN_KEYS.contains(&key.as_str()) {
                        eprintln!("warning: ignoring unknown stdin key '{key}'");
                    }
                }
            }
            Some(value)
        }
        Ok(_) => {
            eprintln!("warning: stdin JSON must be an object; ignoring");
            None
        }
        Err(e) => {
            eprintln!("warning: failed to parse stdin JSON ({e}); ignoring");
            None
        }
    }
}

fn apply_cli_overrides(cli: &mut Cli, value: &Value) {
    if let Some(interval) = value.get("interval").and_then(Value::as_u64) {
        if let Command::Watch { interval: slot } = &mut cli.command {
            *slot = interval;
        }
    }
    if let Command::Serve { host, port, token } = &mut cli.command {
        if let Some(h) = value.get("host").and_then(Value::as_str) {
            *host = h.to_string();
        }
        if let Some(p) = value.get("port").and_then(Value::as_u64) {
            if let Ok(p) = u16::try_from(p) {
                *port = p;
            }
        }
        if let Some(t) = value.get("token").and_then(Value::as_str) {
            *token = Some(t.to_string());
        }
    }
}
