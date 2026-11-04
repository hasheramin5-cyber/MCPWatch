//! MCPWatch: know what your AI agents can access.
//!
//! A static auditor for local Model Context Protocol (MCP) configurations.
//! It never executes server commands and never sends data over a network.

mod config;
mod report;
mod scanner;
mod snapshot;

use clap::{Parser, Subcommand, ValueEnum};
use scanner::Severity;
use std::error::Error;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// Exit status when the command succeeded and nothing needs attention.
const EXIT_OK: u8 = 0;
/// Exit status when findings reached the threshold (scan) or changes were found (diff).
const EXIT_ATTENTION: u8 = 1;
/// Exit status for runtime errors such as unreadable or invalid files.
/// (Usage errors are reported by clap with status 2.)
const EXIT_ERROR: u8 = 3;

#[derive(Parser)]
#[command(
    name = "mcpwatch",
    version,
    about = "Know what your AI agents can access.",
    long_about = "Know what your AI agents can access.\n\nMCPWatch statically audits local MCP configuration files for risky settings. It never runs server commands and never uploads data.",
    after_help = "EXIT CODES:\n  0  success; no findings at or above the threshold, or no changes\n  1  findings at or above --fail-on (scan), or changes detected (diff)\n  2  invalid command-line usage\n  3  runtime error (unreadable or invalid configuration, snapshot I/O failure)",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Disable colored output (the NO_COLOR environment variable is also honored)
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze an MCP configuration file for risky settings
    Scan {
        /// Path to the MCP configuration JSON file
        config_path: PathBuf,

        /// Lowest severity that makes the command exit with status 1
        #[arg(long, value_enum, default_value_t = FailOn::High, value_name = "LEVEL")]
        fail_on: FailOn,
    },
    /// Save a local snapshot of a configuration for later comparison
    Snapshot {
        /// Path to the MCP configuration JSON file
        config_path: PathBuf,

        /// Directory for snapshots (default: a per-user local data directory)
        #[arg(long, env = "MCPWATCH_HOME", value_name = "DIR")]
        snapshot_dir: Option<PathBuf>,
    },
    /// Compare a configuration with its most recent snapshot
    Diff {
        /// Path to the MCP configuration JSON file
        config_path: PathBuf,

        /// Directory that holds snapshots (default: a per-user local data directory)
        #[arg(long, env = "MCPWATCH_HOME", value_name = "DIR")]
        snapshot_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    High,
    Medium,
    Low,
    Info,
    Never,
}

impl FailOn {
    fn threshold(self) -> Option<Severity> {
        match self {
            FailOn::High => Some(Severity::High),
            FailOn::Medium => Some(Severity::Medium),
            FailOn::Low => Some(Severity::Low),
            FailOn::Info => Some(Severity::Info),
            FailOn::Never => None,
        }
    }
}

fn emit(text: &str) {
    let mut stdout = io::stdout();
    // Ignore write errors such as a closed pipe (`mcpwatch scan x | head`).
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

fn resolve_dir(explicit: Option<PathBuf>) -> Result<PathBuf, snapshot::SnapshotError> {
    match explicit {
        Some(dir) => Ok(dir),
        None => snapshot::default_dir(),
    }
}

fn run(command: Commands, style: report::Style) -> Result<u8, Box<dyn Error>> {
    match command {
        Commands::Scan {
            config_path,
            fail_on,
        } => {
            let config = config::load(&config_path)?;
            let findings = scanner::scan(&config);
            emit(&report::render_scan(
                &config_path.display().to_string(),
                config.servers.len(),
                &findings,
                style,
            ));
            let tripped = fail_on
                .threshold()
                .is_some_and(|t| findings.iter().any(|f| f.severity >= t));
            Ok(if tripped { EXIT_ATTENTION } else { EXIT_OK })
        }
        Commands::Snapshot {
            config_path,
            snapshot_dir,
        } => {
            let config = config::load(&config_path)?;
            let dir = resolve_dir(snapshot_dir)?;
            let file = snapshot::save(&dir, &config_path, &config)?;
            emit(&report::render_snapshot_saved(
                &file,
                config.servers.len(),
                style,
            ));
            Ok(EXIT_OK)
        }
        Commands::Diff {
            config_path,
            snapshot_dir,
        } => {
            let config = config::load(&config_path)?;
            let dir = resolve_dir(snapshot_dir)?;
            let loaded = snapshot::load_latest(&dir, &config_path)?;
            let changes = snapshot::diff(&loaded.snapshot, &config);
            let file_name = loaded
                .file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| loaded.file.display().to_string());
            emit(&report::render_diff(
                &config_path.display().to_string(),
                &file_name,
                loaded.snapshot.created_unix,
                config.servers.len(),
                &changes,
                style,
            ));
            Ok(if changes.is_empty() {
                EXIT_OK
            } else {
                EXIT_ATTENTION
            })
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let style = report::Style::new(report::color_enabled(cli.no_color));
    match run(cli.command, style) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
