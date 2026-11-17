//! `datu-indexer`: the optional projection layer.
//!
//! Follows a node's store, verifies each entry, and projects the layer-1
//! tables into the SQL database named by `--db-url`. SQLite is built in;
//! PostgreSQL and MySQL need `--features postgres` / `--features mysql`.

use clap::Parser;
use datu_indexer::{open, run_once, IndexerConfig, VerifyMode};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "datu-indexer",
    about = "Optional projection layer: project verified DATU entries into SQL (SQLite, PostgreSQL, MySQL)"
)]
struct Cli {
    /// Node directory to follow (its node.db is read, never written).
    /// Not needed for --status.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Projection database URL: sqlite:///path, postgres://..., mysql://...
    /// (a bare path is treated as SQLite).
    #[arg(long)]
    db_url: Option<String>,
    /// Backwards-compatible alias for a SQLite path.
    #[arg(long)]
    db: Option<PathBuf>,
    /// Namespace allowlist pattern (repeatable, `gov.*` style). Omit for all.
    #[arg(long = "namespace")]
    namespaces: Vec<String>,
    /// Verification before projecting: signatures (default) or none.
    #[arg(long, default_value = "signatures")]
    verify: String,
    /// Entries per transaction.
    #[arg(long, default_value_t = 500)]
    batch: usize,
    /// Run one pass and exit (default when --every is not given).
    #[arg(long)]
    once: bool,
    /// Loop forever, this many seconds between passes.
    #[arg(long, default_value_t = 0)]
    every: u64,
    /// Drop the layer-1 projection first, then rebuild from the ledger.
    #[arg(long)]
    reindex: bool,
    /// Print projection status as JSON and exit.
    #[arg(long)]
    status: bool,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn resolve_db_url(cli: &Cli) -> Result<String, String> {
    if let Some(url) = &cli.db_url {
        return Ok(url.clone());
    }
    if let Some(path) = &cli.db {
        return Ok(path.display().to_string());
    }
    if cli.status {
        return Err("--status needs --db-url (or --db)".into());
    }
    Err("--db-url is required: sqlite:///path, postgres://..., mysql://...".into())
}

fn run(cli: Cli) -> Result<(), String> {
    let db_url = resolve_db_url(&cli)?;
    let mut db = open(&db_url)?;

    if cli.status {
        let report = db.status()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    let data_dir = cli
        .data_dir
        .clone()
        .ok_or_else(|| "--data-dir is required to index (omit only with --status)".to_string())?;
    let mut cfg = IndexerConfig::new(data_dir);
    cfg.namespaces = cli.namespaces.clone();
    cfg.verify = VerifyMode::parse(&cli.verify)?;
    cfg.batch = cli.batch.max(1);

    if cli.reindex {
        db.reset()?;
        println!("projection reset: {db_url}");
    }

    let mut pass = 0u64;
    loop {
        let stats = run_once(db.as_mut(), &cfg)?;
        pass += 1;
        println!(
            "pass {pass}: applied {} · filtered {} · rejected {} · cursor {} · checkpoint height {}",
            stats.applied, stats.filtered, stats.rejected, stats.cursor, stats.checkpoint_height
        );
        if cli.every == 0 || cli.once {
            let report = db.status()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(cli.every));
    }
}
