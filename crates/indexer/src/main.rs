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
    /// Projection database URL: a sqlite, postgres or mysql scheme, or a bare path
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
    /// Serve /healthz and /metrics (Prometheus text) on this address while
    /// indexing, e.g. 127.0.0.1:7491.
    #[arg(long)]
    http: Option<String>,
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
    Err("--db-url is required: a sqlite, postgres or mysql scheme, or a bare path".into())
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

    if let Some(addr) = cli.http.clone() {
        let url = db_url.clone();
        std::thread::spawn(move || health_server(&addr, &url));
    }

    let mut pass = 0u64;
    loop {
        let stats = run_once(db.as_mut(), &cfg)?;
        pass += 1;
        println!(
            "pass {pass}: applied {} · filtered {} · rejected {} · cursor {} · height {} · members {} · gaps {}",
            stats.applied,
            stats.filtered,
            stats.rejected,
            stats.cursor,
            stats.checkpoint_height,
            stats.members,
            stats.gaps
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

/// Minimal read-only HTTP endpoint for ops: `/healthz` (JSON) and
/// `/metrics` (Prometheus text). One fresh connection per request, so it
/// works for every dialect without sharing state with the indexer loop.
fn health_server(addr: &str, db_url: &str) {
    use std::io::{Read, Write};
    let Ok(listener) = std::net::TcpListener::bind(addr) else {
        eprintln!("health endpoint: cannot bind {addr}");
        return;
    };
    println!("health endpoint on http://{addr}/healthz (metrics at /metrics)");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");
        let (status, ctype, body) = match path {
            "/healthz" => {
                let body = match open(db_url).and_then(|mut db| db.status()) {
                    Ok(v) => v.to_string(),
                    Err(e) => serde_json::json!({"error": e}).to_string(),
                };
                ("200 OK", "application/json", body)
            }
            "/metrics" => {
                let body = match open(db_url).and_then(|mut db| db.status()) {
                    Ok(v) => metrics_text(&v),
                    Err(e) => format!(
                        "# error: {e}
"
                    ),
                };
                ("200 OK", "text/plain; version=0.0.4", body)
            }
            _ => ("404 Not Found", "text/plain", "not found".to_string()),
        };
        let mut head: Vec<u8> = Vec::new();
        head.extend_from_slice(format!("HTTP/1.1 {status}").as_bytes());
        head.extend_from_slice(&[13, 10]);
        head.extend_from_slice(format!("Content-Type: {ctype}").as_bytes());
        head.extend_from_slice(&[13, 10]);
        head.extend_from_slice(b"Cache-Control: no-store");
        head.extend_from_slice(&[13, 10]);
        head.extend_from_slice(format!("Content-Length: {}", body.len()).as_bytes());
        head.extend_from_slice(&[13, 10]);
        head.extend_from_slice(b"Connection: close");
        head.extend_from_slice(&[13, 10, 13, 10]);
        let _ = stream.write_all(&head);
        let _ = stream.write_all(body.as_bytes());
    }
}

fn metrics_text(status: &serde_json::Value) -> String {
    let mut out = String::new();
    for (key, help) in [
        ("entries", "entries projected"),
        ("refs", "citation edges projected"),
        ("feeds", "author feeds tracked"),
        ("checkpoints", "checkpoints projected"),
        ("checkpoint_members", "checkpoint to entry membership rows"),
        ("rejected", "entries rejected by verification"),
        (
            "applied_total",
            "entries applied since the projection began",
        ),
        ("checkpoint_height", "highest checkpoint height seen"),
    ] {
        if let Some(v) = status.get(key).and_then(|v| v.as_i64()) {
            out.push_str(&format!(
                "# HELP datu_indexer_{key} {help}
# TYPE datu_indexer_{key} gauge
datu_indexer_{key} {v}
"
            ));
        }
    }
    if let Some(v) = status.get("seconds_since_update").and_then(|v| v.as_f64()) {
        out.push_str(&format!(
            "# HELP datu_indexer_seconds_since_update seconds since the last pass
# TYPE datu_indexer_seconds_since_update gauge
datu_indexer_seconds_since_update {v}
"
        ));
    }
    out
}
