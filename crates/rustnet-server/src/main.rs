//! rustnet-server entry point.
//!
//! Boots the axum HTTP server on the configured listen address. Default
//! `127.0.0.1:19810`; override with `RUSTNET_SERVER_ADDR` for remote
//! deployments. The SQLite database path defaults to `./rustnet-server.db`
//! and can be overridden with `RUSTNET_SERVER_DB`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustnet_server::api;
use rustnet_server::cleanup::{
    spawn_cleanup_task, DEFAULT_PERIOD, DEFAULT_RETENTION_DAYS,
};
use rustnet_server::db::{init as init_db, ServerDbConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Resolve configuration from the environment.
    let addr: SocketAddr = std::env::var("RUSTNET_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:19810".to_string())
        .parse()
        .context("RUSTNET_SERVER_ADDR is not a valid SocketAddr")?;

    let db_path = std::env::var("RUSTNET_SERVER_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./rustnet-server.db"));

    // Optional retention tuning (days); defaults to 180, max 1095 per §7.4.
    let retention_days: u32 = std::env::var("RUSTNET_SERVER_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
        .min(1095);

    // Open (or create) the SQLite database with schema v2 + PRAGMAs.
    let db = init_db(&db_path, &ServerDbConfig::default())
        .with_context(|| format!("failed to init server db at {}", db_path.display()))?;

    let db = Arc::new(db);

    // Launch the periodic data-retention cleanup task (T2.5). The first
    // purge runs immediately so a freshly booted server trims any data
    // that expired while it was down; subsequent purges fire on each tick.
    // Period can be shortened via RUSTNET_SERVER_CLEANUP_PERIOD_SECS for
    // tests; defaults to 24h.
    let cleanup_period: Duration = std::env::var("RUSTNET_SERVER_CLEANUP_PERIOD_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PERIOD);
    spawn_cleanup_task(Arc::clone(&db), retention_days, cleanup_period);

    let app = api::build_router(db);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("rustnet-server listening on {addr} (db: {})", db_path.display());
    axum::serve(listener, app).await?;
    Ok(())
}
