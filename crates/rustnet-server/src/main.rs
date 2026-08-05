//! rustnet-server entry point.
//!
//! Boots the axum HTTP server on the configured listen address. Default
//! `127.0.0.1:19810`; override with `RUSTNET_SERVER_ADDR` for remote
//! deployments. The SQLite database path defaults to `./rustnet-server.db`
//! and can be overridden with `RUSTNET_SERVER_DB`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustnet_server::api;
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

    // Open (or create) the SQLite database with schema v2 + PRAGMAs.
    let db = init_db(&db_path, &ServerDbConfig::default())
        .with_context(|| format!("failed to init server db at {}", db_path.display()))?;

    let db = Arc::new(db);
    let app = api::build_router(db);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("rustnet-server listening on {addr} (db: {})", db_path.display());
    axum::serve(listener, app).await?;
    Ok(())
}
