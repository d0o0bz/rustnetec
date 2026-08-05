//! rustnet-server entry point.
//!
//! Boots the axum HTTP server on the configured listen address. Default
//! `127.0.0.1:19810`; override with `RUSTNET_SERVER_ADDR` for remote
//! deployments.

use std::net::SocketAddr;

use anyhow::Result;
use rustnet_server::api;

#[tokio::main]
async fn main() -> Result<()> {
    // Simple env-driven config for the skeleton; richer config lands in T2.3.
    let addr: SocketAddr = std::env::var("RUSTNET_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:19810".to_string())
        .parse()?;

    let app = api::build_router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("rustnet-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
