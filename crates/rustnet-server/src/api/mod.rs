//! HTTP API layer: axum routes and app construction.
//!
//! The skeleton wires up four endpoints with placeholder handlers. Real
//! storage-backed implementations land in T2.3/T2.4.

use axum::{
    routing::{get, post},
    Json, Router,
};
use rustnet_core::ingest::{HealthResponse, IngestRequest, IngestResponse};

/// Build the top-level [`Router`] for the server.
///
/// Kept as a free function so integration tests can construct the app without
/// spawning a TCP listener.
pub fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ingest", post(ingest))
        .route("/query", get(query))
        .route("/stats", get(stats))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Accept a client batch. Stub returns zero accepted — real ingestion
/// (dedup, writes, aggregates) is implemented in T2.3.
async fn ingest(Json(_req): Json<IngestRequest>) -> Json<IngestResponse> {
    Json(IngestResponse {
        accepted: 0,
        duplicates: 0,
        cursor: 0,
    })
}

/// Read-only historical query. Stub returns an empty response.
async fn query() -> Json<rustnet_core::ingest::QueryResponse> {
    Json(rustnet_core::ingest::QueryResponse { rows: Vec::new() })
}

/// Aggregate statistics. Stub returns an empty response.
async fn stats() -> Json<rustnet_core::ingest::StatsResponse> {
    Json(rustnet_core::ingest::StatsResponse {
        total_events: 0,
        total_bytes: 0,
        hosts: Vec::new(),
    })
}
