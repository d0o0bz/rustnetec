//! HTTP API layer: axum routes and app construction.
//!
//! The router is wired with [`axum::State`] carrying an
//! [`Arc<ServerDb>`](std::sync::Arc<rustnet_server::db::ServerDb>), so handlers
//! can reach the single writer connection.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rustnet_core::ingest::{
    HealthResponse, IngestRequest, IngestResponse, QueryResponse, StatsResponse,
};
use crate::db::{Error as DbError, ServerDb};

/// Shared application state injected into the router.
pub type AppState = Arc<ServerDb>;

/// Build the top-level [`Router`] backed by `db`.
///
/// Kept as a free function so integration tests can construct the app without
/// spawning a TCP listener.
pub fn build_router(db: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ingest", post(ingest))
        .route("/query", get(query))
        .route("/stats", get(stats))
        .with_state(db)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Accept a client batch and persist it through the single writer.
async fn ingest(
    State(db): State<AppState>,
    Json(req): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, ApiError> {
    let resp = db.ingest(&req).map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// Read-only historical query. Stub returns an empty response (T2.4).
async fn query() -> Json<QueryResponse> {
    Json(QueryResponse { rows: Vec::new() })
}

/// Aggregate statistics. Stub returns an empty response (T2.4).
async fn stats() -> Json<StatsResponse> {
    Json(StatsResponse {
        total_events: 0,
        total_bytes: 0,
        hosts: Vec::new(),
    })
}

/// Error envelope that maps cleanly to an HTTP response.
pub enum ApiError {
    Domain(DbError),
    /// Malformed JSON body or other transport-level issue.
    BadRequest(String),
    Internal(String),
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::InvalidUserId(_) | DbError::InvalidMachineId(_) => Self::Domain(e),
            DbError::Other(_) => Self::Internal(e.to_string()),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Domain(e) => {
                let (code, m) = e.as_http();
                (code, m)
            }
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, msg).into_response()
    }
}
