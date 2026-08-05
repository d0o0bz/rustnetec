//! HTTP API layer: axum routes and app construction (T2.4).
//!
//! ## Routes
//!
//! | Method | Path       | Auth role      | Description                       |
//! |--------|------------|----------------|-----------------------------------|
//! | GET    | `/health`  | none           | Liveness probe                    |
//! | POST   | `/ingest`  | `Ingest`/`Admin`| Accept a client event batch       |
//! | GET    | `/query`   | `Query`/`Admin`| Read-only historical query        |
//! | GET    | `/stats`   | `Query`/`Admin`| Aggregate statistics              |
//!
//! Auth uses Bearer tokens hashed with BLAKE3 (see [`auth`] and [`token`]).
//! `/health` is intentionally unauthenticated so load balancers can probe it.
//!
//! CORS is configured with a strict policy: only `GET`/`POST`, JSON content
//! type, and no credentials by default. Adjust [`cors_layer`] when opening
//! up to browser UIs.

pub mod auth;
pub mod token;

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rustnet_core::ingest::{
    HealthResponse, IngestRequest, IngestResponse, QueryParams, QueryResponse, StatsResponse,
};

use crate::db::{Error as DbError, ServerDb};

/// Shared application state injected into the router.
pub type AppState = Arc<ServerDb>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the top-level [`Router`] backed by `db`.
///
/// Kept as a free function so integration tests can construct the app without
/// spawning a TCP listener.
pub fn build_router(db: AppState) -> Router {
    Router::new()
        // /health is unauthenticated so probes/load balancers can reach it.
        .route("/health", get(health))
        // Authed routes — each is gated by the role it requires.
        .route(
            "/ingest",
            post(ingest).route_layer(from_fn_with_state(db.clone(), require_ingest)),
        )
        .route(
            "/query",
            get(query).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        .route(
            "/stats",
            get(stats).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        .layer(cors_layer())
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Liveness probe (no auth).
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

/// Read-only historical query.
async fn query(
    State(db): State<AppState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueryResponse>, ApiError> {
    let resp = db.query_events(&params).map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// Aggregate statistics.
async fn stats(State(db): State<AppState>) -> Result<Json<StatsResponse>, ApiError> {
    let resp = db.stats().map_err(ApiError::from)?;
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// Auth middleware (one per role — axum 0.8 `from_fn_with_state` needs a
// concrete function, not a closure returning a layer)
// ---------------------------------------------------------------------------

/// Role re-export so handler signatures stay readable.
pub use auth::AuthRole;

async fn require_ingest(
    State(db): State<AppState>,
    headers: HeaderMap,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    auth::check_auth(State(db), AuthRole::Ingest, &headers)
        .await
        .map_err(ApiError::from)?;
    Ok(next.run(req).await)
}

async fn require_query(
    State(db): State<AppState>,
    headers: HeaderMap,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    auth::check_auth(State(db), AuthRole::Query, &headers)
        .await
        .map_err(ApiError::from)?;
    Ok(next.run(req).await)
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// Strict CORS layer. Only `GET`/`POST` are allowed; the browser UI is
/// expected to read via `GET /query` and `GET /stats`, and upload via
/// `POST /ingest` (the client uses a native HTTP client, not CORS).
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::Method;
    use tower_http::cors::{Any, CorsLayer};

    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any)
        .allow_headers(Any)
}

// ---------------------------------------------------------------------------
// Error envelope
// ---------------------------------------------------------------------------

/// Error envelope that maps cleanly to an HTTP response.
pub enum ApiError {
    Domain(DbError),
    /// Malformed JSON body or other transport-level issue.
    BadRequest(String),
    /// Authentication failed (missing/invalid token).
    Unauthorized,
    /// Authorization failed (token valid, wrong role).
    Forbidden,
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

impl From<auth::AuthError> for ApiError {
    fn from(e: auth::AuthError) -> Self {
        match e {
            auth::AuthError::MissingToken | auth::AuthError::InvalidToken => Self::Unauthorized,
            auth::AuthError::Forbidden(_) => Self::Forbidden,
            auth::AuthError::Backend(_) => Self::Internal("auth backend error".into()),
        }
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
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, msg).into_response()
    }
}
