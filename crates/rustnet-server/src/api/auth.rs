//! Bearer-token authentication & role-based authorization (T2.4).
//!
//! Tokens live in the `server_tokens` table as BLAKE3 hashes; the plaintext
//! is shown only once at creation time (see [`super::token::create_token`]).
//!
//! Authorization is role-scoped:
//! - [`AuthRole::Ingest`] — `POST /ingest` only
//! - [`AuthRole::Query`]  — `GET /query`, `GET /stats`
//! - [`AuthRole::Admin`]  — everything except `/health`
//!
//! The middleware does ONE DB lookup per request (hash → role). The
//! `last_used_at` bump is best-effort: a failure there must not fail the
//! request, so it's swallowed.

use std::str::FromStr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rusqlite::params;

use crate::db::ServerDb;

/// Shared app state (mirror of [`super::AppState`] to avoid a circular import).
pub type AppState = std::sync::Arc<ServerDb>;

/// Minimum plaintext token length we'll accept on creation. 32 bytes is the
/// canonical size; the bound exists to refuse degenerate inputs.
pub const MIN_TOKEN_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

/// Authorization role attached to a server token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRole {
    Ingest,
    Query,
    Admin,
}

impl AuthRole {
    /// SQL column value stored in `server_tokens.role`.
    pub fn as_db_str(self) -> &'static str {
        match self {
            AuthRole::Ingest => "ingest",
            AuthRole::Query => "query",
            AuthRole::Admin => "admin",
        }
    }

    /// True when a token with `self` role may access an endpoint that
    /// requires `required`.
    fn authorizes(self, required: AuthRole) -> bool {
        match (self, required) {
            (AuthRole::Admin, _) => true,
            (a, b) => a == b,
        }
    }
}

impl FromStr for AuthRole {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ingest" => Ok(AuthRole::Ingest),
            "query" => Ok(AuthRole::Query),
            "admin" => Ok(AuthRole::Admin),
            other => Err(anyhow::anyhow!("unknown role `{other}`")),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Authentication/authorization failure surfaced to the middleware layer.
#[derive(Debug)]
pub enum AuthError {
    /// No `Authorization` header, or not a Bearer scheme.
    MissingToken,
    /// Token doesn't match any active row.
    InvalidToken,
    /// Token is valid but lacks the role the endpoint requires.
    Forbidden(AuthRole),
    /// DB lookup failed.
    Backend(anyhow::Error),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::MissingToken | AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            AuthError::Backend(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        status.into_response()
    }
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

/// Verify a plaintext bearer token against `server_tokens` and return its
/// role. Also bumps `last_used_at` (best-effort, failure swallowed).
///
/// # Arguments
/// * `db` - Shared server DB.
/// * `plaintext` - The raw token received in the Authorization header.
fn verify_token(db: &ServerDb, plaintext: &str) -> Result<AuthRole, AuthError> {
    let hash = blake3::hash(plaintext.as_bytes());
    let hex = hash.to_hex().to_string();

    let conn = db.lock_writer();
    let role_str: String = conn
        .query_row(
            "SELECT role FROM server_tokens \
             WHERE token_hash = ? AND is_active = 1",
            params![&hex],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => AuthError::InvalidToken,
            other => AuthError::Backend(other.into()),
        })?;

    // Best-effort last_used_at bump.
    let now = chrono::Local::now().to_rfc3339();
    let _ = conn.execute(
        "UPDATE server_tokens SET last_used_at = ? WHERE token_hash = ?",
        params![&now, &hex],
    );

    AuthRole::from_str(&role_str).map_err(AuthError::Backend)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Execute the role check against the request's Bearer token.
///
/// Callers arrange for this to run inside `from_fn_with_state`.
pub async fn check_auth(
    State(db): State<AppState>,
    required: AuthRole,
    headers: &axum::http::HeaderMap,
) -> Result<(), AuthError> {
    let plaintext = extract_bearer(headers)?;
    let role = verify_token(&db, &plaintext)?;
    if role.authorizes(required) {
        Ok(())
    } else {
        Err(AuthError::Forbidden(role))
    }
}

/// Pull `<token>` out of `Authorization: Bearer <token>`.
fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<String, AuthError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::MissingToken)?;

    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or(AuthError::MissingToken)?
        .trim()
        .to_string();

    if token.is_empty() {
        Err(AuthError::MissingToken)
    } else {
        Ok(token)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hdr(value: &str) -> axum::http::HeaderMap {
        let mut m = axum::http::HeaderMap::new();
        m.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        m
    }

    #[test]
    fn authorizes_matrix() {
        assert!(AuthRole::Admin.authorizes(AuthRole::Ingest));
        assert!(AuthRole::Admin.authorizes(AuthRole::Query));
        assert!(AuthRole::Admin.authorizes(AuthRole::Admin));
        assert!(AuthRole::Ingest.authorizes(AuthRole::Ingest));
        assert!(!AuthRole::Ingest.authorizes(AuthRole::Query));
        assert!(AuthRole::Query.authorizes(AuthRole::Query));
        assert!(!AuthRole::Query.authorizes(AuthRole::Ingest));
    }

    #[test]
    fn extract_bearer_variants() {
        assert_eq!(extract_bearer(&hdr("Bearer abc")).unwrap(), "abc");
        assert_eq!(extract_bearer(&hdr("bearer abc")).unwrap(), "abc");
        assert!(matches!(extract_bearer(&hdr("abc")), Err(AuthError::MissingToken)));
        assert!(matches!(
            extract_bearer(&hdr("Bearer  ")),
            Err(AuthError::MissingToken)
        ));
    }

    #[test]
    fn role_roundtrip() {
        for r in [AuthRole::Ingest, AuthRole::Query, AuthRole::Admin] {
            assert_eq!(AuthRole::from_str(r.as_db_str()).unwrap(), r);
        }
    }
}
