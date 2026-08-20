//! Bearer-token authentication & role-based authorization (T2.4).
//!
//! Tokens live in the `server_tokens` table as BLAKE3 hashes; the plaintext
//! is shown only once at creation time (see [`super::token::create_token`]).
//!
//! Authorization is role-scoped:
//! - [`AuthRole::Ingest`] — `POST /ingest` only
//! - [`AuthRole::Query`]  — `GET /query`, `GET /stats`
//! - [`AuthRole::Admin`]  — everything except `/health` and `/ingest`
//!   (rustnetec: `/ingest` 拒绝 admin token，见 `crate::api::require_ingest`)
//!
//! The middleware does ONE DB lookup per request (hash → role). The
//! `last_used_at` bump is best-effort: a failure there must not fail the
//! request, so it's swallowed.

use std::str::FromStr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use log::{debug, error, warn};
use rusqlite::params;

use crate::db::ServerDb;

/// Shared app state (mirror of [`super::AppState`] to avoid a circular import).
pub type AppState = std::sync::Arc<ServerDb>;

/// rustnetec: Authenticated principal resolved from a Bearer token.
///
/// Carries the token's row id, role, and (for non-admin tokens) the
/// `machine_id` scope that limits data visibility. Admin tokens have
/// `scope_machine_id = None`, meaning unrestricted access.
#[derive(Debug, Clone)]
pub struct TokenPrincipal {
    /// Row id in `server_tokens` (needed for e.g. client auto-binding).
    pub token_id: i64,
    pub role: AuthRole,
    /// `None` for admin tokens (full access); `Some(mid)` restricts reads/ingest
    /// to events whose `machine_id` matches `mid`.
    pub scope_machine_id: Option<String>,
}

impl TokenPrincipal {
    /// Whether this principal has unrestricted (cross-machine) access.
    pub fn is_unscoped(&self) -> bool {
        self.scope_machine_id.is_none()
    }
}

/// Minimum plaintext token length we'll accept on creation. 32 bytes is the
/// canonical size; the bound exists to refuse degenerate inputs.
pub const MIN_TOKEN_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

/// Authorization role attached to a server token.
///
/// rustnetec: `Client` — 每机一个 token 的角色：可上报（`POST /ingest`）且
/// 可只读自己的数据（`GET /query` 等）。创建时 `scope_machine_id` 可为
/// `None`（待绑定），机器首次上报时服务端自动绑定到其 `machine_id`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRole {
    Ingest,
    Query,
    Admin,
    Client,
}

impl AuthRole {
    /// SQL column value stored in `server_tokens.role`.
    pub fn as_db_str(self) -> &'static str {
        match self {
            AuthRole::Ingest => "ingest",
            AuthRole::Query => "query",
            AuthRole::Admin => "admin",
            AuthRole::Client => "client",
        }
    }

    /// True when a token with `self` role may access an endpoint that
    /// requires `required`.
    fn authorizes(self, required: AuthRole) -> bool {
        match (self, required) {
            (AuthRole::Admin, _) => true,
            // rustnetec: client = 上传 + 只读自己（ingest 与 query 端点都放行）。
            (AuthRole::Client, AuthRole::Ingest) | (AuthRole::Client, AuthRole::Query) => true,
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
            "client" => Ok(AuthRole::Client),
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

/// Verify a plaintext bearer token against `server_tokens` and return the
/// authenticated principal (role + optional machine scope). Also bumps
/// `last_used_at` (best-effort, failure swallowed).
///
/// # Arguments
/// * `db` - Shared server DB.
/// * `plaintext` - The raw token received in the Authorization header.
fn verify_token(db: &ServerDb, plaintext: &str) -> Result<TokenPrincipal, AuthError> {
    let hash = blake3::hash(plaintext.as_bytes());
    let hex = hash.to_hex().to_string();
    // 仅打印 hash 前缀，绝不打印明文 token。
    debug!("verify_token: hash={}..", &hex[..hex.len().min(8)]);

    let conn = db.lock_writer();
    let (token_id, role_str, scope_machine_id): (i64, String, Option<String>) = conn
        .query_row(
            "SELECT id, role, scope_machine_id FROM server_tokens \
             WHERE token_hash = ? AND is_active = 1",
            params![&hex],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                warn!("verify_token: 无效/已吊销 token (hash={}..)", &hex[..hex.len().min(8)]);
                AuthError::InvalidToken
            }
            other => {
                error!("verify_token: DB 查询失败: {other}");
                AuthError::Backend(other.into())
            }
        })?;

    // Best-effort last_used_at bump.
    let now = chrono::Local::now().to_rfc3339();
    let _ = conn.execute(
        "UPDATE server_tokens SET last_used_at = ? WHERE token_hash = ?",
        params![&now, &hex],
    );

    let role = AuthRole::from_str(&role_str).map_err(AuthError::Backend)?;
    Ok(TokenPrincipal {
        token_id,
        role,
        scope_machine_id,
    })
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Execute the role check against the request's Bearer token and return
/// the authenticated principal on success.
///
/// Callers arrange for this to run inside `from_fn_with_state`.
pub async fn check_auth(
    State(db): State<AppState>,
    required: AuthRole,
    headers: &axum::http::HeaderMap,
) -> Result<TokenPrincipal, AuthError> {
    let plaintext = extract_bearer(headers)?;
    let principal = verify_token(&db, &plaintext)?;
    if principal.role.authorizes(required) {
        debug!("check_auth: 通过 (token_id={}, role={:?})", principal.token_id, principal.role);
        Ok(principal)
    } else {
        warn!(
            "check_auth: 角色不足 (principal role={:?}, required={:?})",
            principal.role, required
        );
        Err(AuthError::Forbidden(principal.role))
    }
}

/// Pull `<token>` out of `Authorization: Bearer <token>`.
fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<String, AuthError> {
    let auth = headers.get(axum::http::header::AUTHORIZATION);
    if auth.is_none() {
        warn!("extract_bearer: 缺少 Authorization 头");
    }
    let header = auth
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
        m.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(value).unwrap(),
        );
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
        assert!(matches!(
            extract_bearer(&hdr("abc")),
            Err(AuthError::MissingToken)
        ));
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
