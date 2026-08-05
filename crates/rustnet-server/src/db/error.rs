//! Server-side error types (T2.3).
//!
//! [`Error`] captures the domain errors surfaced by the ingest write path
//! and maps them to appropriate HTTP status codes for the axum API layer.

use axum::http::StatusCode;

/// Domain errors returned by the server storage layer.
#[derive(Debug)]
pub enum Error {
    /// `user_id` could not be parsed as an `i64` snowflake ID.
    InvalidUserId(String),

    /// `machine_id` was empty or otherwise malformed.
    InvalidMachineId(String),

    /// A generic database/IO error surfaced via `anyhow`.
    Other(anyhow::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidUserId(v) => {
                write!(f, "invalid user_id (expected 64-bit integer snowflake): {v}")
            }
            Error::InvalidMachineId(v) => {
                write!(f, "invalid machine_id (must be non-empty): {v}")
            }
            Error::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Other(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Other(e)
    }
}

impl Error {
    /// Map an [`Error`] to an `(StatusCode, String)` pair suitable for axum's
    /// `IntoResponse`.
    pub fn as_http(&self) -> (StatusCode, String) {
        match self {
            Error::InvalidUserId(_) | Error::InvalidMachineId(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Error::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        }
    }
}
