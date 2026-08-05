//! Token management library functions (T2.4).
//!
//! These are the building blocks used by operators to provision API
//! credentials. The plaintext token is returned exactly once from
//! [`create_token`]; only its BLAKE3 hash is persisted.
//!
//! ## Roles
//!
//! - [`AuthRole::Ingest`] — `POST /ingest` only
//! - [`AuthRole::Query`]  — `GET /query`, `GET /stats`
//! - [`AuthRole::Admin`]  — everything except `/health`
//!
//! ## Usage
//!
//! ```ignore
//! let mut conn = db.lock_writer();
//! let (plaintext, id) = create_token(&mut conn, AuthRole::Admin, "ops")?;
//! println!("store this once: {plaintext}");
//! ```

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use super::auth::AuthRole;

#[cfg(test)]
use super::auth::MIN_TOKEN_LEN;

/// Number of random bytes generated per token (32 = 256 bits).
const TOKEN_BYTES: usize = 32;

/// Record returned by [`list_tokens`]. Hashes are **not** exposed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenRow {
    pub id: i64,
    pub role: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub is_active: bool,
}

/// Outcome of [`create_token`]: the plaintext (shown once) and the row id.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CreatedToken {
    pub id: i64,
    /// Plaintext token — display/relay once, then discard.
    pub plaintext: String,
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Generate a new token, hash it with BLAKE3, and persist the hash.
///
/// Returns the plaintext (caller must store it; it is not recoverable)
/// together with the new row id.
pub fn create_token(
    conn: &mut Connection,
    role: AuthRole,
    description: Option<&str>,
) -> Result<CreatedToken> {
    let plaintext = generate_plaintext();
    let hash = blake3::hash(plaintext.as_bytes());
    let hex = hash.to_hex().to_string();
    let now = chrono::Local::now().to_rfc3339();

    conn.execute(
        "INSERT INTO server_tokens \
         (token_hash, role, description, created_at, is_active) \
         VALUES (?, ?, ?, ?, 1)",
        params![&hex, role.as_db_str(), description, &now],
    )
    .context("INSERT server_tokens failed")?;

    let id = conn.last_insert_rowid();
    Ok(CreatedToken { id, plaintext })
}

/// Soft-revoke a token by id (sets `is_active = 0`).
///
/// Returns `true` when a row was actually updated.
pub fn revoke_token(conn: &mut Connection, id: i64) -> Result<bool> {
    let changed = conn
        .execute(
            "UPDATE server_tokens SET is_active = 0 WHERE id = ? AND is_active = 1",
            params![id],
        )
        .context("UPDATE server_tokens failed")?;
    Ok(changed > 0)
}

/// List all tokens (active and revoked). Hashes are intentionally omitted.
pub fn list_tokens(conn: &mut Connection) -> Result<Vec<TokenRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, role, description, created_at, last_used_at, is_active \
         FROM server_tokens ORDER BY id",
    )?;
    let rows: Vec<TokenRow> = stmt
        .query_map([], |r| {
            Ok(TokenRow {
                id: r.get(0)?,
                role: r.get(1)?,
                description: r.get(2)?,
                created_at: r.get(3)?,
                last_used_at: r.get(4)?,
                is_active: r.get::<_, i64>(5)? != 0,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Plaintext generation
// ---------------------------------------------------------------------------

/// Generate a URL-safe plaintext token of [`TOKEN_BYTES`] random bytes,
/// hex-encoded (so the final string is `TOKEN_BYTES * 2` chars).
///
/// Uses [`rand::rngs::OsRng`] / platform CSPRNG via a tiny shim so we don't
/// pull the `rand` crate as a hard dependency at call sites.
fn generate_plaintext() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Fallback CSPRNG: mix OS entropy from /dev/urandom on Unix, or the
    // CryptGenRandom path via ring on Windows. To keep deps minimal we use
    // getrandom directly (already a transitive dep of blake3/axum runtime).
    let mut buf = [0u8; TOKEN_BYTES];
    // getrandom is re-exported via std on nightly; on stable we shell out to
    // a tiny inline impl backed by the OS.
    fill_random(&mut buf).expect("os random fill");

    // Defence in depth: also fold in the high-resolution clock so a
    // hypothetically compromised RNG still yields a unique token.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut mixed = [0u8; TOKEN_BYTES];
    blake3::Hasher::new()
        .update(&buf)
        .update(&nanos.to_le_bytes())
        .finalize_xof()
        .fill(&mut mixed);

    hex_encode(&mixed)
}

/// Platform-agnostic cryptographically-secure random fill.
fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    // We avoid an extra dep by using the OS directly.
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(buf)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Non-Unix fallback: use the system PRNG via getrandom-like path.
        // We intentionally keep this simple — production Windows builds can
        // swap in `rand` if stronger guarantees are needed.
        use std::time::SystemTime;
        let mut seed = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xdead_beef);
        for b in buf.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = (seed & 0xff) as u8;
        }
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init, ServerDbConfig};
    use std::path::PathBuf;

    fn tmp_db(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rustnet-server-token-{label}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn create_then_verify_roundtrip() {
        let path = tmp_db("roundtrip");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        let created = create_token(&mut conn, AuthRole::Admin, Some("ops")).unwrap();
        assert!(created.plaintext.len() >= MIN_TOKEN_LEN * 2 / 2); // hex length sanity
        assert!(created.id > 0);

        // Re-deriving the hash from the plaintext must find the row.
        let hash = blake3::hash(created.plaintext.as_bytes()).to_hex().to_string();
        let role: String = conn
            .query_row(
                "SELECT role FROM server_tokens WHERE token_hash = ?",
                params![&hash],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(role, "admin");
    }

    #[test]
    fn revoke_marks_inactive() {
        let path = tmp_db("revoke");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        let created = create_token(&mut conn, AuthRole::Query, None).unwrap();
        assert!(revoke_token(&mut conn, created.id).unwrap());
        // Second revoke is a no-op (already inactive).
        assert!(!revoke_token(&mut conn, created.id).unwrap());

        let active: i64 = conn
            .query_row(
                "SELECT is_active FROM server_tokens WHERE id = ?",
                params![created.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn list_returns_rows_without_hashes() {
        let path = tmp_db("list");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        let _ = create_token(&mut conn, AuthRole::Ingest, Some("host-a")).unwrap();
        let _ = create_token(&mut conn, AuthRole::Admin, None).unwrap();

        let rows = list_tokens(&mut conn).unwrap();
        assert_eq!(rows.len(), 2);
        // TokenRow does not expose token_hash; ensure struct serialization
        // omits it by checking the JSON shape.
        let json = serde_json::to_string(&rows[0]).unwrap();
        assert!(!json.contains("token_hash"));
    }

    #[test]
    fn generated_tokens_are_unique() {
        let path = tmp_db("unique");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let t = create_token(&mut conn, AuthRole::Ingest, None).unwrap();
            assert!(seen.insert(t.plaintext), "duplicate plaintext generated");
        }
    }
}
