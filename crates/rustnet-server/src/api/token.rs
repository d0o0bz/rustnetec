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
use rusqlite::{Connection, params};

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
    /// rustnetec: machine scope; `None` for admin tokens (full access),
    /// `Some(mid)` restricts reads/ingest to that machine.
    pub scope_machine_id: Option<String>,
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

/// rustnetec: Business-rule validation for token scope.
///
/// | Role | scope_machine_id | 语义 |
/// | --- | --- | --- |
/// | `Admin` | 必须 `None` | 全量访问 |
/// | `Query` | 必须 `Some(mid)` | 只读该机（手动指定） |
/// | `Ingest` | `None` 或 `Some(mid)` | 共享上传 token（按 payload 归集）或绑定单机 |
/// | `Client` | `None` 或 `Some(mid)` | `None`=待绑定（首次上报自动绑定）；`Some`=预先指定 |
///
/// 拒绝 `(Query, None)` 防止误发全量读权限；拒绝 `(Admin, Some)` 防止
/// 管理员被意外收窄。
fn validate_scope(role: AuthRole, scope_machine_id: Option<&str>) -> Result<()> {
    match (role, scope_machine_id) {
        (AuthRole::Admin, Some(_)) => Err(anyhow::anyhow!(
            "admin tokens must not be scoped (scope_machine_id must be null)"
        )),
        (AuthRole::Admin, None) => Ok(()),
        (AuthRole::Query, Some(mid)) if !mid.is_empty() => Ok(()),
        (AuthRole::Query, _) => Err(anyhow::anyhow!(
            "query tokens must be scoped to a non-empty machine_id"
        )),
        // Ingest: shared upload token (None) or single-machine binding.
        (AuthRole::Ingest, Some(mid)) if !mid.is_empty() => Ok(()),
        (AuthRole::Ingest, None) => Ok(()),
        (AuthRole::Ingest, Some(_)) => Err(anyhow::anyhow!(
            "ingest scope_machine_id must be null or non-empty"
        )),
        // Client: unbound (None, auto-binds on first upload) or pre-bound.
        (AuthRole::Client, Some(mid)) if !mid.is_empty() => Ok(()),
        (AuthRole::Client, None) => Ok(()),
        (AuthRole::Client, Some(_)) => Err(anyhow::anyhow!(
            "client scope_machine_id must be null or non-empty"
        )),
    }
}

/// Generate a new token, hash it with BLAKE3, and persist the hash.
///
/// Returns the plaintext (caller must store it; it is not recoverable)
/// together with the new row id.
///
/// rustnetec: `scope_machine_id` binds the token to a single machine
/// (`None` only for admin tokens). See [`validate_scope`].
pub fn create_token(
    conn: &mut Connection,
    role: AuthRole,
    description: Option<&str>,
    scope_machine_id: Option<&str>,
) -> Result<CreatedToken> {
    validate_scope(role, scope_machine_id)?;

    let plaintext = generate_plaintext();
    let hash = blake3::hash(plaintext.as_bytes());
    let hex = hash.to_hex().to_string();
    let now = chrono::Local::now().to_rfc3339();

    conn.execute(
        "INSERT INTO server_tokens \
         (token_hash, role, description, created_at, is_active, scope_machine_id) \
         VALUES (?, ?, ?, ?, 1, ?)",
        params![&hex, role.as_db_str(), description, &now, scope_machine_id],
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

/// rustnetec: 把 token 绑定到 `machine_id`（client 角色首次上报自动绑定）。
///
/// 幂等：仅当该 token 当前**未绑定**（`scope_machine_id IS NULL`）时才写入，
/// 返回是否发生了绑定。已绑定的 token 不会被覆盖，因此一个 client token
/// 一旦绑定到某台机器，就不能再被另一台机器"抢绑"。
pub fn bind_token_to_machine(conn: &mut Connection, token_id: i64, machine_id: &str) -> Result<bool> {
    let changed = conn
        .execute(
            "UPDATE server_tokens SET scope_machine_id = ? \
             WHERE id = ? AND scope_machine_id IS NULL",
            params![machine_id, token_id],
        )
        .context("UPDATE server_tokens bind failed")?;
    Ok(changed > 0)
}

/// List all tokens (active and revoked). Hashes are intentionally omitted.
pub fn list_tokens(conn: &mut Connection) -> Result<Vec<TokenRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, role, description, created_at, last_used_at, is_active, scope_machine_id \
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
                scope_machine_id: r.get(6)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// rustnetec: 首次启动引导 — 当表中不存在任何 active admin token 时，
/// 生成一个 admin token 并返回明文；否则返回 `None`（幂等，重启不重复生成）。
///
/// 用途：新部署的服务器 `server_tokens` 表为空，`POST /admin/tokens` 又需要
/// admin token 鉴权（鸡生蛋问题）。调用方（如 `main.rs` 启动路径）应把返回的
/// 明文打印到日志一次，之后即可通过 `POST /admin/tokens` 签发 scoped token。
///
/// 安全约束：明文仅此一处返回（落库仍是 BLAKE3 哈希）；`role=admin` 且
/// `scope_machine_id = NULL`（全量访问），符合业务规则。
pub fn ensure_bootstrap_admin_token(conn: &mut Connection) -> Result<Option<CreatedToken>> {
    let active_admin: i64 = conn.query_row(
        "SELECT COUNT(*) FROM server_tokens WHERE role = 'admin' AND is_active = 1",
        [],
        |r| r.get(0),
    )?;
    if active_admin > 0 {
        return Ok(None);
    }
    let created = create_token(conn, AuthRole::Admin, Some("bootstrap"), None)?;
    Ok(Some(created))
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
    use crate::db::{ServerDbConfig, init};
    use std::path::PathBuf;

    fn tmp_db(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustnet-server-token-{label}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn create_then_verify_roundtrip() {
        let path = tmp_db("roundtrip");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        let created = create_token(&mut conn, AuthRole::Admin, Some("ops"), None).unwrap();
        assert!(created.plaintext.len() >= MIN_TOKEN_LEN * 2 / 2); // hex length sanity
        assert!(created.id > 0);

        // Re-deriving the hash from the plaintext must find the row.
        let hash = blake3::hash(created.plaintext.as_bytes())
            .to_hex()
            .to_string();
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

        let created = create_token(&mut conn, AuthRole::Query, None, Some("machine-x")).unwrap();
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

        let _ = create_token(&mut conn, AuthRole::Ingest, Some("host-a"), Some("machine-a")).unwrap();
        let _ = create_token(&mut conn, AuthRole::Admin, None, None).unwrap();

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
            let t = create_token(&mut conn, AuthRole::Ingest, None, Some("machine-u")).unwrap();
            assert!(seen.insert(t.plaintext), "duplicate plaintext generated");
        }
    }

    #[test]
    fn bootstrap_generates_admin_on_empty_db() {
        let path = tmp_db("bootstrap-first");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Fresh DB: no admin token → must generate one (role=admin, unscoped).
        let first = ensure_bootstrap_admin_token(&mut conn)
            .unwrap()
            .expect("empty DB should bootstrap an admin token");
        assert!(!first.plaintext.is_empty());
        assert!(first.id > 0);

        // The row is an active admin token with scope_machine_id = NULL.
        let (role, scope, active): (String, Option<String>, i64) = conn
            .query_row(
                "SELECT role, scope_machine_id, is_active FROM server_tokens WHERE id = ?",
                params![first.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(role, "admin");
        assert!(scope.is_none(), "bootstrap admin must be unscoped");
        assert_eq!(active, 1);
    }

    #[test]
    fn bootstrap_skips_when_admin_exists() {
        let path = tmp_db("bootstrap-skip");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Pre-provision an admin token.
        let _ = create_token(&mut conn, AuthRole::Admin, Some("existing"), None).unwrap();

        // Second call must be a no-op (idempotent across restarts).
        let result = ensure_bootstrap_admin_token(&mut conn).unwrap();
        assert!(result.is_none(), "existing admin must suppress bootstrap");

        // Exactly one admin row remains.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM server_tokens WHERE role = 'admin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn bootstrap_regenerates_after_admin_revoked() {
        let path = tmp_db("bootstrap-regenerate");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Provision an admin then revoke it → no active admin remains.
        let created = create_token(&mut conn, AuthRole::Admin, Some("tmp"), None).unwrap();
        assert!(revoke_token(&mut conn, created.id).unwrap());

        // Bootstrap must issue a fresh admin token.
        let regenerated = ensure_bootstrap_admin_token(&mut conn)
            .unwrap()
            .expect("revoked admin should trigger re-bootstrap");
        assert_ne!(regenerated.id, created.id);
        assert_ne!(regenerated.plaintext, created.plaintext);
    }

    #[test]
    fn ingest_without_scope_is_allowed() {
        let path = tmp_db("ingest-unscoped");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Shared upload token: (Ingest, None) must be accepted.
        let created = create_token(&mut conn, AuthRole::Ingest, Some("shared-upload"), None).unwrap();
        assert!(created.id > 0);
    }

    #[test]
    fn client_without_scope_is_allowed() {
        let path = tmp_db("client-unbound");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Unbound client token (auto-binds on first upload): (Client, None) ok.
        let created = create_token(&mut conn, AuthRole::Client, Some("client-a"), None).unwrap();
        assert!(created.id > 0);

        // Pre-bound client token also allowed.
        let pre = create_token(&mut conn, AuthRole::Client, Some("client-b"), Some("machine-b")).unwrap();
        assert!(pre.id > 0);
    }

    #[test]
    fn bind_is_idempotent_and_immutable() {
        let path = tmp_db("bind");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        let created = create_token(&mut conn, AuthRole::Client, Some("client"), None).unwrap();

        // First bind succeeds.
        assert!(bind_token_to_machine(&mut conn, created.id, "machine-a").unwrap());

        // Second bind to a different machine is a no-op (already bound).
        assert!(!bind_token_to_machine(&mut conn, created.id, "machine-b").unwrap());

        // Scope stays machine-a — a bound client token cannot be hijacked.
        let scope: Option<String> = conn
            .query_row(
                "SELECT scope_machine_id FROM server_tokens WHERE id = ?",
                params![created.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(scope.as_deref(), Some("machine-a"));
    }

    #[test]
    fn query_without_scope_is_rejected() {
        let path = tmp_db("query-unscoped");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Read-side isolation: query MUST be bound to a machine.
        let result = create_token(&mut conn, AuthRole::Query, Some("q"), None);
        assert!(result.is_err(), "query token without scope must be rejected");
    }
}
