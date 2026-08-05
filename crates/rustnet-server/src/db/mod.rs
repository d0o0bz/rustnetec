//! SQLite storage layer for the server.
//!
//! Skeleton module reserved for T2.3 (schema v2 DDL, WAL, busy_timeout,
//! single-writer model). Exposed now so the crate's public surface is stable.

use anyhow::Result;

/// Open (or create) the server database and run migrations.
///
/// Returns a handle to the writer connection. Implemented in T2.3.
pub fn init(_db_path: &std::path::Path) -> Result<()> {
    // T2.3: PRAGMA journal_mode=WAL, auto_vacuum=INCREMENTAL, busy_timeout=5000,
    //       schema_version, server_events, server_aggregates, server_hosts,
    //       server_tokens + indexes.
    Ok(())
}
