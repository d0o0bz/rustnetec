//! Ingest write path (T2.3).
//!
//! [`ingest_write`] folds an [`IngestRequest`] into the server database inside
//! a single transaction:
//!
//! 1. `INSERT INTO server_events ... ON CONFLICT(user_id, local_event_id) DO
//!    NOTHING` — idempotent dedup.
//! 2. `INSERT INTO server_hosts ... ON CONFLICT(machine_id) DO UPDATE` —
//!    upsert the host registry, preserving `first_seen` and accumulating
//!    `event_count`.
//!
//! `prepare_cached` is used on the writer [`Transaction`] so repeated batches
//! reuse the compiled statements.

use anyhow::Result;
use rusqlite::{Connection, Transaction, params};
use rustnet_core::ingest::{ClientEvent, IngestRequest, IngestResponse};

use super::Error;

/// Batch-write an ingest request into `server_events` and upsert
/// `server_hosts`.
///
/// # Returns
/// - `Ok(IngestResponse)` with `accepted`, `duplicates`, and `cursor`
///   (= max `local_event_id` in the batch, or `0` when the batch is empty).
///
/// # Errors
/// - [`Error::InvalidUserId`] when `req.user_id` is not a parseable `i64`.
/// - [`Error::InvalidMachineId`] when `req.machine_id` is empty.
/// - Underlying rusqlite errors are propagated via `anyhow`.
pub fn ingest_write(conn: &mut Connection, req: &IngestRequest) -> Result<IngestResponse> {
    // ---- Validate identity fields ----
    let uid: i64 = req
        .user_id
        .parse()
        .map_err(|_| Error::InvalidUserId(req.user_id.clone()))?;
    if req.machine_id.is_empty() {
        return Err(Error::InvalidMachineId(req.machine_id.clone()).into());
    }

    let now = chrono::Local::now().to_rfc3339();
    let ip_list_json = serde_json::to_string(&req.ip_list).unwrap_or_else(|_| "[]".to_string());

    let tx = conn.transaction()?;

    let mut accepted: u64 = 0;
    let mut max_local_id: i64 = 0;

    for ev in &req.events {
        let changed = insert_event(
            &tx,
            req.machine_id.as_str(),
            uid,
            req.username.as_str(),
            ip_list_json.as_str(),
            ev,
            now.as_str(),
        )?;
        if changed {
            accepted += 1;
        }
        if ev.local_event_id > max_local_id {
            max_local_id = ev.local_event_id;
        }
    }

    upsert_host(
        &tx,
        req.machine_id.as_str(),
        uid,
        req.username.as_str(),
        ip_list_json.as_str(),
        now.as_str(),
        req.events.len() as i64,
    )?;

    tx.commit()?;

    let total = req.events.len() as u64;
    let duplicates = total.saturating_sub(accepted);

    Ok(IngestResponse {
        accepted,
        duplicates,
        cursor: max_local_id,
    })
}

/// Insert one event with idempotent dedup. Returns `true` when the row was
/// actually inserted (i.e. not a duplicate).
fn insert_event(
    tx: &Transaction,
    machine_id: &str,
    user_id: i64,
    username: &str,
    ip_list_json: &str,
    ev: &ClientEvent,
    ingest_ts: &str,
) -> Result<bool> {
    // T2.3 fills only the fields T2.2 ClientEvent exposes; the remaining
    // columns from `docs/数据模型设计.md` §3.2 are left NULL and populated
    // by later tasks (e.g. T2.6 UploadSink) as the protocol grows.
    let inserted = tx
        .prepare_cached(
            r#"
        INSERT INTO server_events (
            machine_id, user_id, username, ip_list,
            local_event_id,
            ts, ingest_ts,
            protocol, source_ip, source_port, dest_ip, dest_port,
            pid, process_name,
            bytes_sent, bytes_received, duration_secs
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, local_event_id) DO NOTHING
        "#,
        )?
        .execute(params![
            machine_id,
            user_id,
            username,
            ip_list_json,
            ev.local_event_id,
            ev.timestamp,
            ingest_ts,
            ev.protocol,
            ev.local_ip,
            ev.local_port,
            ev.remote_ip,
            ev.remote_port,
            ev.pid.map(|p| p as i64),
            ev.process_name,
            ev.bytes_sent as i64,
            ev.bytes_recv as i64,
            ev.duration_ms as i64,
        ])?;

    Ok(inserted > 0)
}

/// Upsert the host registry row. `first_seen` is preserved on conflict
/// (not in the UPDATE SET); `event_count` accumulates.
fn upsert_host(
    tx: &Transaction,
    machine_id: &str,
    user_id: i64,
    username: &str,
    ip_list_json: &str,
    now: &str,
    event_count_delta: i64,
) -> Result<()> {
    tx.prepare_cached(
        r#"
        INSERT INTO server_hosts (
            machine_id, user_id, username, ip_list,
            first_seen, last_seen, event_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(machine_id) DO UPDATE SET
            user_id      = excluded.user_id,
            username     = excluded.username,
            ip_list      = excluded.ip_list,
            last_seen    = excluded.last_seen,
            event_count  = server_hosts.event_count + excluded.event_count
        -- first_seen intentionally NOT updated (preserves original registration)
        "#,
    )?
    .execute(params![
        machine_id,
        user_id,
        username,
        ip_list_json,
        now, // first_seen (only used on initial INSERT)
        now, // last_seen
        event_count_delta,
    ])?;

    Ok(())
}
