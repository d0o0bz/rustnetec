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
//! 3. `INSERT INTO server_reachability ... ON CONFLICT(machine_id, ts) DO
//!    NOTHING` — 可达率样本（决策 A）幂等写入。
//! 4. `INSERT INTO server_aggregates ... ON CONFLICT DO UPDATE` — 分钟桶
//!    流量聚合（决策 2-B），支持 `/stats/realtime` 与 `/stats/range`。
//!
//! `prepare_cached` is used on the writer [`Transaction`] so repeated batches
//! reuse the compiled statements.

use anyhow::{Context, Result};
use rusqlite::{Connection, Transaction, params};
use rustnet_core::ingest::{ClientEvent, IngestRequest, IngestResponse, ReachabilitySample};

use super::Error;

/// 30 分钟（1800 秒）—— 客户端覆盖 department/username 的频率上限。
const FIELD_OVERRIDE_COOLDOWN_SECS: i64 = 1800;

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

    // rustnetec: upsert host，含字段级 30min 覆盖校验（department/username）。
    // 返回最终落盘的 (department, username) 供 IngestResponse 下发。
    let (final_department, final_username) = upsert_host(
        &tx,
        req.machine_id.as_str(),
        uid,
        req.username.as_str(),
        ip_list_json.as_str(),
        now.as_str(),
        req.department.as_deref(),
        req.events.len() as i64,
    )?;

    // rustnetec: 决策 A —— 写入可达率样本（幂等）。
    if !req.reachability.is_empty() {
        insert_reachability_samples(&tx, req.machine_id.as_str(), &req.reachability)?;
    }

    // rustnetec: 决策 2-B —— 同步写 server_aggregates 分钟桶。
    // 仅当本批次有实际插入的事件时才写桶，避免空批次产生零桶。
    if accepted > 0 {
        write_minute_aggregates(&tx, req.machine_id.as_str(), uid, &req.events)?;
    }

    tx.commit()?;

    let total = req.events.len() as u64;
    let duplicates = total.saturating_sub(accepted);

    Ok(IngestResponse {
        accepted,
        duplicates,
        cursor: max_local_id,
        // rustnetec: 下发当前 department/username 给客户端同步。
        // None 表示"无值/无变更"，客户端据此决定是否更新本地 config。
        department_override: final_department,
        username_override: final_username,
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

/// Upsert the host registry row.
///
/// rustnetec: 字段级 30 分钟覆盖校验（department/username）：
///
/// - **department**
///   - `department_source='admin'` → 保持服务端值（管理员锁定，忽略客户端）
///   - `department_source='client'` 且客户端值 == 当前值 → 保持（未变更）
///   - `department_source='client'` 且客户端值 != 当前值 且距上次变更 < 30min → 保持（拒绝覆盖）
///   - `department_source='client'` 且客户端值 != 当前值 且距上次变更 >= 30min → 覆盖，更新 `department_updated_at`
///
/// - **username**（对称逻辑，`username_locked` 0/1 代替 `department_source`）
///   - `username_locked=1` → 保持服务端值
///   - `username_locked=0` 且客户端值 == 当前值 → 保持
///   - `username_locked=0` 且客户端值 != 当前值 且 < 30min → 保持
///   - `username_locked=0` 且客户端值 != 当前值 且 >= 30min → 覆盖，更新 `username_updated_at`
///
/// `first_seen` is preserved on conflict (not in the UPDATE SET);
/// `event_count` accumulates.
///
/// # Returns
/// `(final_department, final_username)` —— 落盘后的值，供 `IngestResponse` 下发。
#[allow(clippy::too_many_arguments)]
fn upsert_host(
    tx: &Transaction,
    machine_id: &str,
    user_id: i64,
    client_username: &str,
    ip_list_json: &str,
    now: &str,
    client_department: Option<&str>,
    event_count_delta: i64,
) -> Result<(Option<String>, Option<String>)> {
    // ---- 1. SELECT 当前 server_hosts 行（若存在）----
    let existing: Option<HostRow> = tx
        .prepare("SELECT department, department_source, department_updated_at, \
                  username, username_locked, username_updated_at \
                  FROM server_hosts WHERE machine_id = ?1")
        .context("prepare SELECT server_hosts for upsert")?
        .query_row(params![machine_id], |r| {
            Ok(HostRow {
                department: r.get::<_, Option<String>>(0)?,
                department_source: r.get::<_, String>(1)?,
                department_updated_at: r.get::<_, Option<String>>(2)?,
                username: r.get::<_, Option<String>>(3)?,
                username_locked: r.get::<_, i64>(4)?,
                username_updated_at: r.get::<_, Option<String>>(5)?,
            })
        })
        .ok();

    // ---- 2. 计算 department 新值 ----
    let (new_department, new_department_source, new_department_updated_at) =
        compute_department(existing.as_ref(), client_department, now)?;

    // ---- 3. 计算 username 新值 ----
    let (new_username_opt, new_username_locked, new_username_updated_at) =
        compute_username(existing.as_ref(), client_username, now);

    // ---- 4. UPSERT ----
    // 注意：department/username 的更新逻辑由 Rust 层计算后传入，
    // 避免在 SQL CASE 中处理时间运算（SQLite 无原生时间类型）。
    tx.prepare_cached(
        r#"
        INSERT INTO server_hosts (
            machine_id, user_id, username, ip_list,
            first_seen, last_seen, event_count,
            department, department_source, department_updated_at,
            username_locked, username_updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(machine_id) DO UPDATE SET
            user_id               = excluded.user_id,
            username              = excluded.username,
            ip_list               = excluded.ip_list,
            last_seen             = excluded.last_seen,
            event_count           = server_hosts.event_count + excluded.event_count,
            department            = excluded.department,
            department_source     = excluded.department_source,
            department_updated_at = excluded.department_updated_at,
            username_locked       = excluded.username_locked,
            username_updated_at   = excluded.username_updated_at
        -- first_seen intentionally NOT updated (preserves original registration)
        "#,
    )?
    .execute(params![
        machine_id,
        user_id,
        new_username_opt,
        ip_list_json,
        now, // first_seen (only used on initial INSERT)
        now, // last_seen
        event_count_delta,
        new_department,
        new_department_source,
        new_department_updated_at,
        new_username_locked,
        new_username_updated_at,
    ])?;

    // ---- 5. 返回落盘后的值 ----
    // username：INSERT 用 Option<String>，但 server_hosts.username 是 NOT NULL。
    // 新插入时若 client_username 为空，用 machine_id 兜底（避免 NOT NULL 违约）。
    let final_username = new_username_opt.or_else(|| Some(machine_id.to_string()));
    Ok((new_department, final_username))
}

/// 一行 `server_hosts` 的字段级覆盖校验所需字段。
struct HostRow {
    department: Option<String>,
    department_source: String,
    department_updated_at: Option<String>,
    username: Option<String>,
    username_locked: i64,
    username_updated_at: Option<String>,
}

/// 计算 department 落盘值、source、updated_at。
///
/// - 首次注册（existing=None）→ 写入客户端值（可能 NULL），source='client'，updated_at=NULL
/// - source='admin' → 保持服务端值不变
/// - source='client' 且客户端值未变 → 保持不变
/// - source='client' 且客户端值变更且 >= 30min → 覆盖，更新 updated_at
/// - source='client' 且客户端值变更且 < 30min → 保持不变（拒绝覆盖）
fn compute_department(
    existing: Option<&HostRow>,
    client_department: Option<&str>,
    now: &str,
) -> Result<(Option<String>, String, Option<String>)> {
    let Some(row) = existing else {
        // 首次注册
        return Ok((
            client_department.map(|s| s.to_string()),
            "client".to_string(),
            None,
        ));
    };

    // source='admin' → 锁定，保持服务端值
    if row.department_source == "admin" {
        return Ok((
            row.department.clone(),
            row.department_source.clone(),
            row.department_updated_at.clone(),
        ));
    }

    // source='client' → 检查客户端值是否变更
    let client_val = client_department.map(|s| s.to_string());
    if client_val == row.department {
        // 未变更，保持
        return Ok((
            row.department.clone(),
            row.department_source.clone(),
            row.department_updated_at.clone(),
        ));
    }

    // 客户端值变更 → 检查 30min 冷却
    if within_cooldown(row.department_updated_at.as_deref(), now) {
        // 冷却期内，拒绝覆盖，保持原值
        log::debug!(
            "upsert_host: department override rejected (within {}s cooldown), \
             machine kept old value",
            FIELD_OVERRIDE_COOLDOWN_SECS
        );
        return Ok((
            row.department.clone(),
            row.department_source.clone(),
            row.department_updated_at.clone(),
        ));
    }

    // 通过冷却，覆盖
    Ok((client_val, "client".to_string(), Some(now.to_string())))
}

/// 计算 username 落盘值、locked、updated_at。
///
/// 逻辑对称于 [`compute_department`]，用 `username_locked` (0/1) 代替 `department_source`。
fn compute_username(
    existing: Option<&HostRow>,
    client_username: &str,
    now: &str,
) -> (Option<String>, i64, Option<String>) {
    let Some(row) = existing else {
        // 首次注册
        return (
            Some(client_username.to_string()),
            0,
            None,
        );
    };

    // locked=1 → 锁定，保持服务端值
    if row.username_locked == 1 {
        return (
            row.username.clone(),
            row.username_locked,
            row.username_updated_at.clone(),
        );
    }

    // locked=0 → 检查客户端值是否变更
    let client_val = client_username.to_string();
    if Some(client_val.clone()) == row.username {
        // 未变更，保持
        return (
            row.username.clone(),
            row.username_locked,
            row.username_updated_at.clone(),
        );
    }

    // 客户端值变更 → 检查 30min 冷却
    if within_cooldown(row.username_updated_at.as_deref(), now) {
        // 冷却期内，拒绝覆盖
        return (
            row.username.clone(),
            row.username_locked,
            row.username_updated_at.clone(),
        );
    }

    // 通过冷却，覆盖
    (Some(client_val), 0, Some(now.to_string()))
}

/// 判断 `updated_at` 距 `now` 是否在冷却期内（< FIELD_OVERRIDE_COOLDOWN_SECS）。
///
/// - `updated_at=None` → 视为"无历史变更"，不在冷却期（返回 false）
/// - 时间解析失败 → 视为不在冷却期（宽松，允许覆盖）
fn within_cooldown(updated_at: Option<&str>, now: &str) -> bool {
    let Some(ts_str) = updated_at else {
        return false;
    };
    let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
        Ok(dt) => dt.timestamp(),
        Err(_) => return false,
    };
    let now_ts = match chrono::DateTime::parse_from_rfc3339(now) {
        Ok(dt) => dt.timestamp(),
        Err(_) => return false,
    };
    (now_ts - ts) < FIELD_OVERRIDE_COOLDOWN_SECS
}

/// rustnetec: 决策 A —— 批量插入可达率样本（幂等）。
///
/// `INSERT INTO server_reachability ... ON CONFLICT(machine_id, ts) DO NOTHING`：
/// 同一 (machine_id, ts) 已存在时跳过，避免重复上报导致主键冲突。
fn insert_reachability_samples(
    tx: &Transaction,
    machine_id: &str,
    samples: &[ReachabilitySample],
) -> Result<()> {
    let mut stmt = tx.prepare_cached(
        r#"
        INSERT INTO server_reachability
            (machine_id, ts, reachable, latency_ms, targets_ok, targets_total)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(machine_id, ts) DO NOTHING
        "#,
    )?;

    for s in samples {
        stmt.execute(params![
            machine_id,
            s.ts,
            s.reachable,
            s.latency_ms,
            s.targets_ok,
            s.targets_total,
        ])?;
    }

    Ok(())
}

/// rustnetec: 决策 2-B —— 写 server_aggregates 分钟桶。
///
/// 遍历本批次 events，按 `timestamp`（unix millis）截断到分钟，
/// `INSERT INTO server_aggregates ... ON CONFLICT(bucket_ts, bucket_width, machine_id)
///  DO UPDATE SET bytes_rx += excluded.bytes_rx, ...`。
///
/// **注意**：`ClientEvent.timestamp` 是 unix millis (i64)，
/// `server_aggregates.bucket_ts` 是 RFC 3339 文本。
/// 需将 millis → UTC 分钟 → RFC 3339。
///
/// 空批次不调用此函数（`ingest_write` 中 `accepted > 0` 守卫）。
fn write_minute_aggregates(
    tx: &Transaction,
    machine_id: &str,
    user_id: i64,
    events: &[ClientEvent],
) -> Result<()> {
    // 按分钟桶聚合本批次 events
    use std::collections::BTreeMap;
    let mut buckets: BTreeMap<i64, AggAcc> = BTreeMap::new();

    for ev in events {
        // timestamp 是 unix millis，截断到分钟（60000ms）
        let minute_millis = ev.timestamp - (ev.timestamp.rem_euclid(60_000));
        let acc = buckets.entry(minute_millis).or_default();
        acc.bytes_rx += ev.bytes_recv as i64;
        acc.bytes_tx += ev.bytes_sent as i64;
        acc.conn_count += 1;
    }

    let mut stmt = tx.prepare_cached(
        r#"
        INSERT INTO server_aggregates
            (bucket_ts, bucket_width, machine_id, user_id,
             bytes_rx, bytes_tx, conn_count)
        VALUES (?, 'minute', ?, ?, ?, ?, ?)
        ON CONFLICT (bucket_ts, bucket_width, machine_id) DO UPDATE SET
            bytes_rx    = server_aggregates.bytes_rx + excluded.bytes_rx,
            bytes_tx    = server_aggregates.bytes_tx + excluded.bytes_tx,
            conn_count  = server_aggregates.conn_count + excluded.conn_count
        "#,
    )?;

    for (minute_millis, acc) in &buckets {
        // unix millis → UTC DateTime → RFC 3339
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(*minute_millis)
            .context("invalid minute bucket timestamp")?;
        let bucket_ts = dt.format("%Y-%m-%dT%H:%M:00+00:00").to_string();

        stmt.execute(params![
            bucket_ts,
            machine_id,
            user_id,
            acc.bytes_rx,
            acc.bytes_tx,
            acc.conn_count,
        ])?;
    }

    Ok(())
}

/// 分钟桶聚合累加器。
#[derive(Default)]
struct AggAcc {
    bytes_rx: i64,
    bytes_tx: i64,
    conn_count: i64,
}
