//! T2.4 API integration tests.
//!
//! Covers the full authed chain: token provisioning → POST /ingest →
//! GET /query → GET /stats, plus the auth-negative cases (missing token,
//! wrong role, revoked token).

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use rustnet_core::ingest::{ClientEvent, IngestRequest};
use rustnet_server::api::{AuthRole, build_router};
use rustnet_server::db::{ServerDbConfig, init};
use tower::ServiceExt; // provides Router::oneshot

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp_db(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "rustnet-server-api-{label}-{}-{n}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn sample_event(local_event_id: i64, ts: i64) -> ClientEvent {
    ClientEvent {
        local_event_id,
        timestamp: ts,
        interface: "eth0".into(),
        protocol: "tcp".into(),
        local_ip: "10.0.0.5".into(),
        local_port: 44321,
        remote_ip: "93.184.216.34".into(),
        remote_port: 443,
        state: "ESTABLISHED".into(),
        pid: Some(1234),
        process_name: Some("curl".into()),
        bytes_sent: 1024,
        bytes_recv: 2048,
        packets_sent: 10,
        packets_recv: 20,
        duration_ms: 500,
        service: Some("https".into()),
        sni: Some("example.com".into()),
        geo_country: Some("US".into()),
        geo_city: None,
        dns_name: None,
        k8s: None,
    }
}

fn sample_request(events: Vec<ClientEvent>) -> IngestRequest {
    IngestRequest {
        machine_id: "machine-abc".into(),
        user_id: "12345".into(),
        username: "alice".into(),
        ip_list: vec!["10.0.0.5".into()],
        events,
        department: None,
        reachability: Vec::new(),
    }
}

/// Set up: fresh DB + router, with one token per role provisioned.
/// Returns (router, ingest_token, query_token, admin_token).
///
/// rustnetec: ingest/query tokens are scoped to `machine_id = "machine-abc"`
/// to match `sample_request()`. Admin token is unscoped (full access).
fn setup() -> (axum::Router, String, String, String) {
    let path = tmp_db("api");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    // Provision tokens directly through the db writer.
    let ingest_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Ingest,
            Some("ingest"),
            Some("machine-abc"),
        )
        .unwrap()
        .plaintext
    };
    let query_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Query,
            Some("query"),
            Some("machine-abc"),
        )
        .unwrap()
        .plaintext
    };
    let admin_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Admin,
            Some("admin"),
            None,
        )
        .unwrap()
        .plaintext
    };

    let router = build_router(Arc::new(db));
    (router, ingest_tok, query_tok, admin_tok)
}

/// Build a request with an optional Bearer token.
fn authed_request(
    method: Method,
    uri: &str,
    body: Option<Body>,
    token: Option<&str>,
) -> Request<Body> {
    let is_post = method == Method::POST;
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    // axum's Json extractor requires an application/json content-type for
    // methods that carry a body; harmless for GET (no body).
    if is_post {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(body) = body {
        builder.body(body).unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    }
}

async fn body_to_string(body: Body) -> String {
    use axum::body::to_bytes;
    let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// /health — unauthenticated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_is_unauthenticated() {
    let (router, _, _, _) = setup();
    let resp = router
        .oneshot(authed_request(Method::GET, "/health", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Auth-negative
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ingest_without_token_is_401() {
    let (router, _, _, _) = setup();
    let body = Body::from(serde_json::to_vec(&sample_request(vec![])).unwrap());
    let resp = router
        .oneshot(authed_request(Method::POST, "/ingest", Some(body), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ingest_with_garbage_token_is_401() {
    let (router, _, _, _) = setup();
    let body = Body::from(serde_json::to_vec(&sample_request(vec![])).unwrap());
    let resp = router
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(body),
            Some("not-a-real-token"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn query_token_cannot_ingest_403() {
    let (router, _, query_tok, _) = setup();
    let body = Body::from(serde_json::to_vec(&sample_request(vec![])).unwrap());
    let resp = router
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(body),
            Some(&query_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ingest_token_cannot_query_403() {
    let (router, ingest_tok, _, _) = setup();
    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/query",
            None,
            Some(&ingest_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Full chain with admin token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_full_chain_ingest_query_stats() {
    let (router, _, _, admin_tok) = setup();

    // 1. Ingest two events.
    let ev1 = sample_event(1, 1_700_000_000_000);
    let ev2 = sample_event(2, 1_700_000_001_000);
    let req_body = Body::from(serde_json::to_vec(&sample_request(vec![ev1, ev2])).unwrap());
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(req_body),
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "ingest failed");
    let body = body_to_string(resp.into_body()).await;
    let ingest_resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ingest_resp["accepted"], 2);
    assert_eq!(ingest_resp["duplicates"], 0);
    assert_eq!(ingest_resp["cursor"], 2);

    // 2. Query returns the ingested rows.
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::GET,
            "/query?limit=10",
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        let b = body_to_string(resp.into_body()).await;
        panic!("query failed: {b}");
    }
    let body = body_to_string(resp.into_body()).await;
    let query_resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(query_resp["rows"].as_array().unwrap().len(), 2);

    // 3. Stats reflects the totals.
    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/stats",
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        let b = body_to_string(resp.into_body()).await;
        panic!("stats failed: {b}");
    }
    let body = body_to_string(resp.into_body()).await;
    let stats_resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stats_resp["total_events"], 2);
    // bytes_sent (1024) + bytes_recv (2048) per event × 2 events = 6144
    assert_eq!(stats_resp["total_bytes"], 6144);
    assert_eq!(stats_resp["hosts"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn duplicate_ingest_is_idempotent() {
    let (router, _, _, admin_tok) = setup();

    let ev = sample_event(42, 1_700_000_000_000);
    let req = sample_request(vec![ev]);

    // First ingest: accepted=1.
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(serde_json::to_vec(&req).unwrap())),
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    let body = body_to_string(resp.into_body()).await;
    let r1: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(r1["accepted"], 1);

    // Second ingest of identical event: accepted=0, duplicates=1.
    let resp = router
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(serde_json::to_vec(&req).unwrap())),
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    let body = body_to_string(resp.into_body()).await;
    let r2: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(r2["accepted"], 0);
    assert_eq!(r2["duplicates"], 1);
}

#[tokio::test]
async fn revoked_admin_token_is_401() {
    let path = tmp_db("revoke");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    let admin_tok = {
        let mut conn = db.lock_writer();
        let created =
            rustnet_server::api::token::create_token(&mut conn, AuthRole::Admin, Some("ops"), None)
                .unwrap();
        // Revoke it.
        rustnet_server::api::token::revoke_token(&mut conn, created.id).unwrap();
        created.plaintext
    };

    let router = build_router(Arc::new(db));
    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/query",
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Query params: from/to filtering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_from_to_filter() {
    let (router, _, _, admin_tok) = setup();

    // Ingest 3 events at distinct timestamps.
    let events = vec![
        sample_event(1, 1_000),
        sample_event(2, 2_000),
        sample_event(3, 3_000),
    ];
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(
                serde_json::to_vec(&sample_request(events)).unwrap(),
            )),
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Query with from=1500, to=2500 → only event at ts=2000 matches.
    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/query?from=1500&to=2500",
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let q: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(q["rows"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Query params: parsing via the real axum Query extractor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_params_parsed_from_qs() {
    let (router, _, _, admin_tok) = setup();

    // Ingest one event so /query has something to return; we're really
    // verifying that the `from`/`to`/`limit` query string deserializes
    // into QueryParams without a 400.
    let ev = sample_event(1, 1_700_000_000_000);
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(
                serde_json::to_vec(&sample_request(vec![ev])).unwrap(),
            )),
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/query?from=100&to=200&limit=50",
            None, // no token → 401, but that still proves the extractor ran
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// rustnetec: scope_machine_id isolation tests
// ---------------------------------------------------------------------------

/// Helper: build a DB with two machines' data and provision one scoped
/// query token per machine plus one admin token.
///
/// Returns (router, machine_a_query_tok, machine_b_query_tok, admin_tok).
async fn setup_scope_isolation() -> (axum::Router, String, String, String) {
    use rustnet_core::ingest::ClientEvent;

    fn ev(local_id: i64, ts: i64, proc: &str) -> ClientEvent {
        ClientEvent {
            local_event_id: local_id,
            timestamp: ts,
            interface: "eth0".into(),
            protocol: "tcp".into(),
            local_ip: "10.0.0.5".into(),
            local_port: 44321,
            remote_ip: "93.184.216.34".into(),
            remote_port: 443,
            state: "ESTABLISHED".into(),
            pid: Some(1234),
            process_name: Some(proc.into()),
            bytes_sent: 100,
            bytes_recv: 200,
            packets_sent: 5,
            packets_recv: 10,
            duration_ms: 500,
            service: Some("https".into()),
            sni: Some("example.com".into()),
            geo_country: Some("US".into()),
            geo_city: None,
            dns_name: None,
            k8s: None,
        }
    }

    let path = tmp_db("scope");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    // Provision scoped query tokens + unscoped admin.
    let a_query = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Query,
            Some("query-a"),
            Some("machine-a"),
        )
        .unwrap()
        .plaintext
    };
    let b_query = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Query,
            Some("query-b"),
            Some("machine-b"),
        )
        .unwrap()
        .plaintext
    };
    let admin_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Admin,
            Some("admin"),
            None,
        )
        .unwrap()
        .plaintext
    };

    // Ingest data for machine-a and machine-b via admin token.
    let req_a = IngestRequest {
        machine_id: "machine-a".into(),
        user_id: "1".into(),
        username: "alice".into(),
        ip_list: vec!["10.0.0.5".into()],
        events: vec![ev(1, 1_700_000_000_000, "curl")],
        department: None,
        reachability: Vec::new(),
    };
    let req_b = IngestRequest {
        machine_id: "machine-b".into(),
        user_id: "2".into(),
        username: "bob".into(),
        ip_list: vec!["10.0.0.6".into()],
        events: vec![ev(2, 1_700_000_001_000, "wget")],
        department: None,
        reachability: Vec::new(),
    };

    let router = build_router(Arc::new(db));

    // Ingest both via admin token (unscoped).
    for req in [&req_a, &req_b] {
        let resp = router
            .clone()
            .oneshot(authed_request(
                Method::POST,
                "/ingest",
                Some(Body::from(serde_json::to_vec(req).unwrap())),
                Some(&admin_tok),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    (router, a_query, b_query, admin_tok)
}

#[tokio::test]
async fn scoped_query_token_only_sees_own_machine() {
    let (router, a_query, _b_query, _admin) = setup_scope_isolation().await;

    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::GET,
            "/query",
            None,
            Some(&a_query),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let q: serde_json::Value = serde_json::from_str(&body).unwrap();
    let rows = q["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "scoped token should see only machine-a");
    assert_eq!(rows[0]["machine_id"], "machine-a");
}

#[tokio::test]
async fn admin_token_sees_all_machines() {
    let (router, _a, _b, admin_tok) = setup_scope_isolation().await;

    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/query",
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let q: serde_json::Value = serde_json::from_str(&body).unwrap();
    let rows = q["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "admin should see all machines");
}

#[tokio::test]
async fn scoped_stats_only_count_own_machine() {
    let (router, a_query, _b, _admin) = setup_scope_isolation().await;

    let resp = router
        .oneshot(authed_request(
            Method::GET,
            "/stats",
            None,
            Some(&a_query),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let s: serde_json::Value = serde_json::from_str(&body).unwrap();
    // machine-a has 1 event.
    assert_eq!(s["total_events"], 1);
    let hosts = s["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0]["machine_id"], "machine-a");
}

#[tokio::test]
async fn scoped_ingest_rejects_foreign_machine_id() {
    let (router, _a, _b, admin_tok) = setup_scope_isolation().await;

    // Provision a scoped ingest token bound to machine-a.
    let path = tmp_db("scope-ingest");
    let db = init(&path, &ServerDbConfig::default()).unwrap();
    let a_ingest = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Ingest,
            Some("ingest-a"),
            Some("machine-a"),
        )
        .unwrap()
        .plaintext
    };
    let _admin = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Admin,
            Some("admin"),
            None,
        )
        .unwrap()
        .plaintext
    };
    let r = build_router(Arc::new(db));

    // Payload claims machine-b but token is scoped to machine-a → Forbidden.
    let req = IngestRequest {
        machine_id: "machine-b".into(),
        user_id: "2".into(),
        username: "bob".into(),
        ip_list: vec!["10.0.0.6".into()],
        events: vec![sample_event(1, 1_700_000_000_000)],
        department: None,
        reachability: Vec::new(),
    };
    let resp = r
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(serde_json::to_vec(&req).unwrap())),
            Some(&a_ingest),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Same token, correct machine_id → OK.
    let req_ok = IngestRequest {
        machine_id: "machine-a".into(),
        ..req
    };
    let _ = router
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(serde_json::to_vec(&req_ok).unwrap())),
            Some(&admin_tok),
        ))
        .await;
}

#[tokio::test]
async fn create_token_rejects_admin_with_scope() {
    let path = tmp_db("scope-rules");
    let db = init(&path, &ServerDbConfig::default()).unwrap();
    let mut conn = db.lock_writer();

    let result = rustnet_server::api::token::create_token(
        &mut conn,
        AuthRole::Admin,
        Some("scoped-admin"),
        Some("machine-a"),
    );
    assert!(
        result.is_err(),
        "admin token with scope_machine_id must be rejected"
    );
}

#[tokio::test]
async fn create_token_rejects_query_without_scope() {
    let path = tmp_db("scope-rules-q");
    let db = init(&path, &ServerDbConfig::default()).unwrap();
    let mut conn = db.lock_writer();

    let result = rustnet_server::api::token::create_token(
        &mut conn,
        AuthRole::Query,
        Some("unscoped-query"),
        None,
    );
    assert!(
        result.is_err(),
        "non-admin token without scope_machine_id must be rejected"
    );
}

// ---------------------------------------------------------------------------
// rustnetec: client 角色首次上报自动绑定 + 共享 ingest 上传
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_first_upload_auto_binds_and_queries_own_machine() {
    let path = tmp_db("client-autobind");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    // Unbound client token — operator need not know the machine_id up front.
    let client_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Client,
            Some("client-a"),
            None,
        )
        .unwrap()
        .plaintext
    };

    let router = build_router(Arc::new(db));

    // First upload of machine-a: must succeed and auto-bind the token.
    let mut req = sample_request(vec![sample_event(1, 1_700_000_000_000)]);
    req.machine_id = "machine-a".into();
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::POST,
            "/ingest",
            Some(Body::from(serde_json::to_vec(&req).unwrap())),
            Some(&client_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Query now sees only machine-a (auto-bound scope).
    let resp = router
        .clone()
        .oneshot(authed_request(Method::GET, "/query", None, Some(&client_tok)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let q: serde_json::Value = serde_json::from_str(&body).unwrap();
    let rows = q["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "client token should see only its own machine");
    assert_eq!(rows[0]["machine_id"], "machine-a");
}

#[tokio::test]
async fn unbound_client_query_is_forbidden() {
    let path = tmp_db("client-unbound-query");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    // Unbound client token — no upload yet, no scope yet.
    let client_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Client,
            Some("client-unbound"),
            None,
        )
        .unwrap()
        .plaintext
    };

    let router = build_router(Arc::new(db));

    // Query before any upload: must be Forbidden, NOT a full-data view.
    let resp = router
        .oneshot(authed_request(Method::GET, "/query", None, Some(&client_tok)))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unbound client token must not read any data"
    );
}

#[tokio::test]
async fn unscoped_ingest_uploads_any_machine() {
    let path = tmp_db("ingest-shared");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    // Shared upload token (Ingest, None) — one token serves many machines.
    let shared_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Ingest,
            Some("shared-upload"),
            None,
        )
        .unwrap()
        .plaintext
    };

    let router = build_router(Arc::new(db));

    // Upload machine-a, then machine-b with the same token: both accepted.
    for (i, mid) in ["machine-a", "machine-b"].iter().enumerate() {
        let mut req = sample_request(vec![sample_event(i as i64 + 1, 1_700_000_000_000)]);
        req.machine_id = mid.to_string();
        let resp = router
            .clone()
            .oneshot(authed_request(
                Method::POST,
                "/ingest",
                Some(Body::from(serde_json::to_vec(&req).unwrap())),
                Some(&shared_tok),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "shared ingest token must accept machine {mid}"
        );
    }
}

// ---------------------------------------------------------------------------
// rustnetec: /admin/tokens HTTP 级用例 — admin 数量上限(5) + 共享 ingest 创建
// ---------------------------------------------------------------------------

/// 通过 HTTP 创建 token 并返回响应 JSON。
async fn http_create_token(
    router: &axum::Router,
    admin_tok: &str,
    role: &str,
    description: &str,
    scope_machine_id: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "role": role,
        "description": description,
        "scope_machine_id": scope_machine_id,
    });
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::POST,
            "/admin/tokens",
            Some(Body::from(serde_json::to_vec(&body).unwrap())),
            Some(admin_tok),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let json: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap_or_default();
    (status, json)
}

#[tokio::test]
async fn admin_token_http_limit_is_five() {
    let (router, _ingest, _query, admin_tok) = setup();

    // setup() 已直插 1 个活跃 admin（setup 内 create_token），再建 4 个 → 5 个上限。
    let mut first_admin_id: Option<i64> = None;
    for i in 1..=4 {
        let (status, json) = http_create_token(
            &router,
            &admin_tok,
            "admin",
            &format!("ops-{i}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin #{i} must be created: {json}");
        if i == 1 {
            first_admin_id = json["id"].as_i64();
        }
    }
    let first_admin_id = first_admin_id.expect("first admin id");

    // 第 6 个 admin → 400（而非 500）。
    let (status, json) =
        http_create_token(&router, &admin_tok, "admin", "ops-6", None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "sixth admin must be rejected with 400: {json}"
    );

    // 非 admin token 不受上限约束（共享 ingest 可继续建）。
    let (status, json) = http_create_token(
        &router,
        &admin_tok,
        "ingest",
        "shared-1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "shared ingest must still work: {json}");

    // 吊销一个 admin 后名额释放，可再建。
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::DELETE,
            &format!("/admin/tokens/{first_admin_id}"),
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (status, _) = http_create_token(&router, &admin_tok, "admin", "ops-again", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "revoked admin must free a slot for a new admin"
    );
}

#[tokio::test]
async fn shared_ingest_token_via_http_serves_many_machines() {
    let (router, _ingest, _query, admin_tok) = setup();

    // 经 /admin/tokens 创建共享 ingest token（scope_machine_id = null）。
    let (status, json) =
        http_create_token(&router, &admin_tok, "ingest", "shared-http", None).await;
    assert_eq!(status, StatusCode::OK, "shared ingest creation: {json}");
    let shared_tok = json["plaintext"]
        .as_str()
        .expect("shared ingest plaintext")
        .to_string();
    assert_eq!(json["scope_machine_id"], serde_json::Value::Null);

    // 用该 token 上报两台不同机器，均成功。
    for (i, mid) in ["machine-a", "machine-b"].iter().enumerate() {
        let mut req = sample_request(vec![sample_event(i as i64 + 1, 1_700_000_000_000)]);
        req.machine_id = mid.to_string();
        let resp = router
            .clone()
            .oneshot(authed_request(
                Method::POST,
                "/ingest",
                Some(Body::from(serde_json::to_vec(&req).unwrap())),
                Some(&shared_tok),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "shared ingest must accept machine {mid}"
        );
    }

    // GET /admin/tokens 列表含该共享 ingest（scope 为 null）。
    let resp = router
        .clone()
        .oneshot(authed_request(
            Method::GET,
            "/admin/tokens",
            None,
            Some(&admin_tok),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    let shared: Vec<&serde_json::Value> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["role"] == "ingest" && t["description"] == "shared-http")
        .collect();
    assert_eq!(shared.len(), 1, "shared ingest token listed exactly once");
    assert_eq!(shared[0]["scope_machine_id"], serde_json::Value::Null);
}
