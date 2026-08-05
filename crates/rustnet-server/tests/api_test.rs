//! T2.4 API integration tests.
//!
//! Covers the full authed chain: token provisioning → POST /ingest →
//! GET /query → GET /stats, plus the auth-negative cases (missing token,
//! wrong role, revoked token).

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use rustnet_core::ingest::{ClientEvent, IngestRequest};
use rustnet_server::api::{build_router, AuthRole};
use rustnet_server::db::{init, ServerDbConfig};
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
    }
}

/// Set up: fresh DB + router, with one token per role provisioned.
/// Returns (router, ingest_token, query_token, admin_token).
fn setup() -> (
    axum::Router,
    String,
    String,
    String,
) {
    let path = tmp_db("api");
    let db = init(&path, &ServerDbConfig::default()).unwrap();

    // Provision tokens directly through the db writer.
    let ingest_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(&mut conn, AuthRole::Ingest, Some("ingest"))
            .unwrap()
            .plaintext
    };
    let query_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(&mut conn, AuthRole::Query, Some("query"))
            .unwrap()
            .plaintext
    };
    let admin_tok = {
        let mut conn = db.lock_writer();
        rustnet_server::api::token::create_token(&mut conn, AuthRole::Admin, Some("admin"))
            .unwrap()
            .plaintext
    };

    let router = build_router(Arc::new(db));
    (router, ingest_tok, query_tok, admin_tok)
}

/// Build a request with an optional Bearer token.
fn authed_request(method: Method, uri: &str, body: Option<Body>, token: Option<&str>) -> Request<Body> {
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
    let req_body = Body::from(
        serde_json::to_vec(&sample_request(vec![ev1, ev2])).unwrap(),
    );
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
        let created = rustnet_server::api::token::create_token(
            &mut conn,
            AuthRole::Admin,
            Some("ops"),
        )
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
