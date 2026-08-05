//! # rustnet-server
//!
//! Centralized server crate for the rustnetec 二开项目 (R4).
//!
//! Provides:
//! - `POST /ingest` — accept client event batches
//! - `GET /query`   — read-only historical query
//! - `GET /stats`   — aggregate statistics
//! - `GET /health`  — liveness probe
//!
//! The server uses an async stack (axum + tokio) with SQLite (WAL) as the
//! single storage backend. The shared wire protocol lives in
//! [`rustnet_core::ingest`] so both client and server reference one schema
//! (ADR-5).
//!
//! ## Layout
//!
//! - [`api`] — HTTP route handlers and app construction
//! - [`db`]  — SQLite initialization, schema migrations, and writers

pub mod api;
pub mod cleanup;
pub mod db;
