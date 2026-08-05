# rustnet-server

Centralized server for the rustnetec 二开 project (R4).

## Endpoints

| Method | Path       | Description                          |
| ------ | ---------- | ------------------------------------ |
| POST   | `/ingest`  | Accept a client event batch          |
| GET    | `/query`   | Read-only historical query           |
| GET    | `/stats`   | Aggregate statistics                  |
| GET    | `/health`  | Liveness probe                       |

## Run

```sh
cargo run -p rustnet-server
# Override listen address:
RUSTNET_SERVER_ADDR=0.0.0.0:19810 cargo run -p rustnet-server
```

## Stack

- axum 0.8 + tokio (async)
- rusqlite bundled (SQLite WAL, single writer)
- Shared wire protocol: [`rustnet_core::ingest`](../rustnet-core/src/ingest.rs)
