# proxy_core

**Functional L7 proxy kernel** — a programmable HTTP proxy and backend framework in Rust, inspired by Envoy's filter architecture and OpenResty's extensibility.


---

## Philosophy

| Principle | How |
|---|---|
| **Ownership-driven pipeline** | `&mut Request` flows through filters — zero cloning, compiler-enforced single-writer |
| **Streaming by default** | `BodyStream` backed by bounded mpsc — supports multi-GB payloads without buffering |
| **Explicit effects** | `Effects` struct injected into every filter — no global state, fully mockable |
| **Hot reload** | `ArcSwap`-based `ActiveChain` — swap filter chains without dropping connections |
| **Algebraic control flow** | `Verdict::Continue \| Respond` — exhaustive match, no sentinel values |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Control Plane                            │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │ FilterRegistry│──▶│ ChainBuilder │──▶│ ActiveChain       │  │
│  │ (factories)   │    │ (incremental │    │ (ArcSwap, lock-  │  │
│  │              │    │  cache)      │    │  free hot reload) │  │
│  └──────────────┘    └──────────────┘    └────────┬──────────┘  │
└───────────────────────────────────────────────────┼─────────────┘
                                                    │
┌───────────────────────────────────────────────────┼─────────────┐
│                         Data Plane                │             │
│                                                   ▼             │
│  TCP ──▶ Worker ──▶ ┌─────────────────────────────────────┐     │
│  (keep-    (parse,  │         Filter Chain                 │     │
│   alive,    conn    │                                     │     │
│   idle      limits) │  rate_limit → auth → cors →         │     │
│   timeout,          │  access_log → add_header →          │     │
│   graceful          │  phe → encrypt → kv → router        │     │
│   shutdown)         │       │              │              │     │
│                     └───────┼──────────────┼──────────────┘     │
│                             ▼              ▼                    │
│                     Verdict::Respond   RouteTable               │
│                     (short-circuit)    ┌──────────┐             │
│                                       │ HTTP     │             │
│                                       │ upstream │             │
│                                       ├──────────┤             │
│                                       │ redb KV  │             │
│                                       └──────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

### Request Pipeline

```
          on_request (→)                    on_response (←)
              │                                  │
  ┌───────────┼──────────────────────────────────┼────────────┐
  │ Filter 1  │  rate_limit                      │            │
  │           │  check IP quota                  │            │
  │           ▼                                  │            │
  │ Filter 2  │  auth                            │            │
  │           │  verify JWT / API key            │            │
  │           ▼                                  │            │
  │ Filter 3  │  cors                            │  add CORS  │
  │           │  handle preflight OPTIONS        │  headers   │
  │           ▼                                  ▲            │
  │ Filter 4  │  access_log                      │  log req   │
  │           │  record start time               │  + latency │
  │           ▼                                  ▲            │
  │ Filter 5  │  add_header                      │            │
  │           │  inject x-proxy header           │            │
  │           ▼                                  │            │
  │ Filter 6  │  phe                             │            │
  │           │  enroll/verify password-hardened │           │
  │           │  key, store key in metadata      │           │
  │           ▼                                  │            │
  │ Filter 7  │  encrypt                         │  decrypt   │
  │           │  AES-256-GCM body                │  response  │
  │           ▼                                  ▲            │
  │ Filter 8  │  kv                              │            │
  │           │  handle /kv/* CRUD               │            │
  │           ▼                                  │            │
  │ Filter 9  │  router (terminal)               │            │
  │           │  match route → upstream          │            │
  └───────────┴──────────────────────────────────┴────────────┘
```

Each filter receives `&mut Request` + `&Effects` and returns `Verdict`:
- **`Continue`** — pass to next filter (request mutated in-place)
- **`Respond(Response)`** — short-circuit, skip remaining filters

---

## Built-in Filters

| Filter | Phase | Description |
|---|---|---|
| `rate_limit` | request | Per-IP sliding-window rate limiter |
| `auth` | request | JWT (HS256/384/512), API Key (HashMap), Basic Auth (constant-time) |
| `cors` | request + response | CORS preflight (OPTIONS → 204), response header injection |
| `access_log` | request + response | Structured logging: method, path, status, latency (µs), peer addr |
| `add_header` | request | Inject static headers (e.g., `x-proxy: proxy_core/0.1`) |
| `phe` | request | Password-hardened key derivation (P-256), key in metadata only (never in HTTP response) |
| `encrypt` | request + response | AES-256-GCM body encryption/decryption, HMAC key obfuscation |
| `kv` | request | In-process KV store (memory or redb), encrypted at rest |
| `router` | request (terminal) | Route dispatch: prefix, exact, pattern (`/users/:id`) → HTTP/redb upstream |

### PHE Module: Why It Exists

`phe` solves the weak-password problem for encrypted user data in backend services:
- it ties encryption keys to user passwords **and** a server-side hardening secret;
- offline DB dumps are insufficient for password guessing;
- each login guess requires backend/PHE verification (online control + rate limiting);
- encryption keys are not exposed to clients — only placed into request metadata for downstream filters.

This enables a secure flow like: `auth` → `phe` → `encrypt/kv`, where encrypted profile data is only usable after successful password verification.

### PHE Protocol Flow (Implemented)

Enrollment:
1. Server generates `sNonce`, computes `C0`, `C1`, and Schnorr proofs.
2. Backend verifies proofs, computes `HC0`, `HC1` from `(password, cNonce, x)`.
3. Backend samples random `M`, computes `MC`, stores record:
  - `T0 = C0 + HC0`
  - `T1 = C1 + HC1 + MC`
4. Derived encryption key stays backend-side.

Verification:
1. Backend recomputes `HC0`, sends `C0 = T0 - HC0` to server.
2. Server validates and returns `C1` (+ proof) on success.
3. Backend recovers `MC = T1 - C1 - HC1` and derives encryption key.

Rotation:
- server issues update token (`delta = y_new - y_old`);
- records are updated with server-side contribution without requiring plaintext passwords.

### PHE Threat Model and Limitations

What this design protects against:
- **offline password guessing from DB dump** — record data alone is insufficient to validate guesses;
- **key recovery from stored records** — encryption key is reconstructed only after successful PHE verification;
- **key exposure to clients** — PHE-derived key is written to request metadata only, never returned in HTTP payloads.

What it does **not** protect against by itself:
- **online brute force** if rate limiting / lockout is not configured;
- **full backend compromise** (runtime memory + process control);
- **weak operational key management** (e.g. leaked `PHE_SERVER_KEY` / `PHE_CLIENT_KEY`, poor rotation discipline).

Operational requirements:
- keep `PHE_SERVER_KEY`, `PHE_CLIENT_KEY`, and `PROXY_ENCRYPTION_KEY` in a secret manager;
- enable `rate_limit` and authentication before PHE endpoints in production chain;
- rotate PHE server key periodically and apply update token to stored records;
- keep TLS enabled on all client↔backend and backend↔upstream links.

---

## Extension Points

### 1. Custom Filter

Implement the `Filter` trait and register via `FilterFactory`:

```rust
use proxy_core::filter::{Filter, Verdict, Effects};
use proxy_core::types::{Request, Response};
use std::pin::Pin;
use std::future::Future;

pub struct MyFilter { /* config fields */ }

impl Filter for MyFilter {
    fn name(&self) -> &'static str { "my_filter" }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            // Read path params from pattern routes
            if let Some(params) = req.metadata.get::<proxy_core::routing::PathParams>() {
                let id = params.get("id").unwrap();
                fx.log.info("processing", &[("id", id)]);
            }

            // Parse JSON body (SIMD-accelerated via sonic-rs)
            // let payload: MyStruct = req.json_body().await.unwrap();

            // Return JSON response
            // return Verdict::Respond(Response::json(StatusCode::OK, &data));

            Verdict::Continue
        })
    }
}
```

### 2. Typed Metadata

Pass data between filters via compile-time typed keys:

```rust
pub struct UserId;
impl typemap_rev::TypeMapKey for UserId {
    type Value = String;
}

// In auth filter:
req.metadata.insert::<UserId>("user_42".to_string());

// In later filter:
let uid = req.metadata.get::<UserId>().unwrap();
```

Built-in metadata keys: `PathParams`, `AuthIdentity`, `AuthClaims`, `AuthMethod`.

### 3. Body Transform

Stream-process request/response bodies without buffering:

```rust
impl BodyTransform for GzipCompress {
    fn transform_chunk(&mut self, chunk: Bytes) -> Result<Bytes, BodyError> { /* ... */ }
    fn flush(&mut self) -> Result<Option<Bytes>, BodyError> { /* ... */ }
}
req.body_action = BodyAction::Transform(Box::new(GzipCompress::new()));
```

### 4. Route Patterns with Path Parameters

```json
{
  "routes": [
    {
      "match": { "pattern": "/users/:user_id/posts/:post_id" },
      "methods": ["GET"],
      "http": { "url": "http://api-backend:8081" }
    },
    {
      "match": { "prefix": "/static/" },
      "http": { "url": "http://cdn:9090" }
    },
    {
      "match": { "exact": "/healthz" },
      "http": { "url": "http://localhost:8081" }
    }
  ]
}
```

Parameters are injected into `req.metadata` as `PathParams` (`HashMap<String, String>`).

---

## Quick Start

```bash
# Build
cargo build --release

# Run (starts on 127.0.0.1:8080)
cargo run

# With redb KV store support
cargo run --features redb
```

### Test the KV store

```bash
# Write
curl -X PUT http://127.0.0.1:8080/kv/hello -d 'world'

# Read
curl http://127.0.0.1:8080/kv/hello

# List
curl 'http://127.0.0.1:8080/kv/?prefix='

# Delete
curl -X DELETE http://127.0.0.1:8080/kv/hello
```

### Test HTTP proxy

```bash
# Start a backend
python3 -m http.server 9090

# Proxy request
curl http://127.0.0.1:8080/

# Keep-alive
curl -v --http1.1 http://127.0.0.1:8080/kv/hello http://127.0.0.1:8080/kv/
```

### Run tests

```bash
cargo test                  # 224 tests, no redb
cargo test --features redb  # + 20 redb integration tests
```

---

## Configuration

The filter chain is defined as JSON (passed programmatically or from a config file):

```json
{
  "filters": [
    {
      "name": "rate_limit",
      "typed_config": { "max_rps": 100 }
    },
    {
      "name": "auth",
      "typed_config": {
        "strategy": "jwt",
        "jwt_secret": "your-256-bit-secret",
        "jwt_algorithm": "HS256",
        "skip_paths": ["/healthz", "/public"]
      }
    },
    {
      "name": "cors",
      "typed_config": {
        "allowed_origins": ["https://app.example.com"],
        "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
        "allowed_headers": ["Content-Type", "Authorization"],
        "max_age_secs": 86400
      }
    },
    {
      "name": "access_log",
      "typed_config": { "level": "info" }
    },
    {
      "name": "router",
      "typed_config": {
        "routes": [
          {
            "match": { "pattern": "/api/users/:id" },
            "methods": ["GET", "PUT", "DELETE"],
            "http": { "url": "http://users-service:8081" }
          },
          {
            "match": { "prefix": "/" },
            "http": { "url": "http://fallback:9090" }
          }
        ],
        "circuit_breaker": {
          "failure_threshold": 5,
          "recovery_timeout_secs": 30
        }
      }
    }
  ]
}
```

### Minimal production example: `auth -> phe -> encrypt -> kv -> router`

```json
{
  "filters": [
    {
      "name": "auth",
      "typed_config": {
        "strategy": "jwt",
        "jwt_secret": "change-me-256-bit-secret",
        "jwt_algorithm": "HS256"
      }
    },
    {
      "name": "phe",
      "typed_config": {
        "path_prefix": "/phe",
        "server_key_env": "PHE_SERVER_KEY",
        "client_key_env": "PHE_CLIENT_KEY"
      }
    },
    {
      "name": "encrypt",
      "typed_config": {
        "key_env": "PROXY_ENCRYPTION_KEY"
      }
    },
    {
      "name": "kv",
      "typed_config": {
        "path_prefix": "/kv",
        "backend": "redb",
        "db_path": "./proxy.redb",
        "key_env": "PROXY_ENCRYPTION_KEY",
        "encrypt_keys": true,
        "encrypt_values": true
      }
    },
    {
      "name": "router",
      "typed_config": {
        "routes": [
          {
            "match": { "prefix": "/" },
            "http": { "url": "http://127.0.0.1:9090", "timeout_ms": 5000 }
          }
        ]
      }
    }
  ]
}
```

Required environment variables for this example:
- `PHE_SERVER_KEY` — 32-byte hex private key for PHE service side.
- `PHE_CLIENT_KEY` — 32-byte hex private key for backend side.
- `PROXY_ENCRYPTION_KEY` — 32-byte hex key for `encrypt`/`kv` filters.

---

## Module Map

| Module | Lines | Purpose |
|---|---|---|
| `types` | Request, Response, BodyStream, JSON helpers | Core data types with move semantics |
| `filter` | Filter trait, Verdict, Effects, Metrics | Plugin interface + dependency injection |
| `chain` | FilterChain, ActiveChain | Pipeline executor + ArcSwap hot reload |
| `builder` | ChainBuilder, FilterRegistry | Control plane: config → chain (incremental cache) |
| `worker` | Worker, ConnectionTracker | TCP accept, keep-alive, idle timeout, graceful shutdown |
| `routing` | RouteTable, RouteMatcher, PathParams | URL matching: prefix, exact, pattern (`:param`) |
| `upstream` | HttpUpstream, RedbUpstream | Upstream forwarding via reqwest / redb |
| `crypto` | AesGcmCipher, Cipher trait | AES-256-GCM + HMAC-SHA256 + HKDF key derivation |
| `store` | MemoryStore, RedbStore, Store trait | KV abstraction with transparent encryption |
| `circuit_breaker` | CircuitBreaker | Per-upstream Closed/Open/HalfOpen state machine |
| `phe` | PheContext, PheServer, PheClient, PheRecord | Password-hardened encryption protocol on P-256 |
| `filters/*` | 9 built-in filters | See [Built-in Filters](#built-in-filters) |

---

## Features

| Cargo Feature | Default | Description |
|---|---|---|
| `redb` | off | Enable redb embedded KV store backend |

## Key Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `http` + `bytes` | HTTP types |
| `sonic-rs` | SIMD-accelerated JSON (hot path) |
| `serde` + `serde_json` | Serialization (config parsing) |
| `reqwest` | HTTP upstream client (rustls) |
| `aes-gcm` + `hmac` + `sha2` + `hkdf` | Cryptography |
| `p256` + `elliptic-curve` + `subtle` + `zeroize` | PHE primitives (curve math, proofs, constant-time ops, key zeroization) |
| `redb` | Embedded ACID KV store (optional) |
| `jsonwebtoken` | JWT validation |
| `typemap_rev` | Typed heterogeneous metadata |
| `arc-swap` | Lock-free pointer swap (hot reload) |
| `tracing` | Structured logging |

---

## License

MIT
