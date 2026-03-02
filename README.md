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
│   idle      limits) │  rate_limit → auth → sso_bridge →   │     │
│   timeout,          │  ldap_sync → rbac → cors →          │     │
│   graceful          │  access_log → audit → add_header →  │     │
│   shutdown)         │  phe → encrypt → kv → router        │     │
│                     │       │              │              │     │
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

---

## Build Framework (Filters)

proxy_core includes a Build Systems a la Carte framework for building and
evolving filter logic with explicit dependency graphs. It is useful for:

- compiling filter chains or filter-specific artifacts from config with
    incremental rebuilds
- modeling complex filter logic as tasks with explicit deps and trace capture
- comparing rebuild strategies (Busy, Memo, Dirty, Make, Excel, Shake)
    under real tests and conformance suites

The framework exposes `Task`, `Store`, `Scheduler`, `Rebuilder`, and trace
tracking to keep filter creation deterministic and testable. It is especially
handy for filters that want to cache derived data, update only dirty parts, or
trace dynamic dependencies during rebuilds.

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
  │ Filter 3  │  sso_bridge                      │            │
  │           │  map trusted IdP/LDAP headers    │            │
  │           ▼                                  │            │
  │ Filter 4  │  ldap_sync                       │            │
  │           │  enrich claims from directory    │            │
  │           ▼                                  │            │
  │ Filter 5  │  rbac                            │            │
  │           │  enforce role/scope permissions  │            │
  │           ▼                                  │            │
  │ Filter 6  │  cors                            │  add CORS  │
  │           │  handle preflight OPTIONS        │  headers   │
  │           ▼                                  ▲            │
  │ Filter 7  │  access_log                      │  log req   │
  │           │  record start time               │  + latency │
  │           ▼                                  ▲            │
  │ Filter 8  │  audit                           │            │
  │           │  hash-chain audit event          │            │
  │           ▼                                  │            │
  │ Filter 9  │  add_header                      │            │
  │           │  inject x-proxy header           │            │
  │           ▼                                  │            │
  │ Filter 10 │  phe                             │            │
  │           │  enroll/verify password-hardened │           │
  │           │  key, store key in metadata      │           │
  │           ▼                                  │            │
  │ Filter 11 │  encrypt                         │  decrypt   │
  │           │  AES-256-GCM body                │  response  │
  │           ▼                                  ▲            │
  │ Filter 12 │  kv                              │            │
  │           │  handle /kv/* CRUD               │            │
  │           ▼                                  │            │
  │ Filter 13 │  router (terminal)               │            │
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
| `rbac` | request | RBAC + lightweight RLS (org/branch scope checks, deny-overrides, route permissions) |
| `cors` | request + response | CORS preflight (OPTIONS → 204), response header injection |
| `access_log` | request + response | Structured logging: method, path, status, latency (µs), peer addr |
| `audit` | request + response | Tamper-evident audit trail with SHA-256 hash chain over events |
| `sso_bridge` | request | Trusted peer header bridge (SSO/LDAP sidecar/gateway) to `AuthIdentity` / `AuthClaims` |
| `ldap_sync` | request | Claims enrichment from directory (groups/roles/org/branch) with TTL cache |
| `add_header` | request | Inject static headers (e.g., `x-proxy: proxy_core/0.1`) |
| `phe` | request | Password-hardened key derivation (P-256), key in metadata only (never in HTTP response) |
| `encrypt` | request + response | AES-256-GCM body encryption/decryption, HMAC key obfuscation |
| `kv` | request | In-process KV store (memory or redb), encrypted at rest |
| `compute` | request | Per-request compute DAG for headers/metadata/verdict |
| `router` | request (terminal) | Route dispatch: prefix, exact, pattern (`/users/:id`) → HTTP/redb upstream |

### Compute Filter (Runtime DAG)

`compute` evaluates a per-request DAG of cells against request inputs, query params,
and typed metadata. It can write headers, metadata, or enforce a verdict.

Key points:
- `query` inputs support repeated keys (become `List` values)
- typed metadata is mapped into `metadata` names (e.g., `auth.claims.role`)
- budgets enforce node, time, and memory limits
- named subgraphs can be expanded with `call` and an optional `prefix`
- fetch callouts can be restricted by scheme/host and response size
- fetch callouts can be capped via `max_fetch_nodes`
- fetch callouts can be restricted by port and path prefix allowlists
- fetch callouts can be restricted by host suffix allowlists
- fetch callouts can be capped by total bytes per request


Minimal config:

```ron
(
    name: "compute",
    typed_config: {
        "max_eval_us": 2000,
        "cells": [
            {"key": "role", "op": "input", "source": {"metadata": "auth.claims.role"}},
            {"key": "is_admin", "op": "compare", "cmp": "eq", "left": "role", "right": {"const": "admin"}},
            {"key": "tier", "op": "cond", "cond": "is_admin", "then_val": {"const": "unlimited"}, "else_val": {"const": "standard"}},
            {"key": "out", "op": "output", "target": {"header": "X-Rate-Tier"}, "source": "tier"}
        ]
    },
)
```

Subgraph example:

```ron
(
    name: "compute",
    typed_config: {
        "subgraphs": [
            {
                "name": "tiering",
                "cells": [
                    {"key": "role", "op": "input", "source": {"metadata": "auth.claims.role"}},
                    {"key": "is_admin", "op": "compare", "cmp": "eq", "left": "role", "right": {"const": "admin"}},
                    {"key": "tier", "op": "cond", "cond": "is_admin", "then_val": {"const": "unlimited"}, "else_val": {"const": "standard"}}
                ]
            }
        ],
        "cells": [
            {"key": "calc", "op": "call", "subgraph": "tiering"},
            {"key": "out", "op": "output", "target": {"header": "X-Rate-Tier"}, "source": "calc.tier"}
        ]
    },
)
```

Fetch allowlist example:

```ron
(
    name: "compute",
    typed_config: {
        "fetch_allow_schemes": ["https"],
        "fetch_allow_hosts": ["api.example.com"],
        "fetch_allow_host_suffixes": ["example.org"],
        "fetch_allow_ports": [443],
        "fetch_allow_path_prefixes": ["/v1", "/v2"],
        "fetch_max_bytes": 32768,
        "cells": [
            {"key": "url", "op": "const", "value": "https://api.example.com/v1/health"},
            {"key": "resp", "op": "fetch", "url": "url", "timeout_ms": 100},
            {"key": "out", "op": "output", "target": {"metadata": "fetch.body"}, "source": "resp"}
        ]
    },
)
```

### PHE Module: Why It Exists

`phe` solves the weak-password problem for encrypted user data in backend services:
- it ties encryption keys to user passwords **and** a server-side hardening secret;
- offline DB dumps are insufficient for password guessing;
- each login guess requires backend/PHE verification (online control + rate limiting);
- encryption keys are not exposed to clients — only placed into request metadata for downstream filters.

This enables a secure flow like: `auth` → `rbac` → `phe` → `encrypt/kv`, where encrypted profile data is only usable after successful password verification and authorization.

### RBAC + RLS Filter (Iteration 1)

`rbac` consumes metadata from `auth` (`AuthIdentity`, `AuthClaims`) and enforces:
- **role permissions**: claims (`role` / `roles`) map to permission sets from config;
- **group expansion**: claims `groups` map to roles (e.g., AD/LDAP sync output);
- **route rules**: per-path-prefix + HTTP method permission checks;
- **deny-overrides**: global or per-rule `deny_actions` always block;
- **scope guard (RLS-lite)**: request headers (`x-org-id`, `x-branch-id`) must match claims (`org_id`, `branch_id`).

If identity/claims are missing, or scope/permissions fail, filter short-circuits with `401/403`.

### Audit Filter (Iteration 2)

`audit` emits one event per request on response path and links events with hash chain:
- `H_0 = 00..00`;
- `H_n = SHA256(H_{n-1} || event_payload)`.

This provides tamper evidence for runtime audit streams (order + mutation detection).
Filter is designed to run after `auth`/`rbac` so identity and authorization context are included.

Recommended chain segment: `auth -> rbac -> access_log -> audit -> ...`

Minimal config:

```ron
(
    name: "audit",
    typed_config: {
        "skip_paths": ["/health", "/ready"],
        "include_claims": ["org_id", "branch_id", "role"],
    },
)
```

### SSO/LDAP Bridge Filter (Iteration 3)

`sso_bridge` is needed when identity is established upstream (IdP gateway, ingress, LDAP bridge)
and delivered as trusted headers. Filter maps those headers into typed metadata used by `rbac`:
- validates request peer against `trusted_peer_ips`;
- rejects untrusted attempts to inject identity headers;
- maps `x-auth-user` / `x-auth-groups` / `x-auth-roles` and scope headers into claims;
- sets `AuthMethod = sso_bridge` for downstream audit.

Recommended segment: `auth(optional jwt) -> sso_bridge -> ldap_sync(optional) -> rbac -> audit -> ...`

Minimal config:

```ron
(
    name: "sso_bridge",
    typed_config: {
        "trusted_peer_ips": ["127.0.0.1"],
        "require_trusted_peer": true,
        "deny_untrusted_with_headers": true,
        "identity_header": "x-auth-user",
        "groups_header": "x-auth-groups",
        "roles_header": "x-auth-roles",
        "org_header": "x-org-id",
        "branch_header": "x-branch-id",
        "separator": ",",
    },
)
```

### LDAP Sync Filter (Iteration 4)

`ldap_sync` enriches principal claims from a directory source before authorization.
Current implementation provides a safe baseline with static directory + in-memory TTL cache:
- requires authenticated identity (`AuthIdentity`) by default;
- resolves groups/roles/org/branch by principal;
- applies `group_role_map` expansion;
- caches enrichment data for configured TTL.

Recommended segment: `sso_bridge -> ldap_sync -> rbac`.

If `ldap_sync` is enabled, preferred IAM segment is:
`auth(optional jwt) -> sso_bridge -> ldap_sync -> rbac -> audit`.

Minimal config:

```ron
(
    name: "ldap_sync",
    typed_config: {
        "cache_ttl_secs": 60,
        "require_identity": true,
        "directory": {
            "alice": {
                "groups": ["finance"],
                "roles": ["accountant"],
                "org_id": "org-1",
                "branch_id": "b-1",
            },
        },
        "group_role_map": {
            "finance": ["report_viewer"],
        },
    },
)
```

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

```ron
(
    routes: [
        (
            match: {"pattern": "/users/:user_id/posts/:post_id"},
            methods: ["GET"],
            http: {"url": "http://api-backend:8081"},
        ),
        (
            match: {"prefix": "/static/"},
            http: {"url": "http://cdn:9090"},
        ),
        (
            match: {"exact": "/healthz"},
            http: {"url": "http://localhost:8081"},
        ),
    ],
)
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
cargo test                  # current default test suite
cargo test --features redb  # includes redb integration tests
```

---

## Configuration

The filter chain is defined in RON (Rust Object Notation) — passed programmatically or from a config file:

```ron
(
    filters: [
        (
            name: "rate_limit",
            typed_config: {"max_rps": 100},
        ),
        (
            name: "auth",
            typed_config: {
                "strategy": "jwt",
                "jwt": {
                    "secret": "your-256-bit-secret",
                    "algorithm": "HS256",
                },
                "skip_paths": ["/healthz", "/public"],
            },
        ),
        (
            name: "cors",
            typed_config: {
                "allowed_origins": ["https://app.example.com"],
                "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
                "allowed_headers": ["Content-Type", "Authorization"],
                "max_age_secs": 86400,
            },
        ),
        (
            name: "access_log",
            typed_config: {"level": "info"},
        ),
        (
            name: "router",
            typed_config: {
                "routes": [
                    (
                        match: {"pattern": "/api/users/:id"},
                        methods: ["GET", "PUT", "DELETE"],
                        http: {"url": "http://users-service:8081"},
                    ),
                    (
                        match: {"prefix": "/"},
                        http: {"url": "http://fallback:9090"},
                    ),
                ],
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "recovery_timeout_secs": 30,
                },
            },
        ),
    ],
)
```

### Minimal production example: `auth -> sso_bridge -> ldap_sync -> rbac -> audit -> phe -> encrypt -> kv -> router`

```ron
(
    filters: [
        (
            name: "auth",
            typed_config: {
                "strategy": "jwt",
                "jwt": {
                    "secret": "change-me-256-bit-secret",
                    "algorithm": "HS256",
                },
            },
        ),
        (
            name: "sso_bridge",
            typed_config: {
                "trusted_peer_ips": ["127.0.0.1"],
                "require_trusted_peer": true,
                "deny_untrusted_with_headers": true,
                "identity_header": "x-auth-user",
                "groups_header": "x-auth-groups",
                "roles_header": "x-auth-roles",
                "org_header": "x-org-id",
                "branch_header": "x-branch-id",
                "separator": ",",
            },
        ),
        (
            name: "ldap_sync",
            typed_config: {
                "cache_ttl_secs": 60,
                "require_identity": true,
                "directory": {
                    "alice": {
                        "groups": ["finance"],
                        "roles": ["accountant"],
                        "org_id": "org-1",
                        "branch_id": "b-1",
                    },
                },
                "group_role_map": {
                    "finance": ["report_viewer"],
                },
            },
        ),
        (
            name: "rbac",
            typed_config: {
                "default_deny": true,
                "deny_actions": ["doc:post"],
                "roles": {
                    "accountant": ["doc:view", "doc:edit"],
                    "manager": ["doc:view", "doc:approve"],
                },
                "groups": {
                    "finance": ["accountant"],
                },
                "rules": [
                    {
                        "path_prefix": "/docs",
                        "methods": ["GET"],
                        "permissions": ["doc:view"],
                        "action": "doc:view",
                    },
                    {
                        "path_prefix": "/docs",
                        "methods": ["PUT"],
                        "permissions": ["doc:edit"],
                        "action": "doc:edit",
                    },
                ],
                "scope": {
                    "org_claim": "org_id",
                    "org_header": "x-org-id",
                    "branch_claim": "branch_id",
                    "branch_header": "x-branch-id",
                },
            },
        ),
        (
            name: "audit",
            typed_config: {
                "skip_paths": ["/health", "/ready"],
                "include_claims": ["org_id", "branch_id", "role"],
            },
        ),
        (
            name: "phe",
            typed_config: {
                "path_prefix": "/phe",
                "server_key_env": "PHE_SERVER_KEY",
                "client_key_env": "PHE_CLIENT_KEY",
            },
        ),
        (
            name: "encrypt",
            typed_config: {
                "key_env": "PROXY_ENCRYPTION_KEY",
            },
        ),
        (
            name: "kv",
            typed_config: {
                "path_prefix": "/kv",
                "backend": "redb",
                "db_path": "./proxy.redb",
                "key_env": "PROXY_ENCRYPTION_KEY",
                "encrypt_keys": true,
                "encrypt_values": true,
            },
        ),
        (
            name: "router",
            typed_config: {
                "routes": [
                    {
                        "match": {"prefix": "/"},
                        "http": {"url": "http://127.0.0.1:9090", "timeout_ms": 5000},
                    },
                ],
            },
        ),
    ],
)
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
| `filters/*` | 13 built-in filters | See [Built-in Filters](#built-in-filters) |

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
| `serde` + `serde_json` + `ron` | Serialization (RON config parsing, JSON runtime interchange) |
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
