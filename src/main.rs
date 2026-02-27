//! proxy_core — demo server with KV store + HTTP proxy.
//!
//! Starts an L7 proxy with:
//! - **Keep-alive**: persistent TCP connections (idle timeout 60s, max 100 req/conn)
//! - **Graceful shutdown**: Ctrl+C / SIGTERM → drain in-flight, then exit
//! - **Connection limits**: max 1024 concurrent connections (503 when full)
//! - **Circuit breaker**: per-upstream fault isolation (5 failures → 30s open)
//! - Rate limiting (10 req/sec per IP)
//! - KV store at /kv/* with AES-256-GCM encryption at rest
//! - HTTP proxy for all other paths → upstream on 127.0.0.1:9090
//!
//! Quick start:
//!   1. (Optional) Start HTTP backend:  python3 -m http.server 9090
//!   2. Start proxy:                    cargo run
//!   3. Test KV store:
//!      curl -X PUT  http://127.0.0.1:8080/kv/hello -d 'world'
//!      curl         http://127.0.0.1:8080/kv/hello
//!      curl         http://127.0.0.1:8080/kv/
//!      curl -X DELETE http://127.0.0.1:8080/kv/hello
//!   4. Test HTTP proxy:
//!      curl http://127.0.0.1:8080/
//!   5. Test keep-alive:
//!      curl -v --http1.1 http://127.0.0.1:8080/kv/hello http://127.0.0.1:8080/kv/
//!
//! Graceful shutdown:
//!   Press Ctrl+C — server drains in-flight requests, then exits cleanly.

use proxy_core::builder::{ChainBuilder, ChainConfig, FilterRegistry};
use proxy_core::chain::new_active_chain;
use proxy_core::filters::access_log::AccessLogFactory;
use proxy_core::filters::add_header::AddHeaderFactory;
use proxy_core::filters::auth::AuthFactory;
use proxy_core::filters::cors::CorsFactory;
use proxy_core::filters::encrypt::EncryptFactory;
use proxy_core::filters::kv::KvFactory;
use proxy_core::filters::rate_limit::RateLimitFactory;
use proxy_core::filters::router::RouterFactory;
use proxy_core::worker::{Worker, WorkerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("proxy_core starting");

    // --- Control Plane: registry + config → chain ---

    // 1. Register filter factories
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(RateLimitFactory));
    registry.register(Box::new(AuthFactory));
    registry.register(Box::new(CorsFactory));
    registry.register(Box::new(AccessLogFactory));
    registry.register(Box::new(AddHeaderFactory));
    registry.register(Box::new(EncryptFactory));
    registry.register(Box::new(KvFactory));
    registry.register(Box::new(RouterFactory));
    let registry = Arc::new(registry);

    tracing::info!(factories = ?registry.names(), "registered filter factories");

    // Encryption key for KV store (in production: vault / secret manager)
    // Generate with: proxy_core::crypto::AesGcmCipher::generate_key_hex()
    let demo_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::env::set_var("PROXY_ENCRYPTION_KEY", demo_key);

    // 2. Configuration (would come from xDS / config file in production)
    //
    // Chain: rate_limit → add_header → kv → router
    //
    // - /kv/* requests:  handled by kv filter (encrypted at-rest in memory store)
    // - everything else: forwarded to HTTP upstream on :9090
    let config: ChainConfig = serde_json::from_value(serde_json::json!({
        "filters": [
            {
                "name": "rate_limit",
                "typed_config": { "max_rps": 10 }
            },
            {
                "name": "add_header",
                "typed_config": {
                    "header_name": "x-proxy",
                    "header_value": "proxy_core/0.1"
                }
            },
            {
                "name": "kv",
                "typed_config": {
                    "path_prefix": "/kv",
                    "backend": "memory",
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
                            "http": {
                                "url": "http://127.0.0.1:9090",
                                "timeout_ms": 5000
                            }
                        }
                    ],
                    "circuit_breaker": {
                        "failure_threshold": 5,
                        "recovery_timeout_secs": 30,
                        "half_open_max_requests": 3,
                        "success_threshold": 2
                    }
                }
            }
        ]
    }))
    .expect("invalid config");

    // 3. Build chain (incremental builder)
    let mut builder = ChainBuilder::new(Arc::clone(&registry));
    let chain = builder.build(&config).expect("failed to build chain");

    tracing::info!(filters = chain.len(), "filter chain built");

    // 4. Wrap in ActiveChain (ArcSwap for hot reload)
    let active = new_active_chain(chain);

    // --- Data Plane: worker event loop ---

    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("failed to bind 127.0.0.1:8080");

    tracing::info!("listening on http://127.0.0.1:8080");
    tracing::info!("KV store:  PUT/GET/DELETE http://127.0.0.1:8080/kv/{{key}}");
    tracing::info!("KV list:   GET http://127.0.0.1:8080/kv/?prefix=...");
    tracing::info!("HTTP proxy: http://127.0.0.1:8080/ → http://127.0.0.1:9090");
    tracing::info!("encryption: AES-256-GCM (values) + HMAC-SHA256 (keys) at rest");
    tracing::info!("rate limit: 10 req/sec per IP");
    tracing::info!("keep-alive: max 100 req/conn, idle timeout 60s");
    tracing::info!("connections: max 1024 concurrent");
    tracing::info!("circuit breaker: 5 failures → 30s open → half-open probe");
    tracing::info!("graceful shutdown: Ctrl+C / SIGTERM");

    let worker_config = WorkerConfig {
        max_connections: 1024,
        max_requests_per_conn: 100,
        idle_timeout: Duration::from_secs(60),
        max_header_size: 8192,
        drain_timeout: Duration::from_secs(30),
    };

    let worker = Worker::with_config(active, worker_config);
    worker.serve(listener).await;

    tracing::info!("proxy_core stopped");
}
