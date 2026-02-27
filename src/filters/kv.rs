//! KV filter — REST API for the encrypted KV store.
//!
//! Exposes a simple key-value API over HTTP:
//! ```text
//! GET    /kv/{key}           → read value
//! PUT    /kv/{key}  body=... → write value
//! DELETE /kv/{key}           → delete key
//! GET    /kv/                → list all keys
//! GET    /kv/?prefix=x       → list keys with prefix
//! GET    /kv/?prefix=x&limit=50
//! ```
//!
//! Placed as a **semi-terminal** filter in the chain:
//! - Requests matching the path prefix → handled here (`Verdict::Respond`)
//! - Other requests → passed through (`Verdict::Continue`) to downstream filters
//!
//! ## Configuration
//! ```json
//! {
//!   "name": "kv",
//!   "typed_config": {
//!     "path_prefix": "/kv",
//!     "backend": "memory",
//!     "key_env": "PROXY_ENCRYPTION_KEY",
//!     "encrypt_keys": true,
//!     "encrypt_values": true
//!   }
//! }
//! ```
//!
//! ## Encryption
//! When `key_env` or `key_hex` is set, the store encrypts data transparently:
//! - **Values**: AES-256-GCM encrypted at rest
//! - **Keys**: HMAC-SHA256 hashed (when `encrypt_keys = true`)
//!
//! The encryption happens at the store level — data is encrypted before
//! it reaches the backend and decrypted after retrieval.

use crate::builder::FilterFactory;
use crate::crypto::{AesGcmCipher, Cipher};
use crate::filter::{Effects, Filter, Verdict};
use crate::store::{MemoryStore, Store, StoreError};
use crate::types::{Request, Response};
use bytes::Bytes;
use http::StatusCode;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// ─── Filter ─────────────────────────────────────────────────────────

/// KV store filter — semi-terminal filter for key-value operations.
///
/// Intercepts requests matching `path_prefix` and executes CRUD operations
/// against the configured store backend. Non-matching requests pass through.
pub struct KvFilter {
    store: Arc<Store>,
    path_prefix: String,
}

impl Filter for KvFilter {
    fn name(&self) -> &'static str {
        "kv"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            let path = req.uri.path().to_owned();

            // Only handle paths matching our prefix
            let key_path = if path == self.path_prefix || path == format!("{}/", self.path_prefix) {
                "" // List operation (prefix itself or prefix/)
            } else if let Some(rest) = path.strip_prefix(&format!("{}/", self.path_prefix)) {
                rest
            } else {
                // Not our path — pass through to next filter
                return Verdict::Continue;
            };

            let key = key_path.trim_start_matches('/');

            let result = match req.method {
                http::Method::GET => {
                    if key.is_empty() {
                        self.handle_list(req, fx).await
                    } else {
                        self.handle_get(key, fx).await
                    }
                }
                http::Method::PUT | http::Method::POST => {
                    if key.is_empty() {
                        Ok(Response::error(
                            StatusCode::BAD_REQUEST,
                            b"key required in path\n",
                        ))
                    } else {
                        self.handle_set(key, req, fx).await
                    }
                }
                http::Method::DELETE => {
                    if key.is_empty() {
                        Ok(Response::error(
                            StatusCode::BAD_REQUEST,
                            b"key required in path\n",
                        ))
                    } else {
                        self.handle_delete(key, fx).await
                    }
                }
                _ => Ok(Response::error(
                    StatusCode::METHOD_NOT_ALLOWED,
                    b"Method Not Allowed\n",
                )),
            };

            match result {
                Ok(resp) => Verdict::Respond(resp),
                Err(e) => {
                    fx.log.error("kv store error", &[("error", &e.to_string())]);
                    Verdict::Respond(Response::error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error\n",
                    ))
                }
            }
        })
    }
}

impl KvFilter {
    /// Handle GET /kv/{key} — read a value.
    async fn handle_get(&self, key: &str, fx: &Effects) -> Result<Response, StoreError> {
        fx.metrics.counter_inc("kv.get");

        match self.store.get(key).await {
            Ok(value) => {
                fx.metrics.counter_inc("kv.get.hit");
                let len = value.len();
                let mut resp = Response::from_bytes(StatusCode::OK, Bytes::from(value));

                // Try to detect content type
                resp.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/octet-stream"),
                );
                resp.headers.insert(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from_str(&len.to_string())
                        .unwrap_or_else(|_| http::HeaderValue::from_static("0")),
                );

                Ok(resp)
            }
            Err(StoreError::NotFound) => {
                fx.metrics.counter_inc("kv.get.miss");
                Ok(json_error_response(StatusCode::NOT_FOUND, "key not found"))
            }
            Err(e) => Err(e),
        }
    }

    /// Handle PUT/POST /kv/{key} — write a value.
    async fn handle_set(
        &self,
        key: &str,
        req: &Request,
        fx: &Effects,
    ) -> Result<Response, StoreError> {
        fx.metrics.counter_inc("kv.set");

        let body = req
            .body
            .collect()
            .await
            .map_err(|e| StoreError::Backend(format!("body read: {e}")))?;

        self.store.set(key, &body).await?;

        fx.metrics.counter_inc("kv.set.ok");
        tracing::debug!(key, bytes = body.len(), "kv: set");

        let json = serde_json::json!({
            "status": "created",
            "key": key,
            "size": body.len()
        });
        let json_bytes = serde_json::to_vec(&json)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let len = json_bytes.len();

        let mut resp = Response::from_bytes(StatusCode::CREATED, Bytes::from(json_bytes));
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        resp.headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&len.to_string())
                .unwrap_or_else(|_| http::HeaderValue::from_static("0")),
        );

        Ok(resp)
    }

    /// Handle DELETE /kv/{key} — delete a key.
    async fn handle_delete(&self, key: &str, fx: &Effects) -> Result<Response, StoreError> {
        fx.metrics.counter_inc("kv.delete");

        let existed = self.store.delete(key).await?;

        if existed {
            fx.metrics.counter_inc("kv.delete.ok");
            tracing::debug!(key, "kv: deleted");

            let json = serde_json::json!({ "status": "deleted", "key": key });
            let json_bytes = serde_json::to_vec(&json)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let len = json_bytes.len();

            let mut resp = Response::from_bytes(StatusCode::OK, Bytes::from(json_bytes));
            resp.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            resp.headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&len.to_string())
                    .unwrap_or_else(|_| http::HeaderValue::from_static("0")),
            );
            Ok(resp)
        } else {
            fx.metrics.counter_inc("kv.delete.miss");
            Ok(json_error_response(StatusCode::NOT_FOUND, "key not found"))
        }
    }

    /// Handle GET /kv/ or GET /kv/?prefix=xxx — list keys.
    async fn handle_list(&self, req: &Request, fx: &Effects) -> Result<Response, StoreError> {
        fx.metrics.counter_inc("kv.list");

        let query = req.uri.query().unwrap_or("");
        let prefix = parse_query_param(query, "prefix").unwrap_or("");
        let limit: usize = parse_query_param(query, "limit")
            .and_then(|l| l.parse().ok())
            .unwrap_or(100);

        let entries = self.store.list(prefix, limit).await?;

        let json_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                // Try to show value as UTF-8 string; fall back to hex
                let value_display = match std::str::from_utf8(&e.value) {
                    Ok(s) => serde_json::Value::String(s.to_string()),
                    Err(_) => {
                        let hex: String = e.value.iter().map(|b| format!("{b:02x}")).collect();
                        serde_json::Value::String(format!("hex:{hex}"))
                    }
                };
                serde_json::json!({
                    "key": e.key,
                    "value": value_display,
                    "size": e.value.len(),
                })
            })
            .collect();

        let json = serde_json::json!({
            "count": json_entries.len(),
            "prefix": prefix,
            "limit": limit,
            "entries": json_entries,
        });

        let json_bytes = serde_json::to_vec_pretty(&json)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let len = json_bytes.len();

        let mut resp = Response::from_bytes(StatusCode::OK, Bytes::from(json_bytes));
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        resp.headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&len.to_string())
                .unwrap_or_else(|_| http::HeaderValue::from_static("0")),
        );

        Ok(resp)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Parse a query parameter from a URL query string.
fn parse_query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == name {
            Some(v)
        } else {
            None
        }
    })
}

/// Create a JSON error response.
fn json_error_response(status: StatusCode, message: &str) -> Response {
    let json = serde_json::json!({ "error": message });
    let body = serde_json::to_vec(&json).unwrap_or_else(|_| message.as_bytes().to_vec());
    let len = body.len();

    let mut resp = Response::from_bytes(status, Bytes::from(body));
    resp.headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    resp.headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&len.to_string())
            .unwrap_or_else(|_| http::HeaderValue::from_static("0")),
    );
    resp
}

// ─── Factory ─────────────────────────────────────────────────────────

/// Factory for `KvFilter`.
///
/// ## Configuration
/// | Field            | Type    | Default  | Description                      |
/// |------------------|---------|----------|----------------------------------|
/// | `path_prefix`    | string  | `"/kv"`  | URL prefix for KV operations     |
/// | `backend`        | string  | `"memory"` | Backend: `"memory"` or `"redb"` |
/// | `key_env`        | string  | —        | Env var with hex master key      |
/// | `key_hex`        | string  | —        | Inline hex master key (testing)  |
/// | `encrypt_keys`   | bool    | `false`  | HMAC-hash keys in storage        |
/// | `encrypt_values` | bool    | `true`   | Encrypt values with AES-256-GCM  |
/// | `redb_path`      | string  | —        | Database file path (for `redb`)  |
/// | `redb_key_prefix`| string  | `""`     | Key prefix in redb namespace     |
pub struct KvFactory;

impl FilterFactory for KvFactory {
    fn name(&self) -> &str {
        "kv"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let path_prefix = config
            .get("path_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("/kv")
            .trim_end_matches('/')
            .to_string();

        let backend = config
            .get("backend")
            .and_then(|v| v.as_str())
            .unwrap_or("memory");

        let encrypt_values = config
            .get("encrypt_values")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let encrypt_keys = config
            .get("encrypt_keys")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Resolve encryption key
        let cipher: Option<Arc<dyn Cipher>> = if !encrypt_values && !encrypt_keys {
            None
        } else if let Some(env_var) = config.get("key_env").and_then(|v| v.as_str()) {
            let hex = std::env::var(env_var)
                .map_err(|e| format!("kv: env var '{env_var}' not set: {e}"))?;
            Some(Arc::new(
                AesGcmCipher::from_hex(&hex).map_err(|e| format!("kv: {e}"))?,
            ))
        } else if let Some(hex) = config.get("key_hex").and_then(|v| v.as_str()) {
            Some(Arc::new(
                AesGcmCipher::from_hex(hex).map_err(|e| format!("kv: {e}"))?,
            ))
        } else {
            return Err(
                "kv: encryption enabled but no key provided (set 'key_env' or 'key_hex')".into(),
            );
        };

        let store = match backend {
            "memory" => {
                tracing::info!(
                    path_prefix = %path_prefix,
                    encrypt_values = cipher.is_some(),
                    encrypt_keys,
                    "kv store: memory backend"
                );
                Store::Memory(MemoryStore::new(cipher, encrypt_keys))
            }
            #[cfg(feature = "redb")]
            "redb" => {
                let db_path = config
                    .get("redb_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/tmp/proxy_core_kv.redb");
                let key_prefix = config
                    .get("redb_key_prefix")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                tracing::info!(
                    path_prefix = %path_prefix,
                    db_path,
                    redb_prefix = %key_prefix,
                    encrypt_values = cipher.is_some(),
                    encrypt_keys,
                    "kv store: redb backend"
                );
                Store::Redb(crate::store::RedbStore::new(
                    db_path,
                    cipher,
                    encrypt_keys,
                    key_prefix,
                )?)
            }
            #[cfg(not(feature = "redb"))]
            "redb" => {
                return Err(
                    "kv: redb backend not compiled (rebuild with --features redb)".into(),
                );
            }
            other => {
                return Err(format!(
                    "kv: unknown backend '{other}' (use 'memory' or 'redb')"
                ));
            }
        };

        tracing::info!(path_prefix = %path_prefix, backend, "kv filter ready");

        Ok(Arc::new(KvFilter {
            store: Arc::new(store),
            path_prefix,
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AesGcmCipher;
    use crate::filter::*;
    use http::{Method, Uri};
    use std::net::SocketAddr;

    fn test_store(encrypt_keys: bool) -> Arc<Store> {
        let cipher: Arc<dyn Cipher> = Arc::new(AesGcmCipher::from_bytes(&[0u8; 32]).unwrap());
        Arc::new(Store::Memory(MemoryStore::new(Some(cipher), encrypt_keys)))
    }

    fn test_store_plain() -> Arc<Store> {
        Arc::new(Store::Memory(MemoryStore::new(None, false)))
    }

    fn test_effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn kv_filter(store: Arc<Store>) -> KvFilter {
        KvFilter {
            store,
            path_prefix: "/kv".to_string(),
        }
    }

    fn make_request(method: Method, uri: &str) -> Request {
        let uri: Uri = uri.parse().unwrap();
        Request::new(method, uri, "127.0.0.1:1234".parse::<SocketAddr>().unwrap())
    }

    // --- CRUD tests ---

    #[tokio::test]
    async fn put_and_get() {
        let store = test_store(false);
        let filter = kv_filter(store);
        let fx = test_effects();

        // PUT
        let mut req = make_request(Method::PUT, "/kv/mykey");
        req.body = crate::types::BodyStream::from_bytes(Bytes::from_static(b"hello world"));
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => assert_eq!(r.status, StatusCode::CREATED),
            _ => panic!("expected Respond"),
        }

        // GET
        let mut req = make_request(Method::GET, "/kv/mykey");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => {
                assert_eq!(r.status, StatusCode::OK);
                let body = r.body.collect().await.unwrap();
                assert_eq!(&body[..], b"hello world");
            }
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn get_not_found() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        let mut req = make_request(Method::GET, "/kv/nonexistent");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => assert_eq!(r.status, StatusCode::NOT_FOUND),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn delete_existing() {
        let store = test_store_plain();
        store.set("mykey", b"value").await.unwrap();
        let filter = kv_filter(store);
        let fx = test_effects();

        let mut req = make_request(Method::DELETE, "/kv/mykey");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => assert_eq!(r.status, StatusCode::OK),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn delete_not_found() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        let mut req = make_request(Method::DELETE, "/kv/nope");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => assert_eq!(r.status, StatusCode::NOT_FOUND),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn list_empty() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        let mut req = make_request(Method::GET, "/kv/");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => {
                assert_eq!(r.status, StatusCode::OK);
                let body = r.body.collect().await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["count"], 0);
            }
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn list_with_entries() {
        let store = test_store_plain();
        store.set("users/1", b"alice").await.unwrap();
        store.set("users/2", b"bob").await.unwrap();
        store.set("orders/1", b"order").await.unwrap();
        let filter = kv_filter(store);
        let fx = test_effects();

        let mut req = make_request(Method::GET, "/kv/?prefix=users/");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => {
                assert_eq!(r.status, StatusCode::OK);
                let body = r.body.collect().await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["count"], 2);
                assert_eq!(json["entries"][0]["key"], "users/1");
                assert_eq!(json["entries"][0]["value"], "alice");
            }
            _ => panic!("expected Respond"),
        }
    }

    // --- Pass-through for non-matching paths ---

    #[tokio::test]
    async fn passthrough_non_kv_path() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        let mut req = make_request(Method::GET, "/api/users");
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn passthrough_partial_prefix_match() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        // "/kvstore" should NOT match prefix "/kv"
        let mut req = make_request(Method::GET, "/kvstore/key");
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    // --- Encrypted store operations ---

    #[tokio::test]
    async fn encrypted_put_get_roundtrip() {
        let store = test_store(true); // encrypt both keys and values
        let filter = kv_filter(store);
        let fx = test_effects();

        // PUT encrypted
        let mut req = make_request(Method::PUT, "/kv/secret/key");
        req.body = crate::types::BodyStream::from_bytes(Bytes::from_static(b"classified data"));
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(ref r) if r.status == StatusCode::CREATED));

        // GET decrypted
        let mut req = make_request(Method::GET, "/kv/secret/key");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => {
                assert_eq!(r.status, StatusCode::OK);
                let body = r.body.collect().await.unwrap();
                assert_eq!(&body[..], b"classified data");
            }
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn encrypted_list() {
        let store = test_store(true);
        store.set("ns/a", b"1").await.unwrap();
        store.set("ns/b", b"2").await.unwrap();
        store.set("other/c", b"3").await.unwrap();
        let filter = kv_filter(store);
        let fx = test_effects();

        let mut req = make_request(Method::GET, "/kv/?prefix=ns/");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => {
                assert_eq!(r.status, StatusCode::OK);
                let body = r.body.collect().await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["count"], 2);
            }
            _ => panic!("expected Respond"),
        }
    }

    // --- Error cases ---

    #[tokio::test]
    async fn put_without_key() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        let mut req = make_request(Method::PUT, "/kv/");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => assert_eq!(r.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn unsupported_method() {
        let filter = kv_filter(test_store_plain());
        let fx = test_effects();

        let mut req = make_request(Method::PATCH, "/kv/key");
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(r) => assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED),
            _ => panic!("expected Respond"),
        }
    }

    // --- Factory ---

    #[tokio::test]
    async fn factory_memory_no_encryption() {
        let factory = KvFactory;
        let config = serde_json::json!({
            "backend": "memory",
            "encrypt_values": false,
            "encrypt_keys": false
        });
        let filter = factory.build(&config);
        assert!(filter.is_ok());
    }

    #[tokio::test]
    async fn factory_memory_with_encryption() {
        let key = AesGcmCipher::generate_key_hex();
        std::env::set_var("TEST_KV_KEY", &key);

        let factory = KvFactory;
        let config = serde_json::json!({
            "backend": "memory",
            "key_env": "TEST_KV_KEY",
            "encrypt_keys": true,
            "encrypt_values": true
        });
        let filter = factory.build(&config);
        assert!(filter.is_ok());

        std::env::remove_var("TEST_KV_KEY");
    }

    #[tokio::test]
    async fn factory_rejects_encryption_without_key() {
        let factory = KvFactory;
        let config = serde_json::json!({
            "backend": "memory",
            "encrypt_values": true
        });
        let result = factory.build(&config);
        assert!(result.is_err());
    }

    #[cfg(not(feature = "redb"))]
    #[tokio::test]
    async fn factory_rejects_redb_without_feature() {
        let factory = KvFactory;
        let config = serde_json::json!({
            "backend": "redb",
            "encrypt_values": false,
            "encrypt_keys": false
        });
        let result = factory.build(&config);
        match result {
            Err(e) => assert!(e.contains("not compiled"), "unexpected error: {e}"),
            Ok(_) => panic!("expected error for redb without feature"),
        }
    }

    // --- Query param parser ---

    #[test]
    fn parse_query_params() {
        assert_eq!(parse_query_param("prefix=users/&limit=50", "prefix"), Some("users/"));
        assert_eq!(parse_query_param("prefix=users/&limit=50", "limit"), Some("50"));
        assert_eq!(parse_query_param("prefix=users/", "limit"), None);
        assert_eq!(parse_query_param("", "prefix"), None);
    }
}
