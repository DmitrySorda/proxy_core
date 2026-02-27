//! Upstream backends: HTTP forwarding and redb KV operations.
//!
//! - [`HttpUpstream`]: forwards requests to HTTP backends via `reqwest`
//! - `RedbUpstream`: executes redb KV operations (feature-gated behind `redb`)

#[cfg(feature = "redb")]
use crate::routing::RedbOp;
use crate::types::{BodyStream, Request, Response};
#[cfg(feature = "redb")]
use bytes::Bytes;
use http::{HeaderMap, StatusCode, Version};
use std::time::Duration;

// ─── Errors ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum UpstreamError {
    Http(String),
    Redb(String),
    Timeout,
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "http upstream: {e}"),
            Self::Redb(e) => write!(f, "redb: {e}"),
            Self::Timeout => write!(f, "upstream timeout"),
        }
    }
}

impl std::error::Error for UpstreamError {}

// ─── HTTP upstream ──────────────────────────────────────────────────

/// HTTP upstream using `reqwest` with persistent connection pooling.
///
/// Created once by [`RouterFactory`](crate::filters::router::RouterFactory),
/// shared across all requests via `Arc<dyn Filter>`.
pub struct HttpUpstream {
    client: reqwest::Client,
}

impl HttpUpstream {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(32)
            .tcp_nodelay(true)
            .build()
            .expect("failed to build reqwest Client");
        Self { client }
    }

    /// Forward a request to an HTTP upstream and return the response.
    ///
    /// - Preserves method, headers (minus hop-by-hop), query string
    /// - Forwards body for POST/PUT/PATCH
    /// - Collects upstream response body (streaming enhancement: TODO)
    pub async fn forward(
        &self,
        req: &Request,
        base_url: &str,
        captured_path: &str,
        timeout: Duration,
    ) -> Result<Response, UpstreamError> {
        // Build upstream URL
        let forward_path = if captured_path.is_empty() {
            "/"
        } else {
            captured_path
        };
        let query = req
            .uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        let url = format!(
            "{}/{}{}",
            base_url.trim_end_matches('/'),
            forward_path.trim_start_matches('/'),
            query
        );

        // Map method
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);

        let mut builder = self.client.request(method, &url).timeout(timeout);

        // Forward headers (skip hop-by-hop)
        for (name, value) in req.headers.iter() {
            match name.as_str() {
                "host" | "connection" | "transfer-encoding" => continue,
                _ => {
                    if let Ok(v) = value.to_str() {
                        builder = builder.header(name.as_str(), v);
                    }
                }
            }
        }

        // Forward body for write methods
        if matches!(
            req.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH
        ) {
            let body = req
                .body
                .collect()
                .await
                .map_err(|e| UpstreamError::Http(e.to_string()))?;
            builder = builder.body(body.to_vec());
        }

        // Send request to upstream
        let resp = builder
            .send()
            .await
            .map_err(|e| UpstreamError::Http(e.to_string()))?;

        // Convert upstream response → our Response type
        let status = StatusCode::from_u16(resp.status().as_u16())
            .unwrap_or(StatusCode::BAD_GATEWAY);

        let mut headers = HeaderMap::new();
        for (name, value) in resp.headers().iter() {
            // Skip hop-by-hop and framing headers (body is re-buffered)
            match name.as_str() {
                "transfer-encoding" | "connection" | "content-encoding" => continue,
                _ => {
                    if let (Ok(n), Ok(v)) = (
                        http::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                        http::header::HeaderValue::from_bytes(value.as_bytes()),
                    ) {
                        headers.insert(n, v);
                    }
                }
            }
        }

        // Collect body (reqwest auto-decompresses; set correct Content-Length)
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| UpstreamError::Http(e.to_string()))?;

        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&body_bytes.len().to_string()).unwrap(),
        );

        Ok(Response {
            status,
            version: Version::HTTP_11,
            headers,
            body: BodyStream::from_bytes(body_bytes),
            metadata: typemap_rev::TypeMap::new(),
        })
    }
}

impl Default for HttpUpstream {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Redb upstream (feature-gated) ──────────────────────────────────
//
// Enable with: cargo build --features redb
// Pure Rust, ACID, zero C dependencies.

#[cfg(feature = "redb")]
use redb::{Database, ReadableDatabase, TableDefinition};

/// Table definition for the upstream KV data.
#[cfg(feature = "redb")]
const UPSTREAM_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("upstream_kv");

#[cfg(feature = "redb")]
pub struct RedbUpstream {
    db: std::sync::Arc<Database>,
}

#[cfg(feature = "redb")]
unsafe impl Send for RedbUpstream {}
#[cfg(feature = "redb")]
unsafe impl Sync for RedbUpstream {}

#[cfg(feature = "redb")]
impl RedbUpstream {
    /// Open or create a redb database for upstream KV.
    pub fn new(path: &str) -> Result<Self, String> {
        let db = crate::store::db_pool::open(path)?;
        // Pre-create table
        {
            let txn = db.begin_write().map_err(|e| format!("begin_write: {e}"))?;
            { let _t = txn.open_table(UPSTREAM_TABLE).map_err(|e| format!("open table: {e}"))?; }
            txn.commit().map_err(|e| format!("commit: {e}"))?;
        }
        Ok(Self { db })
    }

    /// Helper: convert any Display error into UpstreamError::Redb.
    fn redb_err(e: impl std::fmt::Display) -> UpstreamError {
        UpstreamError::Redb(e.to_string())
    }

    /// Execute a redb KV operation based on the route configuration.
    pub async fn forward(
        &self,
        req: &Request,
        op: &RedbOp,
        key_prefix: &str,
        captured_path: &str,
        _timeout: Duration,
    ) -> Result<Response, UpstreamError> {
        let key = format!("{}{}", key_prefix, captured_path);

        match op {
            RedbOp::Get => {
                let txn = self.db.begin_read().map_err(Self::redb_err)?;
                let table = txn.open_table(UPSTREAM_TABLE).map_err(Self::redb_err)?;
                match table.get(key.as_bytes()).map_err(Self::redb_err)? {
                    Some(v) => Ok(Response::from_bytes(
                        StatusCode::OK,
                        Bytes::copy_from_slice(v.value()),
                    )),
                    None => Ok(Response::error(StatusCode::NOT_FOUND, b"key not found\n")),
                }
            }
            RedbOp::Set => {
                let body = req.body.collect().await.map_err(Self::redb_err)?;
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(UPSTREAM_TABLE).map_err(Self::redb_err)?;
                    table.insert(key.as_bytes(), body.as_ref()).map_err(Self::redb_err)?;
                }
                txn.commit().map_err(Self::redb_err)?;
                Ok(Response::from_bytes(StatusCode::OK, Bytes::from_static(b"OK\n")))
            }
            RedbOp::GetRange => {
                let txn = self.db.begin_read().map_err(Self::redb_err)?;
                let table = txn.open_table(UPSTREAM_TABLE).map_err(Self::redb_err)?;
                let prefix_bytes = key.as_bytes().to_vec();

                let mut items: Vec<serde_json::Value> = Vec::new();
                let iter = table.range(prefix_bytes.as_slice()..).map_err(Self::redb_err)?;
                for item in iter {
                    let (k, v) = item.map_err(Self::redb_err)?;
                    let kb = k.value().to_vec();
                    if !kb.starts_with(&prefix_bytes) {
                        break;
                    }
                    items.push(serde_json::json!({
                        "key": String::from_utf8_lossy(&kb),
                        "value": String::from_utf8_lossy(v.value()),
                    }));
                    if items.len() >= 1000 {
                        break;
                    }
                }

                let json = serde_json::to_vec(&items).map_err(Self::redb_err)?;
                let mut resp = Response::from_bytes(StatusCode::OK, Bytes::from(json));
                resp.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                Ok(resp)
            }
            RedbOp::Delete => {
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(UPSTREAM_TABLE).map_err(Self::redb_err)?;
                    table.remove(key.as_bytes()).map_err(Self::redb_err)?;
                }
                txn.commit().map_err(Self::redb_err)?;
                Ok(Response::from_bytes(StatusCode::OK, Bytes::from_static(b"deleted\n")))
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_error_display_http() {
        let err = UpstreamError::Http("connection refused".into());
        let s = err.to_string();
        assert!(s.contains("http upstream"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn upstream_error_display_redb() {
        let err = UpstreamError::Redb("transaction conflict".into());
        let s = err.to_string();
        assert!(s.contains("redb"));
        assert!(s.contains("transaction conflict"));
    }

    #[test]
    fn upstream_error_display_timeout() {
        let err = UpstreamError::Timeout;
        assert_eq!(err.to_string(), "upstream timeout");
    }

    #[test]
    fn http_upstream_creates_without_panic() {
        // Verifies reqwest Client builder doesn't panic with our settings
        let _upstream = HttpUpstream::new();
    }

    #[test]
    fn http_upstream_default_same_as_new() {
        let _upstream = HttpUpstream::default();
        // Just proves Default impl works
    }
}
