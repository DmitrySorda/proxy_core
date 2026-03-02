//! Audit filter — tamper-evident request/response event logging.
//!
//! Place this filter after `auth`/`rbac` so identity and authorization
//! context are already available in metadata.
//!
//! Features:
//! - per-request audit event on response path;
//! - hash-chain (`H_n = SHA256(H_{n-1} || event_payload)`) for tamper evidence;
//! - optional claims projection (`include_claims`) to avoid leaking sensitive claims;
//! - skip-paths for health/readiness probes.

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::filters::auth::{AuthClaims, AuthIdentity, AuthMethod};
use crate::types::{Request, Response};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use typemap_rev::TypeMapKey;

struct AuditStart;
impl TypeMapKey for AuditStart {
    type Value = Instant;
}

struct AuditSkip;
impl TypeMapKey for AuditSkip {
    type Value = bool;
}

pub struct AuditHash;
impl TypeMapKey for AuditHash {
    type Value = String;
}

#[derive(Debug, Clone, serde::Deserialize)]
struct AuditConfig {
    #[serde(default)]
    skip_paths: Vec<String>,
    #[serde(default)]
    include_claims: Vec<String>,
}

pub struct AuditFilter {
    skip_paths: HashSet<String>,
    include_claims: HashSet<String>,
    sequence: AtomicU64,
    prev_hash: Mutex<[u8; 32]>,
}

impl AuditFilter {
    fn claim_projection(&self, req: &Request) -> String {
        let Some(claims) = req.metadata.get::<AuthClaims>() else {
            return "{}".to_string();
        };

        if self.include_claims.is_empty() {
            return "{}".to_string();
        }

        let mut out = serde_json::Map::new();
        for key in &self.include_claims {
            if let Some(value) = claims.get(key) {
                out.insert(key.clone(), value.clone());
            }
        }

        serde_json::Value::Object(out).to_string()
    }

    fn hash_event(&self, payload: &str) -> (String, String) {
        let mut prev = self.prev_hash.lock().unwrap_or_else(|e| e.into_inner());
        let prev_hex = hex_encode(&prev[..]);

        let mut hasher = Sha256::new();
        hasher.update(&prev[..]);
        hasher.update(payload.as_bytes());
        let next: [u8; 32] = hasher.finalize().into();
        *prev = next;

        (prev_hex, hex_encode(&next))
    }
}

impl Filter for AuditFilter {
    fn name(&self) -> &'static str {
        "audit"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if self.skip_paths.contains(req.uri.path()) {
                req.metadata.insert::<AuditSkip>(true);
                fx.metrics.counter_inc("audit.skipped");
                return Verdict::Continue;
            }

            req.metadata.insert::<AuditStart>(fx.clock.now());
            Verdict::Continue
        })
    }

    fn on_response<'a>(
        &'a self,
        req: &'a Request,
        resp: &'a mut Response,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if req.metadata.get::<AuditSkip>().copied().unwrap_or(false) {
                return Verdict::Continue;
            }

            let seq = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            let method = req.method.as_str();
            let path = req.uri.path();
            let status = resp.status.as_u16();
            let peer = req.peer_addr.to_string();
            let latency_us = req
                .metadata
                .get::<AuditStart>()
                .map(|s| fx.clock.now().duration_since(*s).as_micros())
                .unwrap_or(0);

            let identity = req
                .metadata
                .get::<AuthIdentity>()
                .cloned()
                .unwrap_or_else(|| "anonymous".to_string());
            let auth_method = req
                .metadata
                .get::<AuthMethod>()
                .copied()
                .unwrap_or("none");

            let claims = self.claim_projection(req);

            let payload = format!(
                "seq={seq}|method={method}|path={path}|status={status}|peer={peer}|latency_us={latency_us}|identity={identity}|auth_method={auth_method}|claims={claims}"
            );
            let (prev_hash, hash) = self.hash_event(&payload);

            tracing::info!(
                audit_seq = seq,
                audit_hash = %hash,
                audit_prev_hash = %prev_hash,
                method = %method,
                path,
                status,
                latency_us,
                identity = %identity,
                auth_method,
                "audit event"
            );

            resp.metadata.insert::<AuditHash>(hash);
            fx.metrics.counter_inc("audit.events");
            Verdict::Continue
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub struct AuditFactory;

impl FilterFactory for AuditFactory {
    fn name(&self) -> &str {
        "audit"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: AuditConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid audit config: {e}"))?;

        Ok(Arc::new(AuditFilter {
            skip_paths: cfg.skip_paths.into_iter().collect(),
            include_claims: cfg.include_claims.into_iter().collect(),
            sequence: AtomicU64::new(0),
            prev_hash: Mutex::new([0u8; 32]),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::{Metrics, RequestLogger, SharedState, SystemClock};
    use crate::test_support::TestHttpClient;
    use http::{Method, StatusCode, Uri};
    use std::collections::HashMap;

    fn effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: TestHttpClient::boxed(HashMap::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn req(path: &str) -> Request {
        Request::new(
            Method::GET,
            Uri::try_from(path).unwrap(),
            "127.0.0.1:1111".parse().unwrap(),
        )
    }

    fn filter(cfg: serde_json::Value) -> Arc<dyn Filter> {
        AuditFactory.build(&cfg).unwrap()
    }

    #[tokio::test]
    async fn writes_audit_hash_to_response_metadata() {
        let fx = effects();
        let filter = filter(ron_value(r#"{"include_claims": ["org_id"]}"#));

        let mut request = req("/api/doc");
        request.metadata.insert::<AuthIdentity>("alice".to_string());
        request.metadata.insert::<AuthMethod>("jwt");
        request
            .metadata
            .insert::<AuthClaims>(serde_json::json!({"org_id": "org-1", "role": "manager"}).as_object().unwrap().clone());

        assert!(matches!(filter.on_request(&mut request, &fx).await, Verdict::Continue));

        let mut response = Response::error(StatusCode::OK, b"ok");
        assert!(matches!(filter.on_response(&request, &mut response, &fx).await, Verdict::Continue));

        let hash = response.metadata.get::<AuditHash>().cloned();
        assert!(hash.is_some());
        assert_eq!(fx.metrics.counter_get("audit.events"), 1);
    }

    #[tokio::test]
    async fn hash_chain_changes_between_events() {
        let fx = effects();
        let filter = filter(ron_value("{}"));

        let mut req1 = req("/api/a");
        req1.metadata.insert::<AuthIdentity>("alice".to_string());
        req1.metadata.insert::<AuthMethod>("jwt");
        filter.on_request(&mut req1, &fx).await;
        let mut resp1 = Response::error(StatusCode::OK, b"ok");
        filter.on_response(&req1, &mut resp1, &fx).await;
        let h1 = resp1.metadata.get::<AuditHash>().cloned().unwrap();

        let mut req2 = req("/api/b");
        req2.metadata.insert::<AuthIdentity>("alice".to_string());
        req2.metadata.insert::<AuthMethod>("jwt");
        filter.on_request(&mut req2, &fx).await;
        let mut resp2 = Response::error(StatusCode::OK, b"ok");
        filter.on_response(&req2, &mut resp2, &fx).await;
        let h2 = resp2.metadata.get::<AuditHash>().cloned().unwrap();

        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn skip_path_does_not_emit_audit_event() {
        let fx = effects();
        let filter = filter(ron_value(r#"{"skip_paths": ["/health"]}"#));

        let mut request = req("/health");
        assert!(matches!(filter.on_request(&mut request, &fx).await, Verdict::Continue));

        let mut response = Response::error(StatusCode::OK, b"ok");
        assert!(matches!(filter.on_response(&request, &mut response, &fx).await, Verdict::Continue));

        assert!(response.metadata.get::<AuditHash>().is_none());
        assert_eq!(fx.metrics.counter_get("audit.events"), 0);
        assert_eq!(fx.metrics.counter_get("audit.skipped"), 1);
    }
}
