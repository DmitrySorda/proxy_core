//! Router filter — terminal filter that dispatches to upstream backends.
//!
//! This is the Envoy-style "router" filter: last in the chain, always
//! returns `Verdict::Respond` (either upstream response or error).
//!
//! Supports two backend types:
//! - **HTTP**: forward to HTTP upstream via `reqwest`
//! - **Redb**: execute redb KV operations (feature-gated)
//!
//! Integrates circuit breaker for upstream fault isolation.

use crate::builder::FilterFactory;
use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::filter::{Effects, Filter, Verdict};
use crate::routing::{PathParams, RedbOp, RouteAction, RouteTable, RouteTableConfig};
use crate::types::{Request, Response};
use crate::upstream::{HttpUpstream, UpstreamError};
use http::StatusCode;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Terminal filter that resolves routes and forwards to upstream backends.
///
/// Must be the **last** filter in the chain. All preceding filters
/// see `Verdict::Continue` and mutate the request; the router consumes
/// the request and produces the response.
///
/// Contains a [`CircuitBreaker`] that tracks per-upstream failure rates.
pub struct RouterFilter {
    route_table: RouteTable,
    http: HttpUpstream,
    circuit_breaker: Arc<CircuitBreaker>,
    #[cfg(feature = "redb")]
    redb: Option<crate::upstream::RedbUpstream>,
}

impl RouterFilter {
    /// Dispatch to redb KV backend.
    ///
    /// When compiled without `redb` feature, always returns 501.
    #[cfg(feature = "redb")]
    async fn forward_redb(
        &self,
        req: &Request,
        op: &RedbOp,
        key_prefix: &str,
        captured: &str,
        timeout: std::time::Duration,
    ) -> Result<Response, UpstreamError> {
        match &self.redb {
            Some(redb) => redb.forward(req, op, key_prefix, captured, timeout).await,
            None => Err(UpstreamError::Redb(
                "no redb connection configured (set redb_path in router config)".into(),
            )),
        }
    }

    #[cfg(not(feature = "redb"))]
    async fn forward_redb(
        &self,
        _req: &Request,
        _op: &RedbOp,
        _key_prefix: &str,
        _captured: &str,
        _timeout: std::time::Duration,
    ) -> Result<Response, UpstreamError> {
        Err(UpstreamError::Redb(
            "redb support not compiled (enable 'redb' feature in Cargo.toml)".into(),
        ))
    }
}

impl Filter for RouterFilter {
    fn name(&self) -> &'static str {
        "router"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            // Clone method/path to avoid borrow overlap with &mut req
            let method = req.method.clone();
            let path = req.uri.path().to_owned();

            let resolved = self.route_table.resolve(&method, &path);

            let Some(resolved) = resolved else {
                fx.metrics.counter_inc("router.no_route");
                return Verdict::Respond(Response::error(
                    StatusCode::NOT_FOUND,
                    b"no matching route\n",
                ));
            };

            // Inject path params (from pattern routes) into request metadata
            if !resolved.params.is_empty() {
                req.metadata.insert::<PathParams>(resolved.params.clone());
            }

            // Derive upstream identity for circuit breaker tracking
            let upstream_id = match resolved.action {
                RouteAction::Http { ref url, .. } => url.clone(),
                RouteAction::Redb { ref key_prefix, .. } => format!("redb:{key_prefix}"),
            };

            // --- Circuit breaker check ---
            if let Err(cb_err) = self.circuit_breaker.check(&upstream_id) {
                fx.metrics.counter_inc("router.circuit_open");
                fx.log.error(
                    "circuit breaker open",
                    &[("upstream", &upstream_id), ("error", &cb_err.to_string())],
                );
                return Verdict::Respond(Response::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    b"Service Unavailable (circuit breaker open)\n",
                ));
            }

            let result: Result<Response, UpstreamError> = match resolved.action {
                RouteAction::Http { ref url, timeout } => {
                    fx.metrics.counter_inc("router.http");
                    self.http
                        .forward(req, url, &resolved.captured_path, *timeout)
                        .await
                }
                RouteAction::Redb {
                    ref operation,
                    ref key_prefix,
                    timeout,
                } => {
                    fx.metrics.counter_inc("router.redb");
                    self.forward_redb(
                        req,
                        operation,
                        key_prefix,
                        &resolved.captured_path,
                        *timeout,
                    )
                    .await
                }
            };

            match result {
                Ok(resp) => {
                    // 5xx from upstream counts as failure for circuit breaker
                    if resp.status.is_server_error() {
                        self.circuit_breaker.record_failure(&upstream_id);
                        fx.metrics.counter_inc("router.upstream_5xx");
                    } else {
                        self.circuit_breaker.record_success(&upstream_id);
                    }
                    fx.metrics.counter_inc("router.success");
                    Verdict::Respond(resp)
                }
                Err(e) => {
                    self.circuit_breaker.record_failure(&upstream_id);
                    fx.metrics.counter_inc("router.error");
                    fx.log
                        .error("upstream error", &[("error", &e.to_string())]);
                    Verdict::Respond(Response::error(
                        StatusCode::BAD_GATEWAY,
                        b"Bad Gateway\n",
                    ))
                }
            }
        })
    }
}

// ─── Factory ─────────────────────────────────────────────────────────

/// Factory for `RouterFilter`.
///
/// Config example:
/// ```json
/// {
///   "routes": [
///     { "match": { "prefix": "/api/" }, "http": { "url": "http://backend:8081" } },
///     { "match": { "prefix": "/kv/" }, "redb": { "operation": "get", "key_prefix": "app/" } }
///   ],
///   "redb_path": "/tmp/proxy_core.redb",
///   "circuit_breaker": {
///     "failure_threshold": 5,
///     "recovery_timeout_secs": 30,
///     "half_open_max_requests": 3,
///     "success_threshold": 2
///   }
/// }
/// ```
pub struct RouterFactory;

impl FilterFactory for RouterFactory {
    fn name(&self) -> &str {
        "router"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let route_config: RouteTableConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid router config: {e}"))?;

        tracing::info!(routes = route_config.routes.len(), "building route table");

        let route_table = RouteTable::from_config(&route_config)?;
        let http = HttpUpstream::new();

        // Parse circuit breaker config (optional, uses defaults if absent)
        let cb_config = config
            .get("circuit_breaker")
            .map(|v| {
                let failure_threshold = v
                    .get("failure_threshold")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(5) as u32;
                let recovery_timeout_secs = v
                    .get("recovery_timeout_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(30);
                let half_open_max_requests = v
                    .get("half_open_max_requests")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3) as u32;
                let success_threshold = v
                    .get("success_threshold")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2) as u32;

                CircuitBreakerConfig {
                    failure_threshold,
                    recovery_timeout: std::time::Duration::from_secs(recovery_timeout_secs),
                    half_open_max_requests,
                    success_threshold,
                }
            })
            .unwrap_or_default();

        let circuit_breaker = Arc::new(CircuitBreaker::new(cb_config));

        #[cfg(feature = "redb")]
        let redb = if let Some(ref path) = route_config.redb_path {
            tracing::info!(path, "opening redb database");
            Some(crate::upstream::RedbUpstream::new(path)?)
        } else {
            None
        };

        Ok(Arc::new(RouterFilter {
            route_table,
            http,
            circuit_breaker,
            #[cfg(feature = "redb")]
            redb,
        }))
    }
}
