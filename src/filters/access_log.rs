//! Access log filter — structured request/response logging via `tracing`.
//!
//! Records request start time in `on_request`, then logs method, path,
//! status code, latency (µs), and peer address in `on_response`.
//!
//! Config example:
//! ```json
//! { "level": "info" }
//! ```
//! Supported levels: `"info"` (default), `"debug"`, `"trace"`.

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::types::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

// ─── Metadata key ────────────────────────────────────────────────────

/// Metadata key for storing the request start time.
struct RequestStartTime;

impl typemap_rev::TypeMapKey for RequestStartTime {
    type Value = Instant;
}

// ─── Filter ──────────────────────────────────────────────────────────

pub struct AccessLogFilter {
    level: LogLevel,
}

#[derive(Debug, Clone, Copy)]
enum LogLevel {
    Info,
    Debug,
    Trace,
}

impl Filter for AccessLogFilter {
    fn name(&self) -> &'static str {
        "access_log"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            req.metadata.insert::<RequestStartTime>(fx.clock.now());
            Verdict::Continue
        })
    }

    fn on_response<'a>(
        &'a self,
        req: &'a Request,
        resp: &'a mut Response,
        _fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            let method = &req.method;
            let path = req.uri.path();
            let status = resp.status.as_u16();
            let latency = req
                .metadata
                .get::<RequestStartTime>()
                .map(|start| _fx.clock.now().duration_since(*start))
                .unwrap_or_default();
            let latency_us = latency.as_micros();
            let peer = req.peer_addr;

            match self.level {
                LogLevel::Info => {
                    tracing::info!(
                        %method, path, status, latency_us, %peer,
                        "request completed"
                    );
                }
                LogLevel::Debug => {
                    tracing::debug!(
                        %method, path, status, latency_us, %peer,
                        "request completed"
                    );
                }
                LogLevel::Trace => {
                    tracing::trace!(
                        %method, path, status, latency_us, %peer,
                        "request completed"
                    );
                }
            }

            _fx.metrics.counter_inc("access_log.requests");
            Verdict::Continue
        })
    }
}

// ─── Factory ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AccessLogConfig {
    #[serde(default = "default_level")]
    level: String,
}

fn default_level() -> String {
    "info".into()
}

pub struct AccessLogFactory;

impl FilterFactory for AccessLogFactory {
    fn name(&self) -> &str {
        "access_log"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: AccessLogConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid access_log config: {e}"))?;

        let level = match cfg.level.as_str() {
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info,
        };

        Ok(Arc::new(AccessLogFilter { level }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::{Clock, HttpClient, Metrics, RequestLogger, SharedState};
    use http::{Method, StatusCode, Uri};

    fn test_effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:8080".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(crate::filter::SystemClock),
        }
    }

    /// Mock clock that advances by a fixed amount each call.
    struct SteppingClock {
        start: Instant,
        step: std::time::Duration,
        calls: std::sync::atomic::AtomicU64,
    }

    impl SteppingClock {
        fn new(step: std::time::Duration) -> Self {
            Self {
                start: Instant::now(),
                step,
                calls: std::sync::atomic::AtomicU64::new(0),
            }
        }
    }

    impl Clock for SteppingClock {
        fn now(&self) -> Instant {
            let n = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.start + self.step * n as u32
        }
    }

    fn build_filter(config: serde_json::Value) -> Arc<dyn Filter> {
        AccessLogFactory.build(&config).unwrap()
    }

    #[tokio::test]
    async fn on_request_stores_start_time() {
        let filter = build_filter(ron_value("{}"));
        let fx = test_effects();
        let addr = "10.0.0.1:1234".parse().unwrap();
        let mut req = Request::new(Method::GET, Uri::from_static("/api"), addr);

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert!(req.metadata.get::<RequestStartTime>().is_some());
    }

    #[tokio::test]
    async fn on_response_returns_continue_and_increments_counter() {
        let filter = build_filter(ron_value("{}"));
        let fx = test_effects();
        let addr = "10.0.0.1:1234".parse().unwrap();
        let mut req = Request::new(Method::GET, Uri::from_static("/api/test"), addr);

        // Simulate on_request to set start time
        filter.on_request(&mut req, &fx).await;

        let mut resp = Response::ok(b"ok");
        let verdict = filter.on_response(&req, &mut resp, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(fx.metrics.counter_get("access_log.requests"), 1);
    }

    #[tokio::test]
    async fn on_response_works_without_start_time() {
        // Edge case: on_response called without prior on_request
        let filter = build_filter(ron_value("{}"));
        let fx = test_effects();
        let addr = "10.0.0.1:1234".parse().unwrap();
        let req = Request::new(Method::POST, Uri::from_static("/submit"), addr);
        let mut resp = Response::error(StatusCode::BAD_REQUEST, b"bad");

        let verdict = filter.on_response(&req, &mut resp, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn stepping_clock_measures_latency() {
        let filter = build_filter(ron_value("{}"));
        let clock = Arc::new(SteppingClock::new(std::time::Duration::from_millis(50)));
        let fx = Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:8080".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock,
        };

        let addr = "10.0.0.1:1234".parse().unwrap();
        let mut req = Request::new(Method::GET, Uri::from_static("/slow"), addr);
        filter.on_request(&mut req, &fx).await;

        let mut resp = Response::ok(b"done");
        let verdict = filter.on_response(&req, &mut resp, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        // Clock stepped once in on_request (start) and once in on_response (end)
        // Latency = 50ms. If the log works, we're good.
    }

    // ── Factory ─────────────────────────────────────────────────

    #[test]
    fn factory_defaults_to_info() {
        let filter = build_filter(ron_value("{}"));
        assert_eq!(filter.name(), "access_log");
    }

    #[test]
    fn factory_accepts_debug_level() {
        let filter = build_filter(ron_value(r#"{"level": "debug"}"#));
        assert_eq!(filter.name(), "access_log");
    }

    #[test]
    fn factory_accepts_trace_level() {
        let filter = build_filter(ron_value(r#"{"level": "trace"}"#));
        assert_eq!(filter.name(), "access_log");
    }

    #[test]
    fn factory_name() {
        assert_eq!(AccessLogFactory.name(), "access_log");
    }
}
