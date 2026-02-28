//! Rate limit filter — demonstrates explicit effects and typed metadata.
//!
//! - Uses `effects.shared.rate_check()` — explicit, not hidden
//! - Uses `effects.clock.now()` — injectable for tests
//! - Stores remaining quota in typed metadata (TypeMapKey)

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::types::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use http::StatusCode;
use std::sync::Arc;
use typemap_rev::TypeMapKey;

// ─── Typed metadata key ──────────────────────────────────────────────

/// Metadata key: remaining rate limit quota.
/// Type-safe: downstream filters read `u64`, not `&str`.
pub struct RateLimitRemaining;

impl TypeMapKey for RateLimitRemaining {
    type Value = u64;
}

// ─── Filter implementation ───────────────────────────────────────────

/// Rate limit filter: blocks requests exceeding max_rps per source IP.
pub struct RateLimitFilter {
    max_rps: u64,
}

impl RateLimitFilter {
    pub fn new(max_rps: u64) -> Self {
        Self { max_rps }
    }
}

impl Filter for RateLimitFilter {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
        let ip = req.peer_addr.ip();
        let now = fx.clock.now();
        let remaining = fx.shared.rate_check(ip, now, self.max_rps);

        match remaining {
            Some(n) => {
                // Store typed metadata — next filter can read it type-safely
                req.metadata.insert::<RateLimitRemaining>(n);
                fx.metrics.counter_inc("ratelimit.allowed");
                Verdict::Continue
            }
            None => {
                fx.metrics.counter_inc("ratelimit.rejected");
                fx.log.warn("rate limited", &[("ip", &ip.to_string())]);

                let mut resp = Response::error(
                    StatusCode::TOO_MANY_REQUESTS,
                    b"Too Many Requests\n",
                );
                resp.headers.insert(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("1"),
                );
                Verdict::Respond(resp)
            }
        }
        })
    }
}

// ─── Factory ─────────────────────────────────────────────────────────

/// Factory that creates RateLimitFilter from JSON config.
///
/// Config: `{ "max_rps": 100 }`
pub struct RateLimitFactory;

impl FilterFactory for RateLimitFactory {
    fn name(&self) -> &str {
        "rate_limit"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let max_rps = config
            .get("max_rps")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);

        Ok(Arc::new(RateLimitFilter::new(max_rps)))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::*;
    use http::{Method, Uri};
    use std::net::SocketAddr;

    fn test_effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn test_request() -> Request {
        Request::new(
            Method::GET,
            Uri::from_static("/"),
            "10.0.0.1:5000".parse::<SocketAddr>().unwrap(),
        )
    }

    #[tokio::test]
    async fn allows_within_limit() {
        let filter = RateLimitFilter::new(10);
        let fx = test_effects();
        let mut req = test_request();

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        // Check typed metadata was set
        let remaining = req.metadata.get::<RateLimitRemaining>();
        assert!(remaining.is_some());
        assert_eq!(*remaining.unwrap(), 9); // 10 - 1 = 9
    }

    #[tokio::test]
    async fn blocks_when_exceeded() {
        let filter = RateLimitFilter::new(2);
        let fx = test_effects();

        // First two requests: allowed
        for _ in 0..2 {
            let mut req = test_request();
            let verdict = filter.on_request(&mut req, &fx).await;
            assert!(matches!(verdict, Verdict::Continue));
        }

        // Third request: blocked
        let mut req = test_request();
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("expected Respond with 429"),
        }
    }

    #[tokio::test]
    async fn metrics_tracked() {
        let filter = RateLimitFilter::new(1);
        let fx = test_effects();

        let mut req = test_request();
        filter.on_request(&mut req, &fx).await;
        assert_eq!(fx.metrics.counter_get("ratelimit.allowed"), 1);

        let mut req = test_request();
        filter.on_request(&mut req, &fx).await;
        assert_eq!(fx.metrics.counter_get("ratelimit.rejected"), 1);
    }

    #[tokio::test]
    async fn different_ips_have_independent_limits() {
        let filter = RateLimitFilter::new(1);
        let fx = test_effects();

        // IP-A: first request OK
        let mut req_a = Request::new(
            Method::GET,
            Uri::from_static("/"),
            "10.0.0.1:5000".parse::<SocketAddr>().unwrap(),
        );
        let v = filter.on_request(&mut req_a, &fx).await;
        assert!(matches!(v, Verdict::Continue));

        // IP-B: first request OK (independent counter)
        let mut req_b = Request::new(
            Method::GET,
            Uri::from_static("/"),
            "10.0.0.2:5000".parse::<SocketAddr>().unwrap(),
        );
        let v = filter.on_request(&mut req_b, &fx).await;
        assert!(matches!(v, Verdict::Continue));

        // IP-A: second request blocked (limit was 1)
        let mut req_a2 = Request::new(
            Method::GET,
            Uri::from_static("/"),
            "10.0.0.1:5000".parse::<SocketAddr>().unwrap(),
        );
        let v = filter.on_request(&mut req_a2, &fx).await;
        assert!(matches!(v, Verdict::Respond(ref r) if r.status == StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn blocked_response_has_retry_after_header() {
        let filter = RateLimitFilter::new(1);
        let fx = test_effects();

        // Exhaust
        let mut req = test_request();
        filter.on_request(&mut req, &fx).await;

        // Blocked
        let mut req = test_request();
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(
                    resp.headers.get(http::header::RETRY_AFTER).unwrap().to_str().unwrap(),
                    "1"
                );
            }
            _ => panic!("expected 429"),
        }
    }

    #[tokio::test]
    async fn remaining_metadata_decrements() {
        let filter = RateLimitFilter::new(3);
        let fx = test_effects();

        let mut req1 = test_request();
        filter.on_request(&mut req1, &fx).await;
        assert_eq!(*req1.metadata.get::<RateLimitRemaining>().unwrap(), 2);

        let mut req2 = test_request();
        filter.on_request(&mut req2, &fx).await;
        assert_eq!(*req2.metadata.get::<RateLimitRemaining>().unwrap(), 1);

        let mut req3 = test_request();
        filter.on_request(&mut req3, &fx).await;
        assert_eq!(*req3.metadata.get::<RateLimitRemaining>().unwrap(), 0);
    }

    // ── Factory ─────────────────────────────────────────────────

    #[tokio::test]
    async fn factory_parses_config() {
        let factory = RateLimitFactory;
        let config = ron_value(r#"{"max_rps": 50}"#);
        let filter = factory.build(&config).unwrap();
        assert_eq!(filter.name(), "rate_limit");
    }

    #[tokio::test]
    async fn factory_uses_default_when_config_empty() {
        let factory = RateLimitFactory;
        let config = ron_value("{}");
        // Should not error — defaults to 100 rps
        let filter = factory.build(&config);
        assert!(filter.is_ok());
    }
}
