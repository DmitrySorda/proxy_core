//! CORS filter — Cross-Origin Resource Sharing preflight and response headers.
//!
//! Handles two cases:
//! 1. **Preflight** (OPTIONS with Origin header): short-circuits with 204 + CORS headers.
//! 2. **Actual requests**: adds `Access-Control-Allow-Origin` (and friends) on the response path.
//!
//! Config example:
//! ```json
//! {
//!   "allowed_origins": ["https://example.com", "https://app.example.com"],
//!   "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
//!   "allowed_headers": ["Content-Type", "Authorization"],
//!   "max_age_secs": 86400,
//!   "allow_credentials": false
//! }
//! ```
//!
//! Use `"*"` in `allowed_origins` to allow any origin (incompatible with credentials).

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::types::{Request, Response};
use http::{HeaderValue, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// ─── Filter ──────────────────────────────────────────────────────────

pub struct CorsFilter {
    allowed_origins: Vec<String>,
    allow_any_origin: bool,
    allowed_methods: String,  // pre-joined for header value
    allowed_headers: String,  // pre-joined for header value
    max_age: Option<String>,  // seconds as string
    allow_credentials: bool,
}

impl CorsFilter {
    /// Is the given origin permitted?
    fn origin_allowed(&self, origin: &str) -> bool {
        self.allow_any_origin || self.allowed_origins.iter().any(|o| o == origin)
    }

    /// Add CORS response headers for an allowed origin.
    fn apply_cors_headers(&self, origin: &str, headers: &mut http::HeaderMap) {
        if !self.origin_allowed(origin) {
            return;
        }

        // When credentials enabled, must echo the specific origin (not "*").
        let origin_value = if self.allow_any_origin && !self.allow_credentials {
            "*"
        } else {
            origin
        };

        if let Ok(v) = HeaderValue::from_str(origin_value) {
            headers.insert("access-control-allow-origin", v);
        }

        if self.allow_credentials {
            headers.insert(
                "access-control-allow-credentials",
                HeaderValue::from_static("true"),
            );
        }
    }

    /// Build a preflight (204 No Content) response with full CORS headers.
    fn preflight_response(&self, origin: &str) -> Response {
        let mut resp = Response::error(StatusCode::NO_CONTENT, b"");
        self.apply_cors_headers(origin, &mut resp.headers);

        if !self.allowed_methods.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&self.allowed_methods) {
                resp.headers.insert("access-control-allow-methods", v);
            }
        }
        if !self.allowed_headers.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&self.allowed_headers) {
                resp.headers.insert("access-control-allow-headers", v);
            }
        }
        if let Some(ref max_age) = self.max_age {
            if let Ok(v) = HeaderValue::from_str(max_age) {
                resp.headers.insert("access-control-max-age", v);
            }
        }

        resp
    }
}

impl Filter for CorsFilter {
    fn name(&self) -> &'static str {
        "cors"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        _fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            // Only intercept preflight (OPTIONS with Origin header).
            if req.method != http::Method::OPTIONS {
                return Verdict::Continue;
            }

            let origin = req
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if origin.is_empty() || !self.origin_allowed(&origin) {
                // Not a CORS preflight or origin not allowed — pass through.
                return Verdict::Continue;
            }

            Verdict::Respond(self.preflight_response(&origin))
        })
    }

    fn on_response<'a>(
        &'a self,
        req: &'a Request,
        resp: &'a mut Response,
        _fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if let Some(origin) = req.headers.get("origin").and_then(|v| v.to_str().ok()) {
                self.apply_cors_headers(origin, &mut resp.headers);
            }
            Verdict::Continue
        })
    }
}

// ─── Factory ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default = "default_methods")]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allowed_headers: Vec<String>,
    #[serde(default)]
    max_age_secs: Option<u64>,
    #[serde(default)]
    allow_credentials: bool,
}

fn default_methods() -> Vec<String> {
    ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

pub struct CorsFactory;

impl FilterFactory for CorsFactory {
    fn name(&self) -> &str {
        "cors"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: CorsConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid cors config: {e}"))?;

        let allow_any_origin = cfg.allowed_origins.iter().any(|o| o == "*");

        Ok(Arc::new(CorsFilter {
            allowed_origins: cfg.allowed_origins,
            allow_any_origin,
            allowed_methods: cfg.allowed_methods.join(", "),
            allowed_headers: cfg.allowed_headers.join(", "),
            max_age: cfg.max_age_secs.map(|s| s.to_string()),
            allow_credentials: cfg.allow_credentials,
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::{Metrics, RequestLogger, SharedState};
    use crate::test_support::TestHttpClient;
    use http::{Method, Uri};
    use std::collections::HashMap;

    fn test_effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:8080".parse().unwrap()),
            http_client: TestHttpClient::boxed(HashMap::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(crate::filter::SystemClock),
        }
    }

    fn build_cors(config: serde_json::Value) -> Arc<dyn Filter> {
        CorsFactory.build(&config).unwrap()
    }

    fn make_request(method: Method, origin: Option<&str>) -> Request {
        let addr = "10.0.0.1:1234".parse().unwrap();
        let mut req = Request::new(method, Uri::from_static("/api/test"), addr);
        if let Some(o) = origin {
            req.headers.insert("origin", HeaderValue::from_str(o).unwrap());
        }
        req
    }

    // ── Preflight ───────────────────────────────────────────────

    #[tokio::test]
    async fn preflight_returns_204_with_cors_headers() {
        let filter = build_cors(ron_value(r#"{
            "allowed_origins": ["https://example.com"],
            "allowed_headers": ["Content-Type", "Authorization"],
            "max_age_secs": 3600
        }"#));

        let fx = test_effects();
        let mut req = make_request(Method::OPTIONS, Some("https://example.com"));
        let verdict = filter.on_request(&mut req, &fx).await;

        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::NO_CONTENT);
                assert_eq!(
                    resp.headers.get("access-control-allow-origin").unwrap(),
                    "https://example.com"
                );
                assert!(resp
                    .headers
                    .get("access-control-allow-methods")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("GET"));
                assert_eq!(
                    resp.headers.get("access-control-allow-headers").unwrap(),
                    "Content-Type, Authorization"
                );
                assert_eq!(
                    resp.headers.get("access-control-max-age").unwrap(),
                    "3600"
                );
            }
            Verdict::Continue => panic!("expected Respond for preflight"),
        }
    }

    #[tokio::test]
    async fn preflight_disallowed_origin_passes_through() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["https://example.com"]}"#));

        let fx = test_effects();
        let mut req = make_request(Method::OPTIONS, Some("https://evil.com"));
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn non_options_passes_through() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["https://example.com"]}"#));

        let fx = test_effects();
        let mut req = make_request(Method::GET, Some("https://example.com"));
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn options_without_origin_passes_through() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["https://example.com"]}"#));

        let fx = test_effects();
        let mut req = make_request(Method::OPTIONS, None);
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    // ── Wildcard origin ─────────────────────────────────────────

    #[tokio::test]
    async fn wildcard_origin_allows_any() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["*"]}"#));

        let fx = test_effects();
        let mut req = make_request(Method::OPTIONS, Some("https://anything.com"));
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(
                    resp.headers.get("access-control-allow-origin").unwrap(),
                    "*"
                );
            }
            _ => panic!("expected Respond"),
        }
    }

    // ── Credentials mode ────────────────────────────────────────

    #[tokio::test]
    async fn credentials_echoes_specific_origin_not_wildcard() {
        let filter = build_cors(ron_value(r#"{
            "allowed_origins": ["*"],
            "allow_credentials": true
        }"#));

        let fx = test_effects();
        let mut req = make_request(Method::OPTIONS, Some("https://app.example.com"));
        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                // Must echo the specific origin, not "*", when credentials are enabled.
                assert_eq!(
                    resp.headers.get("access-control-allow-origin").unwrap(),
                    "https://app.example.com"
                );
                assert_eq!(
                    resp.headers
                        .get("access-control-allow-credentials")
                        .unwrap(),
                    "true"
                );
            }
            _ => panic!("expected Respond"),
        }
    }

    // ── on_response adds headers ────────────────────────────────

    #[tokio::test]
    async fn on_response_adds_cors_header() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["https://example.com"]}"#));

        let fx = test_effects();
        let req = make_request(Method::GET, Some("https://example.com"));
        let mut resp = Response::ok(b"hello");

        filter.on_response(&req, &mut resp, &fx).await;

        assert_eq!(
            resp.headers.get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn on_response_no_origin_no_headers() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["https://example.com"]}"#));

        let fx = test_effects();
        let req = make_request(Method::GET, None);
        let mut resp = Response::ok(b"hello");

        filter.on_response(&req, &mut resp, &fx).await;

        assert!(resp.headers.get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn on_response_disallowed_origin_no_headers() {
        let filter = build_cors(ron_value(r#"{"allowed_origins": ["https://example.com"]}"#));

        let fx = test_effects();
        let req = make_request(Method::GET, Some("https://evil.com"));
        let mut resp = Response::ok(b"hello");

        filter.on_response(&req, &mut resp, &fx).await;

        assert!(resp.headers.get("access-control-allow-origin").is_none());
    }

    // ── Factory ─────────────────────────────────────────────────

    #[test]
    fn factory_builds_with_defaults() {
        let filter = CorsFactory.build(&ron_value("{}"));
        assert!(filter.is_ok());
        assert_eq!(filter.unwrap().name(), "cors");
    }

    #[test]
    fn factory_rejects_invalid_config() {
        // Config type errors should produce Err
        let result = CorsFactory.build(&ron_value(r#"{"max_age_secs": "not_a_number"}"#));
        assert!(result.is_err());
    }

    #[test]
    fn factory_name() {
        assert_eq!(CorsFactory.name(), "cors");
    }
}
