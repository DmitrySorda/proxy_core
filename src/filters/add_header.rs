//! Add-header filter — simplest possible filter for demos and testing.
//!
//! Adds a static header to every request passing through.

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::types::Request;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Filter that adds a static header to every request.
pub struct AddHeaderFilter {
    header_name: String,
    header_value: String,
}

impl AddHeaderFilter {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header_name: name.into(),
            header_value: value.into(),
        }
    }
}

impl Filter for AddHeaderFilter {
    fn name(&self) -> &'static str {
        "add_header"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(self.header_name.as_bytes()),
                http::header::HeaderValue::from_str(&self.header_value),
            ) {
                req.headers.insert(name, value);
                fx.metrics.counter_inc("add_header.applied");
            }
            Verdict::Continue
        })
    }
}

/// Factory: `{ "header_name": "x-proxy", "header_value": "proxy_core" }`
pub struct AddHeaderFactory;

impl FilterFactory for AddHeaderFactory {
    fn name(&self) -> &str {
        "add_header"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let header_name = config
            .get("header_name")
            .and_then(|v| v.as_str())
            .unwrap_or("x-proxy")
            .to_string();

        let header_value = config
            .get("header_value")
            .and_then(|v| v.as_str())
            .unwrap_or("proxy_core")
            .to_string();

        Ok(Arc::new(AddHeaderFilter::new(header_name, header_value)))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

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
    async fn adds_configured_header() {
        let filter = AddHeaderFilter::new("x-proxy", "proxy_core/0.1");
        let fx = test_effects();
        let mut req = test_request();

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(
            req.headers.get("x-proxy").unwrap().to_str().unwrap(),
            "proxy_core/0.1"
        );
    }

    #[tokio::test]
    async fn always_continues_never_blocks() {
        let filter = AddHeaderFilter::new("x-whatever", "value");
        let fx = test_effects();
        let mut req = test_request();

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn increments_metrics_counter() {
        let filter = AddHeaderFilter::new("x-test", "v");
        let fx = test_effects();
        let mut req = test_request();

        filter.on_request(&mut req, &fx).await;
        assert_eq!(fx.metrics.counter_get("add_header.applied"), 1);

        let mut req2 = test_request();
        filter.on_request(&mut req2, &fx).await;
        assert_eq!(fx.metrics.counter_get("add_header.applied"), 2);
    }

    #[tokio::test]
    async fn overwrites_existing_header() {
        let filter = AddHeaderFilter::new("x-proxy", "new");
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert("x-proxy", http::HeaderValue::from_static("old"));

        filter.on_request(&mut req, &fx).await;
        assert_eq!(
            req.headers.get("x-proxy").unwrap().to_str().unwrap(),
            "new"
        );
    }

    // ── Factory ─────────────────────────────────────────────────

    #[tokio::test]
    async fn factory_builds_with_config() {
        let factory = AddHeaderFactory;
        let config = ron_value(r#"{"header_name": "x-custom", "header_value": "custom-val"}"#);
        let filter = factory.build(&config).unwrap();

        let fx = test_effects();
        let mut req = test_request();
        filter.on_request(&mut req, &fx).await;
        assert_eq!(
            req.headers.get("x-custom").unwrap().to_str().unwrap(),
            "custom-val"
        );
    }

    #[tokio::test]
    async fn factory_uses_defaults_when_config_empty() {
        let factory = AddHeaderFactory;
        let config = ron_value("{}");
        let filter = factory.build(&config).unwrap();

        let fx = test_effects();
        let mut req = test_request();
        filter.on_request(&mut req, &fx).await;
        // Default: x-proxy: proxy_core
        assert_eq!(
            req.headers.get("x-proxy").unwrap().to_str().unwrap(),
            "proxy_core"
        );
    }
}
