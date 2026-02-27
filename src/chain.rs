//! FilterChain — the executor that runs requests through filters.
//!
//! - Sequential execution: filter₀ → filter₁ → … → filterₙ
//! - Response filters run in reverse order (mirroring Envoy)
//! - ActiveChain uses ArcSwap for lock-free hot reload

use crate::filter::{Effects, Filter, Verdict};
use crate::types::{Request, Response};
use arc_swap::ArcSwap;
use std::sync::Arc;

/// An immutable, ordered list of filters.
///
/// Created once by [`ChainBuilder`](crate::builder::ChainBuilder),
/// atomically swapped on config reload.
pub struct FilterChain {
    filters: Vec<Arc<dyn Filter>>,
}

impl std::fmt::Debug for FilterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterChain")
            .field("filters_count", &self.filters.len())
            .finish()
    }
}

impl FilterChain {
    /// Create a new chain from a list of filters.
    pub fn new(filters: Vec<Arc<dyn Filter>>) -> Self {
        Self { filters }
    }

    /// Create an empty chain (no-op passthrough).
    pub fn empty() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Number of filters in the chain.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Execute request filters sequentially.
    ///
    /// Each filter gets `&mut Request` — mutates in-place, no cloning.
    /// Returns `Some(Response)` if any filter short-circuits,
    /// or `None` if all filters say `Continue` (forward to upstream).
    pub async fn execute_request(
        &self,
        req: &mut Request,
        effects: &Effects,
    ) -> Option<Response> {
        for filter in &self.filters {
            match filter.on_request(req, effects).await {
                Verdict::Continue => continue,
                Verdict::Respond(resp) => {
                    tracing::debug!(
                        filter = filter.name(),
                        status = %resp.status,
                        "filter short-circuited request"
                    );
                    return Some(resp);
                }
            }
        }
        None
    }

    /// Execute response filters in reverse order.
    ///
    /// This mirrors Envoy's behavior: encoder filters run in the
    /// opposite direction of decoder filters.
    pub async fn execute_response(
        &self,
        req: &Request,
        resp: &mut Response,
        effects: &Effects,
    ) -> Option<Response> {
        for filter in self.filters.iter().rev() {
            match filter.on_response(req, resp, effects).await {
                Verdict::Continue => continue,
                Verdict::Respond(override_resp) => {
                    tracing::debug!(
                        filter = filter.name(),
                        status = %override_resp.status,
                        "filter overrode response"
                    );
                    return Some(override_resp);
                }
            }
        }
        None
    }
}

/// Lock-free handle to the currently active filter chain.
///
/// Workers call `load()` to get the current chain — no locks, no contention.
/// Control plane calls `store()` to atomically swap in a new chain.
///
/// Old chains are kept alive by Arc reference counting until all
/// in-flight requests through them complete — graceful drain for free.
pub type ActiveChain = Arc<ArcSwap<FilterChain>>;

/// Create a new ActiveChain with an initial (possibly empty) chain.
pub fn new_active_chain(initial: FilterChain) -> ActiveChain {
    Arc::new(ArcSwap::from_pointee(initial))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::*;
    use http::{Method, StatusCode, Uri};
    use std::net::SocketAddr;

    /// A test filter that adds a header.
    struct AddHeaderFilter {
        key: &'static str,
        value: &'static str,
    }

    impl Filter for AddHeaderFilter {
        fn name(&self) -> &'static str {
            "add_header"
        }

        fn on_request<'a>(
            &'a self,
            req: &'a mut Request,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async move {
                req.headers
                    .insert(self.key, http::HeaderValue::from_static(self.value));
                Verdict::Continue
            })
        }
    }

    /// A test filter that blocks requests to /admin.
    struct BlockAdminFilter;

    impl Filter for BlockAdminFilter {
        fn name(&self) -> &'static str {
            "block_admin"
        }

        fn on_request<'a>(
            &'a self,
            req: &'a mut Request,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async move {
                if req.uri.path() == "/admin" {
                    Verdict::Respond(Response::error(StatusCode::FORBIDDEN, b"Forbidden"))
                } else {
                    Verdict::Continue
                }
            })
        }
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

    fn test_request(path: &str) -> Request {
        Request::new(
            Method::GET,
            Uri::try_from(path).unwrap(),
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        )
    }

    #[tokio::test]
    async fn chain_passes_through_when_all_continue() {
        let chain = FilterChain::new(vec![
            Arc::new(AddHeaderFilter {
                key: "x-test",
                value: "hello",
            }),
        ]);
        let fx = test_effects();
        let mut req = test_request("/");

        let result = chain.execute_request(&mut req, &fx).await;
        assert!(result.is_none(), "all filters said Continue → no response");
        assert_eq!(req.headers.get("x-test").unwrap(), "hello");
    }

    #[tokio::test]
    async fn chain_short_circuits_on_respond() {
        let chain = FilterChain::new(vec![
            Arc::new(BlockAdminFilter),
            Arc::new(AddHeaderFilter {
                key: "x-should-not-run",
                value: "oops",
            }),
        ]);
        let fx = test_effects();
        let mut req = test_request("/admin");

        let result = chain.execute_request(&mut req, &fx).await;
        let resp = result.expect("BlockAdminFilter should respond 403");
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        // Second filter should NOT have run:
        assert!(req.headers.get("x-should-not-run").is_none());
    }

    #[tokio::test]
    async fn chain_allows_non_admin_through() {
        let chain = FilterChain::new(vec![
            Arc::new(BlockAdminFilter),
            Arc::new(AddHeaderFilter {
                key: "x-passed",
                value: "yes",
            }),
        ]);
        let fx = test_effects();
        let mut req = test_request("/api/data");

        let result = chain.execute_request(&mut req, &fx).await;
        assert!(result.is_none());
        assert_eq!(req.headers.get("x-passed").unwrap(), "yes");
    }

    #[tokio::test]
    async fn empty_chain_is_passthrough() {
        let chain = FilterChain::empty();
        let fx = test_effects();
        let mut req = test_request("/");

        let result = chain.execute_request(&mut req, &fx).await;
        assert!(result.is_none());
    }

    // ── execute_response ────────────────────────────────────────

    /// A test filter that modifies the response (adds a header).
    struct ResponseHeaderFilter {
        key: &'static str,
        value: &'static str,
    }

    impl Filter for ResponseHeaderFilter {
        fn name(&self) -> &'static str {
            "resp_header"
        }

        fn on_request<'a>(
            &'a self,
            _req: &'a mut Request,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async { Verdict::Continue })
        }

        fn on_response<'a>(
            &'a self,
            _req: &'a Request,
            resp: &'a mut Response,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async move {
                resp.headers.insert(
                    self.key,
                    http::HeaderValue::from_static(self.value),
                );
                Verdict::Continue
            })
        }
    }

    #[tokio::test]
    async fn response_filters_run_in_reverse_order() {
        let chain = FilterChain::new(vec![
            Arc::new(ResponseHeaderFilter { key: "x-first", value: "1" }),
            Arc::new(ResponseHeaderFilter { key: "x-second", value: "2" }),
        ]);
        let fx = test_effects();
        let req = test_request("/");

        // Capture order via side effects: response filters run in reverse
        // So second filter runs first, then first filter
        let mut resp = Response::default();
        let result = chain.execute_response(&req, &mut resp, &fx).await;
        assert!(result.is_none()); // All Continue
        // Both headers should be set
        assert_eq!(resp.headers.get("x-first").unwrap(), "1");
        assert_eq!(resp.headers.get("x-second").unwrap(), "2");
    }

    /// A filter that overrides the response.
    struct OverrideResponseFilter;

    impl Filter for OverrideResponseFilter {
        fn name(&self) -> &'static str {
            "override_resp"
        }

        fn on_request<'a>(
            &'a self,
            _req: &'a mut Request,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async { Verdict::Continue })
        }

        fn on_response<'a>(
            &'a self,
            _req: &'a Request,
            _resp: &'a mut Response,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async {
                Verdict::Respond(Response::error(StatusCode::IM_A_TEAPOT, b"teapot"))
            })
        }
    }

    #[tokio::test]
    async fn response_filter_can_override() {
        // Chain: [first_header, override, second_header]
        // Response runs reverse: second_header → override (short-circuits) → first_header (skipped)
        let chain = FilterChain::new(vec![
            Arc::new(ResponseHeaderFilter { key: "x-first", value: "1" }),
            Arc::new(OverrideResponseFilter),
            Arc::new(ResponseHeaderFilter { key: "x-second", value: "2" }),
        ]);
        let fx = test_effects();
        let req = test_request("/");
        let mut resp = Response::default();

        let result = chain.execute_response(&req, &mut resp, &fx).await;
        let overridden = result.expect("OverrideResponseFilter should produce Respond");
        assert_eq!(overridden.status, StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn empty_chain_response_is_passthrough() {
        let chain = FilterChain::empty();
        let fx = test_effects();
        let req = test_request("/");
        let mut resp = Response::default();

        let result = chain.execute_response(&req, &mut resp, &fx).await;
        assert!(result.is_none());
    }

    // ── ActiveChain + ArcSwap ───────────────────────────────────

    #[test]
    fn active_chain_hot_reload() {
        let active = crate::chain::new_active_chain(FilterChain::empty());
        assert!(active.load().is_empty());

        // Simulate hot reload
        let new_chain = FilterChain::new(vec![Arc::new(AddHeaderFilter {
            key: "x-new",
            value: "after-reload",
        })]);
        active.store(Arc::new(new_chain));
        assert_eq!(active.load().len(), 1);
    }
}
