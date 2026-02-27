//! Filter trait, Verdict, and Effects.
//!
//! Design:
//! - Filter is an async trait with `&mut Request` (zero-copy mutation)
//! - Effects are injected explicitly — no hidden global state
//! - Verdict is an algebraic type — exhaustive match, no sentinel values

use crate::types::{Request, Response};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

// ─── Verdict ─────────────────────────────────────────────────────────

/// Decision returned by a filter after processing.
///
/// Exhaustive: the compiler forces you to handle every case.
pub enum Verdict {
    /// Continue to the next filter. Request was mutated in-place.
    Continue,
    /// Short-circuit: respond to the client immediately, skip remaining filters.
    Respond(Response),
}

// ─── Effects ─────────────────────────────────────────────────────────

/// Explicit side-effect capabilities injected into every filter call.
///
/// A filter cannot do anything not declared here:
/// - No global singletons
/// - No hidden redis calls
/// - Testing: swap real impls for mocks
pub struct Effects {
    pub metrics: Arc<Metrics>,
    pub log: RequestLogger,
    pub http_client: Arc<HttpClient>,
    pub shared: Arc<SharedState>,
    pub clock: Arc<dyn Clock + Send + Sync>,
}

// ─── Clock (injectable time) ─────────────────────────────────────────

/// Injectable clock for testability.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Real system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

// ─── Metrics ─────────────────────────────────────────────────────────

/// Per-worker, lock-free metrics counters.
///
/// In a real implementation this would be a registry of named counters/gauges.
/// Simplified here to demonstrate the pattern.
pub struct Metrics {
    counters: dashmap_lite::Counters,
}

/// Minimal lock-free counter store (placeholder for a real metrics library).
pub mod dashmap_lite {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::RwLock;

    pub struct Counters {
        map: RwLock<HashMap<String, AtomicU64>>,
    }

    impl Counters {
        pub fn new() -> Self {
            Self {
                map: RwLock::new(HashMap::new()),
            }
        }

        pub fn inc(&self, name: &str) {
            let map = self.map.read().unwrap_or_else(|e| e.into_inner());
            if let Some(counter) = map.get(name) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
            drop(map);
            let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
            map.entry(name.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }

        pub fn get(&self, name: &str) -> u64 {
            let map = self.map.read().unwrap_or_else(|e| e.into_inner());
            map.get(name)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0)
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            counters: dashmap_lite::Counters::new(),
        }
    }

    pub fn counter_inc(&self, name: &str) {
        self.counters.inc(name);
    }

    pub fn counter_get(&self, name: &str) -> u64 {
        self.counters.get(name)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RequestLogger ───────────────────────────────────────────────────

/// Structured logger scoped to a single request.
pub struct RequestLogger {
    peer_addr: std::net::SocketAddr,
}

impl RequestLogger {
    pub fn new(peer_addr: std::net::SocketAddr) -> Self {
        Self { peer_addr }
    }

    pub fn info(&self, msg: &str, fields: &[(&str, &str)]) {
        tracing::info!(peer = %self.peer_addr, msg, ?fields);
    }

    pub fn warn(&self, msg: &str, fields: &[(&str, &str)]) {
        tracing::warn!(peer = %self.peer_addr, msg, ?fields);
    }

    pub fn error(&self, msg: &str, fields: &[(&str, &str)]) {
        tracing::error!(peer = %self.peer_addr, msg, ?fields);
    }
}

// ─── HttpClient ──────────────────────────────────────────────────────

/// HTTP client for filter callouts (auth, rate limit, etc.).
///
/// Placeholder — a real implementation would use hyper or reqwest with
/// a per-worker connection pool.
pub struct HttpClient;

impl HttpClient {
    pub fn new() -> Self {
        Self
    }

    /// Perform an HTTP GET callout. Placeholder.
    pub async fn get(&self, _url: &str) -> Result<Vec<u8>, String> {
        // In production: use hyper client with connection pooling
        Ok(Vec::new())
    }

    /// Perform an HTTP POST callout. Placeholder.
    pub async fn post(&self, _url: &str, _body: &[u8]) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SharedState ─────────────────────────────────────────────────────

/// Shared mutable state across requests (rate limiters, circuit breakers).
///
/// Uses `Mutex` per-map to avoid TOCTOU races between read/write paths.
/// The critical section is very short (HashMap lookup + increment), so
/// contention is minimal in practice.
pub struct SharedState {
    rate_counters: std::sync::Mutex<std::collections::HashMap<IpAddr, RateEntry>>,
}

struct RateEntry {
    count: u64,
    window_start: Instant,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            rate_counters: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Check rate limit for an IP. Returns remaining quota, or None if exceeded.
    ///
    /// Mutex ensures atomicity: no TOCTOU between window-check and counter-update.
    pub fn rate_check(&self, ip: IpAddr, now: Instant, max_rps: u64) -> Option<u64> {
        let mut map = self.rate_counters.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(ip).or_insert_with(|| RateEntry {
            count: 0,
            window_start: now,
        });

        let elapsed = now.duration_since(entry.window_start);
        if elapsed.as_secs() >= 1 {
            // Window expired — reset
            entry.window_start = now;
            entry.count = 1;
            Some(max_rps - 1)
        } else {
            entry.count += 1;
            if entry.count > max_rps {
                None
            } else {
                Some(max_rps - entry.count)
            }
        }
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Filter Trait ────────────────────────────────────────────────────

/// The core Filter trait.
///
/// Why `&mut Request` instead of `Fn(Request) -> Request`:
/// - Zero-copy: HeaderMap is mutated in-place, not recreated
/// - Streaming: BodyStream can't be cloned (mpsc::Receiver is unique)
/// - Rust ownership guarantees only one filter holds &mut at a time
///
/// Why async:
/// - Filters may need to do HTTP callouts (auth, rate limit)
/// - Tokio executor handles scheduling, not our code
///
/// Why Effects as parameter:
/// - Explicit dependency injection, no global state
/// - Testable: mock the clock, mock the http client
pub trait Filter: Send + Sync + 'static {
    /// Filter name — for logging and metrics.
    fn name(&self) -> &'static str;

    /// Process request headers (body is still streaming).
    ///
    /// Mutate `req` in place. Return `Verdict::Continue` to pass to next filter,
    /// or `Verdict::Respond` to short-circuit with a direct response.
    ///
    /// Uses `Pin<Box<dyn Future>>` for dyn-compatibility.
    /// The allocation cost is negligible: one Box per filter per request,
    /// vs. the IO cost of handling the request itself.
    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        effects: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>>;

    /// Process response from upstream (optional, default: pass through).
    ///
    /// `req` is read-only (already sent to upstream).
    fn on_response<'a>(
        &'a self,
        _req: &'a Request,
        _resp: &'a mut Response,
        _effects: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async { Verdict::Continue })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    // ── Metrics: correctness ────────────────────────────────────

    #[test]
    fn metrics_counter_starts_at_zero() {
        let m = Metrics::new();
        assert_eq!(m.counter_get("nonexistent"), 0);
    }

    #[test]
    fn metrics_counter_increments() {
        let m = Metrics::new();
        m.counter_inc("requests");
        m.counter_inc("requests");
        m.counter_inc("requests");
        assert_eq!(m.counter_get("requests"), 3);
    }

    #[test]
    fn metrics_independent_counters() {
        let m = Metrics::new();
        m.counter_inc("a");
        m.counter_inc("a");
        m.counter_inc("b");
        assert_eq!(m.counter_get("a"), 2);
        assert_eq!(m.counter_get("b"), 1);
        assert_eq!(m.counter_get("c"), 0);
    }

    #[test]
    fn metrics_concurrent_increments() {
        // Proves lock-free counters are thread-safe under contention
        let m = Arc::new(Metrics::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let m = Arc::clone(&m);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        m.counter_inc("hot");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(m.counter_get("hot"), 8000);
    }

    // ── SharedState::rate_check ─────────────────────────────────

    #[test]
    fn rate_check_allows_within_limit() {
        let state = SharedState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let now = Instant::now();

        // 5 rps limit, first request
        let remaining = state.rate_check(ip, now, 5);
        assert_eq!(remaining, Some(4)); // 5 - 1

        // Second request in same window
        let remaining = state.rate_check(ip, now, 5);
        assert_eq!(remaining, Some(3)); // 5 - 2
    }

    #[test]
    fn rate_check_blocks_when_exceeded() {
        let state = SharedState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let now = Instant::now();

        // Fill the window
        for _ in 0..3 {
            state.rate_check(ip, now, 3);
        }

        // 4th request: blocked
        assert_eq!(state.rate_check(ip, now, 3), None);
    }

    #[test]
    fn rate_check_resets_after_window() {
        let state = SharedState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t0 = Instant::now();

        // Fill to limit
        for _ in 0..3 {
            state.rate_check(ip, t0, 3);
        }
        assert_eq!(state.rate_check(ip, t0, 3), None);

        // Jump 1 second forward — window resets
        let t1 = t0 + Duration::from_secs(1);
        let remaining = state.rate_check(ip, t1, 3);
        assert_eq!(remaining, Some(2)); // fresh window, first request
    }

    #[test]
    fn rate_check_independent_ips() {
        let state = SharedState::new();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let now = Instant::now();

        // Fill IP-A to limit
        for _ in 0..2 {
            state.rate_check(ip_a, now, 2);
        }
        assert_eq!(state.rate_check(ip_a, now, 2), None);

        // IP-B is unaffected
        assert_eq!(state.rate_check(ip_b, now, 2), Some(1));
    }

    // ── Clock trait ─────────────────────────────────────────────

    #[test]
    fn system_clock_returns_monotonic_time() {
        let clock = SystemClock;
        let t1 = clock.now();
        let t2 = clock.now();
        assert!(t2 >= t1);
    }

    // ── RequestLogger ───────────────────────────────────────────

    #[test]
    fn request_logger_does_not_panic() {
        // Logging is a side effect — we verify it doesn't panic
        let logger = RequestLogger::new("127.0.0.1:8080".parse().unwrap());
        logger.info("test info", &[("key", "val")]);
        logger.warn("test warn", &[]);
        logger.error("test error", &[("a", "b"), ("c", "d")]);
    }
}
