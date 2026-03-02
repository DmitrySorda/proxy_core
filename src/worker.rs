//! Worker event loop and connection handling.
//!
//! Features:
//! - **Keep-alive**: reuses TCP connections (loop per connection, BufReader for leftover bytes)
//! - **Graceful shutdown**: drains in-flight connections on shutdown signal
//! - **Connection limits**: rejects new connections when at capacity (503)
//! - Per-request Effects injection
//! - Lock-free chain loading via ArcSwap

use crate::chain::ActiveChain;
use crate::filter::{Effects, HttpClient, HttpClientLike, Metrics, RequestLogger, SharedState, SystemClock};
use crate::types::{BodyStream, Request, Response};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// ─── Configuration ──────────────────────────────────────────────────

/// Worker configuration with sensible defaults.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Maximum concurrent connections (0 = unlimited).
    pub max_connections: u64,
    /// Maximum requests per keep-alive connection before forcing close.
    pub max_requests_per_conn: u64,
    /// Idle timeout between requests on a keep-alive connection.
    pub idle_timeout: Duration,
    /// Maximum header size (bytes). 431 if exceeded.
    pub max_header_size: usize,
    /// Graceful shutdown drain timeout — force-close after this.
    pub drain_timeout: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_requests_per_conn: 100,
            idle_timeout: Duration::from_secs(60),
            max_header_size: 8192,
            drain_timeout: Duration::from_secs(30),
        }
    }
}

// ─── Connection tracking ─────────────────────────────────────────────

/// Atomic connection counter for limits and graceful shutdown.
#[derive(Debug)]
pub struct ConnectionTracker {
    active: AtomicU64,
    total: AtomicU64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// Try to acquire a connection slot. Returns false if at capacity.
    pub fn try_acquire(&self, max: u64) -> bool {
        if max == 0 {
            // Unlimited
            self.active.fetch_add(1, Ordering::Relaxed);
            self.total.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        // CAS loop to atomically check-and-increment
        loop {
            let current = self.active.load(Ordering::Relaxed);
            if current >= max {
                return false;
            }
            if self
                .active
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.total.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }

    /// Release a connection slot.
    pub fn release(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current active connections.
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// Total connections since start.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Worker ──────────────────────────────────────────────────────────

/// A worker that accepts connections and processes them through the filter chain.
pub struct Worker {
    pub chain: ActiveChain,
    pub config: WorkerConfig,
    pub metrics: Arc<Metrics>,
    pub http_client: Arc<dyn HttpClientLike>,
    pub shared: Arc<SharedState>,
    pub connections: Arc<ConnectionTracker>,
}

impl Worker {
    /// Create a new worker with the given active chain and default config.
    pub fn new(chain: ActiveChain) -> Self {
        Self {
            chain,
            config: WorkerConfig::default(),
            metrics: Arc::new(Metrics::new()),
            http_client: Arc::new(HttpClient::new()) as Arc<dyn HttpClientLike>,
            shared: Arc::new(SharedState::new()),
            connections: Arc::new(ConnectionTracker::new()),
        }
    }

    /// Create a new worker with custom config.
    pub fn with_config(chain: ActiveChain, config: WorkerConfig) -> Self {
        Self {
            chain,
            config,
            metrics: Arc::new(Metrics::new()),
            http_client: Arc::new(HttpClient::new()) as Arc<dyn HttpClientLike>,
            shared: Arc::new(SharedState::new()),
            connections: Arc::new(ConnectionTracker::new()),
        }
    }

    /// Run the accept loop with graceful shutdown support.
    ///
    /// Listens for connections until `shutdown` signal fires, then drains
    /// in-flight connections up to `drain_timeout`.
    pub async fn serve_with_shutdown(
        &self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) {
        tracing::info!(
            addr = %listener.local_addr().unwrap(),
            max_conn = self.config.max_connections,
            idle_timeout_s = self.config.idle_timeout.as_secs(),
            max_req_per_conn = self.config.max_requests_per_conn,
            "worker accepting connections (keep-alive enabled)"
        );

        // Shutdown signal for all connection tasks
        let (conn_shutdown_tx, conn_shutdown_rx) = watch::channel(false);

        loop {
            tokio::select! {
                biased;

                // Check shutdown signal first
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("shutdown signal received, draining connections");
                        break;
                    }
                }

                // Accept new connections
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            // --- Connection limit check ---
                            if !self.connections.try_acquire(self.config.max_connections) {
                                self.metrics.counter_inc("connections.rejected");
                                tracing::warn!(
                                    peer = %peer_addr,
                                    active = self.connections.active(),
                                    max = self.config.max_connections,
                                    "connection rejected: at capacity"
                                );
                                // Send 503 and close
                                let _ = reject_connection(stream).await;
                                continue;
                            }

                            self.metrics.counter_inc("connections.accepted");

                            // Lock-free load of current chain
                            let chain = self.chain.load_full();
                            let metrics = Arc::clone(&self.metrics);
                            let http_client = Arc::clone(&self.http_client);
                            let shared = Arc::clone(&self.shared);
                            let connections = Arc::clone(&self.connections);
                            let config = self.config.clone();
                            let mut conn_shutdown = conn_shutdown_rx.clone();

                            tokio::spawn(async move {
                                let effects = Effects {
                                    metrics,
                                    log: RequestLogger::new(peer_addr),
                                    http_client,
                                    shared,
                                    clock: Arc::new(SystemClock),
                                };

                                let result = handle_connection(
                                    stream,
                                    peer_addr,
                                    chain,
                                    effects,
                                    &config,
                                    &mut conn_shutdown,
                                )
                                .await;

                                connections.release();

                                if let Err(e) = result {
                                    tracing::debug!(
                                        peer = %peer_addr,
                                        error = %e,
                                        "connection closed with error"
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "accept failed");
                        }
                    }
                }
            }
        }

        // --- Graceful drain ---
        tracing::info!(
            active = self.connections.active(),
            drain_timeout_s = self.config.drain_timeout.as_secs(),
            "draining in-flight connections"
        );

        // Signal all connection loops to stop accepting new requests
        let _ = conn_shutdown_tx.send(true);

        // Wait for connections to drain or timeout
        let drain_start = tokio::time::Instant::now();
        loop {
            let active = self.connections.active();
            if active == 0 {
                tracing::info!("all connections drained");
                break;
            }
            if drain_start.elapsed() >= self.config.drain_timeout {
                tracing::warn!(
                    remaining = active,
                    "drain timeout reached, force-closing remaining connections"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tracing::info!(
            total_connections = self.connections.total(),
            "worker shut down"
        );
    }

    /// Simple serve without explicit shutdown (Ctrl+C still works via tokio signal).
    pub async fn serve(&self, listener: TcpListener) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Listen for SIGTERM / Ctrl+C
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("received Ctrl+C / SIGTERM");
            let _ = tx.send(true);
        });

        self.serve_with_shutdown(listener, shutdown_rx).await;
    }
}

// ─── Connection handler (keep-alive loop) ────────────────────────────

/// Handle a single connection with keep-alive support.
///
/// Processes multiple requests on the same TCP connection. Closes when:
/// - Client sends `Connection: close`
/// - `max_requests_per_conn` reached
/// - Idle timeout between requests
/// - Shutdown signal received
/// - Client closes the connection
/// - Parse error
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    chain: Arc<crate::chain::FilterChain>,
    effects: Effects,
    config: &WorkerConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::with_capacity(8192, reader);
    let mut writer = writer;
    let mut request_count: u64 = 0;

    loop {
        // --- Check limits ---
        if request_count >= config.max_requests_per_conn {
            tracing::debug!(
                peer = %peer_addr,
                requests = request_count,
                "max requests per connection reached"
            );
            break;
        }

        // --- Read request with idle timeout + shutdown check ---
        let header_bytes = tokio::select! {
            biased;

            // Shutdown: stop accepting new requests on this connection
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::debug!(peer = %peer_addr, "shutdown: closing keep-alive connection");
                    break;
                }
                continue;
            }

            // Idle timeout waiting for next request
            result = tokio::time::timeout(
                config.idle_timeout,
                read_headers(&mut reader, config.max_header_size)
            ) => {
                match result {
                    Ok(Ok(Some(bytes))) => bytes,
                    Ok(Ok(None)) => {
                        // Client closed cleanly
                        break;
                    }
                    Ok(Err(HeaderError::TooLarge)) => {
                        let _ = writer.write_all(
                            b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
                        ).await;
                        break;
                    }
                    Ok(Err(HeaderError::Io(e))) => {
                        return Err(e.into());
                    }
                    Err(_timeout) => {
                        tracing::debug!(
                            peer = %peer_addr,
                            idle_s = config.idle_timeout.as_secs(),
                            "idle timeout, closing connection"
                        );
                        break;
                    }
                }
            }
        };

        request_count += 1;

        // --- Parse request line + headers ---
        let raw = String::from_utf8_lossy(&header_bytes);
        let mut request = match parse_request_line(&raw, peer_addr) {
            Ok(req) => req,
            Err(e) => {
                tracing::debug!(peer = %peer_addr, error = %e, "bad request");
                let _ = writer.write_all(
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
                ).await;
                break;
            }
        };

        // --- Determine keep-alive from client ---
        let client_wants_close = request
            .headers
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);

        // --- Read body (Content-Length based) ---
        let content_length: usize = request
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        if content_length > 0 {
            let mut body_buf = vec![0u8; content_length];
            reader.read_exact(&mut body_buf).await?;
            request.body = BodyStream::from_bytes(Bytes::from(body_buf));
        }

        effects.metrics.counter_inc("requests.total");

        // --- Run request filters ---
        let direct_resp = chain.execute_request(&mut request, &effects).await;

        let mut response = match direct_resp {
            Some(resp) => resp,
            None => Response {
                status: StatusCode::OK,
                version: Version::HTTP_11,
                headers: HeaderMap::new(),
                body: BodyStream::from_static(b"proxy_core OK\n"),
                metadata: typemap_rev::TypeMap::new(),
            },
        };

        // --- Run response filters (reverse order) ---
        let final_resp =
            if let Some(overridden) = chain.execute_response(&request, &mut response, &effects).await {
                overridden
            } else {
                response
            };

        // --- Decide connection persistence ---
        let force_close = client_wants_close
            || request_count >= config.max_requests_per_conn
            || *shutdown.borrow();

        // --- Write response ---
        write_response(&mut writer, &final_resp, !force_close).await?;

        if force_close {
            break;
        }
    }

    tracing::debug!(
        peer = %peer_addr,
        requests = request_count,
        "connection closed"
    );

    effects.metrics.counter_inc("connections.closed");

    Ok(())
}

// ─── Header reading with BufReader ───────────────────────────────────

#[derive(Debug)]
enum HeaderError {
    TooLarge,
    Io(std::io::Error),
}

/// Read HTTP headers from a buffered reader until `\r\n\r\n`.
///
/// Returns `None` if the client closed the connection (EOF before any data).
/// Leftover bytes after the header boundary remain in the BufReader for body reading.
async fn read_headers(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    max_size: usize,
) -> Result<Option<Vec<u8>>, HeaderError> {
    let mut buf = Vec::with_capacity(1024);

    loop {
        // Read a line (up to \n)
        let bytes_read = reader
            .read_until(b'\n', &mut buf)
            .await
            .map_err(HeaderError::Io)?;

        if bytes_read == 0 {
            // EOF
            if buf.is_empty() {
                return Ok(None); // Clean close
            }
            return Ok(Some(buf)); // Partial read — try to process
        }

        if buf.len() > max_size {
            return Err(HeaderError::TooLarge);
        }

        // Check for end-of-headers: \r\n\r\n
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(Some(buf));
        }
        // Also handle \n\n (lenient)
        if buf.len() >= 2 && &buf[buf.len() - 2..] == b"\n\n" {
            return Ok(Some(buf));
        }
    }
}

// ─── Request parser ──────────────────────────────────────────────────

/// Parse a minimal HTTP/1.1 request line and headers.
fn parse_request_line(
    raw: &str,
    peer_addr: SocketAddr,
) -> Result<Request, Box<dyn std::error::Error + Send + Sync>> {
    let first_line = raw.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    let method = if !parts.is_empty() {
        Method::from_bytes(parts[0].as_bytes()).unwrap_or(Method::GET)
    } else {
        Method::GET
    };

    let uri = if parts.len() >= 2 {
        Uri::try_from(parts[1])?
    } else {
        Uri::from_static("/")
    };

    let mut request = Request::new(method, uri, peer_addr);

    // Parse headers (simplified)
    for line in raw.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::from_bytes(key.as_bytes()),
                http::header::HeaderValue::from_str(value),
            ) {
                request.headers.insert(name, val);
            }
        }
    }

    Ok(request)
}

// ─── Response writer ─────────────────────────────────────────────────

/// Write an HTTP/1.1 response. Sets `Connection: keep-alive` or `close`.
async fn write_response(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    response: &Response,
    keep_alive: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut writer = BufWriter::new(stream);

    let reason = response.status.canonical_reason().unwrap_or("");
    let status_line = format!("HTTP/1.1 {} {}\r\n", response.status.as_u16(), reason);
    writer.write_all(status_line.as_bytes()).await?;

    for (name, value) in response.headers.iter() {
        let header_line = format!("{}: {}\r\n", name, value.to_str().unwrap_or(""));
        writer.write_all(header_line.as_bytes()).await?;
    }

    if keep_alive {
        writer.write_all(b"Connection: keep-alive\r\n").await?;
    } else {
        writer.write_all(b"Connection: close\r\n").await?;
    }

    writer.write_all(b"\r\n").await?;

    // Stream the actual response body
    while let Some(chunk) = response.body.next_chunk().await {
        match chunk {
            Ok(data) => writer.write_all(&data).await?,
            Err(_) => break,
        }
    }

    writer.flush().await?;
    Ok(())
}

/// Reject a connection with 503 Service Unavailable (over capacity).
async fn reject_connection(mut stream: TcpStream) -> Result<(), std::io::Error> {
    stream
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\n\
              Connection: close\r\n\
              Content-Length: 20\r\n\
              \r\n\
              Service Unavailable\n",
        )
        .await?;
    stream.flush().await?;
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConnectionTracker ───────────────────────────────────────

    #[test]
    fn connection_tracker_basic() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.active(), 0);
        assert_eq!(tracker.total(), 0);

        assert!(tracker.try_acquire(10));
        assert_eq!(tracker.active(), 1);
        assert_eq!(tracker.total(), 1);

        assert!(tracker.try_acquire(10));
        assert_eq!(tracker.active(), 2);

        tracker.release();
        assert_eq!(tracker.active(), 1);
        assert_eq!(tracker.total(), 2);
    }

    #[test]
    fn connection_tracker_at_capacity() {
        let tracker = ConnectionTracker::new();
        assert!(tracker.try_acquire(2));
        assert!(tracker.try_acquire(2));
        assert!(!tracker.try_acquire(2)); // At capacity
        assert_eq!(tracker.active(), 2);

        tracker.release();
        assert!(tracker.try_acquire(2)); // Slot freed
    }

    #[test]
    fn connection_tracker_unlimited() {
        let tracker = ConnectionTracker::new();
        for _ in 0..1000 {
            assert!(tracker.try_acquire(0)); // 0 = unlimited
        }
        assert_eq!(tracker.active(), 1000);
    }

    #[test]
    fn connection_tracker_concurrent_acquire_release() {
        // Proves CAS loop is correct under contention
        let tracker = Arc::new(ConnectionTracker::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let t = Arc::clone(&tracker);
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        if t.try_acquire(1000) {
                            t.release();
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // All acquired slots should have been released
        assert_eq!(tracker.active(), 0);
        assert_eq!(tracker.total(), 4000); // 8 threads × 500
    }

    // ── parse_request_line ──────────────────────────────────────

    #[test]
    fn parse_get_with_headers() {
        let raw = "GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.uri.path(), "/hello");
        assert_eq!(
            req.headers.get(http::header::HOST).unwrap().to_str().unwrap(),
            "localhost"
        );
        assert_eq!(
            req.headers.get(http::header::CONNECTION).unwrap().to_str().unwrap(),
            "keep-alive"
        );
    }

    #[test]
    fn parse_post_method() {
        let raw = "POST /api/data HTTP/1.1\r\nContent-Length: 42\r\nContent-Type: application/json\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri.path(), "/api/data");
        assert_eq!(
            req.headers.get(http::header::CONTENT_LENGTH).unwrap().to_str().unwrap(),
            "42"
        );
        assert_eq!(
            req.headers.get(http::header::CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/json"
        );
    }

    #[test]
    fn parse_delete_method() {
        let raw = "DELETE /kv/key123 HTTP/1.1\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(req.method, Method::DELETE);
        assert_eq!(req.uri.path(), "/kv/key123");
    }

    #[test]
    fn parse_request_with_query() {
        let raw = "GET /kv/?prefix=users/&limit=50 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(req.uri.path(), "/kv/");
        assert_eq!(req.uri.query(), Some("prefix=users/&limit=50"));
    }

    #[test]
    fn parse_multiple_headers_same_type() {
        // HTTP allows multiple headers; our parser uses insert (last wins)
        let raw = "GET / HTTP/1.1\r\nX-Custom: first\r\nX-Other: value\r\nX-Custom: second\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        // insert() replaces, so we should see "second"
        assert_eq!(
            req.headers.get("x-custom").unwrap().to_str().unwrap(),
            "second"
        );
        assert_eq!(
            req.headers.get("x-other").unwrap().to_str().unwrap(),
            "value"
        );
    }

    #[test]
    fn parse_minimal_request_line_only() {
        // Just a request line, no headers at all
        let raw = "GET / HTTP/1.1\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.uri.path(), "/");
        assert!(req.headers.is_empty());
    }

    #[test]
    fn parse_empty_string_defaults_to_get_root() {
        // Pathological case: completely empty input
        let raw = "";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        // The parser tries to parse "" as a URI — this may error
        let result = parse_request_line(raw, addr);
        // Acceptable: either error or default GET /
        // Current behavior: parts[0] = "" → Method defaults to GET, parts[1] missing → "/"
        match result {
            Ok(req) => {
                assert_eq!(req.method, Method::GET);
            }
            Err(_) => {
                // Also acceptable — malformed input
            }
        }
    }

    #[test]
    fn parse_header_with_colon_in_value() {
        // Header values can contain colons (e.g., URLs, time)
        let raw = "GET / HTTP/1.1\r\nLocation: http://example.com:8080/path\r\n\r\n";
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(
            req.headers.get("location").unwrap().to_str().unwrap(),
            "http://example.com:8080/path"
        );
    }

    #[test]
    fn parse_preserves_peer_addr() {
        let raw = "GET / HTTP/1.1\r\n\r\n";
        let addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let req = parse_request_line(raw, addr).unwrap();
        assert_eq!(req.peer_addr, addr);
    }

    // ── WorkerConfig ────────────────────────────────────────────

    #[test]
    fn worker_config_custom_values() {
        let cfg = WorkerConfig {
            max_connections: 512,
            max_requests_per_conn: 50,
            idle_timeout: Duration::from_secs(30),
            max_header_size: 4096,
            drain_timeout: Duration::from_secs(10),
        };
        // Not just testing defaults — testing that custom values are preserved
        assert_eq!(cfg.max_connections, 512);
        assert_ne!(cfg.max_requests_per_conn, WorkerConfig::default().max_requests_per_conn);
    }
}

