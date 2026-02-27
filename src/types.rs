//! Core types: Request, Response, BodyStream, Metadata.
//!
//! Design principles:
//! - Request/Response own their data → move semantics, zero cloning
//! - BodyStream is lazy (mpsc channel) → streaming, backpressure, bounded memory
//! - Metadata is a typed heterogeneous map → extensible + type-safe

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use typemap_rev::TypeMap;

// ─── Metadata ────────────────────────────────────────────────────────

/// Typed heterogeneous metadata map.
///
/// Each filter defines its own key as a zero-sized type:
/// ```ignore
/// struct UserId;
/// impl typemap_rev::TypeMapKey for UserId {
///     type Value = String;
/// }
/// ```
///
/// Reading is compile-time type-checked:
/// ```ignore
/// let uid: Option<&String> = metadata.get::<UserId>();
/// ```
pub type Metadata = TypeMap;

// ─── Body ────────────────────────────────────────────────────────────

/// Error during body streaming.
#[derive(Debug)]
pub enum BodyError {
    /// Upstream / client closed the connection.
    ConnectionClosed,
    /// Timeout waiting for the next chunk.
    Timeout,
    /// Generic IO error.
    Io(std::io::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::Timeout => write!(f, "body read timeout"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// Lazy body stream backed by a bounded mpsc channel.
///
/// - Not loaded into memory all at once → supports multi-GB uploads
/// - Bounded channel → natural backpressure
/// - `Sync` via `tokio::sync::Mutex` → allows `&Request` to be `Send`
///   (required for `tokio::spawn`). The mutex is uncontended in practice
///   because only one task ever reads the body.
pub struct BodyStream {
    rx: tokio::sync::Mutex<mpsc::Receiver<Result<Bytes, BodyError>>>,
    bytes_received: std::sync::atomic::AtomicU64,
}

impl BodyStream {
    /// Create a new body stream from a channel receiver.
    pub fn new(rx: mpsc::Receiver<Result<Bytes, BodyError>>) -> Self {
        Self {
            rx: tokio::sync::Mutex::new(rx),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a body stream from static bytes (for direct responses).
    pub fn from_static(data: &'static [u8]) -> Self {
        let (tx, rx) = mpsc::channel(1);
        // Fire-and-forget: channel has capacity 1, receiver exists.
        let _ = tx.try_send(Ok(Bytes::from_static(data)));
        drop(tx); // close channel → receiver will get None after this chunk
        Self {
            rx: tokio::sync::Mutex::new(rx),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a body stream from owned bytes (for dynamic responses).
    pub fn from_bytes(data: bytes::Bytes) -> Self {
        let (tx, rx) = mpsc::channel(1);
        let _ = tx.try_send(Ok(data));
        drop(tx);
        Self {
            rx: tokio::sync::Mutex::new(rx),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create an empty body stream.
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel(1);
        // tx is dropped immediately → receiver gets None on first poll
        Self {
            rx: tokio::sync::Mutex::new(rx),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Read the next chunk. Returns None when the body is complete.
    ///
    /// Takes `&self` (not `&mut self`) so that `BodyStream` can be
    /// behind a shared reference. The tokio Mutex ensures exclusive access.
    pub async fn next_chunk(&self) -> Option<Result<Bytes, BodyError>> {
        let mut rx = self.rx.lock().await;
        let result = rx.recv().await?;
        if let Ok(ref chunk) = result {
            self.bytes_received
                .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Some(result)
    }

    /// Total bytes received so far.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Collect entire body into memory. Use only for small bodies.
    pub async fn collect(&self) -> Result<Bytes, BodyError> {
        let mut buf = Vec::new();
        while let Some(chunk) = self.next_chunk().await {
            buf.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(buf))
    }
}

// ─── Body Transform ──────────────────────────────────────────────────

/// Trait for chunk-level body transformations (gzip, rewrite, etc.).
pub trait BodyTransform: Send + Sync {
    /// Transform a single chunk.
    fn transform_chunk(&mut self, chunk: Bytes) -> Result<Bytes, BodyError>;
    /// Flush any buffered data at end-of-stream.
    fn flush(&mut self) -> Result<Option<Bytes>, BodyError>;
}

/// What a filter wants to do with the body.
pub enum BodyAction {
    /// Don't touch the body — proxy chunks as-is (zero overhead).
    Pass,
    /// Replace the entire body with a new stream.
    Replace(BodyStream),
    /// Wrap the body in a streaming transformation.
    Transform(Box<dyn BodyTransform>),
}

// ─── Request ─────────────────────────────────────────────────────────

/// HTTP request flowing through the filter chain.
///
/// Ownership semantics: only one filter holds a `&mut Request` at a time.
/// The compiler enforces this — no cloning, no data races.
pub struct Request {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: BodyStream,
    pub metadata: Metadata,
    pub peer_addr: SocketAddr,
    /// Optional body action set by a filter.
    pub body_action: BodyAction,
}

impl Request {
    /// Create a minimal request (for testing / direct construction).
    pub fn new(method: Method, uri: Uri, peer_addr: SocketAddr) -> Self {
        Self {
            method,
            uri,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyStream::empty(),
            metadata: TypeMap::new(),
            peer_addr,
            body_action: BodyAction::Pass,
        }
    }

    /// Deserialize the request body as JSON (SIMD-accelerated via `sonic-rs`).
    ///
    /// Consumes the body stream — subsequent calls return an empty-body error.
    pub async fn json_body<T: serde::de::DeserializeOwned>(&self) -> Result<T, JsonBodyError> {
        let data = self.body.collect().await.map_err(JsonBodyError::Body)?;
        sonic_rs::from_slice(&data).map_err(JsonBodyError::Json)
    }
}

// ─── Response ────────────────────────────────────────────────────────

/// HTTP response flowing back through the filter chain.
pub struct Response {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: BodyStream,
    pub metadata: Metadata,
}

impl Response {
    /// Quick error response with a static body.
    pub fn error(status: StatusCode, body: &'static [u8]) -> Self {
        Self {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyStream::from_static(body),
            metadata: TypeMap::new(),
        }
    }

    /// Quick 200 OK with a static body.
    pub fn ok(body: &'static [u8]) -> Self {
        Self::error(StatusCode::OK, body)
    }

    /// Create a response from owned bytes (for upstream / redb responses).
    pub fn from_bytes(status: StatusCode, body: bytes::Bytes) -> Self {
        Self {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyStream::from_bytes(body),
            metadata: TypeMap::new(),
        }
    }

    /// Create a JSON response with `Content-Type: application/json`.
    ///
    /// Serializes `value` via `sonic-rs` (SIMD-accelerated). On serialization
    /// failure, returns 500 Internal Server Error.
    pub fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Self {
        match sonic_rs::to_vec(value) {
            Ok(body) => {
                let mut resp = Self::from_bytes(status, bytes::Bytes::from(body));
                resp.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::header::HeaderValue::from_static("application/json"),
                );
                resp
            }
            Err(_) => Self::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"JSON serialization error",
            ),
        }
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyStream::empty(),
            metadata: TypeMap::new(),
        }
    }
}
// ─── JSON body error ─────────────────────────────────────────────────

/// Error when parsing the request body as JSON.
#[derive(Debug)]
pub enum JsonBodyError {
    /// Failed to read the body stream.
    Body(BodyError),
    /// Failed to deserialize JSON (sonic-rs SIMD parser).
    Json(sonic_rs::Error),
}

impl std::fmt::Display for JsonBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(e) => write!(f, "body error: {e}"),
            Self::Json(e) => write!(f, "json error: {e}"),
        }
    }
}

impl std::error::Error for JsonBodyError {}
// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, StatusCode, Uri};

    // ── BodyStream ──────────────────────────────────────────────

    #[tokio::test]
    async fn body_from_static_collects_correctly() {
        let body = BodyStream::from_static(b"hello world");
        let data = body.collect().await.unwrap();
        assert_eq!(&data[..], b"hello world");
    }

    #[tokio::test]
    async fn body_from_bytes_collects_correctly() {
        let body = BodyStream::from_bytes(Bytes::from("dynamic content"));
        let data = body.collect().await.unwrap();
        assert_eq!(&data[..], b"dynamic content");
    }

    #[tokio::test]
    async fn body_empty_collects_to_empty() {
        let body = BodyStream::empty();
        let data = body.collect().await.unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn body_next_chunk_returns_none_after_exhaustion() {
        let body = BodyStream::from_static(b"one chunk");
        // First call: data
        let chunk = body.next_chunk().await;
        assert!(chunk.is_some());
        assert_eq!(&chunk.unwrap().unwrap()[..], b"one chunk");
        // Second call: stream ended
        let chunk = body.next_chunk().await;
        assert!(chunk.is_none());
    }

    #[tokio::test]
    async fn body_bytes_received_tracks_correctly() {
        let body = BodyStream::from_bytes(Bytes::from(vec![0u8; 42]));
        assert_eq!(body.bytes_received(), 0);
        let _ = body.collect().await.unwrap();
        assert_eq!(body.bytes_received(), 42);
    }

    #[tokio::test]
    async fn body_empty_bytes_received_is_zero() {
        let body = BodyStream::empty();
        let _ = body.collect().await.unwrap();
        assert_eq!(body.bytes_received(), 0);
    }

    #[tokio::test]
    async fn body_large_payload_roundtrip() {
        // 256KB — proves channel handles larger-than-single-message payloads
        let large = vec![0xABu8; 256 * 1024];
        let body = BodyStream::from_bytes(Bytes::from(large.clone()));
        let collected = body.collect().await.unwrap();
        assert_eq!(collected.len(), 256 * 1024);
        assert_eq!(&collected[..], &large[..]);
    }

    #[tokio::test]
    async fn body_multi_chunk_stream() {
        // Manually feed multiple chunks through the channel
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(Ok(Bytes::from("chunk1"))).await.unwrap();
        tx.send(Ok(Bytes::from("chunk2"))).await.unwrap();
        tx.send(Ok(Bytes::from("chunk3"))).await.unwrap();
        drop(tx); // close

        let body = BodyStream::new(rx);
        let data = body.collect().await.unwrap();
        assert_eq!(&data[..], b"chunk1chunk2chunk3");
        assert_eq!(body.bytes_received(), 18); // 6+6+6
    }

    #[tokio::test]
    async fn body_error_chunk_propagates() {
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tx.send(Ok(Bytes::from("good"))).await.unwrap();
        tx.send(Err(BodyError::ConnectionClosed)).await.unwrap();
        drop(tx);

        let body = BodyStream::new(rx);
        // collect should return error because second chunk is an error
        let result = body.collect().await;
        assert!(result.is_err());
    }

    // ── Response constructors ───────────────────────────────────

    #[tokio::test]
    async fn response_error_sets_status_and_body() {
        let resp = Response::error(StatusCode::FORBIDDEN, b"denied");
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        assert_eq!(resp.version, Version::HTTP_11);
        let body = resp.body.collect().await.unwrap();
        assert_eq!(&body[..], b"denied");
    }

    #[tokio::test]
    async fn response_ok_is_200() {
        let resp = Response::ok(b"fine");
        assert_eq!(resp.status, StatusCode::OK);
        let body = resp.body.collect().await.unwrap();
        assert_eq!(&body[..], b"fine");
    }

    #[tokio::test]
    async fn response_from_bytes_roundtrip() {
        let data = Bytes::from("dynamic response body");
        let resp = Response::from_bytes(StatusCode::CREATED, data);
        assert_eq!(resp.status, StatusCode::CREATED);
        let body = resp.body.collect().await.unwrap();
        assert_eq!(&body[..], b"dynamic response body");
    }

    #[test]
    fn response_default_is_200_empty() {
        let resp = Response::default();
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.is_empty());
    }

    // ── Request constructor ─────────────────────────────────────

    #[test]
    fn request_new_sets_fields() {
        let addr: std::net::SocketAddr = "10.0.0.1:5678".parse().unwrap();
        let req = Request::new(Method::POST, Uri::from_static("/api/data"), addr);
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri.path(), "/api/data");
        assert_eq!(req.peer_addr, addr);
        assert_eq!(req.version, Version::HTTP_11);
        assert!(req.headers.is_empty());
        assert!(matches!(req.body_action, BodyAction::Pass));
    }

    // ── BodyError Display ───────────────────────────────────────

    #[test]
    fn body_error_display() {
        assert_eq!(BodyError::ConnectionClosed.to_string(), "connection closed");
        assert_eq!(BodyError::Timeout.to_string(), "body read timeout");
        let io_err = BodyError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"));
        assert!(io_err.to_string().contains("broken"));
    }

    // ── JSON helpers ────────────────────────────────────────────

    #[tokio::test]
    async fn response_json_sets_content_type_and_body() {
        let data = serde_json::json!({"key": "value", "num": 42});
        let resp = Response::json(StatusCode::OK, &data);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        let body = resp.body.collect().await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["key"], "value");
        assert_eq!(parsed["num"], 42);
    }

    #[tokio::test]
    async fn response_json_with_custom_status() {
        let resp = Response::json(StatusCode::CREATED, &vec![1, 2, 3]);
        assert_eq!(resp.status, StatusCode::CREATED);
        let body = resp.body.collect().await.unwrap();
        let parsed: Vec<i32> = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn request_json_body_deserializes() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct Payload {
            name: String,
            age: u32,
        }
        let json_bytes = br#"{"name":"Alice","age":30}"#;
        let addr: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut req = Request::new(Method::POST, Uri::from_static("/api"), addr);
        req.body = BodyStream::from_bytes(Bytes::from(&json_bytes[..]));

        let payload: Payload = req.json_body().await.unwrap();
        assert_eq!(payload.name, "Alice");
        assert_eq!(payload.age, 30);
    }

    #[tokio::test]
    async fn request_json_body_invalid_json_returns_error() {
        let addr: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut req = Request::new(Method::POST, Uri::from_static("/api"), addr);
        req.body = BodyStream::from_bytes(Bytes::from("not json"));

        let result: Result<serde_json::Value, _> = req.json_body().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("json error"));
    }

    #[test]
    fn json_body_error_display() {
        let err = JsonBodyError::Body(BodyError::Timeout);
        assert!(err.to_string().contains("body error"));
    }
}
