//! Encrypt filter — transparent encryption/decryption of request/response bodies.
//!
//! Placed **before** the router filter in the chain:
//! ```text
//! [rate_limit] → [auth] → [encrypt] → [router] → redb / HTTP upstream
//! ```
//!
//! On request (SET/PUT/POST):
//! - Encrypts the body with AES-256-GCM before it reaches the router
//! - Optionally HMACs the URI key segment for storage key obfuscation
//!
//! On response (GET):
//! - Decrypts the body coming back from redb/upstream
//!
//! Configuration:
//! ```json
//! {
//!   "name": "encrypt",
//!   "typed_config": {
//!     "key_hex": "abcdef0123456789...",  // 64 hex chars = 32-byte master key
//!     "key_env": "PROXY_ENCRYPTION_KEY", // or read from env var (preferred)
//!     "encrypt_keys": false,              // HMAC-SHA256 URI path segments
//!     "encrypt_request_body": true,       // encrypt body on write methods
//!     "decrypt_response_body": true       // decrypt body on GET responses
//!   }
//! }
//! ```

use crate::builder::FilterFactory;
use crate::crypto::{AesGcmCipher, Cipher};
use crate::filter::{Effects, Filter, Verdict};
use crate::types::{BodyStream, Request, Response};
use bytes::Bytes;
use http::StatusCode;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use typemap_rev::TypeMapKey;

// ─── Typed metadata keys ────────────────────────────────────────────

/// Metadata key: signals that the request body has been encrypted.
/// Downstream filters (e.g., router) can check this.
pub struct BodyEncrypted;

impl TypeMapKey for BodyEncrypted {
    type Value = bool;
}

// ─── Filter ─────────────────────────────────────────────────────────

/// Transparent encryption filter.
///
/// - Encrypts request bodies (for SET/PUT/POST) with AES-256-GCM
/// - Decrypts response bodies (for GET) from encrypted storage
/// - Optionally HMACs URI path segments for key privacy
pub struct EncryptFilter {
    cipher: Arc<AesGcmCipher>,
    encrypt_keys: bool,
    encrypt_request_body: bool,
    decrypt_response_body: bool,
}

impl Filter for EncryptFilter {
    fn name(&self) -> &'static str {
        "encrypt"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            // --- Encrypt URI key segments (optional) ---
            if self.encrypt_keys {
                let path = req.uri.path().to_owned();
                if let Some(new_uri) = self.hmac_path(&path) {
                    if let Ok(uri) = new_uri.parse::<http::Uri>() {
                        req.uri = uri;
                        fx.metrics.counter_inc("encrypt.key_hashed");
                    }
                }
            }

            // --- Encrypt request body (for write methods) ---
            if self.encrypt_request_body
                && matches!(
                    req.method,
                    http::Method::POST | http::Method::PUT | http::Method::PATCH
                )
            {
                match req.body.collect().await {
                    Ok(plaintext) => {
                        if !plaintext.is_empty() {
                            match self.cipher.encrypt(&plaintext) {
                                Ok(ciphertext) => {
                                    req.body = BodyStream::from_bytes(Bytes::from(ciphertext));
                                    req.metadata.insert::<BodyEncrypted>(true);
                                    fx.metrics.counter_inc("encrypt.body_encrypted");
                                }
                                Err(e) => {
                                    fx.log.error(
                                        "encryption failed",
                                        &[("error", &e.to_string())],
                                    );
                                    return Verdict::Respond(Response::error(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        b"encryption error\n",
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        fx.log
                            .error("body read failed", &[("error", &e.to_string())]);
                        return Verdict::Respond(Response::error(
                            StatusCode::BAD_REQUEST,
                            b"failed to read body\n",
                        ));
                    }
                }
            }

            Verdict::Continue
        })
    }

    fn on_response<'a>(
        &'a self,
        _req: &'a Request,
        resp: &'a mut Response,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            // --- Decrypt response body ---
            if !self.decrypt_response_body {
                return Verdict::Continue;
            }

            // Only decrypt successful responses (upstream may return 404 etc. with plain text)
            if !resp.status.is_success() {
                return Verdict::Continue;
            }

            match resp.body.collect().await {
                Ok(ciphertext) => {
                    if ciphertext.is_empty() {
                        return Verdict::Continue;
                    }

                    match self.cipher.decrypt(&ciphertext) {
                        Ok(plaintext) => {
                            let len = plaintext.len();
                            resp.body = BodyStream::from_bytes(Bytes::from(plaintext));
                            // Update Content-Length if present
                            resp.headers.insert(
                                http::header::CONTENT_LENGTH,
                                http::HeaderValue::from_str(&len.to_string())
                                    .unwrap_or_else(|_| http::HeaderValue::from_static("0")),
                            );
                            fx.metrics.counter_inc("encrypt.body_decrypted");
                        }
                        Err(_) => {
                            // Not encrypted data — pass through unmodified.
                            // This allows mixed encrypted/plain responses (e.g., 404 from router).
                            tracing::debug!("response body not encrypted, passing through");
                            resp.body = BodyStream::from_bytes(ciphertext);
                        }
                    }
                }
                Err(e) => {
                    fx.log
                        .error("response body read failed", &[("error", &e.to_string())]);
                }
            }

            Verdict::Continue
        })
    }
}

impl EncryptFilter {
    /// HMAC the last segment of the URI path.
    ///
    /// `/kv/users/123` → `/kv/users/<hmac-hex-of-123>`
    ///
    /// Preserves prefix structure for routing while hiding the actual key.
    fn hmac_path(&self, path: &str) -> Option<String> {
        let (prefix, key) = path.rsplit_once('/')?;
        if key.is_empty() {
            return None;
        }
        let hashed = self.cipher.hmac_key(key.as_bytes());
        let hex: String = hashed.iter().map(|b| format!("{b:02x}")).collect();
        Some(format!("{prefix}/{hex}"))
    }
}

// ─── Factory ─────────────────────────────────────────────────────────

/// Factory for `EncryptFilter`.
///
/// Config:
/// ```json
/// {
///   "key_hex": "64-char-hex-string",      // direct key (for testing)
///   "key_env": "PROXY_ENCRYPTION_KEY",    // read key from env var (preferred)
///   "encrypt_keys": false,                 // HMAC URI path segments
///   "encrypt_request_body": true,          // encrypt body on write
///   "decrypt_response_body": true          // decrypt body on read
/// }
/// ```
pub struct EncryptFactory;

impl FilterFactory for EncryptFactory {
    fn name(&self) -> &str {
        "encrypt"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        // Resolve encryption key: env var takes precedence over inline hex
        let key_hex = if let Some(env_var) = config.get("key_env").and_then(|v| v.as_str()) {
            std::env::var(env_var).map_err(|e| {
                format!("encrypt filter: env var '{env_var}' not set: {e}")
            })?
        } else if let Some(hex) = config.get("key_hex").and_then(|v| v.as_str()) {
            hex.to_string()
        } else {
            return Err(
                "encrypt filter: must set 'key_hex' or 'key_env' in typed_config".into(),
            );
        };

        let cipher = AesGcmCipher::from_hex(&key_hex)
            .map_err(|e| format!("encrypt filter: {e}"))?;

        let encrypt_keys = config
            .get("encrypt_keys")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let encrypt_request_body = config
            .get("encrypt_request_body")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let decrypt_response_body = config
            .get("decrypt_response_body")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::info!(
            encrypt_keys,
            encrypt_request_body,
            decrypt_response_body,
            "encrypt filter configured"
        );

        Ok(Arc::new(EncryptFilter {
            cipher: Arc::new(cipher),
            encrypt_keys,
            encrypt_request_body,
            decrypt_response_body,
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::crypto::AesGcmCipher;
    use crate::filter::*;
    use http::{Method, Uri};
    use std::net::SocketAddr;

    fn test_cipher() -> Arc<AesGcmCipher> {
        Arc::new(AesGcmCipher::from_bytes(&[0u8; 32]).unwrap())
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

    #[tokio::test]
    async fn encrypts_put_body() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: false,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };
        let fx = test_effects();

        let mut req = Request::new(
            Method::PUT,
            Uri::from_static("/kv/test"),
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        );
        req.body = BodyStream::from_bytes(Bytes::from_static(b"secret data"));

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<BodyEncrypted>(), Some(&true));

        // Body should be encrypted (different from plaintext)
        let encrypted_body = req.body.collect().await.unwrap();
        assert_ne!(&encrypted_body[..], b"secret data");
        assert!(encrypted_body.len() > b"secret data".len());

        // Should be decryptable
        let cipher = AesGcmCipher::from_bytes(&[0u8; 32]).unwrap();
        let decrypted = cipher.decrypt(&encrypted_body).unwrap();
        assert_eq!(&decrypted, b"secret data");
    }

    #[tokio::test]
    async fn skips_get_request_body() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: false,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };
        let fx = test_effects();

        let mut req = Request::new(
            Method::GET,
            Uri::from_static("/kv/test"),
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        // No encryption marker on GET
        assert!(req.metadata.get::<BodyEncrypted>().is_none());
    }

    #[tokio::test]
    async fn decrypts_response_body() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: false,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };
        let fx = test_effects();

        // Simulate encrypted response from storage
        let cipher = AesGcmCipher::from_bytes(&[0u8; 32]).unwrap();
        let ciphertext = cipher.encrypt(b"hello world").unwrap();

        let req = Request::new(
            Method::GET,
            Uri::from_static("/kv/test"),
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        );

        let mut resp = Response::from_bytes(StatusCode::OK, Bytes::from(ciphertext));

        let verdict = filter.on_response(&req, &mut resp, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        let body = resp.body.collect().await.unwrap();
        assert_eq!(&body[..], b"hello world");
    }

    #[tokio::test]
    async fn passthrough_on_decrypt_failure() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: false,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };
        let fx = test_effects();

        let req = Request::new(
            Method::GET,
            Uri::from_static("/kv/test"),
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        );

        // Non-encrypted response body — should pass through
        let mut resp =
            Response::from_bytes(StatusCode::OK, Bytes::from_static(b"plain text data"));

        let verdict = filter.on_response(&req, &mut resp, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        let body = resp.body.collect().await.unwrap();
        assert_eq!(&body[..], b"plain text data");
    }

    #[test]
    fn hmac_path_transforms_last_segment() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: true,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };

        let result = filter.hmac_path("/kv/users/123").unwrap();
        assert!(result.starts_with("/kv/users/"));
        assert_ne!(result, "/kv/users/123");
        assert_eq!(result.len(), "/kv/users/".len() + 64); // SHA256 = 32 bytes = 64 hex

        // Deterministic
        let result2 = filter.hmac_path("/kv/users/123").unwrap();
        assert_eq!(result, result2);

        // Different key → different hash
        let result3 = filter.hmac_path("/kv/users/456").unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn hmac_path_preserves_prefix() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: true,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };

        let result = filter.hmac_path("/kv/mykey").unwrap();
        assert!(result.starts_with("/kv/"));
    }

    #[test]
    fn hmac_path_skips_trailing_slash() {
        let filter = EncryptFilter {
            cipher: test_cipher(),
            encrypt_keys: true,
            encrypt_request_body: true,
            decrypt_response_body: true,
        };
        assert!(filter.hmac_path("/kv/").is_none());
    }

    #[tokio::test]
    async fn factory_from_env() {
        let key_hex = AesGcmCipher::generate_key_hex();
        std::env::set_var("TEST_ENCRYPT_KEY", &key_hex);

        let factory = EncryptFactory;
        let config = ron_value(r#"{"key_env": "TEST_ENCRYPT_KEY"}"#);
        let filter = factory.build(&config);
        assert!(filter.is_ok());

        std::env::remove_var("TEST_ENCRYPT_KEY");
    }

    #[test]
    fn factory_rejects_missing_key() {
        let factory = EncryptFactory;
        let config = ron_value("{}");
        assert!(factory.build(&config).is_err());
    }
}
