//! PHE (Password-Hardened Encryption) filter.
//!
//! Integrates the [`crate::phe`] protocol into the proxy pipeline as a
//! non-terminal filter.  The encryption key **never leaves the backend** —
//! it is stored in request metadata for downstream filters to consume.
//!
//! # Security Model
//!
//! ```text
//! ┌──────────┐               ┌──────────────┐
//! │  Client  │               │   Backend    │
//! └────┬─────┘               └──────┬───────┘
//!      │ POST /phe/enroll           │
//!      │ {"password":"..."}         │
//!      │───────────────────────────►│
//!      │                            │─┐ PHE.enroll()
//!      │                            │ │ → (record, enc_key)
//!      │                            │◄┘
//!      │  {"record":"<base64>",     │    enc_key → metadata
//!      │   "status":"enrolled"}     │    (key stays on server!)
//!      │◄───────────────────────────│
//!      │                            │
//!      │ POST /phe/verify           │
//!      │ {"password":"...",         │
//!      │  "record":"<base64>"}      │
//!      │───────────────────────────►│
//!      │                            │─┐ PHE.verify()
//!      │                            │ │ → enc_key
//!      │                            │◄┘
//!      │                            │─┐ downstream filter reads
//!      │                            │ │ PheEncKey from metadata,
//!      │                            │ │ decrypts user data
//!      │                            │◄┘
//!      │  {"status":"authenticated"}│    (key NEVER sent to client)
//!      │◄───────────────────────────│
//! ```
//!
//! # Endpoints
//!
//! | Method | Path             | Action                                    |
//! |--------|------------------|-------------------------------------------|
//! | `POST` | `{prefix}/enroll`| Enroll → record (for DB), key → metadata  |
//! | `POST` | `{prefix}/verify`| Verify → key → metadata (or 401)         |
//!
//! # Request / Response Format
//!
//! ## Enroll
//! ```json
//! // Request:
//! { "password": "user-password" }
//! // Response (200):
//! { "status": "enrolled", "record": "<base64-encoded PHE record>" }
//! ```
//! **Note:** The encryption key is NOT in the response — it goes into
//! [`Request::metadata`] under [`PheEncKey`].
//!
//! ## Verify
//! ```json
//! // Request:
//! { "password": "user-password", "record": "<base64-encoded PHE record>" }
//! // Response (200):
//! { "status": "authenticated" }
//! // Response (401):
//! { "error": "wrong password" }
//! ```
//!
//! # Configuration
//!
//! ```json
//! {
//!   "name": "phe",
//!   "typed_config": {
//!     "path_prefix": "/phe",
//!     "server_key_env": "PHE_SERVER_KEY",
//!     "client_key_env": "PHE_CLIENT_KEY"
//!   }
//! }
//! ```
//!
//! If key env vars are not set, random keys are generated at startup
//! (useful for development, **not for production**).
//!
//! # Downstream Usage
//!
//! After successful enrollment or verification the encryption key is
//! available via typed metadata:
//!
//! ```rust,ignore
//! if let Some(key) = req.metadata.get::<PheEncKey>() {
//!     let cipher = AesGcmCipher::from_bytes(key.as_bytes()).unwrap();
//!     let plaintext = cipher.decrypt(&encrypted_user_data).unwrap();
//! }
//! ```

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::phe::{PheContext, PheRecord};
use crate::types::{Request, Response};
use base64::Engine;
use http::StatusCode;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use typemap_rev::TypeMapKey;

// ─── Typed metadata key ─────────────────────────────────────────────

/// PHE-derived encryption key stored in request metadata.
///
/// Downstream filters read this to decrypt/encrypt user-specific data.
/// The key **never** appears in any HTTP response.
pub struct PheEncKey;

impl TypeMapKey for PheEncKey {
    type Value = crate::phe::EncryptionKey;
}

// ─── Filter ─────────────────────────────────────────────────────────

/// PHE filter — enrollment and verification endpoints.
///
/// Placed in the chain before filters that need per-user encryption
/// keys (e.g.\ a user-data filter or an encrypted KV store).
pub struct PheFilter {
    ctx: PheContext,
    path_prefix: String,
}

impl Filter for PheFilter {
    fn name(&self) -> &'static str {
        "phe"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        effects: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            let path = req.uri.path().to_owned();

            if !path.starts_with(&self.path_prefix) {
                return Verdict::Continue;
            }

            let sub_path = &path[self.path_prefix.len()..];

            match (req.method.as_str(), sub_path) {
                ("POST", "/enroll") => self.handle_enroll(req, effects).await,
                ("POST", "/verify") => self.handle_verify(req, effects).await,
                _ => Verdict::Respond(Response::json(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": format!("unknown PHE endpoint: {sub_path}")}),
                )),
            }
        })
    }
}

impl PheFilter {
    /// Handle enrollment: password → (record to client, key to metadata).
    ///
    /// The **record** is returned to the client (opaque, no secret material).
    /// The **encryption key** is placed in `req.metadata` only — it NEVER
    /// leaves the backend.
    async fn handle_enroll(&self, req: &mut Request, effects: &Effects) -> Verdict {
        let body_bytes = match req.body.collect().await {
            Ok(b) => b,
            Err(e) => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": format!("body read error: {e}")}),
                ));
            }
        };

        let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(e) => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": format!("invalid JSON: {e}")}),
                ));
            }
        };

        let password = match parsed.get("password").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": "missing 'password' field"}),
                ));
            }
        };

        match self.ctx.enroll(password.as_bytes()) {
            Ok((record, enc_key)) => {
                let record_b64 =
                    base64::engine::general_purpose::STANDARD.encode(record.to_bytes());

                // ✅ Key stays on backend — metadata only.
                req.metadata.insert::<PheEncKey>(enc_key);

                effects.log.info("PHE enrollment", &[("status", "ok")]);

                // ✅ Only the opaque record goes to the client.
                Verdict::Respond(Response::json(
                    StatusCode::OK,
                    &serde_json::json!({
                        "status": "enrolled",
                        "record": record_b64
                    }),
                ))
            }
            Err(e) => {
                effects
                    .log
                    .error("PHE enrollment failed", &[("error", &e.to_string())]);
                Verdict::Respond(Response::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": "enrollment failed"}),
                ))
            }
        }
    }

    /// Handle verification: password + record → key in metadata (or 401).
    ///
    /// On success the encryption key is placed in `req.metadata`. The
    /// client receives only a status message — **never** the key.
    async fn handle_verify(&self, req: &mut Request, effects: &Effects) -> Verdict {
        let body_bytes = match req.body.collect().await {
            Ok(b) => b,
            Err(e) => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": format!("body read error: {e}")}),
                ));
            }
        };

        let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(e) => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": format!("invalid JSON: {e}")}),
                ));
            }
        };

        let password = match parsed.get("password").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": "missing 'password' field"}),
                ));
            }
        };

        let record_b64 = match parsed.get("record").and_then(|v| v.as_str()) {
            Some(r) => r,
            None => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": "missing 'record' field"}),
                ));
            }
        };

        let record_bytes = match base64::engine::general_purpose::STANDARD.decode(record_b64) {
            Ok(b) => b,
            Err(e) => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": format!("invalid base64 record: {e}")}),
                ));
            }
        };

        let record = match PheRecord::from_bytes(&record_bytes) {
            Ok(r) => r,
            Err(e) => {
                return Verdict::Respond(Response::json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": format!("invalid PHE record: {e}")}),
                ));
            }
        };

        match self.ctx.verify(password.as_bytes(), &record) {
            Ok(enc_key) => {
                // ✅ Key stays on backend — metadata only.
                req.metadata.insert::<PheEncKey>(enc_key);

                effects
                    .log
                    .info("PHE verification", &[("status", "authenticated")]);

                // ✅ Client gets status only, NEVER the key.
                Verdict::Respond(Response::json(
                    StatusCode::OK,
                    &serde_json::json!({"status": "authenticated"}),
                ))
            }
            Err(crate::phe::PheError::WrongPassword) => {
                effects
                    .log
                    .warn("PHE verification", &[("status", "wrong_password")]);

                Verdict::Respond(Response::json(
                    StatusCode::UNAUTHORIZED,
                    &serde_json::json!({"error": "wrong password"}),
                ))
            }
            Err(e) => {
                effects
                    .log
                    .error("PHE verification failed", &[("error", &e.to_string())]);
                Verdict::Respond(Response::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": "verification failed"}),
                ))
            }
        }
    }
}

// ─── Factory ────────────────────────────────────────────────────────

/// Factory for creating [`PheFilter`] instances from JSON configuration.
pub struct PheFactory;

impl FilterFactory for PheFactory {
    fn name(&self) -> &str {
        "phe"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let path_prefix = config
            .get("path_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("/phe")
            .to_string();

        let server_key_env = config
            .get("server_key_env")
            .and_then(|v| v.as_str())
            .unwrap_or("PHE_SERVER_KEY");

        let client_key_env = config
            .get("client_key_env")
            .and_then(|v| v.as_str())
            .unwrap_or("PHE_CLIENT_KEY");

        let ctx = match (
            std::env::var(server_key_env).ok(),
            std::env::var(client_key_env).ok(),
        ) {
            (Some(sk_hex), Some(ck_hex)) => {
                let sk =
                    hex_decode(&sk_hex).map_err(|e| format!("invalid server key hex: {e}"))?;
                let ck =
                    hex_decode(&ck_hex).map_err(|e| format!("invalid client key hex: {e}"))?;

                if sk.len() != 32 {
                    return Err(format!("server key must be 32 bytes, got {}", sk.len()));
                }
                if ck.len() != 32 {
                    return Err(format!("client key must be 32 bytes, got {}", ck.len()));
                }

                let mut sk_arr = [0u8; 32];
                let mut ck_arr = [0u8; 32];
                sk_arr.copy_from_slice(&sk);
                ck_arr.copy_from_slice(&ck);

                PheContext::from_keys(&sk_arr, &ck_arr)
                    .map_err(|e| format!("PHE key init failed: {e}"))?
            }
            _ => {
                tracing::warn!(
                    "PHE: {} and/or {} not set — using random keys (dev mode only!)",
                    server_key_env,
                    client_key_env
                );
                PheContext::new()
            }
        };

        Ok(Arc::new(PheFilter { ctx, path_prefix }))
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at {i}: {e}"))
        })
        .collect()
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{FilterFactory, ron_value};
    use crate::filter::{Effects, HttpClient, Metrics, RequestLogger, SharedState, SystemClock};
    use crate::types::BodyStream;
    use bytes::Bytes;
    use http::{Method, Uri};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn test_effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:9999".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn make_request(method: Method, path: &str, body: &[u8]) -> Request {
        let uri: Uri = path.parse().unwrap();
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let mut req = Request::new(method, uri, addr);
        req.body = BodyStream::from_bytes(Bytes::copy_from_slice(body));
        req
    }

    // ── Factory ─────────────────────────────────────────────────

    #[test]
    fn factory_name_is_phe() {
        assert_eq!(PheFactory.name(), "phe");
    }

    #[test]
    fn factory_builds_with_defaults() {
        assert!(PheFactory.build(&ron_value("{}")).is_ok());
    }

    #[test]
    fn factory_builds_with_custom_prefix() {
        let r = PheFactory.build(&ron_value(r#"{"path_prefix": "/auth/phe"}"#));
        assert!(r.is_ok());
    }

    // ── Enrollment: key NEVER in response ───────────────────────

    #[tokio::test]
    async fn enroll_returns_record_but_not_key() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(
            Method::POST,
            "/phe/enroll",
            br#"{"password":"test123"}"#,
        );
        let verdict = filter.on_request(&mut req, &effects).await;

        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::OK);
                let body = resp.body.collect().await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

                // ✅ Record is present (opaque, no secrets)
                assert!(json.get("record").is_some(), "response must contain record");
                assert_eq!(json["status"].as_str().unwrap(), "enrolled");

                // ✅ KEY IS NOT IN THE RESPONSE
                assert!(
                    json.get("key").is_none(),
                    "encryption key must NEVER be in the response"
                );

                // Verify record is valid base64, 130 bytes
                let record_b64 = json["record"].as_str().unwrap();
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(record_b64)
                    .unwrap();
                assert_eq!(decoded.len(), 130, "PHE record must be 130 bytes");
            }
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn enroll_stores_key_in_metadata() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(
            Method::POST,
            "/phe/enroll",
            br#"{"password":"metadata-test"}"#,
        );
        let _verdict = filter.on_request(&mut req, &effects).await;

        // ✅ Key is available in metadata for downstream filters
        let key = req.metadata.get::<PheEncKey>();
        assert!(key.is_some(), "encryption key must be in metadata");
        assert_ne!(
            key.unwrap().as_bytes(),
            &[0u8; 32],
            "key must not be all zeros"
        );
    }

    #[tokio::test]
    async fn enroll_missing_password_returns_400() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(Method::POST, "/phe/enroll", br#"{}"#);
        let verdict = filter.on_request(&mut req, &effects).await;

        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn enroll_invalid_json_returns_400() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(Method::POST, "/phe/enroll", b"not json");
        let verdict = filter.on_request(&mut req, &effects).await;

        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected Respond"),
        }
    }

    // ── Verification: key NEVER in response ─────────────────────

    #[tokio::test]
    async fn verify_correct_password_does_not_return_key() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        // Step 1: enroll
        let mut enroll_req = make_request(
            Method::POST,
            "/phe/enroll",
            br#"{"password":"secret"}"#,
        );
        let enroll_verdict = filter.on_request(&mut enroll_req, &effects).await;
        let enroll_body = match enroll_verdict {
            Verdict::Respond(resp) => {
                let b = resp.body.collect().await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&b).unwrap()
            }
            _ => panic!("expected Respond"),
        };
        let record = enroll_body["record"].as_str().unwrap().to_string();

        // Step 2: verify with correct password
        let verify_json = serde_json::json!({
            "password": "secret",
            "record": record
        });
        let mut verify_req = make_request(
            Method::POST,
            "/phe/verify",
            verify_json.to_string().as_bytes(),
        );
        let verify_verdict = filter.on_request(&mut verify_req, &effects).await;

        match verify_verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::OK);
                let body = resp.body.collect().await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

                // ✅ Status only
                assert_eq!(json["status"].as_str().unwrap(), "authenticated");

                // ✅ KEY IS NOT IN THE RESPONSE
                assert!(
                    json.get("key").is_none(),
                    "encryption key must NEVER be in the response"
                );
            }
            _ => panic!("expected Respond"),
        }

        // ✅ Key IS in metadata
        assert!(verify_req.metadata.get::<PheEncKey>().is_some());
    }

    #[tokio::test]
    async fn verify_wrong_password_returns_401() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        // Enroll
        let mut enroll_req = make_request(
            Method::POST,
            "/phe/enroll",
            br#"{"password":"correct"}"#,
        );
        let ev = filter.on_request(&mut enroll_req, &effects).await;
        let eb = match ev {
            Verdict::Respond(r) => {
                let b = r.body.collect().await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&b).unwrap()
            }
            _ => panic!("expected Respond"),
        };
        let record = eb["record"].as_str().unwrap().to_string();

        // Verify with wrong password
        let body = serde_json::json!({"password": "wrong", "record": record});
        let mut req = make_request(
            Method::POST,
            "/phe/verify",
            body.to_string().as_bytes(),
        );
        let v = filter.on_request(&mut req, &effects).await;

        match v {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
                let b = resp.body.collect().await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&b).unwrap();
                assert!(json.get("key").is_none(), "key must not leak on failure");
            }
            _ => panic!("expected Respond"),
        }

        // No key in metadata on failure
        assert!(req.metadata.get::<PheEncKey>().is_none());
    }

    #[tokio::test]
    async fn verify_missing_record_returns_400() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(
            Method::POST,
            "/phe/verify",
            br#"{"password":"x"}"#,
        );
        let v = filter.on_request(&mut req, &effects).await;
        match v {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn verify_invalid_record_returns_400() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(
            Method::POST,
            "/phe/verify",
            br#"{"password":"x","record":"dGVzdA=="}"#,
        );
        let v = filter.on_request(&mut req, &effects).await;
        match v {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected Respond"),
        }
    }

    // ── Path routing ────────────────────────────────────────────

    #[tokio::test]
    async fn non_phe_path_passes_through() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(Method::GET, "/other/path", b"");
        let v = filter.on_request(&mut req, &effects).await;
        assert!(matches!(v, Verdict::Continue));
    }

    #[tokio::test]
    async fn unknown_phe_endpoint_returns_404() {
        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        let mut req = make_request(Method::POST, "/phe/unknown", b"");
        let v = filter.on_request(&mut req, &effects).await;
        match v {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::NOT_FOUND),
            _ => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn custom_prefix_works() {
        let filter = PheFactory
            .build(&ron_value(r#"{"path_prefix": "/auth/phe"}"#))
            .unwrap();
        let effects = test_effects();

        let mut req = make_request(
            Method::POST,
            "/auth/phe/enroll",
            br#"{"password":"x"}"#,
        );
        let v = filter.on_request(&mut req, &effects).await;
        match v {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::OK),
            _ => panic!("expected Respond"),
        }
    }

    // ── Integration: downstream filter can use the key ──────────

    #[tokio::test]
    async fn enroll_verify_key_matches_and_can_encrypt() {
        use crate::crypto::{AesGcmCipher, Cipher};

        let filter = PheFactory.build(&ron_value("{}")).unwrap();
        let effects = test_effects();

        // 1. Enroll
        let mut enroll_req = make_request(
            Method::POST,
            "/phe/enroll",
            br#"{"password":"integration"}"#,
        );
        let ev = filter.on_request(&mut enroll_req, &effects).await;
        let record = match ev {
            Verdict::Respond(resp) => {
                let b = resp.body.collect().await.unwrap();
                let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
                j["record"].as_str().unwrap().to_string()
            }
            _ => panic!("expected Respond"),
        };

        let enroll_key = enroll_req
            .metadata
            .get::<PheEncKey>()
            .expect("key must be in metadata after enroll")
            .clone();

        // Simulate downstream: encrypt with enrollment key
        let cipher = AesGcmCipher::from_bytes(enroll_key.as_bytes()).unwrap();
        let plaintext = b"sensitive user data";
        let ciphertext = cipher.encrypt(plaintext).unwrap();

        // 2. Verify (simulates next request from the same user)
        let verify_json = serde_json::json!({
            "password": "integration",
            "record": record
        });
        let mut verify_req = make_request(
            Method::POST,
            "/phe/verify",
            verify_json.to_string().as_bytes(),
        );
        let _vv = filter.on_request(&mut verify_req, &effects).await;

        let verify_key = verify_req
            .metadata
            .get::<PheEncKey>()
            .expect("key must be in metadata after verify");

        // 3. Keys must match (deterministic for same password + record)
        assert_eq!(
            enroll_key.as_bytes(),
            verify_key.as_bytes(),
            "enroll and verify must derive the same key"
        );

        // 4. Downstream can decrypt
        let cipher2 = AesGcmCipher::from_bytes(verify_key.as_bytes()).unwrap();
        let decrypted = cipher2.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    // ── Hex helper ──────────────────────────────────────────────

    #[test]
    fn hex_decode_roundtrip() {
        let decoded = hex_decode("abcdef01").unwrap();
        assert_eq!(decoded, [0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_rejects_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }
}
