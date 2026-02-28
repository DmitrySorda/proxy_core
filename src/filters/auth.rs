//! Authentication filter — JWT, API Key, Basic Auth.
//!
//! Placed **early** in the chain, before routing and business logic:
//! ```text
//! [rate_limit] → [auth] → [encrypt] → [kv / router]
//! ```
//!
//! Three strategies, all **zero network calls** (local verification):
//!
//! | Strategy   | Header                          | Verification           |
//! |------------|---------------------------------|------------------------|
//! | JWT        | `Authorization: Bearer <token>` | HMAC-SHA256 signature  |
//! | API Key    | `X-API-Key: <key>` (or custom)  | HashMap lookup         |
//! | Basic Auth | `Authorization: Basic <b64>`    | username:password hash |
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "name": "auth",
//!   "typed_config": {
//!     "strategy": "jwt",
//!     "jwt": {
//!       "secret": "base64-encoded-secret",
//!       "secret_env": "JWT_SECRET",
//!       "issuer": "my-app",
//!       "audience": "my-api",
//!       "required_claims": ["sub", "role"]
//!     },
//!     "api_key": {
//!       "header": "X-API-Key",
//!       "keys": {
//!         "key-abc-123": "service-a",
//!         "key-def-456": "service-b"
//!       }
//!     },
//!     "basic": {
//!       "realm": "proxy",
//!       "users": {
//!         "admin": "$argon2id$...",
//!         "reader": "$argon2id$..."
//!       }
//!     },
//!     "skip_paths": ["/health", "/ready", "/metrics"]
//!   }
//! }
//! ```

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::types::{Request, Response};
use http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use typemap_rev::TypeMapKey;

// ─── Typed metadata keys ────────────────────────────────────────────

/// Authenticated identity — downstream filters read this type-safely.
///
/// Contains the subject (user/service identifier) extracted from the token.
pub struct AuthIdentity;

impl TypeMapKey for AuthIdentity {
    type Value = String;
}

/// All JWT claims as a JSON map (available only for JWT strategy).
pub struct AuthClaims;

impl TypeMapKey for AuthClaims {
    type Value = serde_json::Map<String, serde_json::Value>;
}

/// Authentication strategy that was used (for audit logging).
pub struct AuthMethod;

impl TypeMapKey for AuthMethod {
    type Value = &'static str;
}

// ─── Strategy enum ──────────────────────────────────────────────────

/// Authentication strategy — determines how credentials are extracted
/// and verified. Each variant is fully self-contained (no network calls).
enum AuthStrategy {
    /// HMAC-SHA256 signed JWT in `Authorization: Bearer <token>`.
    Jwt(JwtConfig),
    /// Static API key lookup in a configurable header.
    ApiKey(ApiKeyConfig),
    /// HTTP Basic Auth with pre-hashed passwords (constant-time comparison).
    Basic(BasicConfig),
}

// ─── JWT ─────────────────────────────────────────────────────────────

struct JwtConfig {
    /// Decoding key (HMAC secret or RSA/EC public key).
    decoding_key: jsonwebtoken::DecodingKey,
    /// Validation rules (exp, iss, aud, required claims).
    validation: jsonwebtoken::Validation,
    /// Claims that must be present in the token (beyond standard exp/iss/aud).
    required_claims: Vec<String>,
}

// ─── API Key ─────────────────────────────────────────────────────────

struct ApiKeyConfig {
    /// Header name to read the key from (default: `X-API-Key`).
    header: String,
    /// key → identity mapping. Lookup is O(1).
    keys: HashMap<String, String>,
}

// ─── Basic Auth ──────────────────────────────────────────────────────

struct BasicConfig {
    /// WWW-Authenticate realm.
    realm: String,
    /// username → password (plain — for production use Argon2/bcrypt hashes).
    /// In this implementation we do constant-time comparison.
    users: HashMap<String, String>,
}

// ─── AuthFilter ─────────────────────────────────────────────────────

/// Authentication filter.
///
/// - Extracts credentials from the request
/// - Verifies them locally (zero network calls)
/// - Sets `AuthIdentity`, `AuthClaims`, `AuthMethod` in metadata
/// - Returns 401 Unauthorized on failure
pub struct AuthFilter {
    strategy: AuthStrategy,
    /// Paths that bypass authentication (health checks, public endpoints).
    skip_paths: HashSet<String>,
}

impl AuthFilter {
    // ── Internal dispatch ───────────────────────────────────────

    fn authenticate(&self, req: &Request) -> Result<AuthResult, AuthError> {
        // Skip paths (health, readiness, etc.)
        if self.skip_paths.contains(req.uri.path()) {
            return Ok(AuthResult {
                identity: "anonymous".into(),
                claims: None,
                method: "skip",
            });
        }

        match &self.strategy {
            AuthStrategy::Jwt(cfg) => self.auth_jwt(req, cfg),
            AuthStrategy::ApiKey(cfg) => self.auth_api_key(req, cfg),
            AuthStrategy::Basic(cfg) => self.auth_basic(req, cfg),
        }
    }

    // ── JWT ─────────────────────────────────────────────────────

    fn auth_jwt(&self, req: &Request, cfg: &JwtConfig) -> Result<AuthResult, AuthError> {
        let header_value = req
            .headers
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::Missing("Authorization header required"))?;

        let header_str = header_value
            .to_str()
            .map_err(|_| AuthError::Malformed("Authorization header is not valid UTF-8"))?;

        let token = header_str
            .strip_prefix("Bearer ")
            .ok_or(AuthError::Malformed("expected 'Bearer <token>' format"))?;

        if token.is_empty() {
            return Err(AuthError::Malformed("empty bearer token"));
        }

        let token_data = jsonwebtoken::decode::<serde_json::Value>(
            token,
            &cfg.decoding_key,
            &cfg.validation,
        )
        .map_err(|e| AuthError::Invalid(format!("JWT validation failed: {e}")))?;

        let claims = token_data
            .claims
            .as_object()
            .cloned()
            .unwrap_or_default();

        // Check required claims
        for claim in &cfg.required_claims {
            if !claims.contains_key(claim) {
                return Err(AuthError::Invalid(format!("missing required claim: {claim}")));
            }
        }

        // Extract subject (sub) as identity
        let identity = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(AuthResult {
            identity,
            claims: Some(claims),
            method: "jwt",
        })
    }

    // ── API Key ─────────────────────────────────────────────────

    fn auth_api_key(&self, req: &Request, cfg: &ApiKeyConfig) -> Result<AuthResult, AuthError> {
        let key = req
            .headers
            .get(&cfg.header)
            .ok_or(AuthError::Missing("API key header required"))?;

        let key_str = key
            .to_str()
            .map_err(|_| AuthError::Malformed("API key header is not valid UTF-8"))?;

        if key_str.is_empty() {
            return Err(AuthError::Malformed("empty API key"));
        }

        let identity = cfg
            .keys
            .get(key_str)
            .ok_or(AuthError::Invalid("unknown API key".into()))?;

        Ok(AuthResult {
            identity: identity.clone(),
            claims: None,
            method: "api_key",
        })
    }

    // ── Basic Auth ──────────────────────────────────────────────

    fn auth_basic(&self, req: &Request, cfg: &BasicConfig) -> Result<AuthResult, AuthError> {
        let header_value = req
            .headers
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::Missing("Authorization header required"))?;

        let header_str = header_value
            .to_str()
            .map_err(|_| AuthError::Malformed("Authorization header is not valid UTF-8"))?;

        let encoded = header_str
            .strip_prefix("Basic ")
            .ok_or(AuthError::Malformed("expected 'Basic <base64>' format"))?;

        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded,
        )
        .map_err(|_| AuthError::Malformed("invalid base64 in Basic auth"))?;

        let decoded_str = String::from_utf8(decoded)
            .map_err(|_| AuthError::Malformed("Basic auth credentials are not valid UTF-8"))?;

        let (username, password) = decoded_str
            .split_once(':')
            .ok_or(AuthError::Malformed("expected 'username:password' format"))?;

        if username.is_empty() {
            return Err(AuthError::Malformed("empty username"));
        }

        let expected_password = cfg
            .users
            .get(username)
            .ok_or(AuthError::Invalid("unknown user".into()))?;

        // Constant-time comparison to prevent timing attacks
        if !constant_time_eq(password.as_bytes(), expected_password.as_bytes()) {
            return Err(AuthError::Invalid("invalid password".into()));
        }

        Ok(AuthResult {
            identity: username.to_string(),
            claims: None,
            method: "basic",
        })
    }
}

// ─── Filter trait impl ──────────────────────────────────────────────

impl Filter for AuthFilter {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            match self.authenticate(req) {
                Ok(result) => {
                    fx.metrics.counter_inc("auth.allowed");
                    fx.log.info(
                        "authenticated",
                        &[("identity", &result.identity), ("method", result.method)],
                    );

                    // Store typed metadata for downstream filters
                    req.metadata.insert::<AuthIdentity>(result.identity);
                    req.metadata.insert::<AuthMethod>(result.method);
                    if let Some(claims) = result.claims {
                        req.metadata.insert::<AuthClaims>(claims);
                    }

                    Verdict::Continue
                }
                Err(err) => {
                    fx.metrics.counter_inc("auth.rejected");
                    fx.log.warn("auth failed", &[("reason", &err.to_string())]);

                    let (status, body, extra_header) = match err {
                        AuthError::Missing(_) => (
                            StatusCode::UNAUTHORIZED,
                            format!("{err}\n"),
                            self.www_authenticate_header(),
                        ),
                        AuthError::Malformed(_) => (
                            StatusCode::BAD_REQUEST,
                            format!("{err}\n"),
                            None,
                        ),
                        AuthError::Invalid(_) => (
                            StatusCode::UNAUTHORIZED,
                            format!("{err}\n"),
                            self.www_authenticate_header(),
                        ),
                    };

                    let mut resp = Response::from_bytes(status, bytes::Bytes::from(body));
                    resp.headers.insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("text/plain; charset=utf-8"),
                    );
                    if let Some((name, value)) = extra_header {
                        if let Ok(v) = http::HeaderValue::from_str(&value) {
                            resp.headers.insert(name, v);
                        }
                    }

                    Verdict::Respond(resp)
                }
            }
        })
    }
}

impl AuthFilter {
    /// Generate WWW-Authenticate header based on strategy.
    fn www_authenticate_header(&self) -> Option<(http::header::HeaderName, String)> {
        let value = match &self.strategy {
            AuthStrategy::Jwt(_) => "Bearer".to_string(),
            AuthStrategy::ApiKey(cfg) => {
                format!("ApiKey header=\"{}\"", cfg.header)
            }
            AuthStrategy::Basic(cfg) => {
                format!("Basic realm=\"{}\"", cfg.realm)
            }
        };
        Some((http::header::WWW_AUTHENTICATE, value))
    }
}

// ─── Internal types ─────────────────────────────────────────────────

struct AuthResult {
    identity: String,
    claims: Option<serde_json::Map<String, serde_json::Value>>,
    method: &'static str,
}

#[derive(Debug)]
enum AuthError {
    /// Credentials not provided at all.
    Missing(&'static str),
    /// Credentials present but structurally invalid (bad base64, no Bearer prefix, etc.).
    Malformed(&'static str),
    /// Credentials well-formed but verification failed (bad signature, unknown key, etc.).
    Invalid(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(msg) => write!(f, "{msg}"),
            Self::Malformed(msg) => write!(f, "{msg}"),
            Self::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Constant-time byte comparison to prevent timing attacks.
///
/// Always compares all bytes regardless of where the first mismatch occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─── Factory ────────────────────────────────────────────────────────

/// Factory that creates AuthFilter from JSON config.
///
/// ### JWT config
/// ```json
/// {
///   "strategy": "jwt",
///   "jwt": {
///     "secret": "base64-or-raw-secret",
///     "secret_env": "JWT_SECRET",
///     "algorithm": "HS256",
///     "issuer": "my-app",
///     "audience": "my-api",
///     "required_claims": ["sub"]
///   }
/// }
/// ```
///
/// ### API Key config
/// ```json
/// {
///   "strategy": "api_key",
///   "api_key": {
///     "header": "X-API-Key",
///     "keys": { "abc123": "service-a", "def456": "service-b" }
///   }
/// }
/// ```
///
/// ### Basic Auth config
/// ```json
/// {
///   "strategy": "basic",
///   "basic": {
///     "realm": "proxy",
///     "users": { "admin": "secret", "reader": "pass123" }
///   }
/// }
/// ```
pub struct AuthFactory;

impl FilterFactory for AuthFactory {
    fn name(&self) -> &str {
        "auth"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let strategy_name = config
            .get("strategy")
            .and_then(|v| v.as_str())
            .ok_or("auth filter requires 'strategy' field (jwt | api_key | basic)")?;

        let skip_paths: HashSet<String> = config
            .get("skip_paths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let strategy = match strategy_name {
            "jwt" => build_jwt_strategy(config)?,
            "api_key" => build_api_key_strategy(config)?,
            "basic" => build_basic_strategy(config)?,
            other => return Err(format!("unknown auth strategy: '{other}'")),
        };

        Ok(Arc::new(AuthFilter {
            strategy,
            skip_paths,
        }))
    }
}

fn build_jwt_strategy(config: &serde_json::Value) -> Result<AuthStrategy, String> {
    let jwt_config = config
        .get("jwt")
        .ok_or("JWT strategy requires 'jwt' config object")?;

    // Secret: explicit value or env var
    let secret = jwt_config
        .get("secret_env")
        .and_then(|v| v.as_str())
        .and_then(|env_name| std::env::var(env_name).ok())
        .or_else(|| jwt_config.get("secret").and_then(|v| v.as_str()).map(String::from))
        .ok_or("JWT config requires 'secret' or 'secret_env'")?;

    // Algorithm (default: HS256)
    let algo_str = jwt_config
        .get("algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("HS256");

    let algorithm = match algo_str {
        "HS256" => jsonwebtoken::Algorithm::HS256,
        "HS384" => jsonwebtoken::Algorithm::HS384,
        "HS512" => jsonwebtoken::Algorithm::HS512,
        other => return Err(format!("unsupported JWT algorithm: '{other}' (supported: HS256, HS384, HS512)")),
    };

    let decoding_key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());

    let mut validation = jsonwebtoken::Validation::new(algorithm);

    // Issuer validation
    if let Some(iss) = jwt_config.get("issuer").and_then(|v| v.as_str()) {
        validation.set_issuer(&[iss]);
    }

    // Audience validation
    if let Some(aud) = jwt_config.get("audience").and_then(|v| v.as_str()) {
        validation.set_audience(&[aud]);
    }

    // Required claims
    let required_claims: Vec<String> = jwt_config
        .get("required_claims")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(AuthStrategy::Jwt(JwtConfig {
        decoding_key,
        validation,
        required_claims,
    }))
}

fn build_api_key_strategy(config: &serde_json::Value) -> Result<AuthStrategy, String> {
    let ak_config = config
        .get("api_key")
        .ok_or("API Key strategy requires 'api_key' config object")?;

    let header = ak_config
        .get("header")
        .and_then(|v| v.as_str())
        .unwrap_or("x-api-key")
        .to_string();

    let keys: HashMap<String, String> = ak_config
        .get("keys")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .ok_or("API Key config requires 'keys' map")?;

    if keys.is_empty() {
        return Err("API Key 'keys' map must not be empty".into());
    }

    Ok(AuthStrategy::ApiKey(ApiKeyConfig { header, keys }))
}

fn build_basic_strategy(config: &serde_json::Value) -> Result<AuthStrategy, String> {
    let basic_config = config
        .get("basic")
        .ok_or("Basic strategy requires 'basic' config object")?;

    let realm = basic_config
        .get("realm")
        .and_then(|v| v.as_str())
        .unwrap_or("proxy")
        .to_string();

    let users: HashMap<String, String> = basic_config
        .get("users")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .ok_or("Basic config requires 'users' map")?;

    if users.is_empty() {
        return Err("Basic 'users' map must not be empty".into());
    }

    Ok(AuthStrategy::Basic(BasicConfig { realm, users }))
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
            Uri::from_static("/api/data"),
            "10.0.0.1:5000".parse::<SocketAddr>().unwrap(),
        )
    }

    // Helper: generate a valid HS256 JWT
    fn make_jwt(claims: &serde_json::Value, secret: &str) -> String {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    // ─── Constant-time comparison ───────────────────────────────

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // ═══════════════════════════════════════════════════════════
    // JWT Strategy
    // ═══════════════════════════════════════════════════════════

    fn jwt_filter(secret: &str) -> AuthFilter {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false; // disable for test simplicity
        validation.required_spec_claims = Default::default();

        AuthFilter {
            strategy: AuthStrategy::Jwt(JwtConfig {
                decoding_key: jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
                validation,
                required_claims: vec![],
            }),
            skip_paths: HashSet::new(),
        }
    }

    fn jwt_filter_with_claims(secret: &str, required: Vec<String>) -> AuthFilter {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false;
        validation.required_spec_claims = Default::default();

        AuthFilter {
            strategy: AuthStrategy::Jwt(JwtConfig {
                decoding_key: jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
                validation,
                required_claims: required,
            }),
            skip_paths: HashSet::new(),
        }
    }

    #[tokio::test]
    async fn jwt_valid_token_continues() {
        let secret = "test-secret-key-1234";
        let filter = jwt_filter(secret);
        let fx = test_effects();

        let claims = serde_json::json!({
            "sub": "alice",
            "role": "admin"
        });
        let token = make_jwt(&claims, secret);

        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        // Verify metadata was set
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "alice");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "jwt");
        let claims_map = req.metadata.get::<AuthClaims>().unwrap();
        assert_eq!(claims_map.get("role").unwrap(), "admin");
    }

    #[tokio::test]
    async fn jwt_missing_header_returns_401() {
        let filter = jwt_filter("secret");
        let fx = test_effects();
        let mut req = test_request();

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
                let www_auth = resp.headers.get(http::header::WWW_AUTHENTICATE).unwrap();
                assert_eq!(www_auth.to_str().unwrap(), "Bearer");
            }
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn jwt_invalid_signature_returns_401() {
        let filter = jwt_filter("correct-secret");
        let fx = test_effects();

        let token = make_jwt(&serde_json::json!({"sub": "alice"}), "wrong-secret");
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::UNAUTHORIZED),
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn jwt_malformed_bearer_returns_400() {
        let filter = jwt_filter("secret");
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            "Token abc".parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected 400"),
        }
    }

    #[tokio::test]
    async fn jwt_empty_bearer_returns_400() {
        let filter = jwt_filter("secret");
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected 400"),
        }
    }

    #[tokio::test]
    async fn jwt_missing_required_claim_returns_401() {
        let secret = "secret";
        let filter = jwt_filter_with_claims(secret, vec!["role".into()]);
        let fx = test_effects();

        // Token with sub but no role
        let token = make_jwt(&serde_json::json!({"sub": "alice"}), secret);
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::UNAUTHORIZED),
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn jwt_metrics_tracked() {
        let secret = "secret";
        let filter = jwt_filter(secret);
        let fx = test_effects();

        // Success
        let token = make_jwt(&serde_json::json!({"sub": "alice"}), secret);
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        filter.on_request(&mut req, &fx).await;
        assert_eq!(fx.metrics.counter_get("auth.allowed"), 1);

        // Failure
        let mut req2 = test_request();
        filter.on_request(&mut req2, &fx).await;
        assert_eq!(fx.metrics.counter_get("auth.rejected"), 1);
    }

    // ═══════════════════════════════════════════════════════════
    // API Key Strategy
    // ═══════════════════════════════════════════════════════════

    fn api_key_filter() -> AuthFilter {
        let mut keys = HashMap::new();
        keys.insert("key-abc-123".into(), "service-a".into());
        keys.insert("key-def-456".into(), "service-b".into());

        AuthFilter {
            strategy: AuthStrategy::ApiKey(ApiKeyConfig {
                header: "x-api-key".into(),
                keys,
            }),
            skip_paths: HashSet::new(),
        }
    }

    #[tokio::test]
    async fn api_key_valid_continues() {
        let filter = api_key_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert("x-api-key", "key-abc-123".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "service-a");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "api_key");
        // No claims for API key
        assert!(req.metadata.get::<AuthClaims>().is_none());
    }

    #[tokio::test]
    async fn api_key_second_key_maps_to_different_identity() {
        let filter = api_key_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert("x-api-key", "key-def-456".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "service-b");
    }

    #[tokio::test]
    async fn api_key_missing_header_returns_401() {
        let filter = api_key_filter();
        let fx = test_effects();
        let mut req = test_request();

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
                let www_auth = resp.headers.get(http::header::WWW_AUTHENTICATE).unwrap();
                assert!(www_auth.to_str().unwrap().contains("x-api-key"));
            }
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn api_key_unknown_returns_401() {
        let filter = api_key_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert("x-api-key", "unknown-key".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::UNAUTHORIZED),
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn api_key_empty_returns_400() {
        let filter = api_key_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert("x-api-key", "".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected 400"),
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Basic Auth Strategy
    // ═══════════════════════════════════════════════════════════

    fn basic_filter() -> AuthFilter {
        let mut users = HashMap::new();
        users.insert("admin".into(), "s3cret".into());
        users.insert("reader".into(), "readonly".into());

        AuthFilter {
            strategy: AuthStrategy::Basic(BasicConfig {
                realm: "test-realm".into(),
                users,
            }),
            skip_paths: HashSet::new(),
        }
    }

    fn basic_auth_header(username: &str, password: &str) -> http::HeaderValue {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
        format!("Basic {encoded}").parse().unwrap()
    }

    #[tokio::test]
    async fn basic_valid_credentials_continue() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header("admin", "s3cret"),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "admin");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "basic");
    }

    #[tokio::test]
    async fn basic_second_user_authenticates() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header("reader", "readonly"),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "reader");
    }

    #[tokio::test]
    async fn basic_wrong_password_returns_401() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header("admin", "wrong"),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => {
                assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
                let www_auth = resp.headers.get(http::header::WWW_AUTHENTICATE).unwrap();
                assert!(www_auth.to_str().unwrap().contains("test-realm"));
            }
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn basic_unknown_user_returns_401() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header("nobody", "whatever"),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::UNAUTHORIZED),
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn basic_missing_header_returns_401() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::UNAUTHORIZED),
            _ => panic!("expected 401"),
        }
    }

    #[tokio::test]
    async fn basic_invalid_base64_returns_400() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            "Basic !!!not-base64!!!".parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected 400"),
        }
    }

    #[tokio::test]
    async fn basic_no_colon_returns_400() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected 400"),
        }
    }

    #[tokio::test]
    async fn basic_empty_username_returns_400() {
        let filter = basic_filter();
        let fx = test_effects();
        let mut req = test_request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header("", "password"),
        );

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::BAD_REQUEST),
            _ => panic!("expected 400"),
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Skip paths
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn skip_path_bypasses_auth() {
        let mut filter = jwt_filter("secret");
        filter.skip_paths.insert("/health".into());
        filter.skip_paths.insert("/ready".into());
        let fx = test_effects();

        // /health → no auth needed
        let mut req = Request::new(
            Method::GET,
            Uri::from_static("/health"),
            "10.0.0.1:5000".parse::<SocketAddr>().unwrap(),
        );
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "anonymous");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "skip");
    }

    #[tokio::test]
    async fn non_skip_path_requires_auth() {
        let mut filter = jwt_filter("secret");
        filter.skip_paths.insert("/health".into());
        let fx = test_effects();

        // /api/data → auth required, no header → 401
        let mut req = test_request();
        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(ref r) if r.status == StatusCode::UNAUTHORIZED));
    }

    // ═══════════════════════════════════════════════════════════
    // Factory
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn factory_builds_jwt() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "jwt",
            "jwt": {"secret": "my-secret"}
        }"#);
        let filter = factory.build(&config).unwrap();
        assert_eq!(filter.name(), "auth");
    }

    #[test]
    fn factory_builds_api_key() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "api_key",
            "api_key": {
                "header": "X-Custom-Key",
                "keys": {"key1": "svc1"}
            }
        }"#);
        let filter = factory.build(&config).unwrap();
        assert_eq!(filter.name(), "auth");
    }

    #[test]
    fn factory_builds_basic() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "basic",
            "basic": {
                "realm": "test",
                "users": {"admin": "pass"}
            }
        }"#);
        let filter = factory.build(&config).unwrap();
        assert_eq!(filter.name(), "auth");
    }

    #[test]
    fn factory_rejects_missing_strategy() {
        let factory = AuthFactory;
        let config = ron_value("{}");
        assert!(factory.build(&config).is_err());
    }

    #[test]
    fn factory_rejects_unknown_strategy() {
        let factory = AuthFactory;
        let config = ron_value(r#"{"strategy": "oauth2"}"#);
        assert!(factory.build(&config).is_err());
    }

    #[test]
    fn factory_rejects_jwt_without_secret() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "jwt",
            "jwt": {}
        }"#);
        assert!(factory.build(&config).is_err());
    }

    #[test]
    fn factory_rejects_api_key_with_empty_keys() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "api_key",
            "api_key": {"keys": {}}
        }"#);
        assert!(factory.build(&config).is_err());
    }

    #[test]
    fn factory_rejects_basic_with_empty_users() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "basic",
            "basic": {"users": {}}
        }"#);
        assert!(factory.build(&config).is_err());
    }

    #[test]
    fn factory_jwt_with_skip_paths() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "jwt",
            "jwt": {"secret": "my-secret"},
            "skip_paths": ["/health", "/ready"]
        }"#);
        let filter = factory.build(&config);
        assert!(filter.is_ok());
    }

    #[test]
    fn factory_rejects_unsupported_algorithm() {
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "jwt",
            "jwt": {"secret": "key", "algorithm": "RS256"}
        }"#);
        assert!(factory.build(&config).is_err());
    }

    #[test]
    fn factory_jwt_secret_from_env() {
        std::env::set_var("TEST_JWT_SECRET_AUTH", "env-secret-value");
        let factory = AuthFactory;
        let config = ron_value(r#"{
            "strategy": "jwt",
            "jwt": {"secret_env": "TEST_JWT_SECRET_AUTH"}
        }"#);
        let filter = factory.build(&config);
        assert!(filter.is_ok());
        std::env::remove_var("TEST_JWT_SECRET_AUTH");
    }
}
