//! Route table: URL matching and action dispatching.
//!
//! Routes map HTTP requests to upstream backends (HTTP or redb KV).
//! Evaluated in order — first match wins (like Envoy's route table).

use std::collections::HashMap;
use std::time::Duration;

// ─── Config types (deserialized from JSON) ──────────────────────────

/// Top-level route configuration (parsed from `typed_config` of the router filter).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RouteTableConfig {
    /// Ordered list of route entries. First match wins.
    pub routes: Vec<RouteEntryConfig>,
    /// Redb database file path (required if any route uses `redb`).
    #[serde(default)]
    pub redb_path: Option<String>,
}

/// Configuration for a single route entry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RouteEntryConfig {
    /// Match criteria.
    #[serde(rename = "match")]
    pub matcher: MatchConfig,
    /// Allowed HTTP methods. `None` = all methods allowed.
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// HTTP upstream action.
    #[serde(default)]
    pub http: Option<HttpRouteConfig>,
    /// Redb KV action.
    #[serde(default)]
    pub redb: Option<RedbRouteConfig>,
}

/// Match criteria for a route.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MatchConfig {
    /// Match requests whose URI path starts with this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Match requests with exactly this URI path.
    #[serde(default)]
    pub exact: Option<String>,
    /// Match requests using a pattern with named parameters (e.g., `/users/:id/posts/:post_id`).
    #[serde(default)]
    pub pattern: Option<String>,
}

// ─── Pattern matching ────────────────────────────────────────────────

/// Segment in a URL pattern.
#[derive(Debug, Clone)]
pub enum PatternSegment {
    /// Must match literally (e.g., `users`).
    Static(String),
    /// Named parameter that captures a single path segment (e.g., `:id`).
    Param(String),
}

/// Parse a pattern string like `/users/:id/posts/:post_id` into segments.
fn parse_pattern(pattern: &str) -> Result<Vec<PatternSegment>, String> {
    let parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err("pattern must have at least one segment".into());
    }
    let mut segments = Vec::with_capacity(parts.len());
    let mut seen_params = std::collections::HashSet::new();
    for part in parts {
        if let Some(name) = part.strip_prefix(':') {
            if name.is_empty() {
                return Err("parameter name cannot be empty (bare ':')".into());
            }
            if !seen_params.insert(name) {
                return Err(format!("duplicate parameter name: '{name}'"));
            }
            segments.push(PatternSegment::Param(name.to_string()));
        } else {
            segments.push(PatternSegment::Static(part.to_string()));
        }
    }
    Ok(segments)
}

// ─── Path Params metadata key ───────────────────────────────────────

/// Typed metadata key for path parameters extracted from pattern routes.
///
/// Usage in a filter:
/// ```ignore
/// if let Some(params) = req.metadata.get::<PathParams>() {
///     let user_id = params.get("id").unwrap();
/// }
/// ```
pub struct PathParams;

impl typemap_rev::TypeMapKey for PathParams {
    type Value = HashMap<String, String>;
}

/// HTTP upstream route configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HttpRouteConfig {
    /// Base URL of the upstream (e.g., `"http://backend:8081"`).
    pub url: String,
    /// Request timeout in milliseconds (default: 5000).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Redb KV operation route configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RedbRouteConfig {
    /// Operation: `"get"`, `"set"`, `"get_range"`, `"delete"`.
    pub operation: String,
    /// Key prefix prepended to the captured path segment.
    #[serde(default)]
    pub key_prefix: Option<String>,
    /// Request timeout in milliseconds (default: 5000).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    5000
}

// ─── Runtime types ──────────────────────────────────────────────────

/// Compiled route matcher.
pub enum RouteMatcher {
    Prefix(String),
    Exact(String),
    /// Pattern with named parameters (e.g., `/users/:id`).
    Pattern(Vec<PatternSegment>),
}

impl RouteMatcher {
    /// Does this matcher match the given path?
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Prefix(p) => path.starts_with(p.as_str()),
            Self::Exact(p) => path == p.as_str(),
            Self::Pattern(segments) => {
                let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                if parts.len() != segments.len() {
                    return false;
                }
                segments.iter().zip(parts.iter()).all(|(seg, part)| match seg {
                    PatternSegment::Static(s) => s == part,
                    PatternSegment::Param(_) => true,
                })
            }
        }
    }

    /// Extract the path segment after the matched portion.
    pub fn capture<'a>(&self, path: &'a str) -> &'a str {
        match self {
            Self::Prefix(p) => path.strip_prefix(p.as_str()).unwrap_or(""),
            Self::Exact(_) | Self::Pattern(_) => "",
        }
    }

    /// Extract named parameters from a pattern match.
    ///
    /// Returns an empty map for `Prefix` and `Exact` matchers.
    pub fn extract_params(&self, path: &str) -> HashMap<String, String> {
        match self {
            Self::Prefix(_) | Self::Exact(_) => HashMap::new(),
            Self::Pattern(segments) => {
                let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                let mut params = HashMap::new();
                for (seg, part) in segments.iter().zip(parts.iter()) {
                    if let PatternSegment::Param(name) = seg {
                        params.insert(name.clone(), (*part).to_string());
                    }
                }
                params
            }
        }
    }
}

/// Action to take when a route matches.
pub enum RouteAction {
    /// Forward to an HTTP upstream.
    Http {
        url: String,
        timeout: Duration,
    },
    /// Execute a redb KV operation.
    Redb {
        operation: RedbOp,
        key_prefix: String,
        timeout: Duration,
    },
}

/// Redb KV operation type.
#[derive(Debug, Clone)]
pub enum RedbOp {
    Get,
    Set,
    GetRange,
    Delete,
}

impl RedbOp {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "get" => Ok(Self::Get),
            "set" => Ok(Self::Set),
            "get_range" | "getrange" => Ok(Self::GetRange),
            "delete" => Ok(Self::Delete),
            other => Err(format!("unknown redb operation: '{other}'")),
        }
    }
}

/// A compiled route entry.
pub struct RouteEntry {
    pub matcher: RouteMatcher,
    pub methods: Option<Vec<http::Method>>,
    pub action: RouteAction,
}

/// The result of resolving a request against the route table.
pub struct ResolvedRoute<'a> {
    /// The action to take.
    pub action: &'a RouteAction,
    /// Path segment captured after the matched prefix.
    pub captured_path: String,
    /// Named path parameters extracted from pattern routes.
    pub params: HashMap<String, String>,
}

/// Compiled route table for fast first-match resolution.
pub struct RouteTable {
    entries: Vec<RouteEntry>,
}

impl RouteTable {
    /// Build a `RouteTable` from deserialized configuration.
    pub fn from_config(config: &RouteTableConfig) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(config.routes.len());

        for rc in &config.routes {
            let matcher = if let Some(ref prefix) = rc.matcher.prefix {
                RouteMatcher::Prefix(prefix.clone())
            } else if let Some(ref exact) = rc.matcher.exact {
                RouteMatcher::Exact(exact.clone())
            } else if let Some(ref pattern) = rc.matcher.pattern {
                RouteMatcher::Pattern(parse_pattern(pattern)?)
            } else {
                return Err("each route must have 'prefix', 'exact', or 'pattern' in 'match'".into());
            };

            let methods = rc.methods.as_ref().map(|ms| {
                ms.iter()
                    .filter_map(|m| http::Method::from_bytes(m.as_bytes()).ok())
                    .collect()
            });

            let action = if let Some(ref http_cfg) = rc.http {
                RouteAction::Http {
                    url: http_cfg.url.clone(),
                    timeout: Duration::from_millis(http_cfg.timeout_ms),
                }
            } else if let Some(ref redb_cfg) = rc.redb {
                RouteAction::Redb {
                    operation: RedbOp::parse(&redb_cfg.operation)?,
                    key_prefix: redb_cfg.key_prefix.clone().unwrap_or_default(),
                    timeout: Duration::from_millis(redb_cfg.timeout_ms),
                }
            } else {
                return Err("each route must have 'http' or 'redb' action".into());
            };

            entries.push(RouteEntry {
                matcher,
                methods,
                action,
            });
        }

        Ok(Self { entries })
    }

    /// Resolve a request to a route. First match wins.
    pub fn resolve(&self, method: &http::Method, path: &str) -> Option<ResolvedRoute<'_>> {
        for entry in &self.entries {
            if !entry.matcher.matches(path) {
                continue;
            }
            if let Some(ref methods) = entry.methods {
                if !methods.contains(method) {
                    continue;
                }
            }
            let captured = entry.matcher.capture(path).to_string();
            let params = entry.matcher.extract_params(path);
            return Some(ResolvedRoute {
                action: &entry.action,
                captured_path: captured,
                params,
            });
        }
        None
    }

    /// Number of routes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RouteTableConfig {
        serde_json::from_value(serde_json::json!({
            "routes": [
                {
                    "match": { "prefix": "/api/" },
                    "methods": ["GET", "POST"],
                    "http": { "url": "http://backend:8081", "timeout_ms": 3000 }
                },
                {
                    "match": { "exact": "/healthz" },
                    "http": { "url": "http://backend:8081" }
                },
                {
                    "match": { "prefix": "/" },
                    "http": { "url": "http://fallback:9090" }
                }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn resolves_prefix_with_method() {
        let table = RouteTable::from_config(&test_config()).unwrap();
        let r = table.resolve(&http::Method::GET, "/api/users/123");
        assert!(r.is_some());
        let r = r.unwrap();
        assert_eq!(r.captured_path, "users/123");
        match r.action {
            RouteAction::Http { ref url, .. } => assert_eq!(url, "http://backend:8081"),
            _ => panic!("expected Http action"),
        }
    }

    #[test]
    fn rejects_wrong_method() {
        let table = RouteTable::from_config(&test_config()).unwrap();
        // /api/ only allows GET and POST, DELETE should fall through to catch-all
        let r = table.resolve(&http::Method::DELETE, "/api/users/123");
        assert!(r.is_some());
        match r.unwrap().action {
            RouteAction::Http { ref url, .. } => assert_eq!(url, "http://fallback:9090"),
            _ => panic!("expected fallback"),
        }
    }

    #[test]
    fn resolves_exact() {
        let table = RouteTable::from_config(&test_config()).unwrap();
        let r = table.resolve(&http::Method::GET, "/healthz");
        assert!(r.is_some());
        assert_eq!(r.unwrap().captured_path, "");
    }

    #[test]
    fn no_match_returns_none() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "exact": "/only-this" }, "http": { "url": "http://x" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        assert!(table.resolve(&http::Method::GET, "/other").is_none());
    }

    #[test]
    fn empty_route_table_matches_nothing() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": []
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        assert!(table.resolve(&http::Method::GET, "/").is_none());
        assert!(table.resolve(&http::Method::POST, "/api").is_none());
    }

    #[test]
    fn timeout_parsed_from_config() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                {
                    "match": { "prefix": "/" },
                    "http": { "url": "http://backend:8081", "timeout_ms": 3000 }
                }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        let r = table.resolve(&http::Method::GET, "/anything").unwrap();
        match r.action {
            RouteAction::Http { timeout, .. } => {
                assert_eq!(*timeout, std::time::Duration::from_millis(3000));
            }
            _ => panic!("expected Http action"),
        }
    }

    #[test]
    fn exact_match_does_not_match_prefix() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "exact": "/health" }, "http": { "url": "http://x" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        // Exact: /health matches, but /healthz and /health/check should NOT
        assert!(table.resolve(&http::Method::GET, "/health").is_some());
        assert!(table.resolve(&http::Method::GET, "/healthz").is_none());
        assert!(table.resolve(&http::Method::GET, "/health/check").is_none());
    }

    #[test]
    fn routes_evaluated_in_order_first_match_wins() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "prefix": "/api/" }, "http": { "url": "http://api-backend" } },
                { "match": { "prefix": "/api/" }, "http": { "url": "http://should-not-match" } },
                { "match": { "prefix": "/" }, "http": { "url": "http://fallback" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        let r = table.resolve(&http::Method::GET, "/api/users").unwrap();
        match r.action {
            RouteAction::Http { ref url, .. } => assert_eq!(url, "http://api-backend"),
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn prefix_captured_path_strips_prefix() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "prefix": "/v1/api/" }, "http": { "url": "http://backend" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        let r = table.resolve(&http::Method::GET, "/v1/api/users/123").unwrap();
        assert_eq!(r.captured_path, "users/123");
    }

    #[test]
    fn method_any_when_no_methods_specified() {
        // When "methods" is not specified, all methods should match
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "prefix": "/" }, "http": { "url": "http://backend" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();
        assert!(table.resolve(&http::Method::GET, "/x").is_some());
        assert!(table.resolve(&http::Method::POST, "/x").is_some());
        assert!(table.resolve(&http::Method::DELETE, "/x").is_some());
        assert!(table.resolve(&http::Method::PATCH, "/x").is_some());
    }

    // ── Pattern matching ────────────────────────────────────────

    #[test]
    fn pattern_matches_simple() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "pattern": "/users/:id" }, "http": { "url": "http://api" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        let r = table.resolve(&http::Method::GET, "/users/123");
        assert!(r.is_some());
        let r = r.unwrap();
        assert_eq!(r.params.get("id").unwrap(), "123");
        assert_eq!(r.captured_path, "");
    }

    #[test]
    fn pattern_matches_multiple_params() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "pattern": "/users/:user_id/posts/:post_id" }, "http": { "url": "http://api" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        let r = table.resolve(&http::Method::GET, "/users/42/posts/99").unwrap();
        assert_eq!(r.params.get("user_id").unwrap(), "42");
        assert_eq!(r.params.get("post_id").unwrap(), "99");
    }

    #[test]
    fn pattern_rejects_wrong_segment_count() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "pattern": "/users/:id" }, "http": { "url": "http://api" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        // Too many segments
        assert!(table.resolve(&http::Method::GET, "/users/123/extra").is_none());
        // Too few segments
        assert!(table.resolve(&http::Method::GET, "/users").is_none());
        // Completely different
        assert!(table.resolve(&http::Method::GET, "/other/123").is_none());
    }

    #[test]
    fn pattern_rejects_wrong_static_segment() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "pattern": "/api/v1/:resource" }, "http": { "url": "http://api" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        assert!(table.resolve(&http::Method::GET, "/api/v1/users").is_some());
        assert!(table.resolve(&http::Method::GET, "/api/v2/users").is_none());
    }

    #[test]
    fn pattern_with_method_filter() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                {
                    "match": { "pattern": "/users/:id" },
                    "methods": ["GET", "DELETE"],
                    "http": { "url": "http://api" }
                }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        assert!(table.resolve(&http::Method::GET, "/users/1").is_some());
        assert!(table.resolve(&http::Method::DELETE, "/users/1").is_some());
        assert!(table.resolve(&http::Method::POST, "/users/1").is_none());
    }

    #[test]
    fn pattern_first_match_wins() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "pattern": "/users/:id" }, "http": { "url": "http://specific" } },
                { "match": { "prefix": "/" }, "http": { "url": "http://fallback" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        let r = table.resolve(&http::Method::GET, "/users/42").unwrap();
        match r.action {
            RouteAction::Http { ref url, .. } => assert_eq!(url, "http://specific"),
            _ => panic!("wrong action"),
        }
        assert_eq!(r.params.get("id").unwrap(), "42");
    }

    #[test]
    fn pattern_prefix_and_exact_params_are_empty() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "prefix": "/api/" }, "http": { "url": "http://api" } },
                { "match": { "exact": "/health" }, "http": { "url": "http://health" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        let r = table.resolve(&http::Method::GET, "/api/test").unwrap();
        assert!(r.params.is_empty());

        let r = table.resolve(&http::Method::GET, "/health").unwrap();
        assert!(r.params.is_empty());
    }

    #[test]
    fn parse_pattern_rejects_duplicate_params() {
        let result = parse_pattern("/users/:id/friends/:id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn parse_pattern_rejects_empty_name() {
        let result = parse_pattern("/users/:/test");
        assert!(result.is_err());
    }

    #[test]
    fn parse_pattern_rejects_empty() {
        let result = parse_pattern("");
        assert!(result.is_err());
    }

    #[test]
    fn pattern_url_encoded_param_values() {
        let config: RouteTableConfig = serde_json::from_value(serde_json::json!({
            "routes": [
                { "match": { "pattern": "/files/:name" }, "http": { "url": "http://api" } }
            ]
        }))
        .unwrap();
        let table = RouteTable::from_config(&config).unwrap();

        let r = table.resolve(&http::Method::GET, "/files/hello%20world").unwrap();
        assert_eq!(r.params.get("name").unwrap(), "hello%20world");
    }
}
