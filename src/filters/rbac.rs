//! RBAC + lightweight RLS authorization filter.
//!
//! This filter is intended to run **after** `auth` and before business filters.
//! It reads identity/claims from typed metadata set by `auth` and decides whether
//! a request is allowed to continue.
//!
//! ## What it enforces
//! - Role-based permissions (`roles` -> `permissions`)
//! - Group expansion (`groups` -> `roles`)
//! - Route-level permission rules (`path_prefix` + HTTP methods)
//! - Global and rule-level deny actions (deny-overrides)
//! - Data scope checks (RLS-lite) by `org` / `branch` claim vs request headers
//!
//! ## Typical chain order
//! `rate_limit -> auth -> rbac -> phe -> encrypt -> kv -> router`
//!
//! ## Config example
//! ```json
//! {
//!   "name": "rbac",
//!   "typed_config": {
//!     "skip_paths": ["/health", "/ready"],
//!     "default_deny": true,
//!     "deny_actions": ["doc:post"],
//!     "roles": {
//!       "accountant": ["doc:view", "doc:edit"],
//!       "manager": ["doc:view", "doc:approve"]
//!     },
//!     "groups": {
//!       "finance": ["accountant"],
//!       "ops": ["manager"]
//!     },
//!     "rules": [
//!       {
//!         "path_prefix": "/docs",
//!         "methods": ["GET"],
//!         "permissions": ["doc:view"],
//!         "action": "doc:view"
//!       },
//!       {
//!         "path_prefix": "/docs",
//!         "methods": ["PUT"],
//!         "permissions": ["doc:edit"],
//!         "action": "doc:edit"
//!       }
//!     ],
//!     "scope": {
//!       "org_claim": "org_id",
//!       "org_header": "x-org-id",
//!       "branch_claim": "branch_id",
//!       "branch_header": "x-branch-id"
//!     }
//!   }
//! }
//! ```

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::filters::auth::{AuthClaims, AuthIdentity};
use crate::types::{Request, Response};
use http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Debug, Clone, serde::Deserialize)]
struct RbacScopeConfig {
    #[serde(default = "default_org_claim")]
    org_claim: String,
    #[serde(default = "default_org_header")]
    org_header: String,
    #[serde(default = "default_branch_claim")]
    branch_claim: String,
    #[serde(default = "default_branch_header")]
    branch_header: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RbacRuleConfig {
    path_prefix: String,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    deny_actions: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RbacConfig {
    #[serde(default)]
    skip_paths: Vec<String>,
    #[serde(default)]
    default_deny: bool,
    #[serde(default)]
    deny_actions: Vec<String>,
    #[serde(default)]
    roles: HashMap<String, Vec<String>>,
    #[serde(default)]
    groups: HashMap<String, Vec<String>>,
    #[serde(default)]
    rules: Vec<RbacRuleConfig>,
    #[serde(default)]
    scope: Option<RbacScopeConfig>,
}

fn default_org_claim() -> String {
    "org_id".to_string()
}
fn default_org_header() -> String {
    "x-org-id".to_string()
}
fn default_branch_claim() -> String {
    "branch_id".to_string()
}
fn default_branch_header() -> String {
    "x-branch-id".to_string()
}

pub struct RbacFilter {
    skip_paths: HashSet<String>,
    default_deny: bool,
    deny_actions: HashSet<String>,
    roles: HashMap<String, Vec<String>>,
    groups: HashMap<String, Vec<String>>,
    rules: Vec<RbacRuleConfig>,
    scope: RbacScopeConfig,
}

impl Filter for RbacFilter {
    fn name(&self) -> &'static str {
        "rbac"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        effects: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if self.skip_paths.contains(req.uri.path()) {
                effects.metrics.counter_inc("rbac.skipped");
                return Verdict::Continue;
            }

            if req.metadata.get::<AuthIdentity>().is_none() {
                effects.metrics.counter_inc("rbac.missing_identity");
                return Verdict::Respond(Response::json(
                    StatusCode::UNAUTHORIZED,
                    &serde_json::json!({"error": "rbac requires authenticated identity"}),
                ));
            }

            let claims = req.metadata.get::<AuthClaims>();
            let Some(claims) = claims else {
                effects.metrics.counter_inc("rbac.missing_claims");
                return Verdict::Respond(Response::json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({"error": "rbac requires claims metadata"}),
                ));
            };

            if let Err(reason) = self.check_scope(req, claims) {
                effects.metrics.counter_inc("rbac.denied.scope");
                effects.log.warn("rbac denied (scope)", &[("reason", &reason)]);
                return Verdict::Respond(Response::json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({"error": reason}),
                ));
            }

            let principal_permissions = self.permissions_from_claims(claims);
            let method = req.method.as_str();
            let path = req.uri.path();

            let matched_rules: Vec<&RbacRuleConfig> = self
                .rules
                .iter()
                .filter(|rule| path.starts_with(&rule.path_prefix))
                .filter(|rule| rule.methods.is_empty() || rule.methods.iter().any(|m| m == method))
                .collect();

            if matched_rules.is_empty() {
                if self.default_deny {
                    effects.metrics.counter_inc("rbac.denied.default");
                    return Verdict::Respond(Response::json(
                        StatusCode::FORBIDDEN,
                        &serde_json::json!({"error": "rbac: no matching rule"}),
                    ));
                }

                effects.metrics.counter_inc("rbac.allowed.no_rule");
                return Verdict::Continue;
            }

            for rule in matched_rules {
                let action = rule
                    .action
                    .clone()
                    .or_else(|| rule.permissions.first().cloned())
                    .unwrap_or_else(|| format!("{}:{}", method.to_lowercase(), rule.path_prefix));

                if self.deny_actions.contains(&action) || rule.deny_actions.contains(&action) {
                    effects.metrics.counter_inc("rbac.denied.action");
                    return Verdict::Respond(Response::json(
                        StatusCode::FORBIDDEN,
                        &serde_json::json!({"error": format!("rbac deny action: {action}")}),
                    ));
                }

                let missing: Vec<String> = rule
                    .permissions
                    .iter()
                    .filter(|perm| !principal_permissions.contains(*perm))
                    .cloned()
                    .collect();

                if missing.is_empty() {
                    effects.metrics.counter_inc("rbac.allowed");
                    return Verdict::Continue;
                }
            }

            effects.metrics.counter_inc("rbac.denied.permissions");
            Verdict::Respond(Response::json(
                StatusCode::FORBIDDEN,
                &serde_json::json!({"error": "rbac: missing required permissions"}),
            ))
        })
    }
}

impl RbacFilter {
    fn permissions_from_claims(
        &self,
        claims: &serde_json::Map<String, serde_json::Value>,
    ) -> HashSet<String> {
        let mut roles = HashSet::new();

        if let Some(role) = claims.get("role").and_then(|v| v.as_str()) {
            roles.insert(role.to_string());
        }

        if let Some(items) = claims.get("roles").and_then(|v| v.as_array()) {
            for item in items.iter().filter_map(|v| v.as_str()) {
                roles.insert(item.to_string());
            }
        }

        if let Some(groups) = claims.get("groups").and_then(|v| v.as_array()) {
            for group in groups.iter().filter_map(|v| v.as_str()) {
                if let Some(group_roles) = self.groups.get(group) {
                    for role in group_roles {
                        roles.insert(role.clone());
                    }
                }
            }
        }

        let mut permissions = HashSet::new();

        if let Some(items) = claims.get("permissions").and_then(|v| v.as_array()) {
            for item in items.iter().filter_map(|v| v.as_str()) {
                permissions.insert(item.to_string());
            }
        }

        for role in roles {
            if let Some(role_perms) = self.roles.get(&role) {
                for perm in role_perms {
                    permissions.insert(perm.clone());
                }
            }
        }

        permissions
    }

    fn check_scope(
        &self,
        req: &Request,
        claims: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), String> {
        self.compare_scope_pair(req, claims, &self.scope.org_header, &self.scope.org_claim)?;
        self.compare_scope_pair(
            req,
            claims,
            &self.scope.branch_header,
            &self.scope.branch_claim,
        )?;
        Ok(())
    }

    fn compare_scope_pair(
        &self,
        req: &Request,
        claims: &serde_json::Map<String, serde_json::Value>,
        header_name: &str,
        claim_name: &str,
    ) -> Result<(), String> {
        let Some(header_value) = req.headers.get(header_name).and_then(|v| v.to_str().ok()) else {
            return Ok(());
        };

        let Some(claim_value) = claims.get(claim_name).and_then(|v| v.as_str()) else {
            return Err(format!("rbac scope claim missing: {claim_name}"));
        };

        if header_value == claim_value {
            Ok(())
        } else {
            Err(format!(
                "rbac scope mismatch: header {header_name}={header_value}, claim {claim_name}={claim_value}"
            ))
        }
    }
}

pub struct RbacFactory;

impl FilterFactory for RbacFactory {
    fn name(&self) -> &str {
        "rbac"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: RbacConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid rbac config: {e}"))?;

        let scope = cfg.scope.unwrap_or(RbacScopeConfig {
            org_claim: default_org_claim(),
            org_header: default_org_header(),
            branch_claim: default_branch_claim(),
            branch_header: default_branch_header(),
        });

        Ok(Arc::new(RbacFilter {
            skip_paths: cfg.skip_paths.into_iter().collect(),
            default_deny: cfg.default_deny,
            deny_actions: cfg.deny_actions.into_iter().collect(),
            roles: cfg.roles,
            groups: cfg.groups,
            rules: cfg.rules,
            scope,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::{Metrics, RequestLogger, SharedState, SystemClock};
    use crate::test_support::TestHttpClient;
    use http::{Method, Uri};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tokio::task::JoinSet;

    fn test_effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: TestHttpClient::boxed(HashMap::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn request(method: Method, path: &str) -> Request {
        Request::new(
            method,
            Uri::try_from(path).unwrap(),
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        )
    }

    fn base_filter() -> Arc<dyn Filter> {
        RbacFactory
            .build(&ron_value(r#"{
                "default_deny": true,
                "deny_actions": ["doc:post"],
                "roles": {
                    "accountant": ["doc:view", "doc:edit"],
                    "manager": ["doc:view", "doc:approve"]
                },
                "groups": {
                    "finance": ["accountant"]
                },
                "rules": [
                    {
                        "path_prefix": "/docs",
                        "methods": ["GET"],
                        "permissions": ["doc:view"],
                        "action": "doc:view"
                    },
                    {
                        "path_prefix": "/docs",
                        "methods": ["PUT"],
                        "permissions": ["doc:edit"],
                        "action": "doc:edit"
                    },
                    {
                        "path_prefix": "/docs/post",
                        "methods": ["POST"],
                        "permissions": ["doc:post"],
                        "action": "doc:post"
                    }
                ]
            }"#))
            .unwrap()
    }

    fn set_identity(req: &mut Request) {
        req.metadata.insert::<AuthIdentity>("alice".to_string());
    }

    fn set_claims(req: &mut Request, claims: serde_json::Value) {
        let map = claims.as_object().unwrap().clone();
        req.metadata.insert::<AuthClaims>(map);
    }

    #[tokio::test]
    async fn allow_by_role_permission() {
        let filter = base_filter();
        let fx = test_effects();
        let mut req = request(Method::GET, "/docs/123");
        set_identity(&mut req);
        set_claims(
            &mut req,
            serde_json::json!({"role": "accountant", "org_id": "org-1", "branch_id": "b-1"}),
        );
        req.headers.insert("x-org-id", "org-1".parse().unwrap());
        req.headers.insert("x-branch-id", "b-1".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn allow_by_group_expansion() {
        let filter = base_filter();
        let fx = test_effects();
        let mut req = request(Method::PUT, "/docs/123");
        set_identity(&mut req);
        set_claims(
            &mut req,
            serde_json::json!({"groups": ["finance"], "org_id": "org-1", "branch_id": "b-1"}),
        );
        req.headers.insert("x-org-id", "org-1".parse().unwrap());
        req.headers.insert("x-branch-id", "b-1".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
    }

    #[tokio::test]
    async fn deny_missing_permission() {
        let filter = base_filter();
        let fx = test_effects();
        let mut req = request(Method::PUT, "/docs/123");
        set_identity(&mut req);
        set_claims(
            &mut req,
            serde_json::json!({"role": "manager", "org_id": "org-1", "branch_id": "b-1"}),
        );
        req.headers.insert("x-org-id", "org-1".parse().unwrap());
        req.headers.insert("x-branch-id", "b-1".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::FORBIDDEN),
            _ => panic!("expected forbidden response"),
        }
    }

    #[tokio::test]
    async fn deny_global_action() {
        let filter = base_filter();
        let fx = test_effects();
        let mut req = request(Method::POST, "/docs/post");
        set_identity(&mut req);
        set_claims(
            &mut req,
            serde_json::json!({"permissions": ["doc:post"], "org_id": "org-1", "branch_id": "b-1"}),
        );
        req.headers.insert("x-org-id", "org-1".parse().unwrap());
        req.headers.insert("x-branch-id", "b-1".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::FORBIDDEN),
            _ => panic!("expected forbidden response"),
        }
    }

    #[tokio::test]
    async fn deny_scope_mismatch() {
        let filter = base_filter();
        let fx = test_effects();
        let mut req = request(Method::GET, "/docs/123");
        set_identity(&mut req);
        set_claims(
            &mut req,
            serde_json::json!({"role": "accountant", "org_id": "org-1", "branch_id": "b-1"}),
        );
        req.headers.insert("x-org-id", "org-2".parse().unwrap());
        req.headers.insert("x-branch-id", "b-1".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::FORBIDDEN),
            _ => panic!("expected forbidden response"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_short_circuit_storm() {
        let filter = base_filter();
        let mut set = JoinSet::new();

        for _ in 0..1000usize {
            let filter = Arc::clone(&filter);
            set.spawn(async move {
                let fx = test_effects();
                let mut req = request(Method::POST, "/docs/post");
                set_identity(&mut req);
                set_claims(
                    &mut req,
                    serde_json::json!({"permissions": ["doc:post"], "org_id": "org-1", "branch_id": "b-1"}),
                );
                req.headers.insert("x-org-id", "org-1".parse().unwrap());
                req.headers.insert("x-branch-id", "b-1".parse().unwrap());

                match filter.on_request(&mut req, &fx).await {
                    Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::FORBIDDEN),
                    _ => panic!("expected short-circuit deny"),
                }
            });
        }

        while let Some(res) = set.join_next().await {
            res.unwrap();
        }
    }
}
