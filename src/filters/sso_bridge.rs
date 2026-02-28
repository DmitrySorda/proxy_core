//! SSO/LDAP bridge filter.
//!
//! Converts trusted upstream identity headers into typed auth metadata
//! (`AuthIdentity`, `AuthClaims`, `AuthMethod`) for downstream `rbac`/`audit`.

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::filters::auth::{AuthClaims, AuthIdentity, AuthMethod};
use crate::types::{Request, Response};
use http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Debug, Clone, serde::Deserialize)]
struct SsoBridgeConfig {
    #[serde(default)]
    skip_paths: Vec<String>,
    #[serde(default)]
    trusted_peer_ips: Vec<String>,
    #[serde(default = "default_true")]
    require_trusted_peer: bool,
    #[serde(default = "default_true")]
    deny_untrusted_with_headers: bool,
    #[serde(default)]
    overwrite_existing: bool,
    #[serde(default = "default_identity_header")]
    identity_header: String,
    #[serde(default = "default_groups_header")]
    groups_header: String,
    #[serde(default = "default_roles_header")]
    roles_header: String,
    #[serde(default = "default_org_header")]
    org_header: String,
    #[serde(default = "default_branch_header")]
    branch_header: String,
    #[serde(default = "default_separator")]
    separator: String,
    #[serde(default)]
    static_claims: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}
fn default_identity_header() -> String {
    "x-auth-user".to_string()
}
fn default_groups_header() -> String {
    "x-auth-groups".to_string()
}
fn default_roles_header() -> String {
    "x-auth-roles".to_string()
}
fn default_org_header() -> String {
    "x-org-id".to_string()
}
fn default_branch_header() -> String {
    "x-branch-id".to_string()
}
fn default_separator() -> String {
    ",".to_string()
}

pub struct SsoBridgeFilter {
    skip_paths: HashSet<String>,
    trusted_peer_ips: HashSet<IpAddr>,
    require_trusted_peer: bool,
    deny_untrusted_with_headers: bool,
    overwrite_existing: bool,
    identity_header: String,
    groups_header: String,
    roles_header: String,
    org_header: String,
    branch_header: String,
    separator: String,
    static_claims: HashMap<String, String>,
}

impl Filter for SsoBridgeFilter {
    fn name(&self) -> &'static str {
        "sso_bridge"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if self.skip_paths.contains(req.uri.path()) {
                fx.metrics.counter_inc("sso_bridge.skipped");
                return Verdict::Continue;
            }

            let peer_ip = req.peer_addr.ip();
            let is_trusted = self.trusted_peer_ips.contains(&peer_ip);
            let has_bridge_headers = self.has_any_bridge_header(req);

            if self.require_trusted_peer && !is_trusted {
                if self.deny_untrusted_with_headers && has_bridge_headers {
                    fx.metrics.counter_inc("sso_bridge.denied.untrusted");
                    return Verdict::Respond(Response::json(
                        StatusCode::FORBIDDEN,
                        &serde_json::json!({"error":"untrusted peer for sso headers"}),
                    ));
                }
                fx.metrics.counter_inc("sso_bridge.untrusted_ignored");
                return Verdict::Continue;
            }

            if req.metadata.get::<AuthIdentity>().is_some() && !self.overwrite_existing {
                fx.metrics.counter_inc("sso_bridge.preserved_existing");
                return Verdict::Continue;
            }

            let Some(identity) = req
                .headers
                .get(&self.identity_header)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
            else {
                fx.metrics.counter_inc("sso_bridge.no_identity_header");
                return Verdict::Continue;
            };

            let mut claims = req
                .metadata
                .get::<AuthClaims>()
                .cloned()
                .unwrap_or_default();

            claims.insert("sub".to_string(), serde_json::Value::String(identity.clone()));

            if let Some(org) = req
                .headers
                .get(&self.org_header)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                claims.insert("org_id".to_string(), serde_json::Value::String(org.to_string()));
            }

            if let Some(branch) = req
                .headers
                .get(&self.branch_header)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                claims.insert(
                    "branch_id".to_string(),
                    serde_json::Value::String(branch.to_string()),
                );
            }

            let groups = self.parse_list_header(req, &self.groups_header);
            if !groups.is_empty() {
                claims.insert(
                    "groups".to_string(),
                    serde_json::Value::Array(
                        groups
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }

            let roles = self.parse_list_header(req, &self.roles_header);
            if !roles.is_empty() {
                claims.insert(
                    "roles".to_string(),
                    serde_json::Value::Array(
                        roles
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }

            for (k, v) in &self.static_claims {
                claims.insert(k.clone(), serde_json::Value::String(v.clone()));
            }

            req.metadata.insert::<AuthIdentity>(identity);
            req.metadata.insert::<AuthMethod>("sso_bridge");
            req.metadata.insert::<AuthClaims>(claims);
            fx.metrics.counter_inc("sso_bridge.injected");

            Verdict::Continue
        })
    }
}

impl SsoBridgeFilter {
    fn parse_list_header(&self, req: &Request, header: &str) -> Vec<String> {
        req.headers
            .get(header)
            .and_then(|v| v.to_str().ok())
            .map(|raw| {
                raw.split(&self.separator)
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    fn has_any_bridge_header(&self, req: &Request) -> bool {
        req.headers.contains_key(&self.identity_header)
            || req.headers.contains_key(&self.groups_header)
            || req.headers.contains_key(&self.roles_header)
            || req.headers.contains_key(&self.org_header)
            || req.headers.contains_key(&self.branch_header)
    }
}

pub struct SsoBridgeFactory;

impl FilterFactory for SsoBridgeFactory {
    fn name(&self) -> &str {
        "sso_bridge"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: SsoBridgeConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid sso_bridge config: {e}"))?;

        let mut trusted_peer_ips = HashSet::new();
        for value in cfg.trusted_peer_ips {
            let ip: IpAddr = value
                .parse()
                .map_err(|e| format!("invalid trusted peer ip '{value}': {e}"))?;
            trusted_peer_ips.insert(ip);
        }

        Ok(Arc::new(SsoBridgeFilter {
            skip_paths: cfg.skip_paths.into_iter().collect(),
            trusted_peer_ips,
            require_trusted_peer: cfg.require_trusted_peer,
            deny_untrusted_with_headers: cfg.deny_untrusted_with_headers,
            overwrite_existing: cfg.overwrite_existing,
            identity_header: cfg.identity_header,
            groups_header: cfg.groups_header,
            roles_header: cfg.roles_header,
            org_header: cfg.org_header,
            branch_header: cfg.branch_header,
            separator: cfg.separator,
            static_claims: cfg.static_claims,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{HttpClient, Metrics, RequestLogger, SharedState, SystemClock};
    use http::{Method, Uri};
    use std::net::SocketAddr;

    fn effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn req(path: &str, peer: &str) -> Request {
        Request::new(
            Method::GET,
            Uri::try_from(path).unwrap(),
            peer.parse::<SocketAddr>().unwrap(),
        )
    }

    fn filter(cfg: serde_json::Value) -> Arc<dyn Filter> {
        SsoBridgeFactory.build(&cfg).unwrap()
    }

    #[tokio::test]
    async fn injects_identity_and_claims_from_headers() {
        let filter = filter(serde_json::json!({
            "trusted_peer_ips": ["127.0.0.1"],
            "static_claims": {"tenant_type": "enterprise"}
        }));

        let fx = effects();
        let mut req = req("/api/data", "127.0.0.1:1234");
        req.headers.insert("x-auth-user", "alice".parse().unwrap());
        req.headers
            .insert("x-auth-groups", "finance,ops".parse().unwrap());
        req.headers
            .insert("x-auth-roles", "manager,reviewer".parse().unwrap());
        req.headers.insert("x-org-id", "org-1".parse().unwrap());
        req.headers
            .insert("x-branch-id", "branch-9".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "alice");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "sso_bridge");
        let claims = req.metadata.get::<AuthClaims>().unwrap();
        assert_eq!(claims.get("org_id").unwrap(), "org-1");
        assert_eq!(claims.get("branch_id").unwrap(), "branch-9");
        assert_eq!(claims.get("tenant_type").unwrap(), "enterprise");
        assert!(claims.get("groups").unwrap().as_array().unwrap().len() == 2);
        assert!(claims.get("roles").unwrap().as_array().unwrap().len() == 2);
    }

    #[tokio::test]
    async fn untrusted_peer_with_headers_is_denied() {
        let filter = filter(serde_json::json!({
            "trusted_peer_ips": ["127.0.0.1"],
            "require_trusted_peer": true,
            "deny_untrusted_with_headers": true
        }));

        let fx = effects();
        let mut req = req("/api/data", "10.0.0.7:1234");
        req.headers.insert("x-auth-user", "mallory".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::FORBIDDEN),
            _ => panic!("expected forbidden"),
        }
    }

    #[tokio::test]
    async fn preserves_existing_identity_when_not_overwrite() {
        let filter = filter(serde_json::json!({
            "trusted_peer_ips": ["127.0.0.1"],
            "overwrite_existing": false
        }));

        let fx = effects();
        let mut req = req("/api/data", "127.0.0.1:1234");
        req.metadata.insert::<AuthIdentity>("jwt-user".to_string());
        req.metadata.insert::<AuthMethod>("jwt");
        req.headers.insert("x-auth-user", "alice".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "jwt-user");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "jwt");
    }

    #[tokio::test]
    async fn overwrite_existing_identity_when_enabled() {
        let filter = filter(serde_json::json!({
            "trusted_peer_ips": ["127.0.0.1"],
            "overwrite_existing": true
        }));

        let fx = effects();
        let mut req = req("/api/data", "127.0.0.1:1234");
        req.metadata.insert::<AuthIdentity>("jwt-user".to_string());
        req.metadata.insert::<AuthMethod>("jwt");
        req.headers.insert("x-auth-user", "alice".parse().unwrap());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.metadata.get::<AuthIdentity>().unwrap(), "alice");
        assert_eq!(*req.metadata.get::<AuthMethod>().unwrap(), "sso_bridge");
    }
}
