//! LDAP sync filter.
//!
//! Enriches authenticated principal claims from a directory source
//! before authorization (`rbac`).

use crate::builder::FilterFactory;
use crate::filter::{Effects, Filter, Verdict};
use crate::filters::auth::{AuthClaims, AuthIdentity};
use crate::types::{Request, Response};
use http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, serde::Deserialize)]
struct LdapEntryConfig {
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    branch_id: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct LdapSyncConfig {
    #[serde(default)]
    skip_paths: Vec<String>,
    #[serde(default = "default_true")]
    require_identity: bool,
    #[serde(default = "default_cache_ttl")]
    cache_ttl_secs: u64,
    #[serde(default)]
    directory: HashMap<String, LdapEntryConfig>,
    #[serde(default)]
    group_role_map: HashMap<String, Vec<String>>,
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    60
}

#[derive(Clone)]
struct CacheEntry {
    claims: serde_json::Map<String, serde_json::Value>,
    expires_at: Instant,
}

pub struct LdapSyncFilter {
    skip_paths: HashSet<String>,
    require_identity: bool,
    cache_ttl: Duration,
    directory: HashMap<String, LdapEntryConfig>,
    group_role_map: HashMap<String, Vec<String>>,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl Filter for LdapSyncFilter {
    fn name(&self) -> &'static str {
        "ldap_sync"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if self.skip_paths.contains(req.uri.path()) {
                fx.metrics.counter_inc("ldap_sync.skipped");
                return Verdict::Continue;
            }

            let identity = req.metadata.get::<AuthIdentity>().cloned();
            let Some(identity) = identity else {
                if self.require_identity {
                    fx.metrics.counter_inc("ldap_sync.missing_identity");
                    return Verdict::Respond(Response::json(
                        StatusCode::UNAUTHORIZED,
                        &serde_json::json!({"error":"ldap_sync requires authenticated identity"}),
                    ));
                }
                fx.metrics.counter_inc("ldap_sync.no_identity_continue");
                return Verdict::Continue;
            };

            let now = fx.clock.now();

            if let Some(cached) = self.get_cached(&identity, now) {
                let mut claims = req.metadata.get::<AuthClaims>().cloned().unwrap_or_default();
                merge_claims(&mut claims, &cached);
                req.metadata.insert::<AuthClaims>(claims);
                fx.metrics.counter_inc("ldap_sync.cache_hit");
                return Verdict::Continue;
            }

            let Some(entry) = self.directory.get(&identity) else {
                fx.metrics.counter_inc("ldap_sync.directory_miss");
                return Verdict::Respond(Response::json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({"error":"principal not found in directory"}),
                ));
            };

            let mut enriched = serde_json::Map::new();

            if !entry.groups.is_empty() {
                enriched.insert(
                    "groups".to_string(),
                    serde_json::Value::Array(
                        entry
                            .groups
                            .iter()
                            .map(|v| serde_json::Value::String(v.clone()))
                            .collect(),
                    ),
                );
            }

            let mut roles = entry.roles.clone();
            for group in &entry.groups {
                if let Some(mapped_roles) = self.group_role_map.get(group) {
                    roles.extend(mapped_roles.clone());
                }
            }
            dedup_vec(&mut roles);

            if !roles.is_empty() {
                enriched.insert(
                    "roles".to_string(),
                    serde_json::Value::Array(
                        roles
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }

            if let Some(org_id) = &entry.org_id {
                enriched.insert("org_id".to_string(), serde_json::Value::String(org_id.clone()));
            }

            if let Some(branch_id) = &entry.branch_id {
                enriched.insert(
                    "branch_id".to_string(),
                    serde_json::Value::String(branch_id.clone()),
                );
            }

            self.put_cached(&identity, enriched.clone(), now + self.cache_ttl);

            let mut claims = req.metadata.get::<AuthClaims>().cloned().unwrap_or_default();
            merge_claims(&mut claims, &enriched);
            req.metadata.insert::<AuthClaims>(claims);
            fx.metrics.counter_inc("ldap_sync.enriched");

            Verdict::Continue
        })
    }
}

impl LdapSyncFilter {
    fn get_cached(
        &self,
        identity: &str,
        now: Instant,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let entry = cache.get(identity)?;
        if entry.expires_at > now {
            Some(entry.claims.clone())
        } else {
            None
        }
    }

    fn put_cached(
        &self,
        identity: &str,
        claims: serde_json::Map<String, serde_json::Value>,
        expires_at: Instant,
    ) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(
            identity.to_string(),
            CacheEntry { claims, expires_at },
        );
    }
}

fn dedup_vec(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|item| seen.insert(item.clone()));
}

fn merge_claims(
    target: &mut serde_json::Map<String, serde_json::Value>,
    source: &serde_json::Map<String, serde_json::Value>,
) {
    for (k, v) in source {
        match (target.get(k), v) {
            (Some(serde_json::Value::Array(existing)), serde_json::Value::Array(new_values)) => {
                let mut merged = existing.clone();
                merged.extend(new_values.clone());
                let mut as_strings = merged
                    .into_iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>();
                dedup_vec(&mut as_strings);
                target.insert(
                    k.clone(),
                    serde_json::Value::Array(
                        as_strings
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
            _ => {
                target.insert(k.clone(), v.clone());
            }
        }
    }
}

pub struct LdapSyncFactory;

impl FilterFactory for LdapSyncFactory {
    fn name(&self) -> &str {
        "ldap_sync"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: LdapSyncConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("invalid ldap_sync config: {e}"))?;

        Ok(Arc::new(LdapSyncFilter {
            skip_paths: cfg.skip_paths.into_iter().collect(),
            require_identity: cfg.require_identity,
            cache_ttl: Duration::from_secs(cfg.cache_ttl_secs),
            directory: cfg.directory,
            group_role_map: cfg.group_role_map,
            cache: Mutex::new(HashMap::new()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::{Clock, HttpClient, Metrics, RequestLogger, SharedState};
    use crate::filter::SystemClock;
    use http::{Method, Uri};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct SteppingClock {
        start: Instant,
        step: Duration,
        calls: AtomicU64,
    }

    impl SteppingClock {
        fn new(step: Duration) -> Self {
            Self {
                start: Instant::now(),
                step,
                calls: AtomicU64::new(0),
            }
        }
    }

    impl Clock for SteppingClock {
        fn now(&self) -> Instant {
            let n = self.calls.fetch_add(1, Ordering::Relaxed);
            self.start + self.step * n as u32
        }
    }

    fn effects() -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn effects_with_clock(clock: Arc<dyn Clock + Send + Sync>) -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: Arc::new(HttpClient::new()),
            shared: Arc::new(SharedState::new()),
            clock,
        }
    }

    fn req(path: &str) -> Request {
        Request::new(
            Method::GET,
            Uri::try_from(path).unwrap(),
            "127.0.0.1:1111".parse::<SocketAddr>().unwrap(),
        )
    }

    fn filter(cfg: serde_json::Value) -> Arc<dyn Filter> {
        LdapSyncFactory.build(&cfg).unwrap()
    }

    #[tokio::test]
    async fn enriches_claims_from_directory() {
        let filter = filter(ron_value(r#"{
            "directory": {
                "alice": {
                    "groups": ["finance"],
                    "roles": ["accountant"],
                    "org_id": "org-1",
                    "branch_id": "b-1"
                }
            },
            "group_role_map": {
                "finance": ["report_viewer"]
            }
        }"#));

        let fx = effects();
        let mut req = req("/api");
        req.metadata.insert::<AuthIdentity>("alice".to_string());
        req.metadata.insert::<AuthClaims>(serde_json::json!({"source":"jwt"}).as_object().unwrap().clone());

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        let claims = req.metadata.get::<AuthClaims>().unwrap();
        assert_eq!(claims.get("org_id").unwrap(), "org-1");
        assert_eq!(claims.get("branch_id").unwrap(), "b-1");
        assert!(claims.get("groups").unwrap().as_array().unwrap().len() == 1);
        assert!(claims.get("roles").unwrap().as_array().unwrap().len() == 2);
    }

    #[tokio::test]
    async fn denies_when_identity_missing_and_required() {
        let filter = filter(ron_value(r#"{
            "require_identity": true,
            "directory": {}
        }"#));

        let fx = effects();
        let mut req = req("/api");

        let verdict = filter.on_request(&mut req, &fx).await;
        match verdict {
            Verdict::Respond(resp) => assert_eq!(resp.status, StatusCode::UNAUTHORIZED),
            _ => panic!("expected unauthorized"),
        }
    }

    #[tokio::test]
    async fn cache_hit_works() {
        let filter = filter(ron_value(r#"{
            "cache_ttl_secs": 60,
            "directory": {
                "alice": {"groups": ["finance"], "roles": ["accountant"]}
            }
        }"#));

        let fx = effects();
        let mut req1 = req("/api");
        req1.metadata.insert::<AuthIdentity>("alice".to_string());
        filter.on_request(&mut req1, &fx).await;

        let mut req2 = req("/api");
        req2.metadata.insert::<AuthIdentity>("alice".to_string());
        filter.on_request(&mut req2, &fx).await;

        assert_eq!(fx.metrics.counter_get("ldap_sync.cache_hit"), 1);
    }

    #[tokio::test]
    async fn cache_expires() {
        let filter = filter(ron_value(r#"{
            "cache_ttl_secs": 1,
            "directory": {
                "alice": {"groups": ["finance"], "roles": ["accountant"]}
            }
        }"#));

        let clock = Arc::new(SteppingClock::new(Duration::from_secs(2)));
        let fx = effects_with_clock(clock);

        let mut req1 = req("/api");
        req1.metadata.insert::<AuthIdentity>("alice".to_string());
        let _ = filter.on_request(&mut req1, &fx).await;

        let mut req2 = req("/api");
        req2.metadata.insert::<AuthIdentity>("alice".to_string());
        let _ = filter.on_request(&mut req2, &fx).await;

        assert_eq!(fx.metrics.counter_get("ldap_sync.cache_hit"), 0);
        assert_eq!(fx.metrics.counter_get("ldap_sync.enriched"), 2);
    }
}
