//! Control plane: ChainBuilder, FilterFactory, FilterRegistry.
//!
//! This is the "Build Systems à la Carte" part:
//! - "Source" = configuration (JSON)
//! - "Artifact" = FilterChain
//! - "Rebuilder" = needs_rebuild() method on factories
//! - Incremental: only rebuilds filters whose config changed

use crate::chain::{ActiveChain, FilterChain};
use crate::filter::Filter;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

// ─── Config types ────────────────────────────────────────────────────

/// Configuration for a single filter in the chain.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct FilterConfig {
    /// Filter name (must match a registered factory).
    pub name: String,
    /// Filter-specific configuration (opaque JSON).
    #[serde(default)]
    pub typed_config: serde_json::Value,
}

/// Configuration for the entire filter chain.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChainConfig {
    pub filters: Vec<FilterConfig>,
}

// ─── Config errors ───────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigError {
    /// No factory registered for this filter name.
    UnknownFilter(String),
    /// Factory failed to build the filter.
    BuildFailed {
        filter: String,
        reason: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFilter(name) => write!(f, "unknown filter: {name}"),
            Self::BuildFailed { filter, reason } => {
                write!(f, "failed to build filter '{filter}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ─── FilterFactory ───────────────────────────────────────────────────

/// Factory that creates a filter from configuration.
///
/// Analogy to "Build Systems à la Carte":
/// - `build()` = Task: config → artifact (filter)
/// - `needs_rebuild()` = Rebuilder: should we rebuild?
///
/// Default rebuilder: dirty-bit (config changed → rebuild).
/// Override for smarter strategies (verifying traces, constructive).
pub trait FilterFactory: Send + Sync {
    /// Filter type name (e.g., "rate_limit", "jwt_auth").
    fn name(&self) -> &str;

    /// Build a filter instance from JSON config.
    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String>;

    /// Should the filter be rebuilt given old and new configs?
    ///
    /// Default: dirty-bit — rebuild if configs differ.
    fn needs_rebuild(
        &self,
        old_config: &serde_json::Value,
        new_config: &serde_json::Value,
    ) -> bool {
        old_config != new_config
    }
}

// ─── FilterRegistry ──────────────────────────────────────────────────

/// Registry of filter factories, populated at startup.
///
/// Analogous to Envoy's `Registry::registerFactory<>()`.
pub struct FilterRegistry {
    factories: HashMap<String, Box<dyn FilterFactory>>,
}

impl FilterRegistry {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a filter factory.
    pub fn register(&mut self, factory: Box<dyn FilterFactory>) {
        let name = factory.name().to_string();
        self.factories.insert(name, factory);
    }

    /// Look up a factory by name.
    pub fn get(&self, name: &str) -> Option<&dyn FilterFactory> {
        self.factories.get(name).map(|f| f.as_ref())
    }

    /// List all registered filter names.
    pub fn names(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for FilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ChainBuilder ────────────────────────────────────────────────────

/// Builds FilterChain from configuration with incremental caching.
///
/// Cache key: (position_index, filter_name).
/// Stores old config to correctly pass to `needs_rebuild(old, new)`.
/// Supports multiple instances of the same filter type at different positions.
pub struct ChainBuilder {
    registry: Arc<FilterRegistry>,
    /// Cache: (position, filter_name) → (config_hash, old_config, built filter)
    cache: HashMap<(usize, String), (u64, serde_json::Value, Arc<dyn Filter>)>,
}

impl ChainBuilder {
    pub fn new(registry: Arc<FilterRegistry>) -> Self {
        Self {
            registry,
            cache: HashMap::new(),
        }
    }

    /// Build a FilterChain from config.
    ///
    /// Incremental: reuses cached filters when config hasn't changed.
    pub fn build(&mut self, config: &ChainConfig) -> Result<FilterChain, ConfigError> {
        let mut filters = Vec::with_capacity(config.filters.len());
        // Clone the Arc so that `factory` borrows from a local, not `self`.
        let registry = Arc::clone(&self.registry);

        for (idx, fc) in config.filters.iter().enumerate() {
            let factory = registry
                .get(&fc.name)
                .ok_or_else(|| ConfigError::UnknownFilter(fc.name.clone()))?;

            let config_hash = hash_json(&fc.typed_config);
            let cache_key = (idx, fc.name.clone());

            let filter = match self.cache.get(&cache_key) {
                Some((cached_hash, old_config, cached_filter)) if *cached_hash == config_hash => {
                    // Config hash matches — check factory's rebuild policy
                    if !factory.needs_rebuild(old_config, &fc.typed_config) {
                        tracing::debug!(filter = fc.name.as_str(), "reusing cached filter");
                        Arc::clone(cached_filter)
                    } else {
                        self.build_and_cache(factory, fc, config_hash, cache_key)?
                    }
                }
                _ => self.build_and_cache(factory, fc, config_hash, cache_key)?,
            };

            filters.push(filter);
        }

        // Clean up cache entries for filters no longer in config
        let active_keys: std::collections::HashSet<(usize, &str)> =
            config.filters.iter().enumerate().map(|(i, f)| (i, f.name.as_str())).collect();
        self.cache.retain(|k, _| active_keys.contains(&(k.0, k.1.as_str())));

        Ok(FilterChain::new(filters))
    }

    fn build_and_cache(
        &mut self,
        factory: &dyn FilterFactory,
        fc: &FilterConfig,
        config_hash: u64,
        cache_key: (usize, String),
    ) -> Result<Arc<dyn Filter>, ConfigError> {
        tracing::info!(filter = fc.name.as_str(), "building filter from config");
        let filter = factory
            .build(&fc.typed_config)
            .map_err(|reason| ConfigError::BuildFailed {
                filter: fc.name.clone(),
                reason,
            })?;
        self.cache
            .insert(cache_key, (config_hash, fc.typed_config.clone(), Arc::clone(&filter)));
        Ok(filter)
    }
}

/// Hash JSON value for cache keying (deterministic, fast xxHash64).
fn hash_json(value: &serde_json::Value) -> u64 {
    let serialized = value.to_string();
    let mut hasher = twox_hash::XxHash64::default();
    serialized.hash(&mut hasher);
    hasher.finish()
}

// ─── Hot Reload ──────────────────────────────────────────────────────

/// Atomically swap the active filter chain.
///
/// - Workers reading the old chain are not interrupted
/// - Old chain lives until all in-flight requests complete (Arc refcount)
/// - New requests immediately see the new chain
pub fn hot_reload(
    builder: &mut ChainBuilder,
    new_config: &ChainConfig,
    active: &ActiveChain,
) -> Result<(), ConfigError> {
    let new_chain = builder.build(new_config)?;
    let filter_count = new_chain.len();
    active.store(Arc::new(new_chain));
    tracing::info!(filters = filter_count, "hot-reloaded filter chain");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::*;
    use crate::types::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ── Test fixtures ───────────────────────────────────────────

    /// Trivial passthrough filter for testing.
    struct PassthroughFilter;

    impl Filter for PassthroughFilter {
        fn name(&self) -> &'static str {
            "passthrough"
        }

        fn on_request<'a>(
            &'a self,
            _req: &'a mut Request,
            _fx: &'a Effects,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
            Box::pin(async { Verdict::Continue })
        }
    }

    /// Factory that counts how many times build() was called.
    /// Lets us prove caching works (build should not be called on cache hit).
    struct CountingFactory {
        build_count: Arc<AtomicU32>,
    }

    impl CountingFactory {
        fn new() -> (Self, Arc<AtomicU32>) {
            let count = Arc::new(AtomicU32::new(0));
            (Self { build_count: Arc::clone(&count) }, count)
        }
    }

    impl FilterFactory for CountingFactory {
        fn name(&self) -> &str {
            "counting"
        }

        fn build(&self, _config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
            self.build_count.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(PassthroughFilter))
        }
    }

    struct FailingFactory;

    impl FilterFactory for FailingFactory {
        fn name(&self) -> &str {
            "failing"
        }

        fn build(&self, _config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
            Err("intentional build failure".into())
        }
    }

    fn passthrough_factory() -> Box<dyn FilterFactory> {
        struct F;
        impl FilterFactory for F {
            fn name(&self) -> &str { "passthrough" }
            fn build(&self, _config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
                Ok(Arc::new(PassthroughFilter))
            }
        }
        Box::new(F)
    }

    // ── Basic build ─────────────────────────────────────────────

    #[test]
    fn builder_creates_single_filter_chain() {
        let mut registry = FilterRegistry::new();
        registry.register(passthrough_factory());
        let mut builder = ChainBuilder::new(Arc::new(registry));

        let config = ChainConfig {
            filters: vec![FilterConfig {
                name: "passthrough".into(),
                typed_config: serde_json::json!({}),
            }],
        };

        let chain = builder.build(&config).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn builder_creates_multi_filter_chain() {
        let mut registry = FilterRegistry::new();
        registry.register(passthrough_factory());
        let mut builder = ChainBuilder::new(Arc::new(registry));

        let config = ChainConfig {
            filters: vec![
                FilterConfig { name: "passthrough".into(), typed_config: serde_json::json!({}) },
                FilterConfig { name: "passthrough".into(), typed_config: serde_json::json!({"x": 1}) },
                FilterConfig { name: "passthrough".into(), typed_config: serde_json::json!({"x": 2}) },
            ],
        };

        let chain = builder.build(&config).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn builder_empty_config_produces_empty_chain() {
        let registry = Arc::new(FilterRegistry::new());
        let mut builder = ChainBuilder::new(registry);

        let config = ChainConfig { filters: vec![] };
        let chain = builder.build(&config).unwrap();
        assert!(chain.is_empty());
    }

    // ── Caching — the real test ─────────────────────────────────

    #[test]
    fn builder_caches_unchanged_filters_verified_by_build_count() {
        let (factory, build_count) = CountingFactory::new();
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(factory));
        let mut builder = ChainBuilder::new(Arc::new(registry));

        let config = ChainConfig {
            filters: vec![FilterConfig {
                name: "counting".into(),
                typed_config: serde_json::json!({"key": "value"}),
            }],
        };

        // First build: must call factory.build()
        let _chain1 = builder.build(&config).unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 1);

        // Second build same config: cache hit → build NOT called again
        let _chain2 = builder.build(&config).unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 1, "cache should prevent rebuild");
    }

    #[test]
    fn builder_invalidates_cache_on_config_change() {
        let (factory, build_count) = CountingFactory::new();
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(factory));
        let mut builder = ChainBuilder::new(Arc::new(registry));

        let config1 = ChainConfig {
            filters: vec![FilterConfig {
                name: "counting".into(),
                typed_config: serde_json::json!({"version": 1}),
            }],
        };
        let config2 = ChainConfig {
            filters: vec![FilterConfig {
                name: "counting".into(),
                typed_config: serde_json::json!({"version": 2}),
            }],
        };

        let _chain1 = builder.build(&config1).unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 1);

        // Config changed → must rebuild
        let _chain2 = builder.build(&config2).unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 2);
    }

    // ── Error handling ──────────────────────────────────────────

    #[test]
    fn builder_rejects_unknown_filter() {
        let registry = Arc::new(FilterRegistry::new());
        let mut builder = ChainBuilder::new(registry);

        let config = ChainConfig {
            filters: vec![FilterConfig {
                name: "nonexistent".into(),
                typed_config: serde_json::json!({}),
            }],
        };

        let result = builder.build(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::UnknownFilter(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected UnknownFilter, got: {other}"),
        }
    }

    #[test]
    fn builder_propagates_factory_build_error() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(FailingFactory));
        let mut builder = ChainBuilder::new(Arc::new(registry));

        let config = ChainConfig {
            filters: vec![FilterConfig {
                name: "failing".into(),
                typed_config: serde_json::json!({}),
            }],
        };

        let result = builder.build(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::BuildFailed { filter, reason } => {
                assert_eq!(filter, "failing");
                assert!(reason.contains("intentional"));
            }
            other => panic!("expected BuildFailed, got: {other}"),
        }
    }

    // ── Registry ────────────────────────────────────────────────

    #[test]
    fn registry_names_returns_registered_factories() {
        let mut registry = FilterRegistry::new();
        registry.register(passthrough_factory());
        let names = registry.names();
        assert!(names.contains(&"passthrough"));
    }

    // ── hash_json determinism ───────────────────────────────────

    #[test]
    fn hash_json_same_input_same_output() {
        let v = serde_json::json!({"a": 1, "b": [2, 3]});
        assert_eq!(hash_json(&v), hash_json(&v));
    }

    #[test]
    fn hash_json_different_input_different_output() {
        let a = serde_json::json!({"a": 1});
        let b = serde_json::json!({"a": 2});
        assert_ne!(hash_json(&a), hash_json(&b));
    }
}
