use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use crate::build_system::task::{Task, TaskContext};
use crate::build_system::{BuildError, BuildTrace};

/// Result of a rebuild decision.
pub struct Rebuild<V> {
    value: V,
    should_store: bool,
}

impl<V> Rebuild<V> {
    pub fn built(value: V) -> Self {
        Self {
            value,
            should_store: true,
        }
    }

    pub fn cached(value: V) -> Self {
        Self {
            value,
            should_store: false,
        }
    }

    pub fn value(self) -> V {
        self.value
    }

    pub fn should_store(&self) -> bool {
        self.should_store
    }
}

/// Rebuilder strategy: decide how to compute a value given an optional cached value.
pub trait Rebuilder<K, V> {
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError>;
}

/// Always recompute, ignore any cached value.
pub struct BusyRebuilder;

impl<K, V> Rebuilder<K, V> for BusyRebuilder {
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        _cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError> {
        let value = task.run(key, ctx)?;
        Ok(Rebuild::built(value))
    }
}

/// Reuse cached value if present, otherwise compute.
pub struct MemoRebuilder;

impl<K, V> Rebuilder<K, V> for MemoRebuilder {
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError> {
        if let Some(value) = cached {
            return Ok(Rebuild::cached(value));
        }
        let value = task.run(key, ctx)?;
        Ok(Rebuild::built(value))
    }
}

/// Rebuild only if `is_dirty(key)` reports true; otherwise reuse cached value.
pub struct DirtyRebuilder<F> {
    is_dirty: F,
}

impl<F> DirtyRebuilder<F> {
    pub fn new(is_dirty: F) -> Self {
        Self { is_dirty }
    }
}

impl<K, V, F> Rebuilder<K, V> for DirtyRebuilder<F>
where
    F: Fn(&K) -> bool,
{
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError> {
        if !((self.is_dirty)(key)) {
            if let Some(value) = cached {
                return Ok(Rebuild::cached(value));
            }
        }
        let value = task.run(key, ctx)?;
        Ok(Rebuild::built(value))
    }
}

/// Make-like rebuilder: reuse cache if key and its deps are clean.
pub struct MakeRebuilder<K> {
    is_dirty: Arc<dyn Fn(&K) -> bool + Send + Sync>,
    trace: Arc<Mutex<HashMap<K, Vec<K>>>>,
}

impl<K> Clone for MakeRebuilder<K> {
    fn clone(&self) -> Self {
        Self {
            is_dirty: Arc::clone(&self.is_dirty),
            trace: Arc::clone(&self.trace),
        }
    }
}

impl<K> MakeRebuilder<K>
where
    K: Eq + Hash + Clone,
{
    pub fn new(is_dirty: Arc<dyn Fn(&K) -> bool + Send + Sync>) -> Self {
        Self {
            is_dirty,
            trace: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn update_trace(&self, trace: BuildTrace<K>) {
        let mut guard = self.trace.lock().expect("trace mutex poisoned");
        *guard = trace.into_map();
    }

    fn deps_dirty(
        key: &K,
        trace: &HashMap<K, Vec<K>>,
        is_dirty: &dyn Fn(&K) -> bool,
        visiting: &mut HashSet<K>,
    ) -> bool
    where
        K: Eq + Hash + Clone,
    {
        if visiting.contains(key) {
            return false;
        }
        visiting.insert(key.clone());

        let deps = match trace.get(key) {
            Some(d) => d,
            None => return true,
        };

        for dep in deps {
            if is_dirty(dep) {
                return true;
            }
            if Self::deps_dirty(dep, trace, is_dirty, visiting) {
                return true;
            }
        }

        false
    }
}

/// Receives build trace updates after a run.
pub trait TraceConsumer<K> {
    fn update_trace(&self, trace: BuildTrace<K>);
}

impl<K> TraceConsumer<K> for MakeRebuilder<K>
where
    K: Eq + Hash + Clone,
{
    fn update_trace(&self, trace: BuildTrace<K>) {
        self.update_trace(trace)
    }
}

impl<K, V> Rebuilder<K, V> for MakeRebuilder<K>
where
    K: Eq + Hash + Clone,
{
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError> {
        if cached.is_none() || (self.is_dirty)(key) {
            let value = task.run(key, ctx)?;
            return Ok(Rebuild::built(value));
        }

        let trace_snapshot = {
            let guard = self.trace.lock().expect("trace mutex poisoned");
            guard.clone()
        };

        let mut visiting = HashSet::new();
        if Self::deps_dirty(key, &trace_snapshot, &*self.is_dirty, &mut visiting) {
            let value = task.run(key, ctx)?;
            return Ok(Rebuild::built(value));
        }

        Ok(Rebuild::cached(cached.expect("cached value required")))
    }
}

/// Shake-like rebuilder: trace-based dirty checking with dynamic deps.
pub struct ShakeRebuilder<K> {
    is_dirty: Arc<dyn Fn(&K) -> bool + Send + Sync>,
    trace: Arc<Mutex<HashMap<K, Vec<K>>>>,
}

impl<K> ShakeRebuilder<K>
where
    K: Eq + Hash + Clone,
{
    pub fn new(is_dirty: Arc<dyn Fn(&K) -> bool + Send + Sync>) -> Self {
        Self {
            is_dirty,
            trace: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn update_trace(&self, trace: BuildTrace<K>) {
        let mut guard = self.trace.lock().expect("trace mutex poisoned");
        *guard = trace.into_map();
    }

    fn deps_dirty(
        key: &K,
        trace: &HashMap<K, Vec<K>>,
        is_dirty: &dyn Fn(&K) -> bool,
        visiting: &mut HashSet<K>,
    ) -> bool
    where
        K: Eq + Hash + Clone,
    {
        if visiting.contains(key) {
            return false;
        }
        visiting.insert(key.clone());

        let deps = match trace.get(key) {
            Some(d) => d,
            None => return true,
        };

        for dep in deps {
            if is_dirty(dep) {
                return true;
            }
            if Self::deps_dirty(dep, trace, is_dirty, visiting) {
                return true;
            }
        }

        false
    }
}

impl<K> Clone for ShakeRebuilder<K> {
    fn clone(&self) -> Self {
        Self {
            is_dirty: Arc::clone(&self.is_dirty),
            trace: Arc::clone(&self.trace),
        }
    }
}

impl<K, V> Rebuilder<K, V> for ShakeRebuilder<K>
where
    K: Eq + Hash + Clone,
{
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError> {
        if cached.is_none() || (self.is_dirty)(key) {
            let value = task.run(key, ctx)?;
            return Ok(Rebuild::built(value));
        }

        let trace_snapshot = {
            let guard = self.trace.lock().expect("trace mutex poisoned");
            guard.clone()
        };

        let mut visiting = HashSet::new();
        if Self::deps_dirty(key, &trace_snapshot, &*self.is_dirty, &mut visiting) {
            let value = task.run(key, ctx)?;
            return Ok(Rebuild::built(value));
        }

        Ok(Rebuild::cached(cached.expect("cached value required")))
    }
}

impl<K> TraceConsumer<K> for ShakeRebuilder<K>
where
    K: Eq + Hash + Clone,
{
    fn update_trace(&self, trace: BuildTrace<K>) {
        self.update_trace(trace)
    }
}
