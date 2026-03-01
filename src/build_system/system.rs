use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use crate::build_system::rebuilder::{Rebuilder, TraceConsumer};
use crate::build_system::store::Store;
use crate::build_system::task::{Fetch, Task, TaskContext, Trace};

/// Errors produced by the build framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    CycleDetected,
    TaskFailed(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::CycleDetected => write!(f, "cycle detected"),
            BuildError::TaskFailed(msg) => write!(f, "task failed: {msg}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Basic build stats (can be extended later).
#[derive(Debug, Default, Clone)]
pub struct BuildStats {
    pub nodes_built: usize,
    pub cache_hits: usize,
}

/// Dependency trace collected during a build.
#[derive(Debug, Clone)]
pub struct BuildTrace<K> {
    deps: HashMap<K, Vec<K>>,
}

impl<K> Default for BuildTrace<K> {
    fn default() -> Self {
        Self {
            deps: HashMap::new(),
        }
    }
}

impl<K> BuildTrace<K>
where
    K: Eq + Hash + Clone,
{
    pub fn record(&mut self, key: K, deps: Vec<K>) {
        self.deps.insert(key, deps);
    }

    pub fn into_map(self) -> HashMap<K, Vec<K>> {
        self.deps
    }

    pub fn deps_of(&self, key: &K) -> Option<&[K]> {
        self.deps.get(key).map(|v| v.as_slice())
    }
}

/// Scheduler strategy: defines evaluation order.
pub trait Scheduler<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn run(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<V, BuildError>;

    fn run_with_stats(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats), BuildError> {
        let value = self.run(rebuilder, task, store, target)?;
        Ok((value, BuildStats::default()))
    }

    fn run_with_trace(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats, BuildTrace<K>), BuildError> {
        let (value, stats) = self.run_with_stats(rebuilder, task, store, target)?;
        Ok((value, stats, BuildTrace::default()))
    }
}

/// Build system: scheduler + store.
pub struct BuildSystem<S, R, St> {
    scheduler: S,
    rebuilder: R,
    store: St,
}

impl<S, R, St> BuildSystem<S, R, St> {
    pub fn new(scheduler: S, rebuilder: R, store: St) -> Self {
        Self {
            scheduler,
            rebuilder,
            store,
        }
    }

    pub fn run<K, V>(&mut self, task: &dyn Task<K, V>, target: K) -> Result<V, BuildError>
    where
        S: Scheduler<K, V>,
        R: Rebuilder<K, V>,
        St: Store<K, V>,
        K: Eq + Hash + Clone,
        V: Clone,
    {
        self.scheduler
            .run(&self.rebuilder, task, &mut self.store, target)
    }

    pub fn run_with_stats<K, V>(
        &mut self,
        task: &dyn Task<K, V>,
        target: K,
    ) -> Result<(V, BuildStats), BuildError>
    where
        S: Scheduler<K, V>,
        R: Rebuilder<K, V>,
        St: Store<K, V>,
        K: Eq + Hash + Clone,
        V: Clone,
    {
        self.scheduler
            .run_with_stats(&self.rebuilder, task, &mut self.store, target)
    }

    pub fn run_with_trace<K, V>(
        &mut self,
        task: &dyn Task<K, V>,
        target: K,
    ) -> Result<(V, BuildStats, BuildTrace<K>), BuildError>
    where
        S: Scheduler<K, V>,
        R: Rebuilder<K, V>,
        St: Store<K, V>,
        K: Eq + Hash + Clone,
        V: Clone,
    {
        self.scheduler
            .run_with_trace(&self.rebuilder, task, &mut self.store, target)
    }

    pub fn run_and_update_trace<K, V>(
        &mut self,
        task: &dyn Task<K, V>,
        target: K,
    ) -> Result<(V, BuildStats), BuildError>
    where
        S: Scheduler<K, V>,
        R: Rebuilder<K, V> + TraceConsumer<K>,
        St: Store<K, V>,
        K: Eq + Hash + Clone,
        V: Clone,
    {
        let (value, stats, trace) = self
            .scheduler
            .run_with_trace(&self.rebuilder, task, &mut self.store, target)?;
        self.rebuilder.update_trace(trace);
        Ok((value, stats))
    }
}

/// Basic DFS scheduler with memoization and cycle detection.
pub struct BasicScheduler;

impl<K, V> Scheduler<K, V> for BasicScheduler
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn run(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<V, BuildError> {
        let mut visiting: HashSet<K> = HashSet::new();
        let mut stack: Vec<K> = Vec::new();

        fn eval<K, V>(
            key: K,
            rebuilder: &dyn Rebuilder<K, V>,
            task: &dyn Task<K, V>,
            store: &mut dyn Store<K, V>,
            visiting: &mut HashSet<K>,
            stack: &mut Vec<K>,
        ) -> Result<V, BuildError>
        where
            K: Eq + Hash + Clone,
            V: Clone,
        {
            let cached = store.get(&key);
            if visiting.contains(&key) {
                return Err(BuildError::CycleDetected);
            }

            visiting.insert(key.clone());
            stack.push(key.clone());

            struct ClosureFetch<'a, K, V> {
                f: &'a mut dyn FnMut(&K) -> Result<V, BuildError>,
            }

            impl<'a, K, V> Fetch<K, V> for ClosureFetch<'a, K, V> {
                fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
                    (self.f)(key)
                }
            }

            let mut fetcher = ClosureFetch {
                f: &mut |dep: &K| eval(dep.clone(), rebuilder, task, store, visiting, stack),
            };

            let mut ctx = TaskContext::new(&mut fetcher);
            let result = rebuilder.rebuild(&key, task, &mut ctx, cached)?;
            let should_store = result.should_store();
            let value = result.value();
            if should_store {
                store.set(key.clone(), value.clone());
            }

            stack.pop();
            visiting.remove(&key);

            Ok(value)
        }

        eval(
            target,
            rebuilder,
            task,
            store,
            &mut visiting,
            &mut stack,
        )
    }

    fn run_with_stats(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats), BuildError> {
        let mut stats = BuildStats::default();
        let mut visiting: HashSet<K> = HashSet::new();
        let mut stack: Vec<K> = Vec::new();

        fn eval<K, V>(
            key: K,
            rebuilder: &dyn Rebuilder<K, V>,
            task: &dyn Task<K, V>,
            store: &mut dyn Store<K, V>,
            visiting: &mut HashSet<K>,
            stack: &mut Vec<K>,
            stats: &mut BuildStats,
        ) -> Result<V, BuildError>
        where
            K: Eq + Hash + Clone,
            V: Clone,
        {
            let cached = store.get(&key);
            if visiting.contains(&key) {
                return Err(BuildError::CycleDetected);
            }

            visiting.insert(key.clone());
            stack.push(key.clone());

            struct ClosureFetch<'a, K, V> {
                f: &'a mut dyn FnMut(&K) -> Result<V, BuildError>,
            }

            impl<'a, K, V> Fetch<K, V> for ClosureFetch<'a, K, V> {
                fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
                    (self.f)(key)
                }
            }

            let mut fetcher = ClosureFetch {
                f: &mut |dep: &K| eval(dep.clone(), rebuilder, task, store, visiting, stack, stats),
            };

            let mut ctx = TaskContext::new(&mut fetcher);
            let result = rebuilder.rebuild(&key, task, &mut ctx, cached)?;
            let should_store = result.should_store();
            let value = result.value();
            if should_store {
                stats.nodes_built += 1;
                store.set(key.clone(), value.clone());
            } else {
                stats.cache_hits += 1;
            }

            stack.pop();
            visiting.remove(&key);

            Ok(value)
        }

        let value = eval(
            target,
            rebuilder,
            task,
            store,
            &mut visiting,
            &mut stack,
            &mut stats,
        )?;

        Ok((value, stats))
    }

    fn run_with_trace(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats, BuildTrace<K>), BuildError> {
        let mut stats = BuildStats::default();
        let mut trace = BuildTrace::default();
        let mut visiting: HashSet<K> = HashSet::new();
        let mut stack: Vec<K> = Vec::new();

        struct VecTrace<K> {
            deps: Vec<K>,
        }

        impl<K> VecTrace<K> {
            fn new() -> Self {
                Self { deps: Vec::new() }
            }
        }

        impl<K> Trace<K> for VecTrace<K>
        where
            K: Clone,
        {
            fn record(&mut self, key: &K) {
                self.deps.push(key.clone());
            }
        }

        fn eval<K, V>(
            key: K,
            rebuilder: &dyn Rebuilder<K, V>,
            task: &dyn Task<K, V>,
            store: &mut dyn Store<K, V>,
            visiting: &mut HashSet<K>,
            stack: &mut Vec<K>,
            stats: &mut BuildStats,
            trace: &mut BuildTrace<K>,
        ) -> Result<V, BuildError>
        where
            K: Eq + Hash + Clone,
            V: Clone,
        {
            let cached = store.get(&key);
            if visiting.contains(&key) {
                return Err(BuildError::CycleDetected);
            }

            visiting.insert(key.clone());
            stack.push(key.clone());

            struct ClosureFetch<'a, K, V> {
                f: &'a mut dyn FnMut(&K) -> Result<V, BuildError>,
            }

            impl<'a, K, V> Fetch<K, V> for ClosureFetch<'a, K, V> {
                fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
                    (self.f)(key)
                }
            }

            let mut fetcher = ClosureFetch {
                f: &mut |dep: &K| eval(dep.clone(), rebuilder, task, store, visiting, stack, stats, trace),
            };

            let mut local_trace = VecTrace::new();
            let mut ctx = TaskContext::with_tracer(&mut fetcher, &mut local_trace);
            let result = rebuilder.rebuild(&key, task, &mut ctx, cached)?;
            let should_store = result.should_store();
            let value = result.value();

            trace.record(key.clone(), local_trace.deps);

            if should_store {
                stats.nodes_built += 1;
                store.set(key.clone(), value.clone());
            } else {
                stats.cache_hits += 1;
            }

            stack.pop();
            visiting.remove(&key);

            Ok(value)
        }

        let value = eval(
            target,
            rebuilder,
            task,
            store,
            &mut visiting,
            &mut stack,
            &mut stats,
            &mut trace,
        )?;

        Ok((value, stats, trace))
    }
}

/// Excel-style scheduler: executes tasks in topological order of a static trace.
pub struct ExcelScheduler<K> {
    trace: Arc<Mutex<HashMap<K, Vec<K>>>>,
}

impl<K> ExcelScheduler<K>
where
    K: Eq + Hash + Clone,
{
    pub fn new() -> Self {
        Self {
            trace: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn update_trace(&self, trace: BuildTrace<K>) {
        let mut guard = self.trace.lock().expect("trace mutex poisoned");
        *guard = trace.into_map();
    }

    fn topo_order(
        target: &K,
        trace: &HashMap<K, Vec<K>>,
    ) -> Result<Vec<K>, BuildError>
    where
        K: Eq + Hash + Clone,
    {
        let mut temp: HashSet<K> = HashSet::new();
        let mut perm: HashSet<K> = HashSet::new();
        let mut order: Vec<K> = Vec::new();

        fn visit<K>(
            key: &K,
            trace: &HashMap<K, Vec<K>>,
            temp: &mut HashSet<K>,
            perm: &mut HashSet<K>,
            order: &mut Vec<K>,
        ) -> Result<(), BuildError>
        where
            K: Eq + Hash + Clone,
        {
            if perm.contains(key) {
                return Ok(());
            }
            if temp.contains(key) {
                return Err(BuildError::CycleDetected);
            }

            temp.insert(key.clone());

            if let Some(deps) = trace.get(key) {
                for dep in deps {
                    visit(dep, trace, temp, perm, order)?;
                }
            }

            temp.remove(key);
            perm.insert(key.clone());
            order.push(key.clone());
            Ok(())
        }

        visit(target, trace, &mut temp, &mut perm, &mut order)?;
        Ok(order)
    }
}

impl<K> Clone for ExcelScheduler<K> {
    fn clone(&self) -> Self {
        Self {
            trace: Arc::clone(&self.trace),
        }
    }
}

impl<K, V> Scheduler<K, V> for ExcelScheduler<K>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn run(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<V, BuildError> {
        let (value, _stats) = self.run_with_stats(rebuilder, task, store, target)?;
        Ok(value)
    }

    fn run_with_stats(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats), BuildError> {
        let trace_snapshot = {
            let guard = self.trace.lock().expect("trace mutex poisoned");
            guard.clone()
        };

        let order = Self::topo_order(&target, &trace_snapshot)?;
        let mut stats = BuildStats::default();

        for key in order {
            let cached = store.get(&key);

            struct StoreFetch<'a, K, V> {
                store: &'a dyn Store<K, V>,
            }

            impl<'a, K, V> Fetch<K, V> for StoreFetch<'a, K, V>
            where
                K: Eq + Hash + Clone,
                V: Clone,
            {
                fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
                    self.store
                        .get(key)
                        .ok_or_else(|| BuildError::TaskFailed("missing dependency".to_string()))
                }
            }

            let store_ref: &dyn Store<K, V> = &*store;
            let mut fetcher = StoreFetch { store: store_ref };
            let mut ctx = TaskContext::new(&mut fetcher);
            let result = rebuilder.rebuild(&key, task, &mut ctx, cached)?;
            let should_store = result.should_store();
            let value = result.value();

            if should_store {
                stats.nodes_built += 1;
                store.set(key.clone(), value.clone());
            } else {
                stats.cache_hits += 1;
            }
        }

        let value = store
            .get(&target)
            .ok_or_else(|| BuildError::TaskFailed("target not built".to_string()))?;
        Ok((value, stats))
    }

    fn run_with_trace(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats, BuildTrace<K>), BuildError> {
        let trace_snapshot = {
            let guard = self.trace.lock().expect("trace mutex poisoned");
            guard.clone()
        };

        let order = Self::topo_order(&target, &trace_snapshot)?;
        let mut stats = BuildStats::default();
        let mut trace = BuildTrace::default();

        for key in order {
            let cached = store.get(&key);

            struct StoreFetch<'a, K, V> {
                store: &'a dyn Store<K, V>,
            }

            impl<'a, K, V> Fetch<K, V> for StoreFetch<'a, K, V>
            where
                K: Eq + Hash + Clone,
                V: Clone,
            {
                fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
                    self.store
                        .get(key)
                        .ok_or_else(|| BuildError::TaskFailed("missing dependency".to_string()))
                }
            }

            struct VecTrace<K> {
                deps: Vec<K>,
            }

            impl<K> VecTrace<K> {
                fn new() -> Self {
                    Self { deps: Vec::new() }
                }
            }

            impl<K> Trace<K> for VecTrace<K>
            where
                K: Clone,
            {
                fn record(&mut self, key: &K) {
                    self.deps.push(key.clone());
                }
            }

            let store_ref: &dyn Store<K, V> = &*store;
            let mut fetcher = StoreFetch { store: store_ref };
            let mut local_trace = VecTrace::new();
            let mut ctx = TaskContext::with_tracer(&mut fetcher, &mut local_trace);
            let result = rebuilder.rebuild(&key, task, &mut ctx, cached)?;
            let should_store = result.should_store();
            let value = result.value();

            trace.record(key.clone(), local_trace.deps);

            if should_store {
                stats.nodes_built += 1;
                store.set(key.clone(), value.clone());
            } else {
                stats.cache_hits += 1;
            }
        }

        let value = store
            .get(&target)
            .ok_or_else(|| BuildError::TaskFailed("target not built".to_string()))?;
        Ok((value, stats, trace))
    }
}
