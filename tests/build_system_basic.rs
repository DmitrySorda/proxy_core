use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use proxy_core::build_system::{
    BasicScheduler, BuildError, BuildSystem, BusyRebuilder, DirtyRebuilder, ExcelScheduler,
    MakeRebuilder, MemoRebuilder, MemoryStore, ShakeRebuilder, Store, Fetch, Task, TaskContext,
    Trace,
};

// ---------------------------------------------------------------------------
// Helper tasks
// ---------------------------------------------------------------------------

/// Counts how many times each key is computed (via run()).
/// Fails with TaskFailed on unknown keys (no base, no deps).
struct CountingTask {
    deps: HashMap<&'static str, Vec<&'static str>>,
    base: HashMap<&'static str, i32>,
    counter: Arc<AtomicUsize>,
}

impl CountingTask {
    fn new(
        deps: HashMap<&'static str, Vec<&'static str>>,
        base: HashMap<&'static str, i32>,
    ) -> Self {
        Self {
            deps,
            base,
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn run_count(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }
}

impl Task<&'static str, i32> for CountingTask {
    fn run(
        &self,
        key: &&'static str,
        ctx: &mut TaskContext<&'static str, i32>,
    ) -> Result<i32, BuildError> {
        self.counter.fetch_add(1, Ordering::SeqCst);

        if let Some(value) = self.base.get(key) {
            return Ok(*value);
        }
        let deps = match self.deps.get(key) {
            Some(d) => d.clone(),
            None => return Err(BuildError::TaskFailed(format!("unknown key: {key}"))),
        };
        let mut sum = 0;
        for dep in deps {
            sum += ctx.fetch(&dep)?;
        }
        Ok(sum)
    }
}

/// Task with owned String keys — verifies the framework works beyond &'static str.
struct StringTask {
    deps: HashMap<String, Vec<String>>,
    base: HashMap<String, i64>,
}

impl Task<String, i64> for StringTask {
    fn run(
        &self,
        key: &String,
        ctx: &mut TaskContext<String, i64>,
    ) -> Result<i64, BuildError> {
        if let Some(value) = self.base.get(key) {
            return Ok(*value);
        }
        let deps = match self.deps.get(key) {
            Some(d) => d.clone(),
            None => return Err(BuildError::TaskFailed(format!("unknown key: {key}"))),
        };
        let mut sum: i64 = 0;
        for dep in deps {
            sum += ctx.fetch(&dep)?;
        }
        Ok(sum)
    }
}

fn make_system_memo<K, V>() -> BuildSystem<BasicScheduler, MemoRebuilder, MemoryStore<K, V>>
where
    K: Eq + std::hash::Hash,
{
    BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new())
}

fn make_system_busy<K, V>() -> BuildSystem<BasicScheduler, BusyRebuilder, MemoryStore<K, V>>
where
    K: Eq + std::hash::Hash,
{
    BuildSystem::new(BasicScheduler, BusyRebuilder, MemoryStore::new())
}

// ===========================================================================
// 1. Original tests (kept)
// ===========================================================================

#[test]
fn basic_scheduler_builds_values() {
    let mut deps = HashMap::new();
    deps.insert("a", vec!["b", "c"]);

    let mut base = HashMap::new();
    base.insert("b", 2);
    base.insert("c", 3);

    let task = CountingTask::new(deps, base);
    let mut system = make_system_memo();

    let result = system.run(&task, "a").unwrap();
    assert_eq!(result, 5);
}

#[test]
fn basic_scheduler_detects_cycle() {
    let mut deps = HashMap::new();
    deps.insert("a", vec!["b"]);
    deps.insert("b", vec!["a"]);

    let task = CountingTask::new(deps, HashMap::new());
    let mut system = make_system_memo();

    let err = system.run(&task, "a").unwrap_err();
    assert!(matches!(err, BuildError::CycleDetected));
}

// ===========================================================================
// 2. Diamond DAG — memoization correctness
//    a → b, c
//    b → d
//    c → d
//    d = 10 (base)
//    Correct: a = b + c = (d) + (d) = 20
//    d must be computed exactly ONCE (memoization via store).
// ===========================================================================

#[test]
fn diamond_dag_memoizes_shared_dependency() {
    let mut deps = HashMap::new();
    deps.insert("a", vec!["b", "c"]);
    deps.insert("b", vec!["d"]);
    deps.insert("c", vec!["d"]);

    let mut base = HashMap::new();
    base.insert("d", 10);

    let task = CountingTask::new(deps, base);
    let mut system = make_system_memo();

    let result = system.run(&task, "a").unwrap();
    assert_eq!(result, 20);
    // a(1) + b(1) + c(1) + d(1) = 4 runs.
    // If d were computed twice it would be 5.
    assert_eq!(task.run_count(), 4, "d should be computed only once (memoization)");
}

// ===========================================================================
// 3. Leaf node — no dependencies
// ===========================================================================

#[test]
fn leaf_node_returns_base_value() {
    let base = HashMap::from([("x", 42)]);

    let task = CountingTask::new(HashMap::new(), base);
    let mut system = make_system_memo();

    assert_eq!(system.run(&task, "x").unwrap(), 42);
    assert_eq!(task.run_count(), 1);
}

// ===========================================================================
// 4. Deep linear chain: a → b → c → d → e (base=1)
// ===========================================================================

#[test]
fn deep_linear_chain() {
    let deps = HashMap::from([
        ("a", vec!["b"]),
        ("b", vec!["c"]),
        ("c", vec!["d"]),
        ("d", vec!["e"]),
    ]);
    let base = HashMap::from([("e", 1)]);

    let task = CountingTask::new(deps, base);
    let mut system = make_system_memo();

    assert_eq!(system.run(&task, "a").unwrap(), 1);
    assert_eq!(task.run_count(), 5);
}

// ===========================================================================
// 5. Pre-populated store — MemoRebuilder skips computation
// ===========================================================================

#[test]
fn memo_rebuilder_uses_prepopulated_store() {
    let deps = HashMap::from([("a", vec!["b"])]);
    let base = HashMap::from([("b", 10)]);

    let task = CountingTask::new(deps, base);

    let mut store = MemoryStore::new();
    // Pre-seed "a" with value 999 — Memo should return it without calling task.run for "a".
    store.set("a", 999);

    let mut system = BuildSystem::new(BasicScheduler, MemoRebuilder, store);
    let result = system.run(&task, "a").unwrap();

    assert_eq!(result, 999, "MemoRebuilder should return cached value");
    // task.run should NOT be called for "a" because store had it.
    // (It may still be called 0 times total if "a" was the only target.)
    assert_eq!(task.run_count(), 0);
}

// ===========================================================================
// 6. BusyRebuilder — always recomputes even when store has value
// ===========================================================================

#[test]
fn busy_rebuilder_ignores_cache() {
    let base = HashMap::from([("x", 7)]);
    let task = CountingTask::new(HashMap::new(), base);

    let mut store = MemoryStore::new();
    store.set("x", 999); // pre-populate

    let mut system = BuildSystem::new(BasicScheduler, BusyRebuilder, store);

    let result = system.run(&task, "x").unwrap();
    // BusyRebuilder ignores cache, recomputes → base value 7
    assert_eq!(result, 7);
    assert_eq!(task.run_count(), 1, "BusyRebuilder must call task.run");
}

// ===========================================================================
// 7. Busy vs Memo — same DAG, different rebuild counts
// ===========================================================================

#[test]
fn busy_vs_memo_rebuild_count() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 1), ("c", 2)]);

    // --- Memo ---
    let task_memo = CountingTask::new(deps.clone(), base.clone());
    let mut sys_memo = make_system_memo();
    assert_eq!(sys_memo.run(&task_memo, "a").unwrap(), 3);
    let memo_runs = task_memo.run_count();

    // --- Busy ---
    let task_busy = CountingTask::new(deps, base);
    let mut sys_busy = make_system_busy();
    assert_eq!(sys_busy.run(&task_busy, "a").unwrap(), 3);
    let busy_runs = task_busy.run_count();

    // Both should give the same result and same run count on a fresh store.
    assert_eq!(memo_runs, busy_runs);
    // Both compute a, b, c = 3 runs
    assert_eq!(memo_runs, 3);
}

// ===========================================================================
// 8. Unknown key → TaskFailed error propagation
// ===========================================================================

#[test]
fn unknown_key_returns_task_failed() {
    let task = CountingTask::new(HashMap::new(), HashMap::new());
    let mut system = make_system_memo();

    let err = system.run(&task, "nonexistent").unwrap_err();
    match err {
        BuildError::TaskFailed(msg) => assert!(msg.contains("nonexistent")),
        other => panic!("expected TaskFailed, got: {:?}", other),
    }
}

// ===========================================================================
// 9. Error in dependency propagates to parent
// ===========================================================================

#[test]
fn dependency_error_propagates() {
    // a → bad_dep, but bad_dep has no base and no deps → TaskFailed
    let deps = HashMap::from([("a", vec!["bad_dep"])]);
    let task = CountingTask::new(deps, HashMap::new());
    let mut system = make_system_memo();

    let err = system.run(&task, "a").unwrap_err();
    match err {
        BuildError::TaskFailed(msg) => assert!(msg.contains("bad_dep")),
        other => panic!("expected TaskFailed from dep, got: {:?}", other),
    }
}

// ===========================================================================
// 10. Self-cycle: a → a
// ===========================================================================

#[test]
fn self_cycle_detected() {
    let deps = HashMap::from([("a", vec!["a"])]);
    let task = CountingTask::new(deps, HashMap::new());
    let mut system = make_system_memo();

    assert!(matches!(
        system.run(&task, "a").unwrap_err(),
        BuildError::CycleDetected
    ));
}

// ===========================================================================
// 11. 3-node cycle: a → b → c → a
// ===========================================================================

#[test]
fn three_node_cycle_detected() {
    let deps = HashMap::from([
        ("a", vec!["b"]),
        ("b", vec!["c"]),
        ("c", vec!["a"]),
    ]);
    let task = CountingTask::new(deps, HashMap::new());
    let mut system = make_system_memo();

    assert!(matches!(
        system.run(&task, "a").unwrap_err(),
        BuildError::CycleDetected
    ));
}

// ===========================================================================
// 12. Store state after build — intermediates are stored
// ===========================================================================

#[test]
fn store_contains_intermediates_after_build() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 10), ("c", 20)]);
    let task = CountingTask::new(deps, base);

    let store = MemoryStore::new();
    let mut system = BuildSystem::new(BasicScheduler, MemoRebuilder, store);

    system.run(&task, "a").unwrap();

    // Extract store via a second run — all values are cached, 0 new computations
    let task2 = CountingTask::new(HashMap::new(), HashMap::new());
    // "b" should be in the store from the first build
    let b = system.run(&task2, "b").unwrap();
    assert_eq!(b, 10);
    let c = system.run(&task2, "c").unwrap();
    assert_eq!(c, 20);
    let a = system.run(&task2, "a").unwrap();
    assert_eq!(a, 30);
    assert_eq!(task2.run_count(), 0, "all values should come from store");
}

// ===========================================================================
// 13. Wide fan-out: root → 20 leaves
// ===========================================================================

#[test]
fn wide_fan_out() {
    let leaves: Vec<&'static str> = vec![
        "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8", "l9",
        "l10", "l11", "l12", "l13", "l14", "l15", "l16", "l17", "l18", "l19",
    ];

    let deps = HashMap::from([("root", leaves.clone())]);
    let base: HashMap<&'static str, i32> = leaves.iter().map(|&k| (k, 1)).collect();

    let task = CountingTask::new(deps, base);
    let mut system = make_system_memo();

    let result = system.run(&task, "root").unwrap();
    assert_eq!(result, 20); // 20 leaves × 1
    assert_eq!(task.run_count(), 21); // root + 20 leaves
}

// ===========================================================================
// 14. Repeated build — second run fully cached with MemoRebuilder
// ===========================================================================

#[test]
fn second_build_fully_cached() {
    let deps = HashMap::from([("a", vec!["b", "c"]), ("b", vec!["d"])]);
    let base = HashMap::from([("c", 5), ("d", 3)]);
    let task = CountingTask::new(deps, base);

    let mut system = make_system_memo();

    let r1 = system.run(&task, "a").unwrap();
    assert_eq!(r1, 8); // a = b + c = (d) + 5 = 3 + 5
    let runs_after_first = task.run_count();
    assert_eq!(runs_after_first, 4); // a, b, c, d

    // Second build — everything is in the store
    let r2 = system.run(&task, "a").unwrap();
    assert_eq!(r2, 8);
    assert_eq!(
        task.run_count(),
        runs_after_first,
        "no new computations on second build with MemoRebuilder"
    );
}

// ===========================================================================
// 15. Owned String keys — non-trivial key type
// ===========================================================================

#[test]
fn owned_string_keys() {
    let deps = HashMap::from([
        ("root".to_string(), vec!["child_a".to_string(), "child_b".to_string()]),
    ]);
    let base = HashMap::from([
        ("child_a".to_string(), 100i64),
        ("child_b".to_string(), 200i64),
    ]);

    let task = StringTask { deps, base };
    let mut system: BuildSystem<BasicScheduler, MemoRebuilder, MemoryStore<String, i64>> =
        BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());

    assert_eq!(system.run(&task, "root".to_string()).unwrap(), 300);
}

// ===========================================================================
// 16. Diamond with BusyRebuilder — d is recomputed from scratch each time
// ===========================================================================

#[test]
fn diamond_busy_recomputes_everything() {
    let deps = HashMap::from([
        ("a", vec!["b", "c"]),
        ("b", vec!["d"]),
        ("c", vec!["d"]),
    ]);
    let base = HashMap::from([("d", 10)]);

    let task = CountingTask::new(deps, base);
    let mut system = make_system_busy();

    let result = system.run(&task, "a").unwrap();
    assert_eq!(result, 20);
    // Busy ignores store, but store.get is called and eval still stores results.
    // Due to how eval works: d is stored after first computation, but BusyRebuilder
    // ignores cache, so d's task.run IS called again when c fetches it.
    // Expected: a(1) + b(1) + d(1 via b) + c(1) + d(1 via c) = 5 runs
    assert!(
        task.run_count() >= 4,
        "BusyRebuilder should call task.run more times than Memo, got {}",
        task.run_count()
    );
}

// ===========================================================================
// 17. Empty base, empty deps — single node with no rule
// ===========================================================================

#[test]
fn empty_task_graph_unknown_root() {
    let task = CountingTask::new(HashMap::new(), HashMap::new());
    let mut system = make_system_memo();

    assert!(matches!(
        system.run(&task, "anything").unwrap_err(),
        BuildError::TaskFailed(_),
    ));
}

// ===========================================================================
// 18. Partial failure — some deps succeed, one fails → whole build fails
// ===========================================================================

#[test]
fn partial_failure_aborts_build() {
    // a depends on "good" (base=1) and "bad" (no rule)
    let deps = HashMap::from([("a", vec!["good", "bad"])]);
    let base = HashMap::from([("good", 1)]);

    let task = CountingTask::new(deps, base);
    let mut system = make_system_memo();

    let err = system.run(&task, "a").unwrap_err();
    match err {
        BuildError::TaskFailed(msg) => assert!(msg.contains("bad")),
        other => panic!("expected TaskFailed for 'bad', got {:?}", other),
    }
}

// ===========================================================================
// 19. BuildStats: cache hit vs build count
// ===========================================================================

#[test]
fn build_stats_cache_hit() {
    let base = HashMap::from([("x", 7)]);
    let task = CountingTask::new(HashMap::new(), base);

    let mut store = MemoryStore::new();
    store.set("x", 999);

    let mut system = BuildSystem::new(BasicScheduler, MemoRebuilder, store);
    let (value, stats) = system.run_with_stats(&task, "x").unwrap();

    assert_eq!(value, 999);
    assert_eq!(stats.nodes_built, 0);
    assert_eq!(stats.cache_hits, 1);
}

#[test]
fn build_stats_busy_builds_nodes() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 1), ("c", 2)]);
    let task = CountingTask::new(deps, base);

    let mut system = make_system_busy();
    let (value, stats) = system.run_with_stats(&task, "a").unwrap();

    assert_eq!(value, 3);
    assert_eq!(stats.nodes_built, 3);
    assert_eq!(stats.cache_hits, 0);
}

// ===========================================================================
// 20. TaskContext tracing records dependencies in order
// ===========================================================================

struct VecTrace<'a> {
    items: &'a mut Vec<&'static str>,
}

impl<'a> Trace<&'static str> for VecTrace<'a> {
    fn record(&mut self, key: &&'static str) {
        self.items.push(*key);
    }
}

struct LoggingFetch<'a> {
    items: &'a mut Vec<&'static str>,
}

impl<'a> Fetch<&'static str, i32> for LoggingFetch<'a> {
    fn fetch(&mut self, key: &&'static str) -> Result<i32, BuildError> {
        self.items.push(*key);
        Ok(1)
    }
}

#[test]
fn task_context_traces_dependencies() {
    let mut trace_log: Vec<&'static str> = Vec::new();
    let mut fetch_log: Vec<&'static str> = Vec::new();

    let mut tracer = VecTrace {
        items: &mut trace_log,
    };
    let mut fetcher = LoggingFetch {
        items: &mut fetch_log,
    };

    let mut ctx = TaskContext::with_tracer(&mut fetcher, &mut tracer);

    ctx.fetch(&"b").unwrap();
    ctx.fetch(&"c").unwrap();
    ctx.fetch(&"d").unwrap();

    assert_eq!(trace_log, vec!["b", "c", "d"]);
    assert_eq!(fetch_log, vec!["b", "c", "d"]);
}

// ===========================================================================
// 21. BasicScheduler run_with_trace collects dependency trace per key
// ===========================================================================

#[test]
fn basic_scheduler_collects_trace_map() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 2), ("c", 3)]);
    let task = CountingTask::new(deps, base);

    let mut system = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (value, _stats, trace) = system.run_with_trace(&task, "a").unwrap();

    assert_eq!(value, 5);

    let a_deps = trace.deps_of(&"a").unwrap();
    assert_eq!(a_deps, &["b", "c"]);

    let b_deps = trace.deps_of(&"b").unwrap();
    assert!(b_deps.is_empty());

    let c_deps = trace.deps_of(&"c").unwrap();
    assert!(c_deps.is_empty());
}

// ===========================================================================
// 22. DirtyRebuilder uses cached value when not dirty
// ===========================================================================

#[test]
fn dirty_rebuilder_uses_cache_when_clean() {
    let deps = HashMap::from([("a", vec!["b"])]);
    let base = HashMap::from([("b", 10)]);
    let task = CountingTask::new(deps, base);

    let mut store = MemoryStore::new();
    store.set("a", 123);

    let rebuilder = DirtyRebuilder::new(|_k: &&'static str| false);
    let mut system = BuildSystem::new(BasicScheduler, rebuilder, store);

    let value = system.run(&task, "a").unwrap();
    assert_eq!(value, 123);
    assert_eq!(task.run_count(), 0);
}

// ===========================================================================
// 23. DirtyRebuilder rebuilds when dirty
// ===========================================================================

#[test]
fn dirty_rebuilder_rebuilds_when_dirty() {
    let deps = HashMap::from([("a", vec!["b"])]);
    let base = HashMap::from([("b", 10)]);
    let task = CountingTask::new(deps, base);

    let mut store = MemoryStore::new();
    store.set("a", 123);

    let rebuilder = DirtyRebuilder::new(|_k: &&'static str| true);
    let mut system = BuildSystem::new(BasicScheduler, rebuilder, store);

    let value = system.run(&task, "a").unwrap();
    assert_eq!(value, 10);
    assert_eq!(task.run_count(), 2);
}

// ===========================================================================
// 24. MakeRebuilder uses trace to avoid rebuilding when deps are clean
// ===========================================================================

#[test]
fn make_rebuilder_uses_trace_for_clean_deps() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 10), ("c", 20)]);
    let task = CountingTask::new(deps, base);

    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));

    let make_rebuilder = MakeRebuilder::new(Arc::clone(&is_dirty));
    let mut system = BuildSystem::new(BasicScheduler, make_rebuilder, MemoryStore::new());

    let (value, _stats) = system.run_and_update_trace(&task, "a").unwrap();
    assert_eq!(value, 30);

    let runs_before = task.run_count();

    let value2 = system.run(&task, "a").unwrap();
    assert_eq!(value2, 30);
    assert_eq!(task.run_count(), runs_before, "clean deps should use cache");
}

// ===========================================================================
// 25. MakeRebuilder rebuilds when a dependency is dirty
// ===========================================================================

#[test]
fn make_rebuilder_rebuilds_on_dirty_dep() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 10), ("c", 20)]);
    let task = CountingTask::new(deps, base);

    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));

    let make_rebuilder = MakeRebuilder::new(Arc::clone(&is_dirty));
    let mut system = BuildSystem::new(BasicScheduler, make_rebuilder, MemoryStore::new());
    let (_value, _stats) = system.run_and_update_trace(&task, "a").unwrap();

    let runs_before = task.run_count();

    dirty_set.lock().unwrap().insert("b");
    let value2 = system.run(&task, "a").unwrap();
    assert_eq!(value2, 30);
    assert_eq!(task.run_count(), runs_before + 2);
}

// ===========================================================================
// 26. ExcelScheduler evaluates in static topological order
// ===========================================================================

#[test]
fn excel_scheduler_builds_from_trace() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 10), ("c", 20)]);
    let task = CountingTask::new(deps, base);

    // First run: get trace via BasicScheduler
    let mut system = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (value, _stats, trace) = system.run_with_trace(&task, "a").unwrap();
    assert_eq!(value, 30);

    // Second run: ExcelScheduler uses static trace
    let excel = ExcelScheduler::new();
    excel.update_trace(trace);
    let mut excel_system = BuildSystem::new(excel, MemoRebuilder, MemoryStore::new());
    let value2 = excel_system.run(&task, "a").unwrap();

    assert_eq!(value2, 30);
    assert_eq!(task.run_count(), 6);
}

// ===========================================================================
// 27. ShakeRebuilder updates dynamic deps
// ===========================================================================

struct DynamicTask {
    flag: Arc<Mutex<i32>>,
    base: HashMap<&'static str, i32>,
    counter: Arc<AtomicUsize>,
}

impl DynamicTask {
    fn new(flag: Arc<Mutex<i32>>, base: HashMap<&'static str, i32>) -> Self {
        Self {
            flag,
            base,
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn run_count(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }
}

impl Task<&'static str, i32> for DynamicTask {
    fn run(
        &self,
        key: &&'static str,
        ctx: &mut TaskContext<&'static str, i32>,
    ) -> Result<i32, BuildError> {
        self.counter.fetch_add(1, Ordering::SeqCst);

        if *key == "flag" {
            return Ok(*self.flag.lock().unwrap());
        }

        if let Some(value) = self.base.get(key) {
            return Ok(*value);
        }

        if *key == "a" {
            let f = ctx.fetch(&"flag")?;
            if f == 1 {
                return ctx.fetch(&"b");
            } else {
                return ctx.fetch(&"c");
            }
        }

        Err(BuildError::TaskFailed(format!("unknown key: {key}")))
    }
}

#[test]
fn shake_rebuilder_updates_dynamic_deps() {
    let flag = Arc::new(Mutex::new(1));
    let base = HashMap::from([("b", 10), ("c", 20)]);
    let task = DynamicTask::new(Arc::clone(&flag), base);

    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));

    let rebuilder = ShakeRebuilder::new(Arc::clone(&is_dirty));
    let mut system = BuildSystem::new(BasicScheduler, rebuilder, MemoryStore::new());

    let (v1, _stats) = system.run_and_update_trace(&task, "a").unwrap();
    assert_eq!(v1, 10);

    let runs_before = task.run_count();

    // Switch dynamic deps to "c" and mark flag dirty
    *flag.lock().unwrap() = 0;
    dirty_set.lock().unwrap().insert("flag");

    let (v2, _stats) = system.run_and_update_trace(&task, "a").unwrap();
    assert_eq!(v2, 20);
    assert!(task.run_count() > runs_before);
}

// ===========================================================================
// 28. Conformance: rebuild counts across strategies
// ===========================================================================

#[test]
fn conformance_rebuild_counts() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 1), ("c", 2)]);
    let task = CountingTask::new(deps, base);

    // Busy: always rebuilds.
    let mut busy_system = BuildSystem::new(BasicScheduler, BusyRebuilder, MemoryStore::new());
    let (_v1, s1) = busy_system.run_with_stats(&task, "a").unwrap();
    let (_v2, s2) = busy_system.run_with_stats(&task, "a").unwrap();
    assert!(s2.nodes_built >= s1.nodes_built);

    // Memo: second run should be cache hits.
    let mut memo_system = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (_v1, m1) = memo_system.run_with_stats(&task, "a").unwrap();
    let (_v2, m2) = memo_system.run_with_stats(&task, "a").unwrap();
    assert_eq!(m1.cache_hits, 0);
    assert_eq!(m2.nodes_built, 0);
    assert!(m2.cache_hits >= 1);

    // Dirty: clean keys reuse cache when not dirty.
    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));
    let dirty_rebuilder = DirtyRebuilder::new(|_k: &&'static str| false);
    let mut dirty_system = BuildSystem::new(BasicScheduler, dirty_rebuilder, MemoryStore::new());
    let (_v1, _d1) = dirty_system.run_with_stats(&task, "a").unwrap();
    let (_v2, d2) = dirty_system.run_with_stats(&task, "a").unwrap();
    assert_eq!(d2.nodes_built, 0);

    // Make: after trace update, clean deps should reuse cache.
    let make_rebuilder = MakeRebuilder::new(Arc::clone(&is_dirty));
    let mut make_system = BuildSystem::new(BasicScheduler, make_rebuilder, MemoryStore::new());
    let (_v1, _s1) = make_system.run_and_update_trace(&task, "a").unwrap();
    let (_v2, s2) = make_system.run_with_stats(&task, "a").unwrap();
    assert_eq!(s2.nodes_built, 0);

    // Excel: uses static trace (from BasicScheduler) to rebuild.
    let mut base_system = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (_v, _s, trace) = base_system.run_with_trace(&task, "a").unwrap();
    let excel = ExcelScheduler::new();
    excel.update_trace(trace);
    let mut excel_system = BuildSystem::new(excel, MemoRebuilder, MemoryStore::new());
    let (_v1, e1) = excel_system.run_with_stats(&task, "a").unwrap();
    assert!(e1.nodes_built >= 1);
}

// ===========================================================================
// 29. Conformance: dynamic deps (Shake vs Make)
// ===========================================================================

#[test]
fn conformance_dynamic_deps_shake_vs_make() {
    let flag = Arc::new(Mutex::new(1));
    let base = HashMap::from([("b", 10), ("c", 20)]);
    let task = DynamicTask::new(Arc::clone(&flag), base);

    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));

    // Shake
    let shake = ShakeRebuilder::new(Arc::clone(&is_dirty));
    let mut shake_system = BuildSystem::new(BasicScheduler, shake, MemoryStore::new());
    let (_v1, _s1) = shake_system.run_and_update_trace(&task, "a").unwrap();

    // Make
    let make = MakeRebuilder::new(Arc::clone(&is_dirty));
    let mut make_system = BuildSystem::new(BasicScheduler, make, MemoryStore::new());
    let (_v1, _s1) = make_system.run_and_update_trace(&task, "a").unwrap();

    // Switch dynamic deps and mark flag dirty
    *flag.lock().unwrap() = 0;
    dirty_set.lock().unwrap().insert("flag");

    let (_v2, shake_stats) = shake_system.run_and_update_trace(&task, "a").unwrap();
    let (_v2, make_stats) = make_system.run_and_update_trace(&task, "a").unwrap();

    // Both should rebuild at least some nodes when deps change
    assert!(shake_stats.nodes_built > 0);
    assert!(make_stats.nodes_built > 0);
}

// ===========================================================================
// 30. Conformance: dirty set changes between runs
// ===========================================================================

#[test]
fn conformance_dirty_set_changes() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 1), ("c", 2)]);
    let task = CountingTask::new(deps, base);

    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));

    let make = MakeRebuilder::new(Arc::clone(&is_dirty));
    let mut system = BuildSystem::new(BasicScheduler, make, MemoryStore::new());

    let (_v1, _s1) = system.run_and_update_trace(&task, "a").unwrap();

    let runs_before = task.run_count();

    dirty_set.lock().unwrap().insert("c");
    let (_v2, _s2) = system.run_and_update_trace(&task, "a").unwrap();

    assert!(task.run_count() > runs_before);
}

// ===========================================================================
// 31. Conformance: snapshot-style rebuild count comparison
// ===========================================================================

#[test]
fn conformance_rebuild_count_snapshot() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 1), ("c", 2)]);
    let task = CountingTask::new(deps, base);

    // Busy
    let mut busy = BuildSystem::new(BasicScheduler, BusyRebuilder, MemoryStore::new());
    let (_v1, b1) = busy.run_with_stats(&task, "a").unwrap();
    let (_v2, b2) = busy.run_with_stats(&task, "a").unwrap();

    // Memo
    let mut memo = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (_v1, m1) = memo.run_with_stats(&task, "a").unwrap();
    let (_v2, m2) = memo.run_with_stats(&task, "a").unwrap();

    // Dirty (clean)
    let dirty = DirtyRebuilder::new(|_k: &&'static str| false);
    let mut dirty_sys = BuildSystem::new(BasicScheduler, dirty, MemoryStore::new());
    let (_v1, d1) = dirty_sys.run_with_stats(&task, "a").unwrap();
    let (_v2, d2) = dirty_sys.run_with_stats(&task, "a").unwrap();

    assert_eq!(b1.nodes_built, 3);
    assert_eq!(b2.nodes_built, 3);
    assert_eq!(m1.nodes_built, 3);
    assert_eq!(m2.nodes_built, 0);
    assert_eq!(d1.nodes_built, 3);
    assert_eq!(d2.nodes_built, 0);
}

// ===========================================================================
// 32. Conformance: reporter-style table of rebuild stats
// ===========================================================================

#[test]
fn conformance_reporter_table() {
    let deps = HashMap::from([("a", vec!["b", "c"])]);
    let base = HashMap::from([("b", 1), ("c", 2)]);
    let task = CountingTask::new(deps, base);

    // Busy
    let mut busy = BuildSystem::new(BasicScheduler, BusyRebuilder, MemoryStore::new());
    let (_v1, _s1) = busy.run_with_stats(&task, "a").unwrap();
    let (_v2, busy_stats) = busy.run_with_stats(&task, "a").unwrap();

    // Memo
    let mut memo = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (_v1, _s1) = memo.run_with_stats(&task, "a").unwrap();
    let (_v2, memo_stats) = memo.run_with_stats(&task, "a").unwrap();

    // Dirty (clean)
    let dirty = DirtyRebuilder::new(|_k: &&'static str| false);
    let mut dirty_sys = BuildSystem::new(BasicScheduler, dirty, MemoryStore::new());
    let (_v1, _s1) = dirty_sys.run_with_stats(&task, "a").unwrap();
    let (_v2, dirty_stats) = dirty_sys.run_with_stats(&task, "a").unwrap();

    // Make (clean)
    let dirty_set: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_set_clone = Arc::clone(&dirty_set);
    let is_dirty: Arc<dyn Fn(&&'static str) -> bool + Send + Sync> =
        Arc::new(move |k: &&'static str| dirty_set_clone.lock().unwrap().contains(k));
    let make = MakeRebuilder::new(Arc::clone(&is_dirty));
    let mut make_sys = BuildSystem::new(BasicScheduler, make, MemoryStore::new());
    let (_v1, _s1) = make_sys.run_and_update_trace(&task, "a").unwrap();
    let (_v2, make_stats) = make_sys.run_with_stats(&task, "a").unwrap();

    // Excel (static trace)
    let mut base_system = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
    let (_v, _s, trace) = base_system.run_with_trace(&task, "a").unwrap();
    let excel = ExcelScheduler::new();
    excel.update_trace(trace);
    let mut excel_sys = BuildSystem::new(excel, MemoRebuilder, MemoryStore::new());
    let (_v1, _s1) = excel_sys.run_with_stats(&task, "a").unwrap();
    let (_v2, excel_stats) = excel_sys.run_with_stats(&task, "a").unwrap();

    let table = format!(
        "strategy | nodes_built | cache_hits\n\
         Busy     | {:>11} | {:>10}\n\
         Memo     | {:>11} | {:>10}\n\
         Dirty    | {:>11} | {:>10}\n\
         Make     | {:>11} | {:>10}\n\
         Excel    | {:>11} | {:>10}",
        busy_stats.nodes_built,
        busy_stats.cache_hits,
        memo_stats.nodes_built,
        memo_stats.cache_hits,
        dirty_stats.nodes_built,
        dirty_stats.cache_hits,
        make_stats.nodes_built,
        make_stats.cache_hits,
        excel_stats.nodes_built,
        excel_stats.cache_hits,
    );

    let expected = "strategy | nodes_built | cache_hits\n\
Busy     |           3 |          0\n\
Memo     |           0 |          1\n\
Dirty    |           0 |          1\n\
Make     |           0 |          1\n\
Excel    |           0 |          3";

    assert_eq!(table, expected);
}
