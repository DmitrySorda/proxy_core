use crate::build_system::BuildError;

/// Task: compute a value for a key, using dependency fetches.
pub trait Task<K, V>: Send + Sync {
    fn run(&self, key: &K, ctx: &mut TaskContext<K, V>) -> Result<V, BuildError>;
}

/// Fetch dependency values during task execution.
pub trait Fetch<K, V> {
    fn fetch(&mut self, key: &K) -> Result<V, BuildError>;
}

/// Trace dependency keys requested during a task execution.
pub trait Trace<K> {
    fn record(&mut self, key: &K);
}

/// Task execution context (dependency fetch + future extensions).
pub struct TaskContext<'a, K, V> {
    fetcher: &'a mut dyn Fetch<K, V>,
    tracer: Option<&'a mut dyn Trace<K>>,
}

impl<'a, K, V> TaskContext<'a, K, V> {
    pub fn new(fetcher: &'a mut dyn Fetch<K, V>) -> Self {
        Self {
            fetcher,
            tracer: None,
        }
    }

    pub fn with_tracer(
        fetcher: &'a mut dyn Fetch<K, V>,
        tracer: &'a mut dyn Trace<K>,
    ) -> Self {
        Self {
            fetcher,
            tracer: Some(tracer),
        }
    }

    pub fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
        if let Some(tracer) = self.tracer.as_mut() {
            tracer.record(key);
        }
        self.fetcher.fetch(key)
    }
}
