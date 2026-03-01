use std::collections::HashMap;
use std::hash::Hash;

/// Store for build artifacts (key -> value).
pub trait Store<K, V> {
    fn get(&self, key: &K) -> Option<V>;
    fn set(&mut self, key: K, value: V);
    fn clear(&mut self);
}

/// In-memory store implementation.
#[derive(Debug, Default)]
pub struct MemoryStore<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> MemoryStore<K, V>
where
    K: Eq + Hash,
{
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
}

impl<K, V> Store<K, V> for MemoryStore<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn get(&self, key: &K) -> Option<V> {
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: K, value: V) {
        self.map.insert(key, value);
    }

    fn clear(&mut self) {
        self.map.clear();
    }
}
