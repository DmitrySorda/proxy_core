# RFC-0001: Build Framework — à la Carte как Rust-фреймворк build-систем

**Статус:** Draft v4 (переработан: build framework внутри proxy_core)  
**Автор:** —  
**Дата:** 2026-03-01

---

## 0. Мотивация

Проект snowleopard/build (Haskell) реализует идеи статьи
“Build Systems à la Carte”: единая модель задач, разные scheduler/rebuilder,
сравнимость build-систем и воспроизводимые примеры.

Мы хотим **идеоматический Rust-вариант** этой идеи внутри proxy_core:

- единая задача `Task<K, V>`
- взаимозаменяемые планировщики (scheduler) и стратегии перестройки (rebuilder)
- исполняемые примеры и conformance-тесты
- API в стиле Rust, без механического копирования Haskell-кода

Цель — получить **framework для экспериментирования и сравнения build-систем**,
а не один конкретный build tool.

---

## 1. Цели и не-цели

### Цели

1. Сохранить модель: Task → Key → Value + Fetch
2. Разделить scheduler / rebuilder / store
3. Сравнимость: одинаковые задачи выполняются разными системами
4. Библиотека должна быть минимальной, ясной и пригодной для тестирования

### Не-цели

- Реализовать полноценный build tool
- Выдать production-grade Make/Shake
- Встроить DSL конфигов или внешние файлы

---

## 2. Дизайн API (Rust-идиоматичный)

### 2.1 Базовые типы

```rust
pub trait Task<K, V>: Send + Sync {
    fn run(&self, key: &K, ctx: &mut TaskContext<K, V>) -> Result<V, BuildError>;
}

pub trait Fetch<K, V> {
    fn fetch(&mut self, key: &K) -> Result<V, BuildError>;
}

pub trait Trace<K> {
    fn record(&mut self, key: &K);
}

pub struct TaskContext<'a, K, V> {
    fetcher: &'a mut dyn Fetch<K, V>,
    tracer: Option<&'a mut dyn Trace<K>>,
}

impl<'a, K, V> TaskContext<'a, K, V> {
    pub fn fetch(&mut self, key: &K) -> Result<V, BuildError> {
        self.fetcher.fetch(key)
    }
}

pub struct Rebuild<V> {
    value: V,
    should_store: bool,
}

pub trait Rebuilder<K, V> {
    fn rebuild(
        &self,
        key: &K,
        task: &dyn Task<K, V>,
        ctx: &mut TaskContext<K, V>,
        cached: Option<V>,
    ) -> Result<Rebuild<V>, BuildError>;
}

pub trait TraceConsumer<K> {
    fn update_trace(&self, trace: BuildTrace<K>);
}
```

### 2.2 Store

```rust
pub trait Store<K, V> {
    fn get(&self, key: &K) -> Option<V>;
    fn set(&mut self, key: K, value: V);
    fn clear(&mut self);
}
```

### 2.3 Scheduler

```rust
pub trait Scheduler<K, V>
where
    K: Eq + std::hash::Hash + Clone,
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
    ) -> Result<(V, BuildStats), BuildError>;

    fn run_with_trace(
        &self,
        rebuilder: &dyn Rebuilder<K, V>,
        task: &dyn Task<K, V>,
        store: &mut dyn Store<K, V>,
        target: K,
    ) -> Result<(V, BuildStats, BuildTrace<K>), BuildError>;
}
```

### 2.4 BuildSystem

```rust
pub struct BuildSystem<S, R, St> {
    scheduler: S,
    rebuilder: R,
    store: St,
}

impl<S, R, St> BuildSystem<S, R, St> {
    pub fn new(scheduler: S, rebuilder: R, store: St) -> Self {
        Self { scheduler, rebuilder, store }
    }

    pub fn run<K, V>(&mut self, task: &dyn Task<K, V>, target: K) -> Result<V, BuildError>
    where
        S: Scheduler,
        R: Rebuilder<K, V>,
        St: Store<K, V>,
        K: Eq + std::hash::Hash + Clone,
        V: Clone,
    {
        self.scheduler.run(&self.rebuilder, task, &mut self.store, target)
    }

    pub fn run_with_stats<K, V>(
        &mut self,
        task: &dyn Task<K, V>,
        target: K,
    ) -> Result<(V, BuildStats), BuildError>
    where
        S: Scheduler,
        R: Rebuilder<K, V>,
        St: Store<K, V>,
        K: Eq + std::hash::Hash + Clone,
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
        S: Scheduler,
        R: Rebuilder<K, V>,
        St: Store<K, V>,
        K: Eq + std::hash::Hash + Clone,
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
        R: TraceConsumer<K>,
    {
        let (value, stats, trace) = self.scheduler
            .run_with_trace(&self.rebuilder, task, &mut self.store, target)?;
        self.rebuilder.update_trace(trace);
        Ok((value, stats))
    }
}
```

### 2.5 Ошибки, статистика, трассировка

```rust
#[derive(Debug)]
pub enum BuildError {
    CycleDetected,
    TaskFailed(String),
}

#[derive(Debug, Default, Clone)]
pub struct BuildStats {
    pub nodes_built: usize,
    pub cache_hits: usize,
}

#[derive(Debug, Default, Clone)]
pub struct BuildTrace<K> {
    deps: std::collections::HashMap<K, Vec<K>>,
}
```

---

## 3. План реализации

### Phase 1: Core API

- `Task`, `Fetch`, `TaskContext`
- `Trace`, `Rebuilder`, `Rebuild`
- `Store` + `MemoryStore`
- `BuildError`, `BuildStats`, `BuildTrace`

### Phase 2: Basic Scheduler

- `BasicScheduler` (DFS + memoization)
- Cycle detection (stack set)
- `run_with_stats`, `run_with_trace`

### Phase 3: Системы из paper

- `Busy` (rebuild all) — реализован через `BusyRebuilder`
- `Dirty` (dirty-bit, без транзитивной проверки) — `DirtyRebuilder`
- `Make` (dirty-bit + deps)
- `Excel` (static deps)
- `Shake` (trace-based, dynamic deps)

`Make` опирается на `BuildTrace`: при clean key проверяет, что все deps clean.

`Excel` использует сохраненную `BuildTrace` как статический граф
и выполняет задачи в топологическом порядке.

`Shake` использует trace из предыдущего прогона и обновляет его на каждом build;
динамические deps определяются через `TaskContext::fetch()`.

### Phase 4: Conformance tests

- один набор задач
- запуск через разные системы
- сравнение outputs + rebuild count

Базовые конформанс‑кейсы:
- identical DAG: Busy > Memo по nodes_built
- Memo/Dirty/Make на повторном run дают cache_hits
- Excel дает те же outputs при static trace
- Dynamic deps: Shake перестраивает при смене deps (через flag)

Снэпшот сравнение rebuild counts фиксирует ожидаемые значения
для Busy/Memo/Dirty на повторных запусках.

Мини‑reporter в тестах формирует таблицу rebuild counts для стратегий.

---

## 4. Валидация с исходным repo

1. **Equivalence**: одинаковый DAG → одинаковый output
2. **Behavioral diffs**: rebuild count отличается между Busy/Make/Shake
3. **Dynamic deps**: Shake реагирует на смену зависимостей
4. **Trace reuse**: при неизменных deps выполняется минимальный rebuild

---

## 5. Интеграция в proxy_core

Фреймворк живёт внутри `src/build_system/` как отдельный модуль библиотеки.
Он не влияет на существующие фильтры или ChainBuilder.

Импортируется так:

```rust
use proxy_core::build_system::{
    BuildSystem, BasicScheduler, MemoRebuilder, MemoryStore, Task, MakeRebuilder,
};

let mut system = BuildSystem::new(BasicScheduler, MemoRebuilder, MemoryStore::new());
```

