# RFC-0001: Compute Filter — декларативный dataflow-движок внутри proxy_core

**Статус:** Draft  
**Автор:** —  
**Дата:** 2026-02-28

---

## 0. Мотивация

proxy_core — это L7 proxy-kernel с 13 фильтрами, hot reload и инкрементальной
пересборкой цепочки (builder.rs). Фильтры покрывают: auth, IAM, audit, rate
limiting, encryption, routing.

Предложение: добавить **compute-фильтр** — декларативный движок, который
выполняет бизнес-логику, описанную в RON-конфиге, на каждый HTTP-запрос.
Аналогия — «Excel в proxy»: ячейки = вычисляемые значения, формулы = RON-правила,
пересчёт = dataflow-граф.

Прежде чем реализовывать — 4 стратегических вопроса, на каждый нужен
обоснованный ответ.

---

## 1. Proxy-фильтр — правильное ли место для вычислительного движка?

### Проблема

`Filter::on_request` выполняется в **hot path** каждого запроса. Текущие фильтры
(rate_limit, rbac, audit) стоят O(1)–O(log n) и укладываются в микросекунды.
Произвольный DAG-граф из N узлов — это как минимум O(N) с потенциально
неконтролируемой стоимостью каждого узла.

### Аргументы «за» (фильтр)

| # | Аргумент | Вес |
|---|----------|-----|
| 1 | Единая инфраструктура: hot reload, Effects DI, metrics, tracing — всё бесплатно | Высокий |
| 2 | metadata (TypeMap) — входы/выходы совместимы с остальными фильтрами | Высокий |
| 3 | Нет сетевого вызова между proxy и вычислителем | Средний |
| 4 | Для **простых** графов (<50 узлов, чистые функции) overhead ≈ 1–10 µs | Средний |

### Аргументы «против» (фильтр)

| # | Аргумент | Вес |
|---|----------|-----|
| 1 | Нет изоляции: тяжёлый граф блокирует весь pipeline | Критический |
| 2 | Нет отдельного масштабирования: CPU-heavy граф нельзя скейлить отдельно от proxy | Высокий |
| 3 | Panic/OOM в графе убивает worker | Высокий |
| 4 | Тестирование графа требует поднятия всего Filter стека | Средний |

### Решение

**Допустимо**, но только с жёсткими guardrails:

```
Max nodes per graph:    256
Max execution time:     5 ms (configurable)
Max memory per eval:    1 MB
No unbounded loops:     DAG only (cycles = config error)
No arbitrary IO:        fetch-nodes через Effects.http_client с timeout
```

Если граф нарушает лимиты → `Verdict::Respond(503)` + метрика `compute.budget_exceeded`.

---

## 2. «Build Systems à la Carte» — правильная ли модель для per-request вычислений?

### Проблема

Статья Mokhov et al. описывает **инкрементальную пересборку персистентных
артефактов** (файлы, build outputs). У нас два контекста:

| Контекст | Что пересобирается | Персистентность | à la Carte подходит? |
|---|---|---|---|
| Control plane (builder.rs) | FilterChain из RON-конфига | Да (cache между reload-ами) | **Да** — уже работает |
| Data plane (per-request compute) | Значения ячеек из HTTP-запроса | Нет (эфемерно) | **Нет напрямую** |

### Почему à la Carte не работает as-is для per-request

1. **Store** в статье — персистентный. Per-request store живёт ~1 ms и умирает.
   Verifying traces бессмысленны (нечего верифицировать — предыдущего билда нет).

2. **Scheduler** в статье выбирает *что* пересобирать. Per-request нужно считать
   *всё* (все output-ячейки), т.к. входы всегда новые.

3. **Rebuilder** сравнивает с прошлым результатом. Нет прошлого результата.

### Где à la Carte всё-таки применима в compute-фильтре

Не для per-request данных, а для **конструирования самого движка**:

```
RON config  ──→  à la Carte build  ──→  CompiledGraph (persisted artifact)
                  (builder.rs pattern)
                  
HTTP request ──→  CompiledGraph.eval(inputs) ──→  outputs
                  (simple DAG execution, NOT à la Carte)
```

Это **двухуровневая** модель:

- **Уровень 1 (build-time, à la Carte):** RON-конфиг → CompiledGraph.
  Инкрементально: если граф не изменился, не пересобираем.
  `needs_rebuild()` → hash конфига (уже есть паттерн в builder.rs).

- **Уровень 2 (eval-time, dataflow):** CompiledGraph + request inputs → outputs.
  Чистый topological sort. Без инкрементальности (входы всегда свежие).
  Оптимизация: статический порядок вычислений, кешировать topological order.

### Решение

Используем à la Carte для **компиляции графа**, обычный DAG eval для **исполнения**.
Не натягиваем одну модель на оба уровня.

---

## 3. Конфиг-граф — не изобретаем ли мы плохой язык программирования?

### Десятое правило Гринспена

> «Any sufficiently complicated C or Fortran program contains an ad hoc,
> informally-specified, bug-ridden, slow implementation of half of Common Lisp.»

RON-конфиг с условиями, зависимостями, fetch-нодами → это **язык
программирования**, потенциально плохой: нет типов, нет отладчика, нет stack
traces, нет IDE-подсветки (хотя RON лучше JSON благодаря нативной поддержке
Rust-типов, trailing commas и комментариев).

### Альтернативы

| Подход | Плюсы | Минусы | Пример |
|---|---|---|---|
| **JSON DAG** (наша идея) | Простой, безопасный | Нет типов, нет IDE, Greenspun risk | — |
| **CEL** (Common Expression Language) | Стандарт Google, типизированный, быстрый | Не graф, а выражения | Google IAP, Envoy |
| **Rego/OPA** | Policy-as-code, формально верифицируем | Заточен под policy, не data transform | Envoy ext_authz |
| **WASM** | Полноценный sandbox, любой язык | Сложность, холодный старт, debugging | proxy-wasm, Envoy |
| **Lua** | Проверен (OpenResty), быстрый | Нет sandbox, GC pauses | Nginx/OpenResty |
| **Starlark** | Детерминированный subset Python, hermetic | Нужен Rust binding | Buck2, Bazel |

### Решение: ограниченный DSL, не general-purpose язык

Чтобы избежать десятого правила Гринспена, RON-конфиг должен быть
**намеренно ограничен**:

#### Что IN SCOPE (v1):

```
- Lookup:       extract field from request/metadata
- Transform:    string ops (upper, lower, trim, replace, split, join)
- Arithmetic:   +, -, *, /, %, min, max, clamp
- Logic:        and, or, not, if/then/else
- Comparison:   eq, ne, gt, lt, in, contains, matches (regex)
- Coalesce:     first non-null
- Const:        static value
- Template:     string interpolation ("Hello, {name}")
```

#### Что OUT OF SCOPE (v1):

```
- Loops / recursion         → DAG structure prevents this by design
- Arbitrary fetch / IO      → v2 (fetch-node with strict timeout)
- Mutation of external state → never (pure functions only)
- User-defined functions     → v2 (named subgraphs)
- String eval / code exec   → never
```

#### Тьюринг-полнота

DAG без циклов + фиксированный набор операций = **не Тьюринг-полный**.
Это **фича**, не баг. Гарантирует: всегда завершается, предсказуемое время,
нет зависаний.

---

## 4. Есть ли готовые решения, покрывающие 80% потребности?

### Оценка покрытия

| Решение | Data transform | Routing decision | Policy check | Hot reload | Наше покрытие |
|---|---|---|---|---|---|
| OPA/Rego | 30% | 70% | 95% | Да | RBAC filter уже есть |
| CEL | 60% | 80% | 80% | Да | Можно встроить вместо своих выражений |
| WASM plugins | 100% | 100% | 100% | Да | Overkill для конфигов |
| Lua/OpenResty | 100% | 100% | 80% | Да | Другая экосистема |

### Вывод

Ни одно готовое решение не даёт **именно** то, что нужно: типизированный
DAG-вычислитель, интегрированный с TypeMap-metadata proxy_core, с hot reload
через builder.rs. CEL ближе всего для выражений, но не для графов.

**Рекомендация:** делать свой движок, но заимствовать дизайн:

- От CEL: типизированные выражения, предсказуемая стоимость
- От à la Carte: двухуровневая модель (build graph + eval graph)
- От Excel: декларативность, зависимости, автоматический порядок вычислений

---

## 5. Архитектура (если делаем)

### 5.1 Двухуровневая модель

```
                    ┌─────────────────────────────────────┐
  Level 1           │         ComputeFactory              │
  (build-time)      │                                     │
                    │  RON config  ──→ validate ──→ topo  │
                    │                    sort ──→ compile  │
                    │                                     │
                    │  Output: CompiledGraph (Arc)        │
                    │  Cache: hash(config) → compiled     │
                    │  Pattern: à la Carte (builder.rs)   │
                    └──────────────┬──────────────────────┘
                                   │ Arc<CompiledGraph>
                    ┌──────────────▼──────────────────────┐
  Level 2           │         ComputeFilter               │
  (per-request)     │                                     │
                    │  Request + Metadata ──→ eval(graph) │
                    │                                     │
                    │  For each node in topo order:       │
                    │    resolve inputs → apply fn → store│
                    │                                     │
                    │  Output nodes → Verdict / headers / │
                    │                  metadata / body    │
                    └─────────────────────────────────────┘
```

### 5.2 Core types

```rust
/// Значение в графе вычислений.
#[derive(Debug, Clone, PartialEq)]
enum CellValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<CellValue>),
    Map(BTreeMap<String, CellValue>),
}

/// Узел графа (одна «ячейка» Excel).
struct CellDef {
    key: String,                  // уникальное имя ячейки
    deps: Vec<String>,            // имена ячеек-зависимостей
    op: CellOp,                   // операция
}

/// Операции (фиксированный набор, не Тьюринг-полный).
enum CellOp {
    /// Извлечь поле из request: header, path, query, method, metadata
    Input { source: InputSource },
    /// Константа
    Const { value: CellValue },
    /// Арифметика: add, sub, mul, div, mod, min, max, clamp
    Arith { op: ArithOp, args: Vec<String> },
    /// Сравнение: eq, ne, gt, lt, ge, le, in, contains, matches
    Compare { op: CmpOp, left: String, right: String },
    /// Логика: and, or, not
    Logic { op: LogicOp, args: Vec<String> },
    /// Условие: if cond then a else b
    Cond { cond: String, then_val: String, else_val: String },
    /// Строковые: upper, lower, trim, replace, split, join, template
    StringOp { op: StrOp, args: Vec<String> },
    /// Коалесцирование: первое не-null из списка
    Coalesce { args: Vec<String> },
    /// Запись результата: в header, metadata, body, или verdict
    Output { target: OutputTarget, source: String },
}

/// Скомпилированный граф: валидированный + topological order кешированный.
struct CompiledGraph {
    cells: Vec<CellDef>,             // в topological order
    output_indices: Vec<usize>,      // индексы Output-нод
    node_count: usize,
    estimated_cost: u64,             // статическая оценка стоимости
}
```

### 5.3 RON-конфиг (пример)

```ron
(
    name: "compute",
    typed_config: {
        "max_eval_us": 5000,
        "cells": [
            {
                "key": "user_role",
                "op": "input",
                "source": {"metadata": "AuthClaims.role"},
            },
            {
                "key": "is_admin",
                "op": "compare",
                "cmp": "eq",
                "left": "user_role",
                "right": {"const": "admin"},
            },
            {
                "key": "rate_tier",
                "op": "cond",
                "cond": "is_admin",
                "then": {"const": "unlimited"},
                "else": {"const": "standard"},
            },
            {
                "key": "out_header",
                "op": "output",
                "target": {"header": "X-Rate-Tier"},
                "source": "rate_tier",
            },
        ],
    },
)
```

### 5.4 Execution budget

```rust
struct EvalBudget {
    max_nodes: usize,       // 256 default
    max_eval_us: u64,       // 5000 µs default
    max_memory_bytes: usize,// 1 MB default
}

impl CompiledGraph {
    fn eval(
        &self,
        req: &Request,
        effects: &Effects,
        budget: &EvalBudget,
    ) -> Result<EvalOutput, EvalError> {
        // ...topological traversal with budget checks...
    }
}

enum EvalError {
    BudgetExceeded { node: String, resource: &'static str },
    TypeError { node: String, expected: &'static str, got: &'static str },
    MissingDep { node: String, dep: String },
}
```

### 5.5 Observability

Каждое вычисление выдаёт:

```
compute.eval_us         — histogram: время исполнения
compute.nodes_evaluated — counter: сколько узлов вычислено
compute.budget_exceeded — counter: сколько раз превышен лимит
compute.type_errors     — counter: ошибки типов в runtime
compute.cache_hit       — counter: CompiledGraph reuse (level 1)
```

Tracing span: `compute::eval{graph=..., nodes=..., us=...}`.

---

## 6. Фазы реализации

| Фаза | Содержание | Выход |
|---|---|---|
| **0** | Этот RFC. Ревью, уточнение scope. | Принятый RFC |
| **1** | `CellValue`, `CellDef`, `CellOp`, `CompiledGraph::compile()`, topological sort, cycle detection. Юнит-тесты на типы. | Ядро без Filter |
| **2** | `CompiledGraph::eval()` — исполнение с budget. Тесты: арифметика, логика, строки, условия. | Eval engine |
| **3** | `ComputeFilter` + `ComputeFactory`. Интеграция с Filter trait, Effects, TypeMap metadata. | Рабочий фильтр |
| **4** | RON-парсер конфига → CellDef с валидацией. Ошибки с указанием позиции. | Config layer |
| **5** | Observability: метрики, tracing spans, explain-mode (вывод DAG + значений). | Production readiness |
| **6** | (v2) Fetch-nodes через Effects.http_client. Subgraphs. Parametric graphs. | Extended |

---

## 7. Non-goals (явно)

- Заменить backend-сервисы с базами данных
- Тьюринг-полный язык в конфиге
- Произвольный код (eval, exec, WASM в v1)
- Транзакции, саги, оркестрация
- Прямой доступ к файловой системе или сети (кроме fetch-node в v2)

---

## 8. Критерии успеха v1

1. Граф из ≤50 узлов eval < 100 µs на M1
2. Cycle detection при компиляции (не в runtime)
3. Budget enforcement: 100% превышений → 503 + метрика
4. Zero unsafe code
5. ≥30 юнит-тестов на eval engine
6. Hot reload графа через существующий hot_reload()
7. RON-конфиг проходит serde validation с человекочитаемыми ошибками
