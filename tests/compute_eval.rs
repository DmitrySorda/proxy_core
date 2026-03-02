use std::collections::{BTreeMap, HashMap};

use proxy_core::compute::{
    ArithOp, CellDef, CellOp, CellValue, CmpOp, CompiledGraph, EvalBudget, EvalContext, EvalError,
    Fetcher, InputSource, LogicOp, OutputTarget, StrOp,
};

fn budget() -> EvalBudget {
    EvalBudget {
        max_nodes: 64,
        max_eval_us: 1_000_000,
        max_memory_bytes: 64 * 1024,
    }
}

#[test]
fn eval_produces_outputs_and_values() {
    let cells = vec![
        CellDef {
            key: "role".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Metadata("role".to_string()),
            },
        },
        CellDef {
            key: "admin".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("admin".to_string()),
            },
        },
        CellDef {
            key: "is_admin".to_string(),
            deps: vec!["role".to_string(), "admin".to_string()],
            op: CellOp::Compare {
                op: CmpOp::Eq,
                left: "role".to_string(),
                right: "admin".to_string(),
            },
        },
        CellDef {
            key: "tier_admin".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("unlimited".to_string()),
            },
        },
        CellDef {
            key: "tier_std".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("standard".to_string()),
            },
        },
        CellDef {
            key: "tier".to_string(),
            deps: vec![
                "is_admin".to_string(),
                "tier_admin".to_string(),
                "tier_std".to_string(),
            ],
            op: CellOp::Cond {
                cond: "is_admin".to_string(),
                then_val: "tier_admin".to_string(),
                else_val: "tier_std".to_string(),
            },
        },
        CellDef {
            key: "out".to_string(),
            deps: vec!["tier".to_string()],
            op: CellOp::Output {
                target: OutputTarget::Header("X-Rate-Tier".to_string()),
                source: "tier".to_string(),
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let mut ctx = EvalContext::new("GET");
    ctx.metadata
        .insert("role".to_string(), CellValue::Str("admin".to_string()));

    let result = graph.eval(&ctx, &budget()).unwrap();

    assert_eq!(
        result.outputs,
        vec![proxy_core::compute::OutputAction {
            target: OutputTarget::Header("X-Rate-Tier".to_string()),
            value: CellValue::Str("unlimited".to_string())
        }]
    );
    assert_eq!(
        result.values.get("tier"),
        Some(&CellValue::Str("unlimited".to_string()))
    );
    assert!(result.stats.nodes_evaluated > 0);
}

#[test]
fn eval_enforces_node_budget() {
    let cells = vec![
        CellDef {
            key: "a".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Int(1),
            },
        },
        CellDef {
            key: "b".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Int(2),
            },
        },
        CellDef {
            key: "c".to_string(),
            deps: vec!["a".to_string(), "b".to_string()],
            op: CellOp::Arith {
                op: ArithOp::Add,
                args: vec!["a".to_string(), "b".to_string()],
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let budget = EvalBudget {
        max_nodes: 2,
        max_eval_us: 1_000_000,
        max_memory_bytes: 1024,
    };

    let err = graph.eval(&ctx, &budget).unwrap_err();
    assert!(matches!(err, EvalError::BudgetExceeded(_)));
}

#[test]
fn eval_detects_type_mismatch() {
    let cells = vec![
        CellDef {
            key: "a".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("oops".to_string()),
            },
        },
        CellDef {
            key: "b".to_string(),
            deps: vec!["a".to_string()],
            op: CellOp::Arith {
                op: ArithOp::Add,
                args: vec!["a".to_string()],
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");

    let err = graph.eval(&ctx, &budget()).unwrap_err();
    assert!(matches!(err, EvalError::TypeMismatch { .. }));
}

#[test]
fn eval_string_ops_and_coalesce_work() {
    let cells = vec![
        CellDef {
            key: "raw".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("  hello world  ".to_string()),
            },
        },
        CellDef {
            key: "trimmed".to_string(),
            deps: vec!["raw".to_string()],
            op: CellOp::StringOp {
                op: StrOp::Trim,
                args: vec!["raw".to_string()],
            },
        },
        CellDef {
            key: "upper".to_string(),
            deps: vec!["trimmed".to_string()],
            op: CellOp::StringOp {
                op: StrOp::Upper,
                args: vec!["trimmed".to_string()],
            },
        },
        CellDef {
            key: "empty".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Null,
            },
        },
        CellDef {
            key: "coalesce".to_string(),
            deps: vec!["empty".to_string(), "upper".to_string()],
            op: CellOp::Coalesce {
                args: vec!["empty".to_string(), "upper".to_string()],
            },
        },
        CellDef {
            key: "out".to_string(),
            deps: vec!["coalesce".to_string()],
            op: CellOp::Output {
                target: OutputTarget::Metadata("msg".to_string()),
                source: "coalesce".to_string(),
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let result = graph.eval(&ctx, &budget()).unwrap();

    assert_eq!(
        result.outputs,
        vec![proxy_core::compute::OutputAction {
            target: OutputTarget::Metadata("msg".to_string()),
            value: CellValue::Str("HELLO WORLD".to_string())
        }]
    );
}

#[test]
fn eval_logic_and_compare_work() {
    let cells = vec![
        CellDef {
            key: "status".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Int(200),
            },
        },
        CellDef {
            key: "ok".to_string(),
            deps: vec!["status".to_string()],
            op: CellOp::Compare {
                op: CmpOp::Eq,
                left: "status".to_string(),
                right: "status".to_string(),
            },
        },
        CellDef {
            key: "method".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
        CellDef {
            key: "is_get".to_string(),
            deps: vec!["method".to_string()],
            op: CellOp::Compare {
                op: CmpOp::Eq,
                left: "method".to_string(),
                right: "method".to_string(),
            },
        },
        CellDef {
            key: "both".to_string(),
            deps: vec!["ok".to_string(), "is_get".to_string()],
            op: CellOp::Logic {
                op: LogicOp::And,
                args: vec!["ok".to_string(), "is_get".to_string()],
            },
        },
        CellDef {
            key: "out".to_string(),
            deps: vec!["both".to_string()],
            op: CellOp::Output {
                target: OutputTarget::Metadata("ok".to_string()),
                source: "both".to_string(),
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let result = graph.eval(&ctx, &budget()).unwrap();

    assert_eq!(
        result.outputs,
        vec![proxy_core::compute::OutputAction {
            target: OutputTarget::Metadata("ok".to_string()),
            value: CellValue::Bool(true)
        }]
    );
}

#[test]
fn eval_matches_regex() {
    let cells = vec![
        CellDef {
            key: "text".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("user-123".to_string()),
            },
        },
        CellDef {
            key: "pattern".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str(r"^user-\d+$".to_string()),
            },
        },
        CellDef {
            key: "ok".to_string(),
            deps: vec!["text".to_string(), "pattern".to_string()],
            op: CellOp::Compare {
                op: CmpOp::Matches,
                left: "text".to_string(),
                right: "pattern".to_string(),
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let result = graph.eval(&ctx, &budget()).unwrap();
    assert_eq!(result.values.get("ok"), Some(&CellValue::Bool(true)));
}

#[test]
fn eval_consumes_inputs_from_context() {
    let mut headers = BTreeMap::new();
    headers.insert("x-user".to_string(), "alice".to_string());

    let cells = vec![
        CellDef {
            key: "user".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Header("x-user".to_string()),
            },
        },
        CellDef {
            key: "out".to_string(),
            deps: vec!["user".to_string()],
            op: CellOp::Output {
                target: OutputTarget::Metadata("user".to_string()),
                source: "user".to_string(),
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let mut ctx = EvalContext::new("GET");
    ctx.headers = headers;

    let result = graph.eval(&ctx, &budget()).unwrap();
    assert_eq!(
        result.outputs,
        vec![proxy_core::compute::OutputAction {
            target: OutputTarget::Metadata("user".to_string()),
            value: CellValue::Str("alice".to_string())
        }]
    );
}

#[test]
fn eval_query_repeated_keys_return_list() {
    let cells = vec![
        CellDef {
            key: "q".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Query("q".to_string()),
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let mut ctx = EvalContext::new("GET");
    ctx.query
        .entry("q".to_string())
        .or_default()
        .extend(["a".to_string(), "b".to_string()]);

    let result = graph.eval(&ctx, &budget()).unwrap();
    assert_eq!(
        result.values.get("q"),
        Some(&CellValue::List(vec![
            CellValue::Str("a".to_string()),
            CellValue::Str("b".to_string())
        ]))
    );
}

struct TableFetcher {
    responses: HashMap<String, Result<Vec<u8>, String>>,
}

impl TableFetcher {
    fn new(responses: HashMap<String, Result<Vec<u8>, String>>) -> Self {
        Self { responses }
    }
}

impl Fetcher for TableFetcher {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        _timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CellValue, EvalError>> + Send + 'a>> {
        Box::pin(async move {
            if !url.starts_with("http") {
                return Err(EvalError::InvalidArgs("fetch.url".to_string()));
            }
            match self.responses.get(url) {
                Some(Ok(bytes)) => Ok(CellValue::Str(String::from_utf8_lossy(bytes).to_string())),
                Some(Err(err)) => Err(EvalError::TaskFailed(err.clone())),
                None => Err(EvalError::MissingInput(format!("fetch:{url}"))),
            }
        })
    }
}

#[tokio::test]
async fn eval_fetch_node_uses_fetcher() {
    let cells = vec![
        CellDef {
            key: "url".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("http://example".to_string()),
            },
        },
        CellDef {
            key: "resp".to_string(),
            deps: vec!["url".to_string()],
            op: CellOp::Fetch {
                url: "url".to_string(),
                timeout_ms: 50,
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let mut responses = HashMap::new();
    responses.insert("http://example".to_string(), Ok(b"hello".to_vec()));
    let fetcher = TableFetcher::new(responses);
    let result = graph
        .eval_with_fetcher(&ctx, &budget(), &fetcher)
        .await
        .unwrap();
    assert_eq!(
        result.values.get("resp"),
        Some(&CellValue::Str("hello".to_string()))
    );
}

#[tokio::test]
async fn eval_fetch_propagates_errors() {
    let cells = vec![
        CellDef {
            key: "url".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("http://example".to_string()),
            },
        },
        CellDef {
            key: "resp".to_string(),
            deps: vec!["url".to_string()],
            op: CellOp::Fetch {
                url: "url".to_string(),
                timeout_ms: 50,
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let mut responses = HashMap::new();
    responses.insert("http://example".to_string(), Err("boom".to_string()));
    let fetcher = TableFetcher::new(responses);
    let err = graph
        .eval_with_fetcher(&ctx, &budget(), &fetcher)
        .await
        .unwrap_err();
    assert!(matches!(err, EvalError::TaskFailed(msg) if msg == "boom"));
}

struct CountingFetcher {
    chunk_size: usize,
    max_total: usize,
    total: std::sync::atomic::AtomicUsize,
}

impl CountingFetcher {
    fn new(chunk_size: usize, max_total: usize) -> Self {
        Self {
            chunk_size,
            max_total,
            total: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl Fetcher for CountingFetcher {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        _timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CellValue, EvalError>> + Send + 'a>> {
        Box::pin(async move {
            if !url.starts_with("http") {
                return Err(EvalError::InvalidArgs("fetch.url".to_string()));
            }
            let next_total = self
                .total
                .fetch_add(self.chunk_size, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(self.chunk_size);
            if next_total > self.max_total {
                return Err(EvalError::BudgetExceeded("fetch_total_bytes".to_string()));
            }
            Ok(CellValue::Str("x".repeat(self.chunk_size).to_string()))
        })
    }
}

#[tokio::test]
async fn eval_fetch_enforces_total_limit_in_fetcher() {
    let cells = vec![
        CellDef {
            key: "url".to_string(),
            deps: vec![],
            op: CellOp::Const {
                value: CellValue::Str("http://example".to_string()),
            },
        },
        CellDef {
            key: "resp1".to_string(),
            deps: vec!["url".to_string()],
            op: CellOp::Fetch {
                url: "url".to_string(),
                timeout_ms: 50,
            },
        },
        CellDef {
            key: "resp2".to_string(),
            deps: vec!["url".to_string()],
            op: CellOp::Fetch {
                url: "url".to_string(),
                timeout_ms: 50,
            },
        },
    ];

    let graph = CompiledGraph::compile(cells).unwrap();
    let ctx = EvalContext::new("GET");
    let fetcher = CountingFetcher::new(8, 10);
    let err = graph
        .eval_with_fetcher(&ctx, &budget(), &fetcher)
        .await
        .unwrap_err();
    assert!(matches!(err, EvalError::BudgetExceeded(reason) if reason == "fetch_total_bytes"));
}
