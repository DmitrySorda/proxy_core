use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use super::types::{
    ArithOp, CellDef, CellOp, CellValue, CmpOp, InputSource, LogicOp, OutputTarget, StrOp,
};
use super::CompiledGraph;
use regex::Regex;

/// Evaluation budget for compute graphs.
#[derive(Debug, Clone, Copy)]
pub struct EvalBudget {
    pub max_nodes: usize,
    pub max_eval_us: u64,
    pub max_memory_bytes: usize,
}

impl EvalBudget {
    pub fn unlimited() -> Self {
        Self {
            max_nodes: 0,
            max_eval_us: 0,
            max_memory_bytes: 0,
        }
    }
}

/// Runtime context for evaluation.
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub query: BTreeMap<String, Vec<String>>,
    pub path_params: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, CellValue>,
}

impl EvalContext {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            headers: BTreeMap::new(),
            query: BTreeMap::new(),
            path_params: BTreeMap::new(),
            metadata: BTreeMap::new(),
        }
    }
}

/// Output action produced by evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputAction {
    pub target: OutputTarget,
    pub value: CellValue,
}

/// Evaluation result for a compute graph.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub values: HashMap<String, CellValue>,
    pub outputs: Vec<OutputAction>,
    pub stats: EvalStats,
}

/// Fetcher for IO-enabled nodes.
pub trait Fetcher: Send + Sync {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CellValue, EvalError>> + Send + 'a>>;
}

/// Evaluation stats for metrics/tracing.
#[derive(Debug, Clone, Copy)]
pub struct EvalStats {
    pub nodes_evaluated: usize,
    pub eval_us: u64,
    pub memory_bytes: usize,
}

/// Runtime evaluation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    MissingInput(String),
    MissingValue(String),
    InvalidArgs(String),
    TaskFailed(String),
    TypeMismatch { op: String, expected: String, found: String },
    DivideByZero,
    BudgetExceeded(String),
    Unimplemented(String),
}

impl CompiledGraph {
    pub fn eval(
        &self,
        ctx: &EvalContext,
        budget: &EvalBudget,
    ) -> Result<EvalResult, EvalError> {
        let index = build_index(&self.cells);
        let mut values: Vec<Option<CellValue>> = vec![None; self.cells.len()];
        let mut outputs: Vec<OutputAction> = Vec::new();
        let mut nodes_evaluated: usize = 0;
        let mut memory_bytes: usize = 0;
        let start = Instant::now();

        for &node in &self.topo {
            if budget.max_nodes > 0 && nodes_evaluated >= budget.max_nodes {
                return Err(EvalError::BudgetExceeded("max_nodes".to_string()));
            }
            if budget.max_eval_us > 0 && start.elapsed().as_micros() as u64 > budget.max_eval_us {
                return Err(EvalError::BudgetExceeded("max_eval_us".to_string()));
            }

            let cell = &self.cells[node];
            let value = eval_cell(
                cell,
                ctx,
                &index,
                &values,
                &mut outputs,
                &self.regex_cache,
            )?;
            memory_bytes = memory_bytes.saturating_add(estimate_value_bytes(&value));
            if budget.max_memory_bytes > 0 && memory_bytes > budget.max_memory_bytes {
                return Err(EvalError::BudgetExceeded("max_memory_bytes".to_string()));
            }

            values[node] = Some(value);
            nodes_evaluated += 1;
        }

        let mut out_values = HashMap::new();
        for (i, cell) in self.cells.iter().enumerate() {
            let value = values[i]
                .as_ref()
                .ok_or_else(|| EvalError::MissingValue(cell.key.clone()))?;
            out_values.insert(cell.key.clone(), value.clone());
        }

        let stats = EvalStats {
            nodes_evaluated,
            eval_us: start.elapsed().as_micros() as u64,
            memory_bytes,
        };

        Ok(EvalResult {
            values: out_values,
            outputs,
            stats,
        })
    }

    pub async fn eval_with_fetcher(
        &self,
        ctx: &EvalContext,
        budget: &EvalBudget,
        fetcher: &dyn Fetcher,
    ) -> Result<EvalResult, EvalError> {
        let index = build_index(&self.cells);
        let mut values: Vec<Option<CellValue>> = vec![None; self.cells.len()];
        let mut outputs: Vec<OutputAction> = Vec::new();
        let mut nodes_evaluated: usize = 0;
        let mut memory_bytes: usize = 0;
        let start = Instant::now();

        for &node in &self.topo {
            if budget.max_nodes > 0 && nodes_evaluated >= budget.max_nodes {
                return Err(EvalError::BudgetExceeded("max_nodes".to_string()));
            }
            if budget.max_eval_us > 0 && start.elapsed().as_micros() as u64 > budget.max_eval_us {
                return Err(EvalError::BudgetExceeded("max_eval_us".to_string()));
            }

            let cell = &self.cells[node];
            let value = eval_cell_async(
                cell,
                ctx,
                &index,
                &values,
                &mut outputs,
                &self.regex_cache,
                fetcher,
            )
            .await?;
            memory_bytes = memory_bytes.saturating_add(estimate_value_bytes(&value));
            if budget.max_memory_bytes > 0 && memory_bytes > budget.max_memory_bytes {
                return Err(EvalError::BudgetExceeded("max_memory_bytes".to_string()));
            }

            values[node] = Some(value);
            nodes_evaluated += 1;
        }

        let mut out_values = HashMap::new();
        for (i, cell) in self.cells.iter().enumerate() {
            let value = values[i]
                .as_ref()
                .ok_or_else(|| EvalError::MissingValue(cell.key.clone()))?;
            out_values.insert(cell.key.clone(), value.clone());
        }

        let stats = EvalStats {
            nodes_evaluated,
            eval_us: start.elapsed().as_micros() as u64,
            memory_bytes,
        };

        Ok(EvalResult {
            values: out_values,
            outputs,
            stats,
        })
    }
}

fn build_index(cells: &[CellDef]) -> HashMap<String, usize> {
    let mut index = HashMap::new();
    for (i, cell) in cells.iter().enumerate() {
        index.insert(cell.key.clone(), i);
    }
    index
}

fn eval_cell(
    cell: &CellDef,
    ctx: &EvalContext,
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
    outputs: &mut Vec<OutputAction>,
    regex_cache: &std::sync::Arc<std::sync::Mutex<HashMap<String, Regex>>>,
) -> Result<CellValue, EvalError> {
    match &cell.op {
        CellOp::Input { source } => eval_input(source, ctx),
        CellOp::Const { value } => Ok(value.clone()),
        CellOp::Arith { op, args } => eval_arith(op, args, index, values),
        CellOp::Compare { op, left, right } => {
            eval_compare(op, left, right, index, values, regex_cache)
        }
        CellOp::Logic { op, args } => eval_logic(op, args, index, values),
        CellOp::Cond {
            cond,
            then_val,
            else_val,
        } => eval_cond(cond, then_val, else_val, index, values),
        CellOp::StringOp { op, args } => eval_string(op, args, index, values),
        CellOp::Coalesce { args } => eval_coalesce(args, index, values),
        CellOp::Fetch { .. } => Err(EvalError::Unimplemented("fetch".to_string())),
        CellOp::Output { target, source } => {
            let value = get_value(source, index, values)?.clone();
            outputs.push(OutputAction {
                target: target.clone(),
                value: value.clone(),
            });
            Ok(value)
        }
    }
}

async fn eval_cell_async(
    cell: &CellDef,
    ctx: &EvalContext,
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
    outputs: &mut Vec<OutputAction>,
    regex_cache: &std::sync::Arc<std::sync::Mutex<HashMap<String, Regex>>>,
    fetcher: &dyn Fetcher,
) -> Result<CellValue, EvalError> {
    match &cell.op {
        CellOp::Fetch { url, timeout_ms } => {
            let url_val = get_value(url, index, values)?;
            let url_str = as_string(url_val, "fetch.url")?;
            fetcher.fetch(&url_str, *timeout_ms).await
        }
        _ => eval_cell(cell, ctx, index, values, outputs, regex_cache),
    }
}

fn eval_input(source: &InputSource, ctx: &EvalContext) -> Result<CellValue, EvalError> {
    match source {
        InputSource::Header(name) => ctx
            .headers
            .get(name)
            .map(|v| CellValue::Str(v.clone()))
            .ok_or_else(|| EvalError::MissingInput(format!("header:{name}"))),
        InputSource::Query(name) => ctx
            .query
            .get(name)
            .map(|values| {
                if values.len() == 1 {
                    CellValue::Str(values[0].clone())
                } else {
                    CellValue::List(values.iter().cloned().map(CellValue::Str).collect())
                }
            })
            .ok_or_else(|| EvalError::MissingInput(format!("query:{name}"))),
        InputSource::PathParam(name) => ctx
            .path_params
            .get(name)
            .map(|v| CellValue::Str(v.clone()))
            .ok_or_else(|| EvalError::MissingInput(format!("path:{name}"))),
        InputSource::Method => Ok(CellValue::Str(ctx.method.clone())),
        InputSource::Metadata(key) => ctx
            .metadata
            .get(key)
            .cloned()
            .ok_or_else(|| EvalError::MissingInput(format!("metadata:{key}"))),
    }
}

fn eval_arith(
    op: &ArithOp,
    args: &[String],
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
) -> Result<CellValue, EvalError> {
    if args.is_empty() {
        return Err(EvalError::InvalidArgs("arith:empty".to_string()));
    }

    let mut nums: Vec<Number> = Vec::with_capacity(args.len());
    for arg in args {
        let value = get_value(arg, index, values)?;
        nums.push(Number::from_value(value, "arith")?);
    }

    match op {
        ArithOp::Add => Ok(Number::sum(&nums).to_cell_value()),
        ArithOp::Sub => Ok(Number::sub(&nums).to_cell_value()),
        ArithOp::Mul => Ok(Number::mul(&nums).to_cell_value()),
        ArithOp::Div => Number::div(&nums),
        ArithOp::Mod => Number::rem(&nums),
        ArithOp::Min => Ok(Number::min(&nums).to_cell_value()),
        ArithOp::Max => Ok(Number::max(&nums).to_cell_value()),
        ArithOp::Clamp => Number::clamp(&nums),
    }
}

fn eval_compare(
    op: &CmpOp,
    left: &str,
    right: &str,
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
    regex_cache: &std::sync::Arc<std::sync::Mutex<HashMap<String, Regex>>>,
) -> Result<CellValue, EvalError> {
    let left_val = get_value(left, index, values)?;
    let right_val = get_value(right, index, values)?;

    let result = match op {
        CmpOp::Eq => left_val == right_val,
        CmpOp::Ne => left_val != right_val,
        CmpOp::Gt => compare_ordered(left_val, right_val, "gt")? == std::cmp::Ordering::Greater,
        CmpOp::Lt => compare_ordered(left_val, right_val, "lt")? == std::cmp::Ordering::Less,
        CmpOp::Ge => {
            let ord = compare_ordered(left_val, right_val, "ge")?;
            ord == std::cmp::Ordering::Greater || ord == std::cmp::Ordering::Equal
        }
        CmpOp::Le => {
            let ord = compare_ordered(left_val, right_val, "le")?;
            ord == std::cmp::Ordering::Less || ord == std::cmp::Ordering::Equal
        }
        CmpOp::In => match right_val {
            CellValue::List(items) => items.iter().any(|v| v == left_val),
            _ => {
                return Err(EvalError::TypeMismatch {
                    op: "compare.in".to_string(),
                    expected: "list".to_string(),
                    found: value_type_name(right_val).to_string(),
                })
            }
        },
        CmpOp::Contains => match (left_val, right_val) {
            (CellValue::Str(haystack), CellValue::Str(needle)) => haystack.contains(needle),
            (CellValue::List(items), needle) => items.iter().any(|v| v == needle),
            _ => {
                return Err(EvalError::TypeMismatch {
                    op: "compare.contains".to_string(),
                    expected: "string or list".to_string(),
                    found: format!(
                        "{}", 
                        value_type_name(left_val)
                    ),
                })
            }
        },
        CmpOp::Matches => match (left_val, right_val) {
            (CellValue::Str(haystack), CellValue::Str(pattern)) => {
                let re = get_cached_regex(pattern, regex_cache)?;
                re.is_match(haystack)
            }
            _ => {
                return Err(EvalError::TypeMismatch {
                    op: "compare.matches".to_string(),
                    expected: "string".to_string(),
                    found: format!(
                        "{} vs {}",
                        value_type_name(left_val),
                        value_type_name(right_val)
                    ),
                })
            }
        },
    };

    Ok(CellValue::Bool(result))
}

fn get_cached_regex(
    pattern: &str,
    cache: &std::sync::Arc<std::sync::Mutex<HashMap<String, Regex>>>,
) -> Result<Regex, EvalError> {
    if let Some(re) = cache
        .lock()
        .expect("regex cache mutex poisoned")
        .get(pattern)
        .cloned()
    {
        return Ok(re);
    }

    let compiled = Regex::new(pattern)
        .map_err(|_| EvalError::InvalidArgs("compare.matches".to_string()))?;
    cache
        .lock()
        .expect("regex cache mutex poisoned")
        .insert(pattern.to_string(), compiled.clone());
    Ok(compiled)
}

fn compare_ordered(
    left: &CellValue,
    right: &CellValue,
    op: &str,
) -> Result<std::cmp::Ordering, EvalError> {
    match (left, right) {
        (CellValue::Int(a), CellValue::Int(b)) => Ok(a.cmp(b)),
        (CellValue::Float(a), CellValue::Float(b)) => a.partial_cmp(b).ok_or_else(|| {
            EvalError::TypeMismatch {
                op: format!("compare.{op}"),
                expected: "number".to_string(),
                found: "nan".to_string(),
            }
        }),
        (CellValue::Int(a), CellValue::Float(b)) => (*a as f64)
            .partial_cmp(b)
            .ok_or_else(|| EvalError::TypeMismatch {
                op: format!("compare.{op}"),
                expected: "number".to_string(),
                found: "nan".to_string(),
            }),
        (CellValue::Float(a), CellValue::Int(b)) => a
            .partial_cmp(&(*b as f64))
            .ok_or_else(|| EvalError::TypeMismatch {
                op: format!("compare.{op}"),
                expected: "number".to_string(),
                found: "nan".to_string(),
            }),
        (CellValue::Str(a), CellValue::Str(b)) => Ok(a.cmp(b)),
        _ => Err(EvalError::TypeMismatch {
            op: format!("compare.{op}"),
            expected: "number or string".to_string(),
            found: format!(
                "{} vs {}",
                value_type_name(left),
                value_type_name(right)
            ),
        }),
    }
}

fn eval_logic(
    op: &LogicOp,
    args: &[String],
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
) -> Result<CellValue, EvalError> {
    match op {
        LogicOp::Not => {
            if args.len() != 1 {
                return Err(EvalError::InvalidArgs("logic.not".to_string()));
            }
            let val = get_value(&args[0], index, values)?;
            let b = as_bool(val, "logic.not")?;
            Ok(CellValue::Bool(!b))
        }
        LogicOp::And | LogicOp::Or => {
            if args.is_empty() {
                return Err(EvalError::InvalidArgs("logic.empty".to_string()));
            }
            let mut acc = if matches!(op, LogicOp::And) { true } else { false };
            for arg in args {
                let val = get_value(arg, index, values)?;
                let b = as_bool(val, "logic")?;
                if matches!(op, LogicOp::And) {
                    acc &= b;
                } else {
                    acc |= b;
                }
            }
            Ok(CellValue::Bool(acc))
        }
    }
}

fn eval_cond(
    cond: &str,
    then_val: &str,
    else_val: &str,
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
) -> Result<CellValue, EvalError> {
    let cond_val = get_value(cond, index, values)?;
    let cond_bool = as_bool(cond_val, "cond")?;
    if cond_bool {
        Ok(get_value(then_val, index, values)?.clone())
    } else {
        Ok(get_value(else_val, index, values)?.clone())
    }
}

fn eval_string(
    op: &StrOp,
    args: &[String],
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
) -> Result<CellValue, EvalError> {
    match op {
        StrOp::Upper => {
            let s = expect_string_arg("string.upper", args, index, values)?;
            Ok(CellValue::Str(s.to_uppercase()))
        }
        StrOp::Lower => {
            let s = expect_string_arg("string.lower", args, index, values)?;
            Ok(CellValue::Str(s.to_lowercase()))
        }
        StrOp::Trim => {
            let s = expect_string_arg("string.trim", args, index, values)?;
            Ok(CellValue::Str(s.trim().to_string()))
        }
        StrOp::Replace => {
            if args.len() != 3 {
                return Err(EvalError::InvalidArgs("string.replace".to_string()));
            }
            let input = expect_string(&args[0], index, values, "string.replace")?;
            let from = expect_string(&args[1], index, values, "string.replace")?;
            let to = expect_string(&args[2], index, values, "string.replace")?;
            Ok(CellValue::Str(input.replace(&from, &to)))
        }
        StrOp::Split => {
            if args.len() != 2 {
                return Err(EvalError::InvalidArgs("string.split".to_string()));
            }
            let input = expect_string(&args[0], index, values, "string.split")?;
            let sep = expect_string(&args[1], index, values, "string.split")?;
            let parts = if sep.is_empty() {
                input.chars().map(|c| CellValue::Str(c.to_string())).collect()
            } else {
                input
                    .split(&sep)
                    .map(|p| CellValue::Str(p.to_string()))
                    .collect()
            };
            Ok(CellValue::List(parts))
        }
        StrOp::Join => {
            if args.len() != 2 {
                return Err(EvalError::InvalidArgs("string.join".to_string()));
            }
            let list_val = get_value(&args[0], index, values)?;
            let sep = expect_string(&args[1], index, values, "string.join")?;
            match list_val {
                CellValue::List(items) => {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        out.push(as_string(item, "string.join")?);
                    }
                    Ok(CellValue::Str(out.join(&sep)))
                }
                _ => Err(EvalError::TypeMismatch {
                    op: "string.join".to_string(),
                    expected: "list".to_string(),
                    found: value_type_name(list_val).to_string(),
                }),
            }
        }
        StrOp::Template => {
            if args.is_empty() {
                return Err(EvalError::InvalidArgs("string.template".to_string()));
            }
            let template = expect_string(&args[0], index, values, "string.template")?;
            let mut out = template;
            for (i, arg) in args.iter().skip(1).enumerate() {
                let val = get_value(arg, index, values)?;
                let rep = as_string(val, "string.template")?;
                out = out.replace(&format!("{{{i}}}"), &rep);
            }
            Ok(CellValue::Str(out))
        }
    }
}

fn eval_coalesce(
    args: &[String],
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
) -> Result<CellValue, EvalError> {
    if args.is_empty() {
        return Err(EvalError::InvalidArgs("coalesce.empty".to_string()));
    }
    for arg in args {
        let val = get_value(arg, index, values)?;
        if !matches!(val, CellValue::Null) {
            return Ok(val.clone());
        }
    }
    Ok(CellValue::Null)
}

fn get_value<'a>(
    key: &str,
    index: &HashMap<String, usize>,
    values: &'a [Option<CellValue>],
) -> Result<&'a CellValue, EvalError> {
    let idx = index
        .get(key)
        .ok_or_else(|| EvalError::MissingValue(key.to_string()))?;
    values[*idx]
        .as_ref()
        .ok_or_else(|| EvalError::MissingValue(key.to_string()))
}

fn as_bool(value: &CellValue, op: &str) -> Result<bool, EvalError> {
    match value {
        CellValue::Bool(b) => Ok(*b),
        _ => Err(EvalError::TypeMismatch {
            op: op.to_string(),
            expected: "bool".to_string(),
            found: value_type_name(value).to_string(),
        }),
    }
}

fn as_string(value: &CellValue, op: &str) -> Result<String, EvalError> {
    match value {
        CellValue::Str(s) => Ok(s.clone()),
        CellValue::Int(i) => Ok(i.to_string()),
        CellValue::Float(f) => Ok(f.to_string()),
        CellValue::Bool(b) => Ok(b.to_string()),
        CellValue::Null => Ok("".to_string()),
        _ => Err(EvalError::TypeMismatch {
            op: op.to_string(),
            expected: "string".to_string(),
            found: value_type_name(value).to_string(),
        }),
    }
}

fn expect_string(
    key: &str,
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
    op: &str,
) -> Result<String, EvalError> {
    let value = get_value(key, index, values)?;
    match value {
        CellValue::Str(s) => Ok(s.clone()),
        _ => Err(EvalError::TypeMismatch {
            op: op.to_string(),
            expected: "string".to_string(),
            found: value_type_name(value).to_string(),
        }),
    }
}

fn expect_string_arg(
    op: &str,
    args: &[String],
    index: &HashMap<String, usize>,
    values: &[Option<CellValue>],
) -> Result<String, EvalError> {
    if args.len() != 1 {
        return Err(EvalError::InvalidArgs(op.to_string()));
    }
    expect_string(&args[0], index, values, op)
}

fn value_type_name(value: &CellValue) -> &'static str {
    match value {
        CellValue::Null => "null",
        CellValue::Bool(_) => "bool",
        CellValue::Int(_) => "int",
        CellValue::Float(_) => "float",
        CellValue::Str(_) => "string",
        CellValue::List(_) => "list",
        CellValue::Map(_) => "map",
    }
}

fn estimate_value_bytes(value: &CellValue) -> usize {
    match value {
        CellValue::Null => 0,
        CellValue::Bool(_) => 1,
        CellValue::Int(_) => 8,
        CellValue::Float(_) => 8,
        CellValue::Str(s) => s.len(),
        CellValue::List(items) => items.iter().map(estimate_value_bytes).sum(),
        CellValue::Map(map) => map
            .iter()
            .map(|(k, v)| k.len() + estimate_value_bytes(v))
            .sum(),
    }
}

#[derive(Debug, Clone, Copy)]
struct Number {
    float: f64,
    is_float: bool,
}

impl Number {
    fn from_value(value: &CellValue, op: &str) -> Result<Self, EvalError> {
        match value {
            CellValue::Int(i) => Ok(Self {
                float: *i as f64,
                is_float: false,
            }),
            CellValue::Float(f) => Ok(Self {
                float: *f,
                is_float: true,
            }),
            _ => Err(EvalError::TypeMismatch {
                op: op.to_string(),
                expected: "number".to_string(),
                found: value_type_name(value).to_string(),
            }),
        }
    }

    fn to_cell_value(self) -> CellValue {
        if self.is_float {
            CellValue::Float(self.float)
        } else {
            CellValue::Int(self.float as i64)
        }
    }

    fn sum(nums: &[Self]) -> Self {
        let mut sum = 0.0;
        let mut is_float = false;
        for n in nums {
            sum += n.float;
            is_float |= n.is_float;
        }
        Self { float: sum, is_float }
    }

    fn sub(nums: &[Self]) -> Self {
        let mut iter = nums.iter();
        let first = iter.next().expect("sub args empty");
        let mut acc = first.float;
        let mut is_float = first.is_float;
        for n in iter {
            acc -= n.float;
            is_float |= n.is_float;
        }
        Self { float: acc, is_float }
    }

    fn mul(nums: &[Self]) -> Self {
        let mut acc = 1.0;
        let mut is_float = false;
        for n in nums {
            acc *= n.float;
            is_float |= n.is_float;
        }
        Self { float: acc, is_float }
    }

    fn div(nums: &[Self]) -> Result<CellValue, EvalError> {
        let mut iter = nums.iter();
        let first = iter.next().expect("div args empty");
        let mut acc = first.float;
        for n in iter {
            if n.float == 0.0 {
                return Err(EvalError::DivideByZero);
            }
            acc /= n.float;
        }
        Ok(CellValue::Float(acc))
    }

    fn rem(nums: &[Self]) -> Result<CellValue, EvalError> {
        if nums.len() != 2 {
            return Err(EvalError::InvalidArgs("arith.mod".to_string()));
        }
        let left = nums[0];
        let right = nums[1];
        if left.is_float || right.is_float {
            return Err(EvalError::TypeMismatch {
                op: "arith.mod".to_string(),
                expected: "int".to_string(),
                found: "float".to_string(),
            });
        }
        if right.float == 0.0 {
            return Err(EvalError::DivideByZero);
        }
        Ok(CellValue::Int((left.float as i64) % (right.float as i64)))
    }

    fn min(nums: &[Self]) -> Self {
        let mut iter = nums.iter();
        let first = iter.next().expect("min args empty");
        let mut acc = first.float;
        let mut is_float = first.is_float;
        for n in iter {
            if n.float < acc {
                acc = n.float;
            }
            is_float |= n.is_float;
        }
        Self { float: acc, is_float }
    }

    fn max(nums: &[Self]) -> Self {
        let mut iter = nums.iter();
        let first = iter.next().expect("max args empty");
        let mut acc = first.float;
        let mut is_float = first.is_float;
        for n in iter {
            if n.float > acc {
                acc = n.float;
            }
            is_float |= n.is_float;
        }
        Self { float: acc, is_float }
    }

    fn clamp(nums: &[Self]) -> Result<CellValue, EvalError> {
        if nums.len() != 3 {
            return Err(EvalError::InvalidArgs("arith.clamp".to_string()));
        }
        let value = nums[0];
        let min = nums[1];
        let max = nums[2];
        let mut out = value.float;
        if out < min.float {
            out = min.float;
        }
        if out > max.float {
            out = max.float;
        }
        let is_float = value.is_float || min.is_float || max.is_float;
        Ok(Number { float: out, is_float }.to_cell_value())
    }
}
