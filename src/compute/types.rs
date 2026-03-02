use std::collections::BTreeMap;

/// Value produced by a cell.
#[derive(Debug, Clone, PartialEq)]
pub enum CellValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<CellValue>),
    Map(BTreeMap<String, CellValue>),
}

/// Input source for a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    Header(String),
    Query(String),
    PathParam(String),
    Method,
    Metadata(String),
}

/// Arithmetic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Min,
    Max,
    Clamp,
}

/// Comparison operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    In,
    Contains,
    Matches,
}

/// Boolean logic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicOp {
    And,
    Or,
    Not,
}

/// String operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrOp {
    Upper,
    Lower,
    Trim,
    Replace,
    Split,
    Join,
    Template,
}

/// Output target for a cell result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputTarget {
    Header(String),
    Metadata(String),
    Verdict,
}

/// Cell operation.
#[derive(Debug, Clone, PartialEq)]
pub enum CellOp {
    Input { source: InputSource },
    Const { value: CellValue },
    Arith { op: ArithOp, args: Vec<String> },
    Compare { op: CmpOp, left: String, right: String },
    Logic { op: LogicOp, args: Vec<String> },
    Cond {
        cond: String,
        then_val: String,
        else_val: String,
    },
    StringOp { op: StrOp, args: Vec<String> },
    Coalesce { args: Vec<String> },
    Fetch { url: String, timeout_ms: u64 },
    Output { target: OutputTarget, source: String },
}

/// Cell definition from config.
#[derive(Debug, Clone, PartialEq)]
pub struct CellDef {
    pub key: String,
    pub deps: Vec<String>,
    pub op: CellOp,
}
