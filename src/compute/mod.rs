//! Runtime compute filter core types and compiler.

mod types;
mod compile;
mod eval;

pub use compile::{CompileError, CompiledGraph};
pub use eval::{EvalBudget, EvalContext, EvalError, EvalResult, EvalStats, Fetcher, OutputAction};
pub use types::{
    ArithOp, CellDef, CellOp, CellValue, CmpOp, InputSource, LogicOp, OutputTarget, StrOp,
};
