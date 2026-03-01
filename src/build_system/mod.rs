//! Build systems a la carte: core abstractions and basic scheduler.

mod task;
mod store;
mod system;
mod rebuilder;

pub use task::{Fetch, Task, TaskContext, Trace};
pub use store::{MemoryStore, Store};
pub use system::{BasicScheduler, BuildError, BuildStats, BuildSystem, BuildTrace, ExcelScheduler};
pub use rebuilder::{
	BusyRebuilder, DirtyRebuilder, MakeRebuilder, MemoRebuilder, Rebuild, Rebuilder,
	ShakeRebuilder, TraceConsumer,
};
