use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use regex::Regex;

use super::types::CellDef;

/// Compile-time errors for the compute graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    DuplicateKey(String),
    MissingDep { key: String, dep: String },
    CycleDetected(String),
}

/// Compiled graph with topological order.
#[derive(Debug, Clone)]
pub struct CompiledGraph {
    pub cells: Vec<CellDef>,
    pub output_indices: Vec<usize>,
    pub topo: Vec<usize>,
    pub(crate) regex_cache: Arc<Mutex<HashMap<String, Regex>>>,
    pub has_fetch: bool,
}

impl CompiledGraph {
    pub fn compile(cells: Vec<CellDef>) -> Result<Self, CompileError> {
        let mut index: HashMap<String, usize> = HashMap::new();
        for (i, cell) in cells.iter().enumerate() {
            if index.insert(cell.key.clone(), i).is_some() {
                return Err(CompileError::DuplicateKey(cell.key.clone()));
            }
        }

        for cell in &cells {
            for dep in &cell.deps {
                if !index.contains_key(dep) {
                    return Err(CompileError::MissingDep {
                        key: cell.key.clone(),
                        dep: dep.clone(),
                    });
                }
            }
        }

        let mut temp: HashSet<usize> = HashSet::new();
        let mut perm: HashSet<usize> = HashSet::new();
        let mut topo: Vec<usize> = Vec::with_capacity(cells.len());

        fn visit(
            node: usize,
            cells: &[CellDef],
            index: &HashMap<String, usize>,
            temp: &mut HashSet<usize>,
            perm: &mut HashSet<usize>,
            topo: &mut Vec<usize>,
        ) -> Result<(), CompileError> {
            if perm.contains(&node) {
                return Ok(());
            }
            if temp.contains(&node) {
                return Err(CompileError::CycleDetected(cells[node].key.clone()));
            }

            temp.insert(node);
            for dep in &cells[node].deps {
                let dep_idx = *index.get(dep).expect("dep index missing");
                visit(dep_idx, cells, index, temp, perm, topo)?;
            }
            temp.remove(&node);
            perm.insert(node);
            topo.push(node);
            Ok(())
        }

        for i in 0..cells.len() {
            visit(i, &cells, &index, &mut temp, &mut perm, &mut topo)?;
        }

        let output_indices: Vec<usize> = cells
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                if matches!(c.op, super::types::CellOp::Output { .. }) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        let has_fetch = cells
            .iter()
            .any(|c| matches!(c.op, super::types::CellOp::Fetch { .. }));

        Ok(Self {
            cells,
            output_indices,
            topo,
            regex_cache: Arc::new(Mutex::new(HashMap::new())),
            has_fetch,
        })
    }
}
