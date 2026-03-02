use proxy_core::compute::{CellDef, CellOp, CompiledGraph, CompileError, InputSource};

#[test]
fn compile_rejects_duplicate_keys() {
    let cells = vec![
        CellDef {
            key: "a".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
        CellDef {
            key: "a".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
    ];

    let err = CompiledGraph::compile(cells).unwrap_err();
    assert!(matches!(err, CompileError::DuplicateKey(_)));
}

#[test]
fn compile_rejects_missing_dep() {
    let cells = vec![CellDef {
        key: "a".to_string(),
        deps: vec!["b".to_string()],
        op: CellOp::Input {
            source: InputSource::Method,
        },
    }];

    let err = CompiledGraph::compile(cells).unwrap_err();
    assert!(matches!(err, CompileError::MissingDep { .. }));
}

#[test]
fn compile_rejects_cycle() {
    let cells = vec![
        CellDef {
            key: "a".to_string(),
            deps: vec!["b".to_string()],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
        CellDef {
            key: "b".to_string(),
            deps: vec!["a".to_string()],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
    ];

    let err = CompiledGraph::compile(cells).unwrap_err();
    assert!(matches!(err, CompileError::CycleDetected(_)));
}

#[test]
fn compile_produces_topo() {
    let cells = vec![
        CellDef {
            key: "b".to_string(),
            deps: vec![],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
        CellDef {
            key: "a".to_string(),
            deps: vec!["b".to_string()],
            op: CellOp::Input {
                source: InputSource::Method,
            },
        },
    ];

    let compiled = CompiledGraph::compile(cells).unwrap();
    assert_eq!(compiled.topo.len(), 2);
    assert_eq!(compiled.cells[compiled.topo[0]].key, "b");
    assert_eq!(compiled.cells[compiled.topo[1]].key, "a");
}
