//! Compute filter — evaluates a per-request DAG and applies outputs.

use crate::builder::FilterFactory;
use crate::compute::{
    ArithOp, CellDef, CellOp, CellValue, CmpOp, CompiledGraph, EvalBudget, EvalContext, EvalError,
    Fetcher, LogicOp, OutputAction, OutputTarget, StrOp,
};
use crate::filter::{Effects, Filter, Verdict};
use crate::filters::auth::{AuthClaims, AuthIdentity, AuthMethod};
use crate::filters::rate_limit::RateLimitRemaining;
use crate::routing::PathParams;
use crate::types::{Request, Response};
use http::StatusCode;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{atomic::AtomicUsize, atomic::Ordering, Arc};
use std::time::Duration;
use typemap_rev::TypeMapKey;

/// Metadata bucket used by the compute filter.
pub struct ComputeMetadata;

impl TypeMapKey for ComputeMetadata {
    type Value = BTreeMap<String, CellValue>;
}

/// Compute filter configuration.
#[derive(Debug, Deserialize)]
struct ComputeConfig {
    #[serde(default = "default_max_nodes")]
    max_nodes: usize,
    #[serde(default = "default_max_eval_us")]
    max_eval_us: u64,
    #[serde(default = "default_max_memory_bytes")]
    max_memory_bytes: usize,
    #[serde(default = "default_max_fetch_nodes")]
    max_fetch_nodes: usize,
    #[serde(default = "default_fetch_allow_schemes")]
    fetch_allow_schemes: Vec<String>,
    #[serde(default)]
    fetch_allow_hosts: Vec<String>,
    #[serde(default)]
    fetch_allow_host_suffixes: Vec<String>,
    #[serde(default)]
    fetch_allow_ports: Vec<u16>,
    #[serde(default)]
    fetch_allow_path_prefixes: Vec<String>,
    #[serde(default = "default_fetch_max_bytes")]
    fetch_max_bytes: usize,
    #[serde(default = "default_fetch_max_total_bytes")]
    fetch_max_total_bytes: usize,
    #[serde(default)]
    subgraphs: Vec<SubgraphConfig>,
    cells: Vec<CellConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct SubgraphConfig {
    name: String,
    cells: Vec<CellConfig>,
}

#[derive(Debug)]
enum ComputeConfigError {
    Serde(String),
    Compile(String),
    InvalidMethod { cell: String },
    InvalidVerdict { cell: String },
    InvalidConst { cell: String, reason: String },
    InvalidFetchLimit { field: String, value: usize },
    FetchNodesExceeded { max: usize, actual: usize },
    UnknownSubgraph { cell: String, subgraph: String },
    DuplicateSubgraph { name: String },
    NestedSubgraph { subgraph: String, cell: String },
}

impl std::fmt::Display for ComputeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serde(msg) => write!(f, "compute config error: {msg}"),
            Self::Compile(msg) => write!(f, "compute compile error: {msg}"),
            Self::InvalidMethod { cell } => {
                write!(f, "input.method must be true (cell: {cell})")
            }
            Self::InvalidVerdict { cell } => {
                write!(f, "output.verdict must be true (cell: {cell})")
            }
            Self::InvalidConst { cell, reason } => {
                write!(f, "invalid const (cell: {cell}): {reason}")
            }
            Self::InvalidFetchLimit { field, value } => {
                write!(f, "invalid fetch limit {field}={value}")
            }
            Self::FetchNodesExceeded { max, actual } => {
                write!(f, "fetch nodes exceeded: {actual} > {max}")
            }
            Self::UnknownSubgraph { cell, subgraph } => {
                write!(f, "unknown subgraph '{subgraph}' (cell: {cell})")
            }
            Self::DuplicateSubgraph { name } => {
                write!(f, "duplicate subgraph '{name}'")
            }
            Self::NestedSubgraph { subgraph, cell } => {
                write!(f, "call is not allowed inside subgraph '{subgraph}' (cell: {cell})")
            }
        }
    }
}

fn default_max_nodes() -> usize {
    256
}

fn default_max_eval_us() -> u64 {
    2_000
}

fn default_max_memory_bytes() -> usize {
    64 * 1024
}

fn default_max_fetch_nodes() -> usize {
    4
}

fn default_fetch_allow_schemes() -> Vec<String> {
    vec!["https".to_string(), "http".to_string()]
}

fn default_fetch_max_bytes() -> usize {
    64 * 1024
}

fn default_fetch_max_total_bytes() -> usize {
    128 * 1024
}

#[derive(Debug, Deserialize, Clone)]
struct CellConfig {
    key: String,
    #[serde(flatten)]
    op: CellOpConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
enum CellOpConfig {
    Input { source: InputSourceConfig },
    Const { value: serde_json::Value },
    Arith { arith: ArithOp, args: Vec<ArgValue> },
    Compare { cmp: CmpOp, left: ArgValue, right: ArgValue },
    Logic { logic: LogicOp, args: Vec<ArgValue> },
    Cond {
        cond: ArgValue,
        then_val: ArgValue,
        else_val: ArgValue,
    },
    StringOp { string: StrOp, args: Vec<ArgValue> },
    Coalesce { args: Vec<ArgValue> },
    Fetch { url: ArgValue, timeout_ms: Option<u64> },
    Call { subgraph: String, prefix: Option<String> },
    Output { target: OutputTargetConfig, source: ArgValue },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum InputSourceConfig {
    Header { header: String },
    Query { query: String },
    PathParam { path_param: String },
    Method { method: bool },
    Metadata { metadata: String },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum OutputTargetConfig {
    Header { header: String },
    Metadata { metadata: String },
    Verdict { verdict: bool },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum ArgValue {
    Ref(String),
    Const { r#const: serde_json::Value },
}

/// Compute filter implementation.
pub struct ComputeFilter {
    graph: CompiledGraph,
    budget: EvalBudget,
    fetch_policy: FetchPolicy,
}

impl ComputeFilter {
    fn new(graph: CompiledGraph, budget: EvalBudget, fetch_policy: FetchPolicy) -> Self {
        Self {
            graph,
            budget,
            fetch_policy,
        }
    }
}

impl Filter for ComputeFilter {
    fn name(&self) -> &'static str {
        "compute"
    }

    fn on_request<'a>(
        &'a self,
        req: &'a mut Request,
        fx: &'a Effects,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            let ctx = build_context(req);
            let eval_result = if self.graph.has_fetch {
                let fetcher = HttpFetcher {
                    fx,
                    policy: &self.fetch_policy,
                    total_bytes: AtomicUsize::new(0),
                };
                self.graph.eval_with_fetcher(&ctx, &self.budget, &fetcher).await
            } else {
                self.graph.eval(&ctx, &self.budget)
            };

            match eval_result {
                Ok(result) => {
                    let outputs_len = result.outputs.len();
                    if let Err(verdict) = apply_outputs(req, result.outputs, fx) {
                        return verdict;
                    }
                    fx.metrics.counter_inc("compute.eval_ok");
                    fx.metrics
                        .counter_add("compute.eval_us", result.stats.eval_us);
                    fx.metrics
                        .counter_add("compute.nodes_evaluated", result.stats.nodes_evaluated as u64);
                    fx.metrics
                        .counter_add("compute.memory_bytes", result.stats.memory_bytes as u64);
                    tracing::debug!(
                        eval_us = result.stats.eval_us,
                        nodes = result.stats.nodes_evaluated,
                        memory_bytes = result.stats.memory_bytes,
                        outputs = outputs_len,
                        "compute eval completed"
                    );
                    Verdict::Continue
                }
                Err(err) => {
                    handle_eval_error(err, fx)
                }
            }
        })
    }
}

/// Factory: `{ "max_eval_us": 2000, "cells": [...] }`.
pub struct ComputeFactory;

impl FilterFactory for ComputeFactory {
    fn name(&self) -> &str {
        "compute"
    }

    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Filter>, String> {
        let cfg: ComputeConfig = serde_json::from_value(config.clone())
            .map_err(|e| ComputeConfigError::Serde(e.to_string()))
            .map_err(|e| e.to_string())?;

        let (cells, budget) = build_cells(&cfg)
            .map_err(|e| e.to_string())?;
        let fetch_policy = build_fetch_policy(&cfg)
            .map_err(|e| e.to_string())?;
        let graph = CompiledGraph::compile(cells)
            .map_err(|e| ComputeConfigError::Compile(format!("{e:?}")))
            .map_err(|e| e.to_string())?;

        Ok(Arc::new(ComputeFilter::new(graph, budget, fetch_policy)))
    }
}

#[derive(Debug, Clone)]
struct FetchPolicy {
    allow_schemes: Vec<String>,
    allow_hosts: Vec<String>,
    allow_host_suffixes: Vec<String>,
    allow_ports: Vec<u16>,
    allow_path_prefixes: Vec<String>,
    max_bytes: usize,
    max_total_bytes: usize,
}

fn build_cells(cfg: &ComputeConfig) -> Result<(Vec<CellDef>, EvalBudget), ComputeConfigError> {
    let budget = EvalBudget {
        max_nodes: cfg.max_nodes,
        max_eval_us: cfg.max_eval_us,
        max_memory_bytes: cfg.max_memory_bytes,
    };

    let subgraphs = collect_subgraphs(cfg)?;

    let mut cells: Vec<CellDef> = Vec::new();
    let mut const_counter: u64 = 0;

    for cell in &cfg.cells {
        match &cell.op {
            CellOpConfig::Call { subgraph, prefix } => {
                let subgraph_cfg = subgraphs.get(subgraph).ok_or_else(|| {
                    ComputeConfigError::UnknownSubgraph {
                        cell: cell.key.clone(),
                        subgraph: subgraph.clone(),
                    }
                })?;
                let prefix = prefix.clone().unwrap_or_else(|| cell.key.clone());
                let expanded = expand_subgraph(subgraph_cfg, &prefix)?;
                for expanded_cell in expanded {
                    build_cell(&expanded_cell, &mut cells, &mut const_counter)?;
                }
            }
            _ => {
                build_cell(cell, &mut cells, &mut const_counter)?;
            }
        }
    }

    if cfg.max_fetch_nodes > 0 {
        let fetch_nodes = cells
            .iter()
            .filter(|cell| matches!(cell.op, CellOp::Fetch { .. }))
            .count();
        if fetch_nodes > cfg.max_fetch_nodes {
            return Err(ComputeConfigError::FetchNodesExceeded {
                max: cfg.max_fetch_nodes,
                actual: fetch_nodes,
            });
        }
    }

    Ok((cells, budget))
}

fn build_fetch_policy(cfg: &ComputeConfig) -> Result<FetchPolicy, ComputeConfigError> {
    if cfg.fetch_max_bytes == 0 {
        return Err(ComputeConfigError::InvalidFetchLimit {
            field: "fetch_max_bytes".to_string(),
            value: cfg.fetch_max_bytes,
        });
    }

    if cfg.fetch_max_total_bytes == 0 {
        return Err(ComputeConfigError::InvalidFetchLimit {
            field: "fetch_max_total_bytes".to_string(),
            value: cfg.fetch_max_total_bytes,
        });
    }

    if let Some(port) = cfg.fetch_allow_ports.iter().find(|port| **port == 0) {
        return Err(ComputeConfigError::InvalidFetchLimit {
            field: "fetch_allow_ports".to_string(),
            value: *port as usize,
        });
    }

    Ok(FetchPolicy {
        allow_schemes: normalize_allowlist(&cfg.fetch_allow_schemes),
        allow_hosts: normalize_allowlist(&cfg.fetch_allow_hosts),
        allow_host_suffixes: normalize_host_suffixes(&cfg.fetch_allow_host_suffixes),
        allow_ports: cfg.fetch_allow_ports.clone(),
        allow_path_prefixes: normalize_path_prefixes(&cfg.fetch_allow_path_prefixes),
        max_bytes: cfg.fetch_max_bytes,
        max_total_bytes: cfg.fetch_max_total_bytes,
    })
}

fn normalize_allowlist(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_path_prefixes(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| {
            if v.starts_with('/') {
                v.to_string()
            } else {
                format!("/{v}")
            }
        })
        .collect()
}

    fn normalize_host_suffixes(values: &[String]) -> Vec<String> {
        values
        .iter()
        .map(|v| v.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
    }

fn collect_subgraphs(
    cfg: &ComputeConfig,
) -> Result<HashMap<String, SubgraphConfig>, ComputeConfigError> {
    let mut out = HashMap::new();
    for subgraph in &cfg.subgraphs {
        if out
            .insert(subgraph.name.clone(), subgraph.clone())
            .is_some()
        {
            return Err(ComputeConfigError::DuplicateSubgraph {
                name: subgraph.name.clone(),
            });
        }
    }
    Ok(out)
}

fn expand_subgraph(
    subgraph: &SubgraphConfig,
    prefix: &str,
) -> Result<Vec<CellConfig>, ComputeConfigError> {
    let keys: HashSet<String> = subgraph.cells.iter().map(|c| c.key.clone()).collect();
    let mut out = Vec::with_capacity(subgraph.cells.len());
    for cell in &subgraph.cells {
        if let CellOpConfig::Call { .. } = &cell.op {
            return Err(ComputeConfigError::NestedSubgraph {
                subgraph: subgraph.name.clone(),
                cell: cell.key.clone(),
            });
        }
        let key = prefixed_key(prefix, &cell.key);
        let op = rewrite_op(&cell.op, prefix, &keys);
        out.push(CellConfig { key, op });
    }
    Ok(out)
}

fn prefixed_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

fn rewrite_op(op: &CellOpConfig, prefix: &str, keys: &HashSet<String>) -> CellOpConfig {
    match op {
        CellOpConfig::Input { source } => CellOpConfig::Input {
            source: source.clone(),
        },
        CellOpConfig::Const { value } => CellOpConfig::Const {
            value: value.clone(),
        },
        CellOpConfig::Arith { arith, args } => CellOpConfig::Arith {
            arith: *arith,
            args: rewrite_args(args, prefix, keys),
        },
        CellOpConfig::Compare { cmp, left, right } => CellOpConfig::Compare {
            cmp: *cmp,
            left: rewrite_arg(left, prefix, keys),
            right: rewrite_arg(right, prefix, keys),
        },
        CellOpConfig::Logic { logic, args } => CellOpConfig::Logic {
            logic: *logic,
            args: rewrite_args(args, prefix, keys),
        },
        CellOpConfig::Cond {
            cond,
            then_val,
            else_val,
        } => CellOpConfig::Cond {
            cond: rewrite_arg(cond, prefix, keys),
            then_val: rewrite_arg(then_val, prefix, keys),
            else_val: rewrite_arg(else_val, prefix, keys),
        },
        CellOpConfig::StringOp { string, args } => CellOpConfig::StringOp {
            string: *string,
            args: rewrite_args(args, prefix, keys),
        },
        CellOpConfig::Coalesce { args } => CellOpConfig::Coalesce {
            args: rewrite_args(args, prefix, keys),
        },
        CellOpConfig::Fetch { url, timeout_ms } => CellOpConfig::Fetch {
            url: rewrite_arg(url, prefix, keys),
            timeout_ms: *timeout_ms,
        },
        CellOpConfig::Call { subgraph, prefix } => CellOpConfig::Call {
            subgraph: subgraph.clone(),
            prefix: prefix.clone(),
        },
        CellOpConfig::Output { target, source } => CellOpConfig::Output {
            target: target.clone(),
            source: rewrite_arg(source, prefix, keys),
        },
    }
}

fn rewrite_args(args: &[ArgValue], prefix: &str, keys: &HashSet<String>) -> Vec<ArgValue> {
    args.iter()
        .map(|arg| rewrite_arg(arg, prefix, keys))
        .collect()
}

fn rewrite_arg(arg: &ArgValue, prefix: &str, keys: &HashSet<String>) -> ArgValue {
    match arg {
        ArgValue::Ref(key) => {
            if keys.contains(key) {
                ArgValue::Ref(prefixed_key(prefix, key))
            } else {
                ArgValue::Ref(key.clone())
            }
        }
        ArgValue::Const { r#const } => ArgValue::Const {
            r#const: r#const.clone(),
        },
    }
}

fn build_cell(
    cell: &CellConfig,
    cells: &mut Vec<CellDef>,
    const_counter: &mut u64,
) -> Result<(), ComputeConfigError> {
    let mut const_cells: Vec<CellDef> = Vec::new();
    let op = match &cell.op {
        CellOpConfig::Input { source } => CellOp::Input {
            source: source_to_input(source, &cell.key)?,
        },
        CellOpConfig::Const { value } => {
            CellOp::Const { value: value_from_json(value, &cell.key)? }
        }
        CellOpConfig::Arith { arith, args } => {
            let args = resolve_args(cell, args, &mut const_cells, const_counter)?;
            CellOp::Arith { op: arith.clone(), args }
        }
        CellOpConfig::Compare { cmp, left, right } => {
            let left_key = resolve_arg(cell, left, &mut const_cells, const_counter)?;
            let right_key = resolve_arg(cell, right, &mut const_cells, const_counter)?;
            CellOp::Compare {
                op: cmp.clone(),
                left: left_key,
                right: right_key,
            }
        }
        CellOpConfig::Logic { logic, args } => {
            let args = resolve_args(cell, args, &mut const_cells, const_counter)?;
            CellOp::Logic { op: logic.clone(), args }
        }
        CellOpConfig::Cond {
            cond,
            then_val,
            else_val,
        } => {
            let cond_key = resolve_arg(cell, cond, &mut const_cells, const_counter)?;
            let then_key = resolve_arg(cell, then_val, &mut const_cells, const_counter)?;
            let else_key = resolve_arg(cell, else_val, &mut const_cells, const_counter)?;
            CellOp::Cond {
                cond: cond_key,
                then_val: then_key,
                else_val: else_key,
            }
        }
        CellOpConfig::StringOp { string, args } => {
            let args = resolve_args(cell, args, &mut const_cells, const_counter)?;
            CellOp::StringOp { op: string.clone(), args }
        }
        CellOpConfig::Coalesce { args } => {
            let args = resolve_args(cell, args, &mut const_cells, const_counter)?;
            CellOp::Coalesce { args }
        }
        CellOpConfig::Fetch { url, timeout_ms } => {
            let url_key = resolve_arg(cell, url, &mut const_cells, const_counter)?;
            CellOp::Fetch {
                url: url_key,
                timeout_ms: timeout_ms.unwrap_or(200),
            }
        }
        CellOpConfig::Call { .. } => {
            return Err(ComputeConfigError::NestedSubgraph {
                subgraph: "root".to_string(),
                cell: cell.key.clone(),
            });
        }
        CellOpConfig::Output { target, source } => {
            let source_key = resolve_arg(cell, source, &mut const_cells, const_counter)?;
            CellOp::Output {
                target: target_to_output(target, &cell.key)?,
                source: source_key,
            }
        }
    };

    cells.extend(const_cells);
    let deps = deps_from_op(&op);
    cells.push(CellDef {
        key: cell.key.clone(),
        deps,
        op,
    });
    Ok(())
}

fn source_to_input(
    source: &InputSourceConfig,
    cell_key: &str,
) -> Result<crate::compute::InputSource, ComputeConfigError> {
    match source {
        InputSourceConfig::Header { header } => {
            Ok(crate::compute::InputSource::Header(header.clone()))
        }
        InputSourceConfig::Query { query } => Ok(crate::compute::InputSource::Query(query.clone())),
        InputSourceConfig::PathParam { path_param } => {
            Ok(crate::compute::InputSource::PathParam(path_param.clone()))
        }
        InputSourceConfig::Method { method } => {
            if !*method {
                return Err(ComputeConfigError::InvalidMethod {
                    cell: cell_key.to_string(),
                });
            }
            Ok(crate::compute::InputSource::Method)
        }
        InputSourceConfig::Metadata { metadata } => {
            Ok(crate::compute::InputSource::Metadata(metadata.clone()))
        }
    }
}

fn target_to_output(
    target: &OutputTargetConfig,
    cell_key: &str,
) -> Result<OutputTarget, ComputeConfigError> {
    match target {
        OutputTargetConfig::Header { header } => Ok(OutputTarget::Header(header.clone())),
        OutputTargetConfig::Metadata { metadata } => Ok(OutputTarget::Metadata(metadata.clone())),
        OutputTargetConfig::Verdict { verdict } => {
            if !*verdict {
                return Err(ComputeConfigError::InvalidVerdict {
                    cell: cell_key.to_string(),
                });
            }
            Ok(OutputTarget::Verdict)
        }
    }
}

fn resolve_args(
    cell: &CellConfig,
    args: &[ArgValue],
    const_cells: &mut Vec<CellDef>,
    const_counter: &mut u64,
) -> Result<Vec<String>, ComputeConfigError> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let key = resolve_arg(cell, arg, const_cells, const_counter)?;
        out.push(key);
    }
    Ok(out)
}

fn resolve_arg(
    cell: &CellConfig,
    arg: &ArgValue,
    const_cells: &mut Vec<CellDef>,
    const_counter: &mut u64,
) -> Result<String, ComputeConfigError> {
    match arg {
        ArgValue::Ref(key) => Ok(key.clone()),
        ArgValue::Const { r#const } => {
            let key = format!("__const_{}_{}", cell.key, const_counter);
            *const_counter += 1;
            let value = value_from_json(r#const, &cell.key)?;
            const_cells.push(CellDef {
                key: key.clone(),
                deps: Vec::new(),
                op: CellOp::Const { value },
            });
            Ok(key)
        }
    }
}

fn deps_from_op(op: &CellOp) -> Vec<String> {
    match op {
        CellOp::Input { .. } | CellOp::Const { .. } => Vec::new(),
        CellOp::Arith { args, .. } => args.clone(),
        CellOp::Compare { left, right, .. } => vec![left.clone(), right.clone()],
        CellOp::Logic { args, .. } => args.clone(),
        CellOp::Cond {
            cond,
            then_val,
            else_val,
        } => vec![cond.clone(), then_val.clone(), else_val.clone()],
        CellOp::StringOp { args, .. } => args.clone(),
        CellOp::Coalesce { args } => args.clone(),
        CellOp::Fetch { url, .. } => vec![url.clone()],
        CellOp::Output { source, .. } => vec![source.clone()],
    }
}

struct HttpFetcher<'a> {
    fx: &'a Effects,
    policy: &'a FetchPolicy,
    total_bytes: AtomicUsize,
}

impl<'a> Fetcher for HttpFetcher<'a> {
    fn fetch<'b>(
        &'b self,
        url: &'b str,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<CellValue, EvalError>> + Send + 'b>> {
        Box::pin(async move {
            let parts = parse_fetch_url(url)?;
            let scheme_ok = self.policy.allow_schemes.is_empty()
                || self.policy.allow_schemes.iter().any(|s| s == &parts.scheme);
            if !scheme_ok {
                self.fx.metrics.counter_inc("compute.fetch_blocked");
                return Err(EvalError::InvalidArgs("fetch.scheme".to_string()));
            }

            let host_ok = self.policy.allow_hosts.is_empty()
                || self.policy.allow_hosts.iter().any(|h| h == &parts.host);
            if !host_ok {
                let suffix_ok = !self.policy.allow_host_suffixes.is_empty()
                    && self
                        .policy
                        .allow_host_suffixes
                        .iter()
                        .any(|suffix| host_has_suffix(&parts.host, suffix));
                if !suffix_ok {
                    self.fx.metrics.counter_inc("compute.fetch_blocked");
                    return Err(EvalError::InvalidArgs("fetch.host".to_string()));
                }
            }

            let port = parts.port.or_else(|| default_port(&parts.scheme));
            let port_ok = self.policy.allow_ports.is_empty()
                || port
                    .map(|port| self.policy.allow_ports.iter().any(|p| *p == port))
                    .unwrap_or(false);
            if !port_ok {
                self.fx.metrics.counter_inc("compute.fetch_blocked");
                return Err(EvalError::InvalidArgs("fetch.port".to_string()));
            }

            let path_ok = self.policy.allow_path_prefixes.is_empty()
                || self
                    .policy
                    .allow_path_prefixes
                    .iter()
                    .any(|prefix| parts.path.starts_with(prefix));
            if !path_ok {
                self.fx.metrics.counter_inc("compute.fetch_blocked");
                return Err(EvalError::InvalidArgs("fetch.path".to_string()));
            }

            let fut = self.fx.http_client.get(url);
            let bytes = match tokio::time::timeout(Duration::from_millis(timeout_ms), fut).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(err)) => {
                    self.fx.metrics.counter_inc("compute.fetch_failed");
                    return Err(EvalError::TaskFailed(err));
                }
                Err(_) => {
                    self.fx.metrics.counter_inc("compute.fetch_timeout");
                    return Err(EvalError::BudgetExceeded("fetch_timeout".to_string()));
                }
            };
            if let Err(err) = check_fetch_size(bytes.len(), self.policy) {
                self.fx.metrics.counter_inc("compute.fetch_too_large");
                return Err(err);
            }
            let total = self
                .total_bytes
                .fetch_add(bytes.len(), Ordering::Relaxed)
                .saturating_add(bytes.len());
            if let Err(err) = check_fetch_total(total, self.policy) {
                self.fx.metrics.counter_inc("compute.fetch_total_exceeded");
                return Err(err);
            }
            self.fx.metrics.counter_inc("compute.fetch_ok");
            Ok(CellValue::Str(String::from_utf8_lossy(&bytes).to_string()))
        })
    }
}

struct FetchUrlParts {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

fn parse_fetch_url(url: &str) -> Result<FetchUrlParts, EvalError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| EvalError::InvalidArgs("fetch.url".to_string()))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| EvalError::InvalidArgs("fetch.url".to_string()))?;
    let authority = uri
        .authority()
        .ok_or_else(|| EvalError::InvalidArgs("fetch.url".to_string()))?;
    let host = authority.host();
    if host.is_empty() {
        return Err(EvalError::InvalidArgs("fetch.url".to_string()));
    }
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    Ok(FetchUrlParts {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        port: authority.port_u16(),
        path: path.to_string(),
    })
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn host_has_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.ends_with(&format!(".{suffix}"))
}

fn check_fetch_size(len: usize, policy: &FetchPolicy) -> Result<(), EvalError> {
    if len > policy.max_bytes {
        return Err(EvalError::BudgetExceeded("fetch_max_bytes".to_string()));
    }
    Ok(())
}

fn check_fetch_total(total: usize, policy: &FetchPolicy) -> Result<(), EvalError> {
    if total > policy.max_total_bytes {
        return Err(EvalError::BudgetExceeded("fetch_total_bytes".to_string()));
    }
    Ok(())
}

fn value_from_json(
    value: &serde_json::Value,
    cell_key: &str,
) -> Result<CellValue, ComputeConfigError> {
    Ok(match value {
        serde_json::Value::Null => CellValue::Null,
        serde_json::Value::Bool(b) => CellValue::Bool(*b),
        serde_json::Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                CellValue::Int(i)
            } else if let Some(f) = num.as_f64() {
                CellValue::Float(f)
            } else {
                return Err(ComputeConfigError::InvalidConst {
                    cell: cell_key.to_string(),
                    reason: "invalid number".to_string(),
                });
            }
        }
        serde_json::Value::String(s) => CellValue::Str(s.clone()),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(value_from_json(item, cell_key)?);
            }
            CellValue::List(out)
        }
        serde_json::Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), value_from_json(v, cell_key)?);
            }
            CellValue::Map(out)
        }
    })
}

fn build_context(req: &Request) -> EvalContext {
    let mut ctx = EvalContext::new(req.method.as_str());

    for (name, value) in req.headers.iter() {
        if let Ok(val) = value.to_str() {
            ctx.headers.insert(name.as_str().to_string(), val.to_string());
        }
    }

    if let Some(query) = req.uri.query() {
        parse_query_into(query, &mut ctx.query);
        for (key, values) in &ctx.query {
            let value = if values.len() == 1 {
                CellValue::Str(values[0].clone())
            } else {
                CellValue::List(values.iter().cloned().map(CellValue::Str).collect())
            };
            ctx.metadata.insert(format!("query.{key}"), value);
        }

        let mut query_map = BTreeMap::new();
        for (key, values) in &ctx.query {
            let value = if values.len() == 1 {
                CellValue::Str(values[0].clone())
            } else {
                CellValue::List(values.iter().cloned().map(CellValue::Str).collect())
            };
            query_map.insert(key.clone(), value);
        }
        ctx.metadata
            .insert("query.params".to_string(), CellValue::Map(query_map));
    }

    if let Some(params) = req.metadata.get::<PathParams>() {
        for (k, v) in params {
            ctx.path_params.insert(k.clone(), v.clone());
            ctx.metadata
                .insert(format!("path.{k}"), CellValue::Str(v.clone()));
        }
        ctx.metadata.insert(
            "path.params".to_string(),
            CellValue::Map(
                params
                    .iter()
                    .map(|(k, v)| (k.clone(), CellValue::Str(v.clone())))
                    .collect(),
            ),
        );
    }

    if let Some(identity) = req.metadata.get::<AuthIdentity>() {
        ctx.metadata
            .insert("auth.identity".to_string(), CellValue::Str(identity.clone()));
    }

    if let Some(method) = req.metadata.get::<AuthMethod>() {
        ctx.metadata
            .insert("auth.method".to_string(), CellValue::Str((*method).to_string()));
    }

    if let Some(claims) = req.metadata.get::<AuthClaims>() {
        let mut map = BTreeMap::new();
        for (k, v) in claims {
            if let Ok(value) = value_from_json(v, "auth.claims") {
                map.insert(k.clone(), value.clone());
                ctx.metadata
                    .insert(format!("auth.claims.{k}"), value);
            }
        }
        ctx.metadata.insert("auth.claims".to_string(), CellValue::Map(map));
    }

    if let Some(remaining) = req.metadata.get::<RateLimitRemaining>() {
        ctx.metadata.insert(
            "rate_limit.remaining".to_string(),
            CellValue::Int(*remaining as i64),
        );
    }

    if let Some(map) = req.metadata.get::<ComputeMetadata>() {
        for (k, v) in map {
            ctx.metadata.insert(k.clone(), v.clone());
        }
    }

    ctx
}

fn apply_outputs(
    req: &mut Request,
    outputs: Vec<OutputAction>,
    fx: &Effects,
) -> Result<(), Verdict> {
    let mut meta = req
        .metadata
        .get::<ComputeMetadata>()
        .cloned()
        .unwrap_or_default();

    for output in outputs {
        match output.target {
            OutputTarget::Header(name) => {
                if let (Ok(header), Ok(value)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(&cell_value_to_string(&output.value)),
                ) {
                    req.headers.insert(header, value);
                }
            }
            OutputTarget::Metadata(key) => {
                meta.insert(key, output.value);
            }
            OutputTarget::Verdict => {
                if let CellValue::Bool(allow) = output.value {
                    if !allow {
                        fx.metrics.counter_inc("compute.verdict_denied");
                        return Err(Verdict::Respond(Response::error(
                            StatusCode::FORBIDDEN,
                            b"Forbidden\n",
                        )));
                    }
                } else {
                    fx.metrics.counter_inc("compute.verdict_type_error");
                    return Err(Verdict::Respond(Response::error(
                        StatusCode::BAD_REQUEST,
                        b"compute verdict expects boolean\n",
                    )));
                }
            }
        }
    }

    req.metadata.insert::<ComputeMetadata>(meta);
    Ok(())
}

fn parse_query_into(query: &str, out: &mut BTreeMap<String, Vec<String>>) {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key_raw = parts.next().unwrap_or("");
        let value_raw = parts.next().unwrap_or("");
        if key_raw.is_empty() {
            continue;
        }
        let key = decode_query_component(key_raw);
        let value = decode_query_component(value_raw);
        out.entry(key).or_default().push(value);
    }
}

fn decode_query_component(input: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];
                if let (Some(hi), Some(lo)) = (hex_val(hi), hex_val(lo)) {
                    out.push(hi * 16 + lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn cell_value_to_string(value: &CellValue) -> String {
    match value {
        CellValue::Null => "".to_string(),
        CellValue::Bool(b) => b.to_string(),
        CellValue::Int(i) => i.to_string(),
        CellValue::Float(f) => f.to_string(),
        CellValue::Str(s) => s.clone(),
        CellValue::List(items) => items
            .iter()
            .map(cell_value_to_string)
            .collect::<Vec<_>>()
            .join(","),
        CellValue::Map(map) => {
            let mut out = Vec::new();
            for (k, v) in map {
                out.push(format!("{k}:{v}", v = cell_value_to_string(v)));
            }
            out.join(",")
        }
    }
}

fn handle_eval_error(err: EvalError, fx: &Effects) -> Verdict {
    match err {
        EvalError::BudgetExceeded(_) => {
            fx.metrics.counter_inc("compute.budget_exceeded");
            Verdict::Respond(Response::error(
                StatusCode::TOO_MANY_REQUESTS,
                b"compute budget exceeded\n",
            ))
        }
        EvalError::TypeMismatch { .. } => {
            fx.metrics.counter_inc("compute.type_errors");
            fx.metrics.counter_inc("compute.eval_error");
            Verdict::Respond(Response::error(
                StatusCode::BAD_REQUEST,
                b"compute evaluation error\n",
            ))
        }
        EvalError::MissingInput(_) | EvalError::InvalidArgs(_) => {
            fx.metrics.counter_inc("compute.eval_error");
            Verdict::Respond(Response::error(
                StatusCode::BAD_REQUEST,
                b"compute evaluation error\n",
            ))
        }
        EvalError::MissingValue(_)
        | EvalError::DivideByZero
        | EvalError::Unimplemented(_)
        | EvalError::TaskFailed(_) => {
            fx.metrics.counter_inc("compute.eval_error");
            Verdict::Respond(Response::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"compute internal error\n",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ron_value;
    use crate::filter::{HttpClient, HttpClientLike, Metrics, RequestLogger, SharedState, SystemClock};
    use crate::filters::auth::{AuthClaims, AuthIdentity, AuthMethod};
    use crate::filters::rate_limit::RateLimitRemaining;
    use crate::routing::PathParams;
    use crate::test_support::{ResponseSpec, TestHttpClient};
    use http::{Method, Uri};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    fn test_effects_with_http(client: Arc<dyn HttpClientLike>) -> Effects {
        Effects {
            metrics: Arc::new(Metrics::new()),
            log: RequestLogger::new("127.0.0.1:0".parse().unwrap()),
            http_client: client,
            shared: Arc::new(SharedState::new()),
            clock: Arc::new(SystemClock),
        }
    }

    fn test_effects() -> Effects {
        test_effects_with_http(Arc::new(HttpClient::new()) as Arc<dyn HttpClientLike>)
    }

    

    fn test_request(uri: &str) -> Request {
        Request::new(
            Method::GET,
            Uri::try_from(uri).unwrap(),
            "10.0.0.1:5000".parse::<SocketAddr>().unwrap(),
        )
    }

    #[tokio::test]
    async fn filter_applies_header_output() {
        let config = ron_value(
            r#"{
                "max_nodes": 32,
                "cells": [
                    {"key": "role", "op": "input", "source": {"metadata": "role"}},
                    {"key": "is_admin", "op": "compare", "cmp": "eq", "left": "role", "right": {"const": "admin"}},
                    {"key": "tier", "op": "cond", "cond": "is_admin", "then_val": {"const": "unlimited"}, "else_val": {"const": "standard"}},
                    {"key": "out", "op": "output", "target": {"header": "x-tier"}, "source": "tier"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");
        let mut meta = BTreeMap::new();
        meta.insert("role".to_string(), CellValue::Str("admin".to_string()));
        req.metadata.insert::<ComputeMetadata>(meta);

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(
            req.headers.get("x-tier").unwrap().to_str().unwrap(),
            "unlimited"
        );
    }

    #[tokio::test]
    async fn filter_writes_metadata_output() {
        let config = ron_value(
            r#"{
                "cells": [
                    {"key": "val", "op": "const", "value": "hello"},
                    {"key": "out", "op": "output", "target": {"metadata": "msg"}, "source": "val"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        let meta = req.metadata.get::<ComputeMetadata>().unwrap();
        assert_eq!(meta.get("msg"), Some(&CellValue::Str("hello".to_string())));
    }

    #[tokio::test]
    async fn filter_blocks_on_budget_exceeded() {
        let config = ron_value(
            r#"{
                "max_nodes": 1,
                "cells": [
                    {"key": "a", "op": "const", "value": 1},
                    {"key": "b", "op": "const", "value": 2}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(resp) if resp.status == StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn filter_decodes_query_params() {
        let config = ron_value(
            r#"{
                "cells": [
                    {"key": "q", "op": "input", "source": {"query": "q"}},
                    {"key": "x", "op": "input", "source": {"query": "x"}},
                    {"key": "tag", "op": "input", "source": {"query": "tag"}},
                    {"key": "tag_meta", "op": "input", "source": {"metadata": "query.tag"}},
                    {"key": "out_q", "op": "output", "target": {"metadata": "q"}, "source": "q"},
                    {"key": "out_x", "op": "output", "target": {"metadata": "x"}, "source": "x"},
                    {"key": "out_tag", "op": "output", "target": {"metadata": "tag"}, "source": "tag"},
                    {"key": "out_tag_meta", "op": "output", "target": {"metadata": "tag_meta"}, "source": "tag_meta"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/?q=hello%20world&x=a+b&tag=one&tag=two");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));

        let meta = req.metadata.get::<ComputeMetadata>().unwrap();
        assert_eq!(meta.get("q"), Some(&CellValue::Str("hello world".to_string())));
        assert_eq!(meta.get("x"), Some(&CellValue::Str("a b".to_string())));
        assert_eq!(
            meta.get("tag"),
            Some(&CellValue::List(vec![
                CellValue::Str("one".to_string()),
                CellValue::Str("two".to_string())
            ]))
        );
        assert_eq!(
            meta.get("tag_meta"),
            Some(&CellValue::List(vec![
                CellValue::Str("one".to_string()),
                CellValue::Str("two".to_string())
            ]))
        );
    }

    #[tokio::test]
    async fn filter_reads_typed_metadata() {
        let config = ron_value(
            r#"{
                "cells": [
                    {"key": "user", "op": "input", "source": {"metadata": "auth.identity"}},
                    {"key": "path", "op": "input", "source": {"metadata": "path.id"}},
                    {"key": "remaining", "op": "input", "source": {"metadata": "rate_limit.remaining"}},
                    {"key": "role", "op": "input", "source": {"metadata": "auth.claims.role"}},
                    {"key": "out_user", "op": "output", "target": {"header": "x-user"}, "source": "user"},
                    {"key": "out_path", "op": "output", "target": {"metadata": "path"}, "source": "path"},
                    {"key": "out_remaining", "op": "output", "target": {"metadata": "remaining"}, "source": "remaining"},
                    {"key": "out_role", "op": "output", "target": {"metadata": "role"}, "source": "role"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/users/42");

        req.metadata.insert::<AuthIdentity>("alice".to_string());
        req.metadata.insert::<AuthMethod>("jwt");
        req.metadata.insert::<RateLimitRemaining>(7);

        let mut params = std::collections::HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        req.metadata.insert::<PathParams>(params);

        let mut claims = serde_json::Map::new();
        claims.insert("role".to_string(), serde_json::Value::String("admin".to_string()));
        req.metadata.insert::<AuthClaims>(claims);

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.headers.get("x-user").unwrap(), "alice");

        let meta = req.metadata.get::<ComputeMetadata>().unwrap();
        assert_eq!(meta.get("path"), Some(&CellValue::Str("42".to_string())));
        assert_eq!(meta.get("remaining"), Some(&CellValue::Int(7)));
        assert_eq!(meta.get("role"), Some(&CellValue::Str("admin".to_string())));
    }

    #[tokio::test]
    async fn filter_expands_subgraph_call() {
        let config = ron_value(
            r#"{
                "subgraphs": [
                    {
                        "name": "tiering",
                        "cells": [
                            {"key": "role", "op": "input", "source": {"metadata": "role"}},
                            {"key": "is_admin", "op": "compare", "cmp": "eq", "left": "role", "right": {"const": "admin"}},
                            {"key": "tier", "op": "cond", "cond": "is_admin", "then_val": {"const": "unlimited"}, "else_val": {"const": "standard"}}
                        ]
                    }
                ],
                "cells": [
                    {"key": "calc", "op": "call", "subgraph": "tiering"},
                    {"key": "out", "op": "output", "target": {"header": "x-tier"}, "source": "calc.tier"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let mut meta = BTreeMap::new();
        meta.insert("role".to_string(), CellValue::Str("admin".to_string()));
        req.metadata.insert::<ComputeMetadata>(meta);

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.headers.get("x-tier").unwrap(), "unlimited");
    }

    #[tokio::test]
    async fn filter_expands_subgraph_with_prefix() {
        let config = ron_value(
            r#"{
                "subgraphs": [
                    {
                        "name": "tiering",
                        "cells": [
                            {"key": "role", "op": "input", "source": {"metadata": "role"}},
                            {"key": "tier", "op": "cond", "cond": {"const": true}, "then_val": "role", "else_val": {"const": "standard"}}
                        ]
                    }
                ],
                "cells": [
                    {"key": "calc", "op": "call", "subgraph": "tiering", "prefix": "tier"},
                    {"key": "out", "op": "output", "target": {"header": "x-tier"}, "source": "tier.tier"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let mut meta = BTreeMap::new();
        meta.insert("role".to_string(), CellValue::Str("gold".to_string()));
        req.metadata.insert::<ComputeMetadata>(meta);

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        assert_eq!(req.headers.get("x-tier").unwrap(), "gold");
    }

    #[test]
    fn config_rejects_unknown_subgraph() {
        let config = ron_value(
            r#"{
                "cells": [
                    {"key": "call", "op": "call", "subgraph": "missing"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("unknown subgraph"));
    }

    #[test]
    fn config_rejects_duplicate_subgraph() {
        let config = ron_value(
            r#"{
                "subgraphs": [
                    {"name": "dup", "cells": [{"key": "a", "op": "const", "value": 1}]},
                    {"name": "dup", "cells": [{"key": "b", "op": "const", "value": 2}]}
                ],
                "cells": [
                    {"key": "call", "op": "call", "subgraph": "dup"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("duplicate subgraph"));
    }

    #[test]
    fn config_rejects_nested_subgraph_call() {
        let config = ron_value(
            r#"{
                "subgraphs": [
                    {
                        "name": "inner",
                        "cells": [
                            {"key": "call", "op": "call", "subgraph": "other"}
                        ]
                    }
                ],
                "cells": [
                    {"key": "main", "op": "call", "subgraph": "inner"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("not allowed inside subgraph"));
    }

    #[tokio::test]
    async fn filter_blocks_fetch_by_host() {
        let config = ron_value(
            r#"{
                "fetch_allow_hosts": ["allowed.local"],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://blocked.local/resource"},
                    {"key": "body", "op": "fetch", "url": "url", "timeout_ms": 50}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(resp) if resp.status == StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn filter_blocks_fetch_by_port() {
        let config = ron_value(
            r#"{
                "fetch_allow_ports": [443],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://example/path"},
                    {"key": "body", "op": "fetch", "url": "url", "timeout_ms": 50}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(resp) if resp.status == StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn filter_blocks_fetch_by_path_prefix() {
        let config = ron_value(
            r#"{
                "fetch_allow_path_prefixes": ["/allowed"],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://example/blocked"},
                    {"key": "body", "op": "fetch", "url": "url", "timeout_ms": 50}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let fx = test_effects();
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(resp) if resp.status == StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn filter_allows_fetch_by_host_suffix() {
        let config = ron_value(
            r#"{
                "fetch_allow_host_suffixes": ["example.com"],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://api.example.com/data"},
                    {"key": "body", "op": "fetch", "url": "url", "timeout_ms": 50},
                    {"key": "out", "op": "output", "target": {"metadata": "body"}, "source": "body"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let mut responses = HashMap::new();
        responses.insert(
            "http://api.example.com/data".to_string(),
            ResponseSpec {
                body: Ok(b"ok".to_vec()),
                delay_ms: 0,
            },
        );
        let fx = test_effects_with_http(TestHttpClient::boxed(responses));
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Continue));
        let meta = req.metadata.get::<ComputeMetadata>().unwrap();
        assert_eq!(meta.get("body"), Some(&CellValue::Str("ok".to_string())));
    }

    #[tokio::test]
    async fn filter_fetch_times_out() {
        let config = ron_value(
            r#"{
                "fetch_allow_hosts": ["slow.local"],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://slow.local/data"},
                    {"key": "body", "op": "fetch", "url": "url", "timeout_ms": 1}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let mut responses = HashMap::new();
        responses.insert(
            "http://slow.local/data".to_string(),
            ResponseSpec {
                body: Ok(b"late".to_vec()),
                delay_ms: 10,
            },
        );
        let fx = test_effects_with_http(TestHttpClient::boxed(responses));
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(resp) if resp.status == StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn filter_fetch_failure_returns_500() {
        let config = ron_value(
            r#"{
                "fetch_allow_hosts": ["fail.local"],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://fail.local/data"},
                    {"key": "body", "op": "fetch", "url": "url", "timeout_ms": 50}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let filter = factory.build(&config).unwrap();
        let mut responses = HashMap::new();
        responses.insert(
            "http://fail.local/data".to_string(),
            ResponseSpec {
                body: Err("upstream_error".to_string()),
                delay_ms: 0,
            },
        );
        let fx = test_effects_with_http(TestHttpClient::boxed(responses));
        let mut req = test_request("/");

        let verdict = filter.on_request(&mut req, &fx).await;
        assert!(matches!(verdict, Verdict::Respond(resp) if resp.status == StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn config_rejects_fetch_max_bytes_zero() {
        let config = ron_value(
            r#"{
                "fetch_max_bytes": 0,
                "cells": [
                    {"key": "url", "op": "const", "value": "http://example"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("fetch_max_bytes"));
    }

    #[test]
    fn config_rejects_fetch_max_total_bytes_zero() {
        let config = ron_value(
            r#"{
                "fetch_max_total_bytes": 0,
                "cells": [
                    {"key": "url", "op": "const", "value": "http://example"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("fetch_max_total_bytes"));
    }

    #[test]
    fn config_rejects_fetch_allow_ports_zero() {
        let config = ron_value(
            r#"{
                "fetch_allow_ports": [0],
                "cells": [
                    {"key": "url", "op": "const", "value": "http://example"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("fetch_allow_ports"));
    }

    #[test]
    fn fetch_rejects_too_large_response() {
        let policy = FetchPolicy {
            allow_schemes: vec!["http".to_string()],
            allow_hosts: Vec::new(),
            allow_host_suffixes: Vec::new(),
            allow_ports: Vec::new(),
            allow_path_prefixes: Vec::new(),
            max_bytes: 4,
            max_total_bytes: 8,
        };

        let err = check_fetch_size(5, &policy).unwrap_err();
        assert!(matches!(err, EvalError::BudgetExceeded(reason) if reason == "fetch_max_bytes"));
    }

    #[test]
    fn fetch_rejects_total_bytes_limit() {
        let policy = FetchPolicy {
            allow_schemes: vec!["http".to_string()],
            allow_hosts: Vec::new(),
            allow_host_suffixes: Vec::new(),
            allow_ports: Vec::new(),
            allow_path_prefixes: Vec::new(),
            max_bytes: 8,
            max_total_bytes: 10,
        };

        let err = check_fetch_total(11, &policy).unwrap_err();
        assert!(matches!(err, EvalError::BudgetExceeded(reason) if reason == "fetch_total_bytes"));
    }

    #[test]
    fn config_rejects_too_many_fetch_nodes() {
        let config = ron_value(
            r#"{
                "max_fetch_nodes": 1,
                "cells": [
                    {"key": "url", "op": "const", "value": "http://example"},
                    {"key": "fetch1", "op": "fetch", "url": "url", "timeout_ms": 10},
                    {"key": "fetch2", "op": "fetch", "url": "url", "timeout_ms": 10}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("fetch nodes exceeded"));
    }

    #[test]
    fn config_rejects_method_false() {
        let config = ron_value(
            r#"{
                "cells": [
                    {"key": "m", "op": "input", "source": {"method": false}}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("input.method"));
    }

    #[test]
    fn config_rejects_verdict_false() {
        let config = ron_value(
            r#"{
                "cells": [
                    {"key": "allow", "op": "const", "value": true},
                    {"key": "out", "op": "output", "target": {"verdict": false}, "source": "allow"}
                ]
            }"#,
        );

        let factory = ComputeFactory;
        let result = factory.build(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("output.verdict"));
    }
}
