//! # proxy_core — Functional L7 Proxy Kernel
//!
//! Architecture:
//! - **Data plane**: ownership-driven pipeline (`&mut Request`, move semantics, streaming body)
//! - **Control plane**: à la Carte (config × rebuilder → chain, incremental rebuild)
//! - **Effects**: explicit injection, no hidden side effects
//!
//! ## Module map
//! - [`types`]   — Request, Response, BodyStream, Metadata, JSON runtime helpers (sonic-rs SIMD)
//! - [`filter`]  — Filter trait, Verdict, Effects (DI container)
//! - [`chain`]   — FilterChain executor + ActiveChain (ArcSwap hot reload)
//! - [`builder`] — ChainBuilder, FilterFactory, FilterRegistry (control plane)
//! - [`worker`]  — Worker event loop, keep-alive, graceful shutdown, connection limits
//! - [`routing`] — RouteTable, RouteMatcher (prefix/exact/pattern with `:param`), PathParams
//! - [`upstream`] — HttpUpstream (reqwest) + RedbUpstream (feature-gated)
//! - [`crypto`]  — AES-256-GCM encryption, HMAC-SHA256 key hashing, HKDF key derivation
//! - [`store`]   — KV store abstraction: MemoryStore + RedbStore with encryption at rest
//! - [`circuit_breaker`] — Per-upstream circuit breaker (Closed/Open/HalfOpen)
//! - [`filters`] — Built-in filters: auth, rate_limit, cors, access_log, audit, sso_bridge, ldap_sync, add_header, rbac, encrypt, kv, router, phe
//! - [`phe`]     — Password-Hardened Encryption (P-256 + Schnorr proofs + HKDF)

pub mod types;
pub mod filter;
pub mod chain;
pub mod builder;
pub mod worker;
pub mod filters;
pub mod routing;
pub mod upstream;
pub mod crypto;
pub mod store;
pub mod circuit_breaker;
pub mod phe;
