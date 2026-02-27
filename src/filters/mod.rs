//! Built-in filter implementations.
//!
//! | Filter | Purpose |
//! |---|---|
//! | [`rate_limit`] | Per-IP sliding window rate limiter |
//! | [`auth`] | JWT (HS256/384/512), API Key, Basic Auth |
//! | [`cors`] | CORS preflight + response headers |
//! | [`access_log`] | Structured request/response logging (tracing) |
//! | [`add_header`] | Inject static headers into requests |
//! | [`encrypt`] | AES-256-GCM body encryption/decryption |
//! | [`kv`] | In-process KV store (memory / redb) |
//! | [`router`] | Terminal — route dispatch to HTTP / redb upstream |
//! | [`phe`] | Password-Hardened Encryption (per-user keys) |

pub mod auth;
pub mod rate_limit;
pub mod add_header;
pub mod router;
pub mod encrypt;
pub mod kv;
pub mod cors;
pub mod access_log;
pub mod phe;
