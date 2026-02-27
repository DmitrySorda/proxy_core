//! KV store abstraction with transparent encryption at rest.
//!
//! Backends:
//! - [`MemoryStore`]: in-memory `BTreeMap` — development / testing
//! - [`RedbStore`]: redb embedded ACID database — production (feature-gated `redb`)
//!
//! Both backends support optional encryption via the [`Cipher`](crate::crypto::Cipher) trait:
//! - **Values**: AES-256-GCM encrypted before write, decrypted after read
//! - **Keys**: HMAC-SHA256 hashed for deterministic lookups (optional)
//!
//! ## Data flow (with encryption)
//! ```text
//! PUT /kv/users/123  body="alice"
//!   → storage_key = HMAC-SHA256("users/123")      [if encrypt_keys]
//!   → stored_value = AES-GCM-Encrypt("alice")     [always with cipher]
//!   → backend.set(storage_key, stored_value)
//!
//! GET /kv/users/123
//!   → storage_key = HMAC-SHA256("users/123")
//!   → encrypted = backend.get(storage_key)
//!   → plaintext = AES-GCM-Decrypt(encrypted)
//!   → 200 OK  body="alice"
//! ```

use crate::crypto::Cipher;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ─── Errors ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StoreError {
    /// Key not found in the store.
    NotFound,
    /// Encryption or decryption failed.
    Crypto(String),
    /// Backend operation failed.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "key not found"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::Backend(e) => write!(f, "backend: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

// ─── KV Entry ───────────────────────────────────────────────────────

/// A key-value pair returned by list operations.
#[derive(Debug, Clone)]
pub struct KvEntry {
    /// Original key (before HMAC, if key encryption is enabled).
    pub key: String,
    /// Decrypted value.
    pub value: Vec<u8>,
}

// ─── Store (enum dispatch) ──────────────────────────────────────────

/// KV store backend — enum dispatch over available backends.
///
/// Using enum instead of `dyn Trait` avoids virtual dispatch overhead
/// and keeps async methods simple (no `Pin<Box<dyn Future>>`).
pub enum Store {
    /// In-memory backend (development / testing).
    Memory(MemoryStore),
    /// redb embedded ACID backend (production).
    #[cfg(feature = "redb")]
    Redb(RedbStore),
}

impl Store {
    /// Get a value by key. Returns decrypted plaintext.
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        match self {
            Self::Memory(s) => s.get(key).await,
            #[cfg(feature = "redb")]
            Self::Redb(s) => s.get(key).await,
        }
    }

    /// Set a key-value pair. Value is encrypted before storage.
    pub async fn set(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        match self {
            Self::Memory(s) => s.set(key, value).await,
            #[cfg(feature = "redb")]
            Self::Redb(s) => s.set(key, value).await,
        }
    }

    /// Delete a key. Returns `true` if the key existed.
    pub async fn delete(&self, key: &str) -> Result<bool, StoreError> {
        match self {
            Self::Memory(s) => s.delete(key).await,
            #[cfg(feature = "redb")]
            Self::Redb(s) => s.delete(key).await,
        }
    }

    /// List entries matching a key prefix. Returns up to `limit` entries.
    ///
    /// **Note**: prefix scan is not available when `encrypt_keys` is enabled
    /// with encrypted keys (HMAC destroys key ordering). MemoryStore maintains
    /// a secondary index to support this.
    pub async fn list(&self, prefix: &str, limit: usize) -> Result<Vec<KvEntry>, StoreError> {
        match self {
            Self::Memory(s) => s.list(prefix, limit).await,
            #[cfg(feature = "redb")]
            Self::Redb(s) => s.list(prefix, limit).await,
        }
    }

    /// Number of stored entries (exact for Memory and Redb).
    pub async fn len(&self) -> usize {
        match self {
            Self::Memory(s) => s.len().await,
            #[cfg(feature = "redb")]
            Self::Redb(s) => s.len().await,
        }
    }

    /// Whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

// ─── MemoryStore ────────────────────────────────────────────────────

/// In-memory KV store backed by `BTreeMap` (ordered for prefix scans).
///
/// Thread-safe via `tokio::sync::RwLock` — readers don't block each other.
///
/// When a `Cipher` is provided:
/// - Values are AES-256-GCM encrypted/decrypted transparently
/// - Keys are HMAC-SHA256 hashed (when `encrypt_keys = true`)
/// - A secondary `key_index` maps original keys to storage keys,
///   enabling prefix-scan even with encrypted keys
pub struct MemoryStore {
    /// storage_key → encrypted_value
    data: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
    /// original_key → storage_key (only used when encrypt_keys = true)
    key_index: RwLock<BTreeMap<String, Vec<u8>>>,
    cipher: Option<Arc<dyn Cipher>>,
    encrypt_keys: bool,
}

impl MemoryStore {
    /// Create a new in-memory store.
    ///
    /// # Arguments
    /// - `cipher`: optional encryption cipher (AES-256-GCM)
    /// - `encrypt_keys`: whether to HMAC-hash keys before storage
    pub fn new(cipher: Option<Arc<dyn Cipher>>, encrypt_keys: bool) -> Self {
        Self {
            data: RwLock::new(BTreeMap::new()),
            key_index: RwLock::new(BTreeMap::new()),
            cipher,
            encrypt_keys,
        }
    }

    /// Compute the storage key: HMAC(key) if encrypt_keys, else raw bytes.
    fn storage_key(&self, key: &str) -> Vec<u8> {
        if self.encrypt_keys {
            if let Some(ref cipher) = self.cipher {
                return cipher.hmac_key(key.as_bytes());
            }
        }
        key.as_bytes().to_vec()
    }

    /// Encrypt a value. Passthrough if no cipher configured.
    fn encrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, StoreError> {
        match &self.cipher {
            Some(c) => c.encrypt(value).map_err(|e| StoreError::Crypto(e.to_string())),
            None => Ok(value.to_vec()),
        }
    }

    /// Decrypt a value. Passthrough if no cipher configured.
    fn decrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, StoreError> {
        match &self.cipher {
            Some(c) => c.decrypt(value).map_err(|e| StoreError::Crypto(e.to_string())),
            None => Ok(value.to_vec()),
        }
    }

    /// Get a value by key.
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let sk = self.storage_key(key);
        let data = self.data.read().await;
        match data.get(&sk) {
            Some(encrypted) => self.decrypt_value(encrypted),
            None => Err(StoreError::NotFound),
        }
    }

    /// Set a key-value pair.
    pub async fn set(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let sk = self.storage_key(key);
        let encrypted = self.encrypt_value(value)?;

        // Lock ordering: key_index first, then data (prevents deadlock)
        if self.encrypt_keys {
            let mut idx = self.key_index.write().await;
            idx.insert(key.to_string(), sk.clone());
        }

        let mut data = self.data.write().await;
        data.insert(sk, encrypted);
        Ok(())
    }

    /// Delete a key. Returns `true` if it existed.
    pub async fn delete(&self, key: &str) -> Result<bool, StoreError> {
        let sk = self.storage_key(key);

        if self.encrypt_keys {
            let mut idx = self.key_index.write().await;
            idx.remove(key);
        }

        let mut data = self.data.write().await;
        Ok(data.remove(&sk).is_some())
    }

    /// List entries matching a prefix, up to `limit`.
    pub async fn list(&self, prefix: &str, limit: usize) -> Result<Vec<KvEntry>, StoreError> {
        if self.encrypt_keys && self.cipher.is_some() {
            // Encrypted keys: use the secondary index for prefix matching.
            // Lock ordering: key_index first, then data.
            let idx = self.key_index.read().await;
            let data = self.data.read().await;

            let prefix_owned = prefix.to_string();
            let entries: Vec<KvEntry> = idx
                .range(prefix_owned..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .take(limit)
                .filter_map(|(original_key, storage_key)| {
                    let encrypted = data.get(storage_key)?;
                    let value = self.decrypt_value(encrypted).ok()?;
                    Some(KvEntry {
                        key: original_key.clone(),
                        value,
                    })
                })
                .collect();

            Ok(entries)
        } else {
            // Unencrypted keys: direct BTreeMap prefix scan.
            let data = self.data.read().await;
            let prefix_bytes = prefix.as_bytes().to_vec();

            let entries: Vec<KvEntry> = data
                .range(prefix_bytes.clone()..)
                .take_while(|(k, _)| k.starts_with(&prefix_bytes))
                .take(limit)
                .filter_map(|(k, v)| {
                    let key = String::from_utf8_lossy(k).to_string();
                    let value = self.decrypt_value(v).ok()?;
                    Some(KvEntry { key, value })
                })
                .collect();

            Ok(entries)
        }
    }

    /// Number of stored entries.
    pub async fn len(&self) -> usize {
        self.data.read().await.len()
    }

    /// Whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.data.read().await.is_empty()
    }
}

// ─── RedbStore (feature-gated) ──────────────────────────────────────
//
// Enable with: cargo build --features redb
// Pure Rust, zero C dependencies, ACID transactions, embedded.

#[cfg(feature = "redb")]
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};

/// Table definition for the primary KV data.
#[cfg(feature = "redb")]
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv_data");

/// Table definition for the key index (original_key → storage_key).
/// Used only when `encrypt_keys = true`.
#[cfg(feature = "redb")]
const INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("kv_index");

// ─── Global Database pool ───────────────────────────────────────────
//
// redb uses an exclusive file lock — only one `Database` handle per file.
// This pool ensures that multiple `RedbStore`/`RedbUpstream` instances
// pointing to the same file share a single `Database` via `Arc`.
// When all `Arc` clones are dropped, the `Weak` ref expires and the
// next open will create a fresh handle.

#[cfg(feature = "redb")]
pub(crate) mod db_pool {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Mutex, Weak};

    static POOL: std::sync::LazyLock<Mutex<HashMap<PathBuf, Weak<Database>>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Open or reuse a `Database` for the given path.
    pub fn open(path: &str) -> Result<Arc<Database>, String> {
        let canonical = std::fs::canonicalize(path)
            .or_else(|_| {
                // File doesn't exist yet — canonicalize the parent dir + filename
                let p = std::path::Path::new(path);
                let parent = p.parent().unwrap_or(std::path::Path::new("."));
                let parent_canon = std::fs::canonicalize(parent)
                    .map_err(|e| format!("cannot resolve parent dir of '{path}': {e}"))?;
                Ok::<PathBuf, String>(parent_canon.join(p.file_name().unwrap_or_default()))
            })?;

        let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());

        // Try to reuse an existing handle.
        if let Some(weak) = pool.get(&canonical) {
            if let Some(arc) = weak.upgrade() {
                return Ok(arc);
            }
        }

        // Create a new Database.
        let db = Database::create(path)
            .map_err(|e| format!("failed to open redb at '{path}': {e}"))?;
        let arc = Arc::new(db);
        pool.insert(canonical, Arc::downgrade(&arc));
        Ok(arc)
    }

    /// For tests: drop all cached weak refs so file locks are released
    /// once all `Arc`s are dropped.
    #[cfg(test)]
    pub fn drain() {
        let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());
        pool.retain(|_, v| v.strong_count() > 0);
    }
}

#[cfg(feature = "redb")]
pub struct RedbStore {
    db: Arc<Database>,
    cipher: Option<Arc<dyn Cipher>>,
    encrypt_keys: bool,
    /// Key prefix prepended to all keys (namespace isolation).
    key_prefix: String,
}

// Safety: Database is Send+Sync in redb, and all other fields are Send+Sync
#[cfg(feature = "redb")]
unsafe impl Send for RedbStore {}
#[cfg(feature = "redb")]
unsafe impl Sync for RedbStore {}

#[cfg(feature = "redb")]
impl RedbStore {
    /// Open or create a redb database at the given path.
    ///
    /// # Arguments
    /// - `path`: filesystem path for the database file
    /// - `cipher`: optional AES-256-GCM cipher for value encryption
    /// - `encrypt_keys`: whether to HMAC-hash keys before storage
    /// - `key_prefix`: namespace prefix for all keys
    pub fn new(
        path: &str,
        cipher: Option<Arc<dyn Cipher>>,
        encrypt_keys: bool,
        key_prefix: String,
    ) -> Result<Self, String> {
        let db = db_pool::open(path)?;

        // Pre-create tables so reads don't fail on empty DB
        {
            let txn = db
                .begin_write()
                .map_err(|e| format!("failed to begin write txn: {e}"))?;
            {
                let _t = txn.open_table(DATA_TABLE)
                    .map_err(|e| format!("failed to create data table: {e}"))?;
                if encrypt_keys {
                    let _t = txn.open_table(INDEX_TABLE)
                        .map_err(|e| format!("failed to create index table: {e}"))?;
                }
            }
            txn.commit()
                .map_err(|e| format!("failed to commit init txn: {e}"))?;
        }

        Ok(Self { db, cipher, encrypt_keys, key_prefix })
    }

    /// Compute the storage key: prefix + HMAC(key) if encrypt_keys, else prefix + key.
    fn storage_key(&self, key: &str) -> Vec<u8> {
        if self.encrypt_keys {
            if let Some(ref cipher) = self.cipher {
                let mut sk = self.key_prefix.as_bytes().to_vec();
                sk.extend_from_slice(&cipher.hmac_key(key.as_bytes()));
                return sk;
            }
        }
        format!("{}{}", self.key_prefix, key).into_bytes()
    }

    fn encrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, StoreError> {
        match &self.cipher {
            Some(c) => c.encrypt(value).map_err(|e| StoreError::Crypto(e.to_string())),
            None => Ok(value.to_vec()),
        }
    }

    fn decrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, StoreError> {
        match &self.cipher {
            Some(c) => c.decrypt(value).map_err(|e| StoreError::Crypto(e.to_string())),
            None => Ok(value.to_vec()),
        }
    }

    /// Helper: convert any Display error into StoreError::Backend.
    fn backend_err(e: impl std::fmt::Display) -> StoreError {
        StoreError::Backend(e.to_string())
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let sk = self.storage_key(key);
        let txn = self.db.begin_read().map_err(Self::backend_err)?;
        let table = txn.open_table(DATA_TABLE).map_err(Self::backend_err)?;

        match table.get(sk.as_slice()).map_err(Self::backend_err)? {
            Some(v) => self.decrypt_value(v.value()),
            None => Err(StoreError::NotFound),
        }
    }

    pub async fn set(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let sk = self.storage_key(key);
        let encrypted = self.encrypt_value(value)?;

        let txn = self.db.begin_write().map_err(Self::backend_err)?;
        {
            let mut table = txn.open_table(DATA_TABLE).map_err(Self::backend_err)?;
            table.insert(sk.as_slice(), encrypted.as_slice()).map_err(Self::backend_err)?;

            if self.encrypt_keys {
                let mut idx = txn.open_table(INDEX_TABLE).map_err(Self::backend_err)?;
                idx.insert(key, sk.as_slice()).map_err(Self::backend_err)?;
            }
        }
        txn.commit().map_err(Self::backend_err)?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<bool, StoreError> {
        let sk = self.storage_key(key);

        let txn = self.db.begin_write().map_err(Self::backend_err)?;
        let existed;
        {
            let mut table = txn.open_table(DATA_TABLE).map_err(Self::backend_err)?;
            existed = table.remove(sk.as_slice()).map_err(Self::backend_err)?.is_some();

            if self.encrypt_keys {
                let mut idx = txn.open_table(INDEX_TABLE).map_err(Self::backend_err)?;
                idx.remove(key).map_err(Self::backend_err)?;
            }
        }
        txn.commit().map_err(Self::backend_err)?;
        Ok(existed)
    }

    pub async fn list(&self, prefix: &str, limit: usize) -> Result<Vec<KvEntry>, StoreError> {
        if self.encrypt_keys && self.cipher.is_some() {
            // With encrypted keys: use the index table for prefix matching
            let txn = self.db.begin_read().map_err(Self::backend_err)?;
            let idx = txn.open_table(INDEX_TABLE).map_err(Self::backend_err)?;
            let data = txn.open_table(DATA_TABLE).map_err(Self::backend_err)?;

            let mut entries = Vec::new();
            let iter = idx.range(prefix..).map_err(Self::backend_err)?;
            for item in iter {
                let (k, v) = item.map_err(Self::backend_err)?;
                let original_key = k.value().to_string();
                if !original_key.starts_with(prefix) {
                    break;
                }
                let storage_key = v.value().to_vec();
                if let Some(encrypted) = data.get(storage_key.as_slice()).map_err(Self::backend_err)? {
                    let value = self.decrypt_value(encrypted.value())?;
                    entries.push(KvEntry { key: original_key, value });
                }
                if entries.len() >= limit {
                    break;
                }
            }
            Ok(entries)
        } else {
            // Without encrypted keys: direct range scan on data table
            let full_prefix = format!("{}{}", self.key_prefix, prefix);
            let txn = self.db.begin_read().map_err(Self::backend_err)?;
            let table = txn.open_table(DATA_TABLE).map_err(Self::backend_err)?;

            let prefix_bytes = full_prefix.as_bytes().to_vec();
            let mut entries = Vec::new();
            let iter = table.range(prefix_bytes.as_slice()..).map_err(Self::backend_err)?;
            let prefix_len = self.key_prefix.len();
            for item in iter {
                let (k, v) = item.map_err(Self::backend_err)?;
                let key_bytes = k.value().to_vec();
                if !key_bytes.starts_with(&prefix_bytes) {
                    break;
                }
                let key = String::from_utf8_lossy(&key_bytes[prefix_len..]).to_string();
                let value = self.decrypt_value(v.value())?;
                entries.push(KvEntry { key, value });
                if entries.len() >= limit {
                    break;
                }
            }
            Ok(entries)
        }
    }

    pub async fn len(&self) -> usize {
        let txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return 0,
        };
        let table = match txn.open_table(DATA_TABLE) {
            Ok(t) => t,
            Err(_) => return 0,
        };
        table.len().unwrap_or(0) as usize
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AesGcmCipher;

    fn test_cipher() -> Arc<dyn Cipher> {
        Arc::new(AesGcmCipher::from_bytes(&[0u8; 32]).unwrap())
    }

    // --- MemoryStore without encryption ---

    #[tokio::test]
    async fn memory_set_get() {
        let store = MemoryStore::new(None, false);
        store.set("key1", b"value1").await.unwrap();
        let val = store.get("key1").await.unwrap();
        assert_eq!(&val, b"value1");
    }

    #[tokio::test]
    async fn memory_get_not_found() {
        let store = MemoryStore::new(None, false);
        let result = store.get("nonexistent").await;
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn memory_overwrite() {
        let store = MemoryStore::new(None, false);
        store.set("key1", b"old").await.unwrap();
        store.set("key1", b"new").await.unwrap();
        let val = store.get("key1").await.unwrap();
        assert_eq!(&val, b"new");
    }

    #[tokio::test]
    async fn memory_delete_existing() {
        let store = MemoryStore::new(None, false);
        store.set("key1", b"value1").await.unwrap();
        let existed = store.delete("key1").await.unwrap();
        assert!(existed);
        assert!(matches!(store.get("key1").await, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn memory_delete_nonexistent() {
        let store = MemoryStore::new(None, false);
        let existed = store.delete("nope").await.unwrap();
        assert!(!existed);
    }

    #[tokio::test]
    async fn memory_list_prefix() {
        let store = MemoryStore::new(None, false);
        store.set("users/1", b"alice").await.unwrap();
        store.set("users/2", b"bob").await.unwrap();
        store.set("orders/1", b"order1").await.unwrap();

        let entries = store.list("users/", 100).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "users/1");
        assert_eq!(&entries[0].value, b"alice");
        assert_eq!(entries[1].key, "users/2");
        assert_eq!(&entries[1].value, b"bob");
    }

    #[tokio::test]
    async fn memory_list_all() {
        let store = MemoryStore::new(None, false);
        store.set("a", b"1").await.unwrap();
        store.set("b", b"2").await.unwrap();
        store.set("c", b"3").await.unwrap();

        let entries = store.list("", 100).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn memory_list_limit() {
        let store = MemoryStore::new(None, false);
        for i in 0..10 {
            store.set(&format!("k{i}"), b"v").await.unwrap();
        }
        let entries = store.list("", 3).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn memory_len() {
        let store = MemoryStore::new(None, false);
        assert_eq!(store.len().await, 0);
        assert!(store.is_empty().await);
        store.set("a", b"1").await.unwrap();
        assert_eq!(store.len().await, 1);
        assert!(!store.is_empty().await);
    }

    // --- MemoryStore with encryption (values only) ---

    #[tokio::test]
    async fn encrypted_values_roundtrip() {
        let store = MemoryStore::new(Some(test_cipher()), false);
        store.set("secret", b"plaintext data").await.unwrap();

        // Value is stored encrypted (not recoverable without cipher)
        let raw_data = store.data.read().await;
        let stored = raw_data.get("secret".as_bytes()).unwrap();
        assert_ne!(stored, b"plaintext data");
        assert!(stored.len() > b"plaintext data".len()); // nonce + tag overhead
        drop(raw_data);

        // Reading decrypts transparently
        let val = store.get("secret").await.unwrap();
        assert_eq!(&val, b"plaintext data");
    }

    #[tokio::test]
    async fn encrypted_values_list() {
        let store = MemoryStore::new(Some(test_cipher()), false);
        store.set("users/1", b"alice").await.unwrap();
        store.set("users/2", b"bob").await.unwrap();

        let entries = store.list("users/", 100).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(&entries[0].value, b"alice");
        assert_eq!(&entries[1].value, b"bob");
    }

    // --- MemoryStore with full encryption (keys + values) ---

    #[tokio::test]
    async fn encrypted_keys_roundtrip() {
        let store = MemoryStore::new(Some(test_cipher()), true);
        store.set("users/123", b"alice").await.unwrap();

        // Storage key is HMAC(original_key), not the original key
        let raw_data = store.data.read().await;
        assert!(!raw_data.contains_key("users/123".as_bytes()));
        assert_eq!(raw_data.len(), 1); // one entry exists
        drop(raw_data);

        // Lookup still works (same HMAC computed)
        let val = store.get("users/123").await.unwrap();
        assert_eq!(&val, b"alice");
    }

    #[tokio::test]
    async fn encrypted_keys_list_with_index() {
        let store = MemoryStore::new(Some(test_cipher()), true);
        store.set("users/1", b"alice").await.unwrap();
        store.set("users/2", b"bob").await.unwrap();
        store.set("orders/1", b"order").await.unwrap();

        // Prefix scan works via the key_index
        let entries = store.list("users/", 100).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "users/1");
        assert_eq!(&entries[0].value, b"alice");
    }

    #[tokio::test]
    async fn encrypted_keys_delete() {
        let store = MemoryStore::new(Some(test_cipher()), true);
        store.set("key1", b"val1").await.unwrap();
        assert!(store.delete("key1").await.unwrap());
        assert!(matches!(store.get("key1").await, Err(StoreError::NotFound)));

        // Index also cleaned up
        let idx = store.key_index.read().await;
        assert!(idx.is_empty());
    }

    // --- Store enum dispatch ---

    #[tokio::test]
    async fn store_enum_memory() {
        let store = Store::Memory(MemoryStore::new(Some(test_cipher()), true));
        store.set("k", b"v").await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), b"v");
        assert_eq!(store.len().await, 1);

        let entries = store.list("", 100).await.unwrap();
        assert_eq!(entries.len(), 1);

        assert!(store.delete("k").await.unwrap());
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn store_binary_values() {
        let store = Store::Memory(MemoryStore::new(Some(test_cipher()), false));
        let binary = vec![0u8, 1, 2, 255, 254, 253, 0, 0];
        store.set("bin", &binary).await.unwrap();
        let val = store.get("bin").await.unwrap();
        assert_eq!(val, binary);
    }

    #[tokio::test]
    async fn store_empty_value() {
        let store = Store::Memory(MemoryStore::new(Some(test_cipher()), false));
        store.set("empty", b"").await.unwrap();
        let val = store.get("empty").await.unwrap();
        assert!(val.is_empty());
    }

    #[tokio::test]
    async fn store_large_value() {
        let store = Store::Memory(MemoryStore::new(Some(test_cipher()), true));
        let large = vec![42u8; 1024 * 64]; // 64KB
        store.set("big", &large).await.unwrap();
        let val = store.get("big").await.unwrap();
        assert_eq!(val, large);
    }

    // ═══════════════════════════════════════════════════════════════════
    // RedbStore integration tests (real DB on disk + AES-256-GCM)
    // ═══════════════════════════════════════════════════════════════════

    #[cfg(feature = "redb")]
    mod redb_integration {
        use super::*;
        use std::sync::atomic::{AtomicU32, Ordering};

        static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

        /// Unique temp DB path per test to avoid file-level locking conflicts.
        fn temp_db_path() -> String {
            let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            let pid = std::process::id();
            format!("/tmp/proxy_core_test_{}_{}.redb", pid, n)
        }

        /// Cleanup helper.
        fn remove_db(path: &str) {
            let _ = std::fs::remove_file(path);
        }

        fn test_cipher() -> Arc<dyn Cipher> {
            Arc::new(AesGcmCipher::from_bytes(&[0xABu8; 32]).unwrap())
        }

        // --- Basic CRUD ---

        #[tokio::test]
        async fn redb_set_get_plaintext() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            store.set("key1", b"value1").await.unwrap();
            let val = store.get("key1").await.unwrap();
            assert_eq!(&val, b"value1");
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_get_not_found() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            let result = store.get("nonexistent").await;
            assert!(matches!(result, Err(StoreError::NotFound)));
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_overwrite() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            store.set("key1", b"old").await.unwrap();
            store.set("key1", b"new").await.unwrap();
            let val = store.get("key1").await.unwrap();
            assert_eq!(&val, b"new");
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_delete_existing() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            store.set("key1", b"value1").await.unwrap();
            let existed = store.delete("key1").await.unwrap();
            assert!(existed);
            assert!(matches!(store.get("key1").await, Err(StoreError::NotFound)));
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_delete_nonexistent() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            let existed = store.delete("nope").await.unwrap();
            assert!(!existed);
            remove_db(&path);
        }

        // --- Prefix scan ---

        #[tokio::test]
        async fn redb_list_prefix() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            store.set("users/1", b"alice").await.unwrap();
            store.set("users/2", b"bob").await.unwrap();
            store.set("orders/1", b"order1").await.unwrap();

            let entries = store.list("users/", 100).await.unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].key, "users/1");
            assert_eq!(&entries[0].value, b"alice");
            assert_eq!(entries[1].key, "users/2");
            assert_eq!(&entries[1].value, b"bob");
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_list_limit() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            for i in 0..10 {
                store.set(&format!("k{i:02}"), b"v").await.unwrap();
            }
            let entries = store.list("", 3).await.unwrap();
            assert_eq!(entries.len(), 3);
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_len() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, None, false, String::new()).unwrap();
            assert_eq!(store.len().await, 0);
            store.set("a", b"1").await.unwrap();
            store.set("b", b"2").await.unwrap();
            assert_eq!(store.len().await, 2);
            remove_db(&path);
        }

        // --- AES-256-GCM encrypted values ---

        #[tokio::test]
        async fn redb_encrypted_values_roundtrip() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();
            store.set("secret", b"plaintext data").await.unwrap();

            // Reading decrypts transparently
            let val = store.get("secret").await.unwrap();
            assert_eq!(&val, b"plaintext data");

            // Open a second handle on the SAME file (shared via db_pool)
            // WITHOUT cipher — reads raw ciphertext
            let raw_store = RedbStore::new(&path, None, false, String::new()).unwrap();
            let raw = raw_store.get("secret").await.unwrap();
            assert_ne!(&raw, b"plaintext data");
            assert!(raw.len() > b"plaintext data".len()); // nonce + tag overhead

            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_encrypted_values_list() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();
            store.set("users/1", b"alice").await.unwrap();
            store.set("users/2", b"bob").await.unwrap();

            let entries = store.list("users/", 100).await.unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(&entries[0].value, b"alice");
            assert_eq!(&entries[1].value, b"bob");
            remove_db(&path);
        }

        // --- Full encryption: HMAC keys + AES values ---

        #[tokio::test]
        async fn redb_encrypted_keys_roundtrip() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), true, String::new()).unwrap();
            store.set("users/123", b"alice").await.unwrap();

            let val = store.get("users/123").await.unwrap();
            assert_eq!(&val, b"alice");

            assert!(matches!(store.get("users/999").await, Err(StoreError::NotFound)));
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_encrypted_keys_list_with_index() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), true, String::new()).unwrap();
            store.set("users/1", b"alice").await.unwrap();
            store.set("users/2", b"bob").await.unwrap();
            store.set("orders/1", b"order").await.unwrap();

            let entries = store.list("users/", 100).await.unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].key, "users/1");
            assert_eq!(&entries[0].value, b"alice");
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_encrypted_keys_delete() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), true, String::new()).unwrap();
            store.set("key1", b"val1").await.unwrap();
            assert!(store.delete("key1").await.unwrap());
            assert!(matches!(store.get("key1").await, Err(StoreError::NotFound)));
            remove_db(&path);
        }

        // --- Store enum dispatch ---

        #[tokio::test]
        async fn redb_store_enum_dispatch() {
            let path = temp_db_path();
            let redb = RedbStore::new(&path, Some(test_cipher()), true, String::new()).unwrap();
            let store = Store::Redb(redb);

            store.set("k", b"v").await.unwrap();
            assert_eq!(store.get("k").await.unwrap(), b"v");
            assert_eq!(store.len().await, 1);

            let entries = store.list("", 100).await.unwrap();
            assert_eq!(entries.len(), 1);

            assert!(store.delete("k").await.unwrap());
            assert!(store.is_empty().await);
            remove_db(&path);
        }

        // --- Edge cases ---

        #[tokio::test]
        async fn redb_binary_values() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();
            let binary = vec![0u8, 1, 2, 255, 254, 253, 0, 0];
            store.set("bin", &binary).await.unwrap();
            let val = store.get("bin").await.unwrap();
            assert_eq!(val, binary);
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_empty_value() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();
            store.set("empty", b"").await.unwrap();
            let val = store.get("empty").await.unwrap();
            assert!(val.is_empty());
            remove_db(&path);
        }

        #[tokio::test]
        async fn redb_large_value_256kb() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), true, String::new()).unwrap();
            let large = vec![42u8; 1024 * 256]; // 256KB
            store.set("big", &large).await.unwrap();
            let val = store.get("big").await.unwrap();
            assert_eq!(val, large);
            remove_db(&path);
        }

        // --- Namespace isolation ---

        #[tokio::test]
        async fn redb_key_prefix_isolates_namespaces() {
            let path = temp_db_path();
            // Both stores share the same Database via db_pool — no lock conflict
            let store_a = RedbStore::new(&path, None, false, "ns_a/".into()).unwrap();
            let store_b = RedbStore::new(&path, None, false, "ns_b/".into()).unwrap();

            store_a.set("key", b"from_a").await.unwrap();
            store_b.set("key", b"from_b").await.unwrap();

            assert_eq!(&store_a.get("key").await.unwrap(), b"from_a");
            assert_eq!(&store_b.get("key").await.unwrap(), b"from_b");
            remove_db(&path);
        }

        // --- Persistence ---

        #[tokio::test]
        async fn redb_data_persists_across_reopen() {
            let path = temp_db_path();
            {
                let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();
                store.set("persist", b"durable").await.unwrap();
            }
            {
                let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();
                let val = store.get("persist").await.unwrap();
                assert_eq!(&val, b"durable");
            }
            remove_db(&path);
        }

        // --- ACID consistency ---

        #[tokio::test]
        async fn redb_many_writes_consistent() {
            let path = temp_db_path();
            let store = RedbStore::new(&path, Some(test_cipher()), false, String::new()).unwrap();

            for i in 0..100u32 {
                store.set(&format!("item/{i:04}"), &i.to_le_bytes()).await.unwrap();
            }

            assert_eq!(store.len().await, 100);

            for i in 0..100u32 {
                let val = store.get(&format!("item/{i:04}")).await.unwrap();
                assert_eq!(val, i.to_le_bytes());
            }

            let entries = store.list("item/", 200).await.unwrap();
            assert_eq!(entries.len(), 100);
            remove_db(&path);
        }
    }
}
