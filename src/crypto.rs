//! Cryptographic primitives for transparent data encryption.
//!
//! - **AES-256-GCM** for value encryption (authenticated, with nonce + tag)
//! - **HMAC-SHA256** for deterministic key hashing (preserves exact lookups)
//! - **HKDF-SHA256** for deriving sub-keys from a master key
//!
//! Wire format for encrypted values:
//! ```text
//! [12-byte nonce][ciphertext][16-byte GCM auth tag]
//! ```

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

// ─── Errors ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CryptoError {
    Encrypt(String),
    Decrypt(String),
    InvalidKey(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypt(e) => write!(f, "encryption failed: {e}"),
            Self::Decrypt(e) => write!(f, "decryption failed: {e}"),
            Self::InvalidKey(e) => write!(f, "invalid key: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ─── Cipher trait ───────────────────────────────────────────────────

/// Trait for encryption/decryption + deterministic key hashing.
///
/// Injected into `EncryptFilter`. Can be swapped for testing.
pub trait Cipher: Send + Sync {
    /// Encrypt plaintext. Returns nonce + ciphertext + tag.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt ciphertext. Expects nonce + ciphertext + tag.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Deterministic key hash (for storage key mapping).
    /// Same input always produces same output — required for lookups.
    fn hmac_key(&self, key: &[u8]) -> Vec<u8>;
}

// ─── AES-256-GCM + HMAC-SHA256 implementation ──────────────────────

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// AES-256-GCM cipher with HMAC-SHA256 key hashing.
///
/// Derives two sub-keys from the master key via HKDF:
/// - `enc_key`: for AES-256-GCM encryption of values
/// - `mac_key`: for HMAC-SHA256 hashing of storage keys
pub struct AesGcmCipher {
    aes: Aes256Gcm,
    mac_key: [u8; KEY_LEN],
}

impl AesGcmCipher {
    /// Create from a hex-encoded master key (64 hex chars = 32 bytes).
    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        let master = hex_decode(hex_key)
            .map_err(|e| CryptoError::InvalidKey(format!("bad hex: {e}")))?;
        if master.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey(format!(
                "expected {KEY_LEN} bytes, got {}",
                master.len()
            )));
        }
        Self::from_bytes(&master)
    }

    /// Create from raw 32-byte master key.
    pub fn from_bytes(master: &[u8]) -> Result<Self, CryptoError> {
        if master.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey(format!(
                "expected {KEY_LEN} bytes, got {}",
                master.len()
            )));
        }

        // Derive enc_key and mac_key via HKDF
        let hk = hkdf::Hkdf::<Sha256>::new(None, master);
        let mut enc_key = [0u8; KEY_LEN];
        let mut mac_key = [0u8; KEY_LEN];
        hk.expand(b"proxy_core_enc", &mut enc_key)
            .map_err(|e| CryptoError::InvalidKey(format!("HKDF expand enc: {e}")))?;
        hk.expand(b"proxy_core_mac", &mut mac_key)
            .map_err(|e| CryptoError::InvalidKey(format!("HKDF expand mac: {e}")))?;

        let aes = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| CryptoError::InvalidKey(format!("AES init: {e}")))?;

        Ok(Self { aes, mac_key })
    }

    /// Generate a random 32-byte master key as hex string.
    /// Useful for creating new keys.
    pub fn generate_key_hex() -> String {
        let mut key = [0u8; KEY_LEN];
        use aes_gcm::aead::rand_core::RngCore;
        OsRng.fill_bytes(&mut key);
        hex_encode(&key)
    }
}

impl Cipher for AesGcmCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .aes
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        // Wire format: [nonce (12)][ciphertext + tag]
        let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Decrypt(format!(
                "ciphertext too short: {} bytes (min {})",
                data.len(),
                NONCE_LEN + TAG_LEN
            )));
        }

        let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
        let ciphertext = &data[NONCE_LEN..];

        self.aes
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::Decrypt(e.to_string()))
    }

    fn hmac_key(&self, key: &[u8]) -> Vec<u8> {
        let mut mac: Hmac<Sha256> =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.mac_key).expect("HMAC key length is valid");
        mac.update(key);
        mac.finalize().into_bytes().to_vec()
    }
}

// ─── Hex helpers (no extra dependency) ──────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> AesGcmCipher {
        // Fixed test key (32 bytes of zeros — never use in production!)
        AesGcmCipher::from_bytes(&[0u8; 32]).unwrap()
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let cipher = test_cipher();
        let plaintext = b"hello, proxy_core!";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        assert_ne!(&encrypted, plaintext); // not plaintext
        assert!(encrypted.len() > plaintext.len()); // nonce + tag overhead

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let cipher = test_cipher();
        let plaintext = b"same input";

        let a = cipher.encrypt(plaintext).unwrap();
        let b = cipher.encrypt(plaintext).unwrap();
        // Different nonces → different ciphertexts (probabilistic encryption)
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_rejects_tampered_data() {
        let cipher = test_cipher();
        let mut encrypted = cipher.encrypt(b"secret").unwrap();
        // Flip a byte in ciphertext (after nonce)
        encrypted[NONCE_LEN] ^= 0xFF;
        assert!(cipher.decrypt(&encrypted).is_err());
    }

    #[test]
    fn decrypt_rejects_too_short() {
        let cipher = test_cipher();
        assert!(cipher.decrypt(&[0u8; 10]).is_err());
    }

    #[test]
    fn hmac_is_deterministic() {
        let cipher = test_cipher();
        let a = cipher.hmac_key(b"users/123");
        let b = cipher.hmac_key(b"users/123");
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_different_inputs_differ() {
        let cipher = test_cipher();
        let a = cipher.hmac_key(b"users/123");
        let b = cipher.hmac_key(b"users/456");
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_output_is_32_bytes() {
        let cipher = test_cipher();
        let h = cipher.hmac_key(b"test");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn generate_key_hex_is_64_chars() {
        let key = AesGcmCipher::generate_key_hex();
        assert_eq!(key.len(), 64);
        // Must be valid hex
        AesGcmCipher::from_hex(&key).unwrap();
    }

    #[test]
    fn from_hex_roundtrip() {
        let key_hex = AesGcmCipher::generate_key_hex();
        let cipher = AesGcmCipher::from_hex(&key_hex).unwrap();
        let plaintext = b"test data";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(AesGcmCipher::from_bytes(&[0u8; 16]).is_err());
        assert!(AesGcmCipher::from_hex("aabb").is_err());
    }
}
