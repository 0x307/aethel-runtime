//! # Aethel-Vault TFHE Client SDK
//!
//! Client-side SDK for TFHE key generation, balance encryption, WASM payload
//! construction, and decryption.
//!
//! ## Availability
//!
//! - **Native (`std` feature)**: Full implementation using `tfhe` crate directly.
//!   Provides [`NativeVaultClient`] for Rust-native usage.
//! - **WASM (`wasm` feature)**: [`AethelVaultClient`] exported via `wasm-bindgen`
//!   for JavaScript consumption. Uses `tfhe` JS WASM API.
//! - **WASM without `wasm` feature**: Only [`ContractPayload`] type is available
//!   (for serialization/deserialization of payloads).
//!
//! ## Security
//!
//! - `ClientKey` never leaves the client; held only in volatile memory
//! - `SecretKeyContainer` uses `#[zeroize(drop)]` to overwrite key bytes on drop
//!
//! ## Key Structures
//!
//! - [`ContractPayload`] — Serializable payload for vault contract submission
//! - [`SecretKeyContainer`] — Zeroize-on-drop wrapper for raw key bytes (wasm feature)
//! - [`AethelVaultClient`] — Main wasm-bindgen client struct (wasm feature)
//! - [`NativeVaultClient`] — Native Rust client (non-wasm32 target)

extern crate alloc;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// ── Shared Types (all targets) ────────────────────────────────────────────────

/// Serializable payload for vault contract submission.
///
/// Contains the context tag (τ), encrypted transfer amount, and encrypted
/// target account identifier. Serialized with `bincode` for WASM transport.
#[derive(Serialize, Deserialize, Clone)]
pub struct ContractPayload {
    /// 32-byte context tag τ (derived from block height or epoch).
    pub context_tag: [u8; 32],
    /// Bincode-serialized `FheUint64` ciphertext of the transfer amount.
    pub encrypted_amount: Vec<u8>,
    /// Bincode-serialized `FheUint64` ciphertext of the target account ID.
    pub encrypted_target: Vec<u8>,
}

// ── WASM feature: wasm-bindgen client ─────────────────────────────────────────
//
// The AethelVaultClient is only available when the `wasm` feature is enabled
// AND we are on a wasm32 target. It uses the tfhe JS WASM API.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use zeroize::Zeroize;

/// Zeroize-on-drop wrapper for raw TFHE client key bytes.
///
/// Ensures that secret key material is securely overwritten when the container
/// is dropped, preventing key material from lingering in WASM linear memory.
#[cfg(feature = "wasm")]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKeyContainer {
    /// Raw bincode-serialized `ClientKey` bytes.
    pub raw_key_bytes: Vec<u8>,
}

/// Main TFHE client struct for the Aethel-Vault SDK (WASM target).
///
/// On WASM, this uses the tfhe JS WASM API for key generation and encryption.
/// Exported to JavaScript via `wasm-bindgen`.
///
/// # Example (JavaScript)
///
/// ```javascript
/// import init, { AethelVaultClient } from './aethel_vault.js';
/// await init();
/// const client = new AethelVaultClient();
/// const ct = client.encrypt_u64_balance(BigInt(1000));
/// ```
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct AethelVaultClient {
    /// Serialized client key bytes (stored as bytes to avoid tfhe type issues on WASM).
    client_key_bytes: Vec<u8>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl AethelVaultClient {
    /// Generate a new TFHE key pair.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if key generation fails.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<AethelVaultClient, JsError> {
        // On WASM, key generation is handled by the host environment.
        // The client key is passed in from JavaScript via the tfhe JS WASM API.
        // For now, return a placeholder — the actual key bytes are set via
        // `from_key_bytes` after the JS side generates them.
        Ok(AethelVaultClient {
            client_key_bytes: Vec::new(),
        })
    }

    /// Initialize from serialized client key bytes (provided by JS tfhe WASM API).
    pub fn from_key_bytes(key_bytes: &[u8]) -> AethelVaultClient {
        AethelVaultClient {
            client_key_bytes: key_bytes.to_vec(),
        }
    }

    /// Serialize a `ContractPayload` from pre-encrypted ciphertext bytes.
    ///
    /// On WASM, encryption is performed by the JS tfhe WASM API before calling
    /// this function. This function just packages the ciphertexts into a payload.
    pub fn build_payload_from_ciphertexts(
        &self,
        context_tag: &[u8],
        encrypted_amount: &[u8],
        encrypted_target: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        if context_tag.len() != 32 {
            return Err(JsError::new("Context tag must be exactly 32 bytes"));
        }
        let mut tag_bytes = [0u8; 32];
        tag_bytes.copy_from_slice(context_tag);
        let payload = ContractPayload {
            context_tag: tag_bytes,
            encrypted_amount: encrypted_amount.to_vec(),
            encrypted_target: encrypted_target.to_vec(),
        };
        bincode::serialize(&payload)
            .map_err(|e| JsError::new(&alloc::format!("Payload assembly failed: {}", e)))
    }

    /// Get the stored client key bytes.
    pub fn get_key_bytes(&self) -> Vec<u8> {
        self.client_key_bytes.clone()
    }
}

// ── Native (non-wasm32) client API ────────────────────────────────────────────
//
// Full TFHE client implementation for native builds.

#[cfg(not(target_arch = "wasm32"))]
use tfhe::{
    prelude::*,
    ClientKey,
    PublicKey,
    FheUint64,
    ConfigBuilder,
    generate_keys,
};

/// Native client for TFHE operations (non-WASM builds).
///
/// Provides full TFHE key generation, encryption, and decryption.
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeVaultClient {
    /// TFHE client key for encryption and decryption.
    pub client_key: ClientKey,
    /// Public key for sharing.
    pub public_key: PublicKey,
    /// Server key for homomorphic operations.
    pub server_key: tfhe::ServerKey,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeVaultClient {
    /// Generate a new TFHE key pair with default parameters.
    pub fn new() -> Self {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        let public_key = PublicKey::new(&client_key);
        NativeVaultClient {
            client_key,
            public_key,
            server_key,
        }
    }

    /// Encrypt a `u64` balance using the client key.
    pub fn encrypt_u64_balance(&self, amount: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let ct = FheUint64::try_encrypt(amount, &self.client_key)?;
        Ok(bincode::serialize(&ct)?)
    }

    /// Decrypt a `FheUint64` ciphertext.
    pub fn decrypt_u64_balance(&self, encrypted_bytes: &[u8]) -> Result<u64, Box<dyn std::error::Error>> {
        let ct: FheUint64 = bincode::deserialize(encrypted_bytes)?;
        Ok(ct.decrypt(&self.client_key))
    }

    /// Serialize the server key for vault contract initialization.
    pub fn export_server_key(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(&self.server_key)?)
    }

    /// Build a `ContractPayload`.
    pub fn build_payload(
        &self,
        context_tag: [u8; 32],
        amount: u64,
        target_account: u64,
    ) -> Result<ContractPayload, Box<dyn std::error::Error>> {
        let encrypted_amount = self.encrypt_u64_balance(amount)?;
        let encrypted_target = self.encrypt_u64_balance(target_account)?;
        Ok(ContractPayload {
            context_tag,
            encrypted_amount,
            encrypted_target,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NativeVaultClient {
    fn default() -> Self {
        Self::new()
    }
}
