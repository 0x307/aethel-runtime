//! # aethel-vault
//!
//! **Aethel-Vault** is the blind-state quantum wallet — a homomorphic
//! encryption-based wallet where the server never sees plaintext balances.
//!
//! ## Architecture
//!
//! Aethel-Vault implements the second of two decoupled end-states in the
//! Aethel protocol suite:
//!
//! ```text
//! +---------------------------------------------------------------------------------+
//! |                          END-STATE 2: AETHEL-VAULT                              |
//! |                (Decoupled Anonymous Quantum Wallet Storage)                     |
//! |                                                                                 |
//! |  - Hybrid Multi-Primitive Core (M-LWE Lattice + Syndrome Decoding Code)         |
//! |  - On-Chain Threshold Fully Homomorphic Encryption (TFHE) Ciphertext States     |
//! |  - Hardware Level: Silicon SRAM PUF Fuzzy Extractor (Keyless Memory)            |
//! |  - 5D Hypercube Disjoint Path Secret Sharing Routing (Q_5 Network)              |
//! +---------------------------------------------------------------------------------+
//! ```
//!
//! ## Modules
//!
//! - [`vault`] — TFHE Vault Smart Contract. Homomorphic balance management
//!   using `FheUint64` ciphertexts via `tfhe-rs`. Entry points:
//!   `init_vault`, `register_vault_ciphertext`, `homomorphic_transfer`.
//!
//! - [`client`] — TFHE Client SDK (wasm-bindgen, `wasm` feature only). Key
//!   generation, balance encryption, payload construction, and decryption.
//!
//! - [`storage`] — HelixDB Storage Adapter (`std` feature only). Vector-graph
//!   hybrid database for encrypted state storage.
//!
//! - [`sdk`] — Client SDK module. TypeScript and Rust SDK utilities.
//!
//! ## Feature Flags
//!
//! - `std` (default) — Enable standard library support. Required for the
//!   HelixDB storage adapter (async I/O, networking).
//! - `wasm` — Enable WASM-specific features: `wasm-bindgen` exports.
//!
//! ## Security Properties
//!
//! - **Zero Plaintext Leakage**: Balances exist on-chain solely as `FheUint64`
//!   ciphertexts. No validator node ever decrypts balance state.
//! - **Post-Quantum Hardness**: Security reduces to LWE hardness over the Torus,
//!   which is not susceptible to Shor's algorithm.
//! - **Ephemeral Vault IDs**: Anonymous vault identifiers derived from
//!   Polymorphic Lattice Projections; no persistent on-chain footprint.

#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

// ── WASM allocator + panic handler ────────────────────────────────────────────
//
// For wasm32-unknown-unknown without std, we need:
// 1. A global allocator (wasm-bindgen provides one via its start function)
// 2. A panic handler
//
// wasm-bindgen automatically provides both when it's linked in.
// We just need to ensure the wasm-bindgen start function runs.

// ── Module Declarations ───────────────────────────────────────────────────────

/// TFHE Vault Smart Contract — homomorphic balance management, `FheUint64`
/// ciphertexts, WASM target.
///
/// Entry points (WASM exports):
/// - `init_vault` — Initialize with TFHE ServerKey
/// - `register_vault_ciphertext` — Deposit encrypted balance
/// - `homomorphic_transfer` — Execute blind transfer
/// - `derive_vault_id` — Derive vault ID from PLP projection
/// - `export_vault_state` — Serialize state for HelixDB
/// - `import_vault_state` — Deserialize state from HelixDB
pub mod vault;

/// TFHE Client SDK — key generation, balance encryption, payload construction.
///
/// Primary type: [`client::AethelVaultClient`] (wasm-bindgen exported struct,
/// available only with `wasm` feature).
pub mod client;

/// Storage layer — HelixDB vector-graph hybrid database adapter.
///
/// Provides async gRPC client for encrypted vault state storage and retrieval.
/// Only available with `std` feature.
#[cfg(feature = "std")]
pub mod storage;

/// SDK module — TypeScript and Rust utilities for HelixDB integration.
pub mod sdk;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use vault::{
    derive_vault_id,
    ERR_OK,
    ERR_NOT_FOUND,
    ERR_INSUFFICIENT_BALANCE,
    ERR_DESER,
    ERR_INVALID_KEY,
};

/// Re-export ContractPayload for all targets.
pub use client::ContractPayload;

#[cfg(feature = "wasm")]
pub use client::{AethelVaultClient, SecretKeyContainer};

#[cfg(not(target_arch = "wasm32"))]
pub use client::NativeVaultClient;

#[cfg(feature = "std")]
pub use storage::helixdb::HelixDbAdapter;

// ── Top-level WASM exports ────────────────────────────────────────────────────
//
// These re-export vault functions with wasm_bindgen for direct JS consumption.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Initialize the vault with a TFHE ServerKey (WASM export).
///
/// Must be called before any other vault operations.
///
/// # Parameters
///
/// - `server_key_bytes`: Bincode-serialized `ServerKey`.
///
/// # Returns
///
/// `0` on success, non-zero error code on failure.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn vault_init(server_key_bytes: &[u8]) -> u32 {
    vault::vault_init_from_bytes(server_key_bytes)
}

/// Register a vault with an encrypted initial balance (WASM export).
///
/// # Parameters
///
/// - `vault_id`: 32-byte vault ID (derived from PLP projection via `vault_derive_id`).
/// - `initial_balance_ct`: Bincode-serialized `FheUint64` initial balance ciphertext.
///
/// # Returns
///
/// `0` on success, non-zero error code on failure.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn vault_register(vault_id: &[u8], initial_balance_ct: &[u8]) -> u32 {
    vault::vault_register_from_bytes(vault_id, initial_balance_ct)
}

/// Execute a homomorphic transfer between two vaults (WASM export).
///
/// # Parameters
///
/// - `sender_id`: 32-byte sender vault ID.
/// - `receiver_id`: 32-byte receiver vault ID.
/// - `transfer_ct`: Bincode-serialized `FheUint64` transfer amount ciphertext.
///
/// # Returns
///
/// `0` on success, non-zero error code on failure.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn vault_transfer(sender_id: &[u8], receiver_id: &[u8], transfer_ct: &[u8]) -> u32 {
    vault::vault_transfer_from_bytes(sender_id, receiver_id, transfer_ct)
}

/// Export the entire vault state as bytes for HelixDB persistence (WASM export).
///
/// # Returns
///
/// Bincode-serialized `VaultState` bytes. Empty if state is uninitialized.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn vault_export_state() -> alloc::vec::Vec<u8> {
    vault::vault_export_state()
}

/// Import vault state from HelixDB bytes (WASM export).
///
/// # Parameters
///
/// - `state_bytes`: Bincode-serialized `VaultState`.
///
/// # Returns
///
/// `0` on success, non-zero error code on failure.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn vault_import_state(state_bytes: &[u8]) -> u32 {
    vault::vault_import_state(state_bytes)
}

/// Derive a vault ID from PLP projection bytes (WASM export).
///
/// # Parameters
///
/// - `projection_bytes`: Serialized `EphemeralProjection` from aethel-core PLP.
///
/// # Returns
///
/// 32-byte vault ID as `Vec<u8>`.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn vault_derive_id(projection_bytes: &[u8]) -> alloc::vec::Vec<u8> {
    vault::derive_vault_id(projection_bytes).to_vec()
}
