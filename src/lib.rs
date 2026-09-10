//! # aethel-vault
//!
//! **aethel-vault** is the agent-held wallet: the crate is `aethel-vault`,
//! the repository is `aethel-runtime`. Not to be confused with
//! `pqc-privacy`'s unrelated AES-GCM + Reed-Solomon *shard* module
//! (historically also called "vault" there — that is a research
//! component; this crate owns the word "wallet").
//!
//! ## Two assets, not one (V-7)
//!
//! This crate holds and moves two entirely separate things, and never
//! bridges between them:
//!
//! - **Confidential internal balance** (`fhe-state` feature,
//!   [`vault`]/[`client`]) — an `FheUint64` ciphertext the vault never
//!   decrypts, homomorphically transferred between agent-chosen ledger
//!   entries. It exists only in the agent's own storage (which may be a
//!   hostile host); privacy here is against *that storage*. **It is not a
//!   token, not on any chain, and not USDC.** Older docs in this crate
//!   described this as "on-chain" with "validator" processing — that
//!   language was wrong and has been corrected; there is no chain and no
//!   validator anywhere in this crate.
//! - **Settlement asset** (`signer` feature, default,
//!   [`settlement`]) — USDC on Base, Ethereum, or Arbitrum One, moved by an
//!   EIP-3009 `transferWithAuthorization` signature the agent's *external*
//!   wallet produces. Public by nature; bounded by [`policy::SpendPolicy`].
//!
//! An FHE transfer never moves USDC, and an EIP-3009 authorization never
//! changes an FHE balance unless the agent explicitly records it — there
//! is no bridge in this crate. See [`vault`]'s module docs for more detail.
//!
//! ## Zero ECDSA / 100% PQC signer; secp256k1 lives in the agent's wallet
//!
//! This crate never implements, produces, or verifies a secp256k1 ECDSA
//! signature. The [`settlement::SettlementSigner`] trait is the injection
//! point: an agent's existing wallet (hardware, MPC, browser, HSM) signs
//! the EIP-712 digest this crate builds. This crate's *own* signatures —
//! spend intents, settlement receipts, wallet-bind attestations, HITL
//! approvals — are all ML-DSA-65 via `aethel_core::signing::Identity`,
//! under the purpose-separated contexts in `aethel_core::signing::purpose`.
//! A hybrid (PQC + classical) posture, if wanted, belongs at SAGP (the
//! gateway), not here. See [`settlement`]'s module docs for the full
//! rationale and the locked rules it encodes.
//!
//! ## Custody rule: the ServerKey — and the settlement signer — never leave the agent
//!
//! - **ServerKey** (`fhe-state` feature): held only in a process-local,
//!   never-serialized runtime structure. It never appears in exported or
//!   persisted [`vault::VaultState`] bytes — see [`vault`]'s "Custody rule"
//!   docs (V-2).
//! - **Settlement signer** (`signer` feature): the
//!   [`settlement::SettlementSigner`] trait is injected by the caller; no
//!   implementation ships in this crate except a test-only mock. This
//!   crate never holds a secp256k1 private key.
//! - **There is no "hosted vault" mode.** Naming a Cargo feature `hosted`
//!   is a hard compile error (see below). Do not host `aethel-vault` on a
//!   third party's infrastructure; the agent runtime, or a wallet process
//!   the principal already runs, holds every secret this crate touches.
//!
//! ## Feature Flags
//!
//! - `signer` (**default**) — [`settlement`] (EIP-3009/x402 export),
//!   [`policy`] (standing spend policy), [`receipt`] (optional signed
//!   receipts). No `tfhe`, no HelixDB gRPC stack. This is the Wave-1
//!   "vault as signer of a normal USDC wallet" path.
//! - `fhe-state` — the confidential internal ledger ([`vault`]'s
//!   `VaultState`/homomorphic transfer state machine, [`client`]'s
//!   `NativeVaultClient`). Pulls `tfhe`. Optional: a differentiator for
//!   agents storing state on a hostile host, not a Wave-1 gate.
//! - `helixdb` — the [`storage::helixdb`] gRPC adapter. Pulls `tokio`,
//!   `tonic`, `prost`, and runs `prost-build` in `build.rs`.
//! - `std` (default) — standard library support. Does not, by itself,
//!   pull `tokio`/`tonic`/`prost` (that is `helixdb`'s job) or `tfhe`
//!   (that is `fhe-state`'s job).
//! - `wasm` — `wasm-bindgen` exports for the confidential-ledger state
//!   machine and client.
//! - `hosted` — **does not exist as a real feature.** Enabling it is a
//!   hard `compile_error!` (see below). This is the custody rule enforced
//!   structurally, not just documented.
//!
//! `default = ["std", "signer"]`: a plain `cargo add aethel-vault` builds
//! the thin signer path only — no `tfhe`, no `tokio`, no `tonic`, no
//! `prost` anywhere in the dependency graph (confirm with `cargo tree -e
//! normal`).
//!
//! ## Modules
//!
//! - [`settlement`] — EIP-3009/x402 export (`signer`, default). `Chain`
//!   table, `TransferWithAuthorization`, `SettlementSigner` trait,
//!   `Wallet::authorize_eip3009`.
//! - [`policy`] — standing spend policy (`signer`, default). `SpendPolicy`,
//!   `PolicyState`, `Rail`, `HitlApproval`.
//! - [`receipt`] — optional signed settlement receipts (`signer`, default).
//! - [`error`] — `VaultError`, the Rust-native error type for the
//!   `signer`-mode surface.
//! - [`vault`] — the confidential-ledger state machine (`fhe-state`).
//!   Homomorphic balance management using `FheUint64` ciphertexts via
//!   `tfhe-rs`.
//! - [`client`] — the confidential ledger's client SDK (`fhe-state`
//!   native, or `wasm` for JS).
//! - [`storage`] — HelixDB storage adapter (`helixdb` feature only).
//! - [`sdk`] — Client SDK module. TypeScript and Rust SDK utilities.
//!
//! ## Security Properties
//!
//! - **Zero Plaintext Leakage (confidential ledger)**: `fhe-state` balances
//!   exist solely as `FheUint64` ciphertexts in the agent's own storage;
//!   this crate never decrypts them.
//! - **Post-Quantum Hardness**: the confidential ledger's security reduces
//!   to LWE hardness over the Torus; this crate's own signatures
//!   (spend intent, receipt, wallet bind, HITL approval) are ML-DSA-65.
//! - **Ephemeral Vault IDs**: anonymous vault identifiers derived from
//!   Polymorphic Lattice Projections; no persistent on-chain footprint —
//!   and no on-chain footprint of any kind, since the confidential ledger
//!   is not on any chain.
//! - **Policy before signature**: [`settlement::Wallet::authorize_eip3009`]
//!   checks [`policy::SpendPolicy`] before it ever calls the injected
//!   `SettlementSigner` or signs a `SpendIntent`. A denied or
//!   unsatisfied-HITL request produces no signature of any kind.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![cfg_attr(not(feature = "std"), no_std)]

// V-2: aethel-vault has no hosted mode, structurally. Naming this feature
// is a hard compile error, not just a documented convention — see the
// crate-level "Custody rule" docs above and `docs/TFHE-VAULT-SPEC.md`.
#[cfg(feature = "hosted")]
compile_error!(
    "aethel-vault has no hosted mode: the ServerKey (fhe-state) and the settlement \
     signer (signer) never leave the agent (SAGP-PG-001 V-2). Do not enable a \
     `hosted` feature; there is nothing behind it and there never will be."
);

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

/// The confidential-ledger state machine (`fhe-state` feature) —
/// homomorphic balance management, `FheUint64` ciphertexts. See the
/// module's own docs for the "Two assets, not one" statement and the V-2
/// custody rule. [`vault::derive_vault_id`] and the `ERR_*` constants are
/// available regardless of `fhe-state`.
pub mod vault;

/// The confidential ledger's client SDK — key generation, balance
/// encryption, payload construction. [`client::LedgerPayload`] is always
/// available; [`client::NativeVaultClient`] requires `fhe-state` and
/// [`client::AethelVaultClient`] requires `wasm`.
pub mod client;

/// EIP-3009/x402 settlement export (`signer` feature, default). See the
/// module's own docs for the "Zero ECDSA / 100% PQC signer" statement.
#[cfg(feature = "signer")]
pub mod settlement;

/// Standing spend policy, enforced before any settlement intent is signed
/// (`signer` feature, default).
#[cfg(feature = "signer")]
pub mod policy;

/// Optional signed settlement receipts (`signer` feature, default).
/// Emitted only on request — see the module's own docs (V-5 / UX-001).
#[cfg(feature = "signer")]
pub mod receipt;

/// `VaultError` — the Rust-native error type for the `signer`-mode surface.
#[cfg(feature = "signer")]
pub mod error;

/// Storage layer — HelixDB vector-graph hybrid database adapter.
///
/// Provides async gRPC client for encrypted vault state storage and retrieval.
/// Only available with the `helixdb` feature.
#[cfg(feature = "helixdb")]
pub mod storage;

/// SDK module — TypeScript and Rust utilities for HelixDB integration.
pub mod sdk;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use vault::{
    derive_vault_id, ERR_DESER, ERR_INSUFFICIENT_BALANCE, ERR_INVALID_KEY, ERR_NOT_FOUND, ERR_OK,
    ERR_UNAUTHORIZED, ERR_WIRE_VERIFY_FAILED,
};

#[cfg(feature = "fhe-state")]
pub use vault::{
    homomorphic_transfer_authenticated, homomorphic_transfer_authenticated_bytes,
    register_vault_with_identity, VaultState,
};

/// Re-export `LedgerPayload` for all targets (V-7: renamed from
/// `ContractPayload`, which remains available as a deprecated alias).
pub use client::LedgerPayload;

#[cfg(feature = "wasm")]
pub use client::{AethelVaultClient, SecretKeyContainer};

#[cfg(all(not(target_arch = "wasm32"), feature = "fhe-state"))]
pub use client::NativeVaultClient;

#[cfg(feature = "signer")]
pub use error::VaultError;

#[cfg(feature = "signer")]
pub use policy::{
    Decision, HitlApproval, PolicyState, PolicyViolation, Rail, SpendPolicy, SpendRequest,
};

#[cfg(feature = "signer")]
pub use receipt::{Receipt, SignedReceipt};

#[cfg(feature = "signer")]
pub use settlement::{
    Chain, SettlementAuthorization, SettlementError, SettlementSigner, SpendIntent,
    TransferWithAuthorization, Wallet,
};

#[cfg(feature = "helixdb")]
pub use storage::helixdb::HelixDbAdapter;

// ── Top-level WASM exports ────────────────────────────────────────────────────
//
// These re-export vault functions with wasm_bindgen for direct JS consumption.
// Homomorphic-ledger exports additionally require `fhe-state`.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Initialize the vault with a TFHE ServerKey (WASM export, `fhe-state`).
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
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_init(server_key_bytes: &[u8]) -> u32 {
    vault::vault_init_from_bytes(server_key_bytes)
}

/// Register a vault with an encrypted initial balance (WASM export, `fhe-state`).
///
/// # Parameters
///
/// - `vault_id`: 32-byte vault ID (derived from PLP projection via `vault_derive_id`).
/// - `initial_balance_ct`: Bincode-serialized `FheUint64` initial balance ciphertext.
///
/// # Returns
///
/// `0` on success, non-zero error code on failure.
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_register(vault_id: &[u8], initial_balance_ct: &[u8]) -> u32 {
    vault::vault_register_from_bytes(vault_id, initial_balance_ct)
}

/// Execute a homomorphic transfer between two vaults (WASM export, `fhe-state`).
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
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_transfer(sender_id: &[u8], receiver_id: &[u8], transfer_ct: &[u8]) -> u32 {
    vault::vault_transfer_from_bytes(sender_id, receiver_id, transfer_ct)
}

/// Execute an authenticated homomorphic transfer from `aethel-plp-1` wire
/// bytes (WASM export, `fhe-state`). Bytes-taking counterpart of
/// [`vault_transfer`] that also checks a PLP ownership proof against the
/// sender vault's registered identity — see
/// [`vault::homomorphic_transfer_authenticated_bytes`] for the full order
/// of checks (SAGP-PG-001 V-3 residual / `docs/ROADMAP.md` §2).
///
/// # Parameters
///
/// - `sender_id` / `receiver_id`: 32-byte vault IDs.
/// - `transfer_ct`: Bincode-serialized `FheUint64` transfer amount ciphertext.
/// - `projection_bytes` / `proof_bytes`: `aethel-plp-1` wire envelopes.
/// - `context`: the verifier's own context bytes.
///
/// # Returns
///
/// `0` on success, non-zero error code on failure (including the new
/// `ERR_WIRE_VERIFY_FAILED` (6)).
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_transfer_authenticated_bytes(
    sender_id: &[u8],
    receiver_id: &[u8],
    transfer_ct: &[u8],
    projection_bytes: &[u8],
    proof_bytes: &[u8],
    context: &[u8],
) -> u32 {
    vault::wasm_vault_transfer_authenticated_bytes(
        sender_id,
        receiver_id,
        transfer_ct,
        projection_bytes,
        proof_bytes,
        context,
    )
}

/// Register a vault bound to an `aethel-core` PLP identity projection
/// (WASM export, `fhe-state`).
///
/// Unlike [`vault_register`], the vault ID is derived server-side from
/// `projection_bytes` rather than caller-supplied, so it cannot be
/// registered under an ID unrelated to the projection.
///
/// # Parameters
///
/// - `projection_bytes`: Serialized `EphemeralProjection` from aethel-core PLP.
/// - `initial_balance_ct`: Bincode-serialized `FheUint64` initial balance ciphertext.
///
/// # Returns
///
/// The derived 32-byte vault ID, or an empty `Vec` if `projection_bytes`
/// does not decode as an `EphemeralProjection`.
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_register_with_identity(
    projection_bytes: &[u8],
    initial_balance_ct: &[u8],
) -> alloc::vec::Vec<u8> {
    vault::wasm_vault_register_with_identity(projection_bytes, initial_balance_ct)
}

/// Export the entire vault state as bytes for HelixDB persistence (WASM
/// export, `fhe-state`).
///
/// Never contains the ServerKey — see [`vault`]'s "Custody rule" docs (V-2).
///
/// # Returns
///
/// Bincode-serialized `VaultState` bytes (version-prefixed). Empty if
/// state is uninitialized.
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_export_state() -> alloc::vec::Vec<u8> {
    vault::vault_export_state()
}

/// Import vault state from HelixDB bytes (WASM export, `fhe-state`).
///
/// # Parameters
///
/// - `state_bytes`: Bincode-serialized `VaultState` (version-prefixed).
///
/// # Returns
///
/// `0` on success, non-zero error code on failure.
#[cfg(all(feature = "wasm", feature = "fhe-state"))]
#[wasm_bindgen]
pub fn vault_import_state(state_bytes: &[u8]) -> u32 {
    vault::vault_import_state(state_bytes)
}

/// Derive a vault ID from PLP projection bytes (WASM export).
///
/// Available regardless of `fhe-state`: pure hashing.
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
