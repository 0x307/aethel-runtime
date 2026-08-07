//! # SDK Module — Vault Client Utilities
//!
//! This module provides SDK utilities for Aethel-Vault integration, including:
//!
//! - **TypeScript SDK stub** (`client.ts`): Vault-specific TypeScript utilities
//!   that extend the shared HelixDB SDK from `aethel-id`. Provides payload
//!   serialization helpers and ephemeral vault ID generation.
//!
//! ## TypeScript SDK Note
//!
//! The canonical HelixDB TypeScript SDK (`AethelClientSDK` with
//! `mapCoeffsToVector256`, `createIngestionPayload`, `verifySaapProof`) lives
//! in `aethel-id/src/sdk/client.ts`. The `client.ts` in this module is a
//! vault-specific stub that re-exports and extends the shared SDK with
//! vault-specific functionality (payload serialization, vault ID generation).
//!
//! ## Vault SDK Responsibilities
//!
//! - Serialize `ContractPayload` structures for WASM contract submission
//! - Generate anonymous ephemeral vault IDs from context tags and nonces
//! - Bridge between the WASM `AethelVaultClient` and the HelixDB storage layer
//!
//! ## See Also
//!
//! - [`crate::client`] — Rust TFHE client SDK (wasm-bindgen)
//! - [`crate::storage::helixdb`] — HelixDB gRPC adapter
//! - `aethel-id/src/sdk/client.ts` — Canonical HelixDB TypeScript SDK
