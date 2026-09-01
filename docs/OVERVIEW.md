---
title: "Aethel-Vault: Technical Overview"
version: "0.2.0"
date: "2026-09-01"
project: "aethel-vault"
---

# Aethel-Vault: Blind-State Quantum Wallet — Technical Overview

This document describes what this crate actually implements. For a target
architecture / roadmap perspective, see [`ROADMAP.md`](./ROADMAP.md).

## Table of Contents

1. [What is Aethel-Vault?](#1-what-is-aethel-vault)
2. [TFHE Homomorphic Encryption: Server-Blind Balance Management](#2-tfhe-homomorphic-encryption-server-blind-balance-management)
3. [WASM Smart Contract Architecture](#3-wasm-smart-contract-architecture)
4. [HelixDB: Vector-Graph Hybrid Storage Layer](#4-helixdb-vector-graph-hybrid-storage-layer)
5. [Identity Coupling](#5-identity-coupling)
6. [Security Properties](#6-security-properties)
7. [Threat Model](#7-threat-model)

---

## 1. What is Aethel-Vault?

**Aethel-Vault** is a blind-state wallet contract: balances exist on-chain
only as `FheUint64` ciphertexts, and homomorphic transfers execute without
any party decrypting them. It is a sibling product built on top of
[`aethel-core`](https://crates.io/crates/aethel-core) (post-quantum identity
primitives — Polymorphic Lattice Projection), not a layer inside it.

Aethel-Vault implements a wallet architecture where:

- **Balances are never decrypted on-chain.** All balance state exists exclusively as `FheUint64` ciphertexts (Torus FHE encrypted 64-bit integers).
- **Smart contracts execute homomorphically.** Deposits and transfers are computed directly over encrypted ciphertexts using the TFHE evaluation key (`ServerKey`), without any validator node ever seeing plaintext values. This is single-party FHE: one `ServerKey`, held by one party. There is no resharing, no distributed decryption, and no validator set.
- **Vault IDs are one-way derived from `aethel-core` PLP projections**, and — for vaults registered via `register_vault_with_identity` — a transfer additionally requires a caller-supplied proof that verifies against that projection via `aethel_core::plp::Verifier`. See [Identity Coupling](#5-identity-coupling).
- **The smart contract targets `wasm32-unknown-unknown`.** With the `wasm` feature and `--no-default-features`, it compiles to a small binary that delegates every homomorphic operation to its host (see [Wasmer Host Integration](../README.md#wasmer-host-integration) in the README).

### Core Design Principle: Blind-State Execution

Classical crypto wallets expose balance state to validators. Even
privacy-preserving systems like Zcash and Monero rely on UTXO shielded pools
where ingress/egress transactions expose metadata. Aethel-Vault's approach:

> **FHE Blind State:** User balances exist on-chain solely as encrypted
> ciphertexts. Smart contracts execute operations (e.g., `E(balance) − E(amount)`)
> using `tfhe-rs` without ever decrypting the underlying data on validator
> nodes. TFHE's security reduces to the hardness of Learning With Errors
> (LWE) over the Torus, a lattice problem not known to be broken by Shor's
> algorithm.

---

## 2. TFHE Homomorphic Encryption: Server-Blind Balance Management

### 2.1 What is TFHE?

**TFHE (Torus Fully Homomorphic Encryption)** is a fully homomorphic encryption scheme operating over the Torus (real numbers modulo 1). It enables arbitrary computation over encrypted data without decryption. The `tfhe-rs` library (by Zama) provides a production-grade Rust implementation.

The key insight enabling blind balance management:

```
E(a) + E(b) = E(a + b)   [Homomorphic Addition]
E(a) - E(b) = E(a - b)   [Homomorphic Subtraction]
E(a) >= E(b) = E(a >= b) [Homomorphic Comparison]
```

All operations produce new ciphertexts. The server (validator) never sees `a` or `b`.

### 2.2 Key Architecture: Client Key vs. Server Key

The TFHE key architecture enforces the blind-state property:

| Key Type | Holder | Capability |
|---|---|---|
| `ClientKey` | Client only (never transmitted) | Encrypt plaintext → ciphertext; Decrypt ciphertext → plaintext |
| `ServerKey` (EvaluationKey) | On-chain contract | Compute over ciphertexts; **cannot decrypt** |

The `ServerKey` contains only the public bootstrap and key-switching parameters. It allows arbitrary additions, subtractions, and comparisons directly over ciphertexts without having the ability to decrypt.

### 2.3 Homomorphic Balance Operations

**Deposit (`register_vault_ciphertext`):**
```
Client: ct_balance = Encrypt(initial_balance, client_key)
Client → Contract: (vault_id, ct_balance)
Contract: store(vault_id, ct_balance)  // No decryption
```

**Transfer (`homomorphic_transfer`):**
```
// 1. Homomorphic Solvency Check
is_sufficient = sk.ge(sender_balance_ct, transfer_amount_ct)

// 2. Conditional Subtraction (Homomorphic Branching)
actual_deduction = sk.select(is_sufficient, transfer_amount_ct, zero_ct)

// 3. Update Balances Homomorphically
new_sender_balance = sk.sub(sender_balance_ct, actual_deduction)
new_receiver_balance = sk.add(receiver_balance_ct, actual_deduction)
```

The critical property: `is_sufficient` is an encrypted boolean. The WASM execution engine cannot read it. Classical `if/else` control flow would leak state. Instead, the homomorphic select acts as a multiplexer — the transfer either applies or doesn't, entirely within ciphertext space, and the return code doesn't distinguish the two cases.

### 2.4 TFHE Parameter Choices

| Parameter Set | N (GLWE Dim) | Bits of Precision | Server Key Size |
|---|---|---|---|
| `PARAM_MESSAGE_1_CARRY_0` | 2^9 = 512 | 1-bit (Boolean) | ~3–8 MB |
| `PARAM_MESSAGE_2_CARRY_2_PBS_KS` | 2^10 = 1024 | 2-bit + 2-bit Carry | ~30–50 MB |
| `PARAM_MESSAGE_4_CARRY_4_KS_PBS` | 2^11 = 2048 | 4-bit + 4-bit Carry | ~120+ MB |

Aethel-Vault uses `PARAM_MESSAGE_2_CARRY_2_KS_PBS` as the default parameter set, balancing precision and server key size.

---

## 3. WASM Smart Contract Architecture

### 3.1 Runtime Target

The Aethel-Vault smart contract compiles to `wasm32-unknown-unknown`. It
delegates homomorphic operations to the host rather than linking `tfhe-rs`
into the wasm32 binary itself (see [Wasmer Host
Integration](../README.md#wasmer-host-integration)):

```
extern crate alloc;
```

### 3.2 Contract Entry Points

The contract exposes these `#[no_mangle] pub extern "C"` functions as WASM exports (see [`README.md`](../README.md#error-codes) for the full error code table):

| Function | Parameters | Returns | Purpose |
|---|---|---|---|
| `init_vault` | `server_key_bytes_ptr`, `len` | `u32` | Initialize contract with TFHE ServerKey |
| `register_vault_ciphertext` | `vault_id_ptr`, `vault_id_len`, `initial_ct_ptr`, `initial_ct_len` | `u32` | Deposit encrypted balance, caller-supplied vault ID |
| `homomorphic_transfer` | sender/receiver IDs + transfer ciphertext | `u32` | Execute blind transfer, authorized by ciphertext + `ServerKey` possession |
| `export_vault_state_len` / `export_vault_state_ptr` | — | — | Serialize state for storage |
| `import_vault_state` | `state_bytes_ptr`, `len` | `u32` | Deserialize state from storage |

Two further entry points exist as native Rust functions (not `extern "C"`, for the reason given in [`ROADMAP.md`](./ROADMAP.md)): `register_vault_with_identity` (derives the vault ID from an `aethel-core` PLP projection server-side) and `homomorphic_transfer_authenticated` (requires a verified PLP ownership proof). See [Identity Coupling](#5-identity-coupling).

### 3.3 State Serialization

Contract state is serialized using `bincode`:

```rust
#[derive(Serialize, Deserialize)]
pub struct VaultState {
    pub balances: Vec<([u8; 32], Vec<u8>)>,
    pub server_key_bytes: Option<Vec<u8>>,
    pub identity_projections: Vec<([u8; 32], Vec<u8>)>,
}
```

- `balances`: vault ID → serialized `FheUint64` ciphertext bytes.
- `server_key_bytes`: the TFHE evaluation key, deserialized once at `init_vault` (native builds only; unused on wasm32, where the host holds it).
- `identity_projections`: vault ID → the `aethel-core` `EphemeralProjection` bytes it was registered under, for vaults registered via `register_vault_with_identity`.

---

## 4. HelixDB: Vector-Graph Hybrid Storage Layer

### 4.1 What is HelixDB?

**HelixDB** is a vector-graph hybrid database used for vault state storage. `src/storage/helixdb.rs` implements a real gRPC client against it (`upsert_state_node`, `traverse_temporal_trajectory`, `vector_proximity_search`, `prune_temporal_node`, matching `proto/aethel_helix.proto`), available under the `std` feature. Deploying and operating a HelixDB cluster is outside this crate; see [`HELIXDB-ADAPTER.md`](./HELIXDB-ADAPTER.md) for the client's own documentation and expected server-side configuration.

---

## 5. Identity Coupling

`register_vault_with_identity` derives a vault ID from an `aethel-core` PLP
`EphemeralProjection` server-side, rather than trusting a caller-supplied
ID the way `register_vault_ciphertext` does. `homomorphic_transfer_authenticated`
additionally requires a caller-supplied `aethel_core::plp::ZkIdentityProof`
that verifies, via `aethel_core::plp::Verifier::verify`, against the exact
projection the sender vault was registered under. This is the first (and
currently only) vault operation authorized by proof of identity rather than
by ciphertext + `ServerKey` possession alone.

`homomorphic_transfer` and `register_vault_ciphertext` are unchanged and
coexist with this path: a vault registered the plain way has no identity
binding, and `homomorphic_transfer_authenticated` refuses to move its funds
regardless of what proof is presented.

See [`ROADMAP.md`](./ROADMAP.md) for why a network-submitted proof can't yet
cross the WASM/`extern "C"` boundary the rest of this module's entry points
use, and the account-de-correlation sequencing constraint this identity work
sits ahead of.

---

## 6. Security Properties

### 6.1 What the Server Can Learn

| Observable | Server Knowledge |
|---|---|
| Vault ID bytes | Opaque byte string; no semantic meaning |
| Balance ciphertext | Computationally indistinguishable from random noise under TFHE lattice hardness |
| Transfer ciphertext | Opaque; amount is never revealed |
| Solvency result | Encrypted boolean; server cannot read it |

### 6.2 What the Server Cannot Learn

- Plaintext balance of any vault
- Transfer amounts
- Whether a transfer succeeded or failed (the homomorphic select always executes)

### 6.3 Post-Quantum Hardness

1. **TFHE Semantic Security**: under the hardness of Learning With Errors (LWE) over the Torus, `FheUint64` ciphertexts are computationally indistinguishable from uniform random noise.
2. **M-LWE Vault ID / Identity-Proof Soundness**: `aethel-core`'s PLP projections and ZK ownership proofs reduce to Decision Module-LWE hardness — see `aethel-core`'s own documentation for the precise reduction.

---

## 7. Threat Model

### 7.1 Adversary Capabilities

| Adversary Class | Capabilities | Aethel-Vault Defense |
|---|---|---|
| Classical Network Observer | Read all on-chain state | TFHE ciphertexts are indistinguishable from random noise |
| Quantum Adversary (Shor's) | Break ECC (secp256k1, Ed25519); solve discrete logarithms | LWE/M-LWE hardness is not known to be broken by Shor's algorithm |
| Validator/Host Compromise | Read WASM memory during execution | `ServerKey` cannot decrypt; all state is ciphertext |
| HNDL ("Harvest Now, Decrypt Later") | Store ciphertexts for future quantum decryption | TFHE and PLP both reduce to LWE-family hardness |

### 7.2 Out-of-Scope Threats

The following are **not** addressed by this crate:

- Side-channel attacks during client-side key generation or encryption (a client-side concern, not this contract's)
- Network-level attacks on a HelixDB deployment's transport (a deployment/infrastructure concern — use mTLS and standard network hardening)
- Bugs in the `tfhe-rs` or `aethel-core` libraries themselves
- Account correlation via public chain addresses — see [`ROADMAP.md`](./ROADMAP.md)'s account de-correlation section; this is explicitly not yet solved and is the main risk in adopting this crate for a public-address-keyed ledger before that work lands

---

*See also:*
- [`TFHE-VAULT-SPEC.md`](./TFHE-VAULT-SPEC.md) — TFHE vault technical specification
- [`HELIXDB-ADAPTER.md`](./HELIXDB-ADAPTER.md) — HelixDB storage adapter specification
- [`WASM-DEPLOYMENT.md`](./WASM-DEPLOYMENT.md) — WASM compilation and deployment guide
- [`CLIENT-SDK.md`](./CLIENT-SDK.md) — Client SDK documentation
- [`ROADMAP.md`](./ROADMAP.md) — sequencing constraints and known gaps
