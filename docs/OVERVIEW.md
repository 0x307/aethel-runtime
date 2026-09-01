---
title: "Aethel-Vault: Technical Overview"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-vault"
---

# Aethel-Vault: Blind-State Quantum Wallet — Technical Overview

> **Implementation status.** This document describes the target architecture
> from the Aethel whitepaper alongside the actual current implementation, and
> does not distinguish them consistently below — read it as a design
> document, not a description of what ships in `src/` today. For what this
> crate actually implements right now, see [`README.md`](../README.md) and
> [`ROADMAP.md`](./ROADMAP.md). In short: single-party TFHE (one `ServerKey`,
> no resharing, no distributed decryption, no validator set), PLP-derived
> vault IDs, and one identity-authorized transfer path
> (`homomorphic_transfer_authenticated`) verified against an `aethel-core`
> PLP ownership proof. The 5D hypercube routing, SRAM PUF fuzzy extraction,
> hybrid M-LWE/code-based/isogeny binding, Kolmogorov-Blind nullifier pools,
> and ZK-STARK identity bridge described below are whitepaper-stage design
> targets, not implemented in this crate.

## Table of Contents

1. [What is Aethel-Vault?](#1-what-is-aethel-vault)
2. [TFHE Homomorphic Encryption: Server-Blind Balance Management](#2-tfhe-homomorphic-encryption-server-blind-balance-management)
3. [WASM Smart Contract Architecture](#3-wasm-smart-contract-architecture)
4. [HelixDB: Vector-Graph Hybrid Storage Layer](#4-helixdb-vector-graph-hybrid-storage-layer)
5. [Integration with Aethel-ID](#5-integration-with-aethel-id)
6. [Security Properties](#6-security-properties)
7. [Threat Model](#7-threat-model)
8. [Comparative Architecture](#8-comparative-architecture)

---

## 1. What is Aethel-Vault?

**Aethel-Vault** is the **Blind-State Quantum Wallet** component of the Aethel protocol suite. It is the second of two decoupled end-states in the Aethel architecture:

```
+---------------------------------------------------------------------------------+
|                            END-STATE 1: AETHEL-ID                               |
|               (Post-Quantum Ephemeral Identifier Standard)                      |
|                                                                                 |
|  - Zero Static Public Keys or DIDs                                              |
|  - 5D Toric Homological Manifold Invariants [γ] ∈ H_2(T^5)                      |
|  - Fiber Bundle De Rham Projector π_τ producing M-LWE Polynomials               |
|  - Kolmogorov-Blind Nullifier Pools with ε-Differential Privacy Noise           |
+---------------------------------------------------------------------------------+
                                          |
                        [ Ephemeral ZK-STARK Bridge ]
                                          |
                                          v
+---------------------------------------------------------------------------------+
|                          END-STATE 2: AETHEL-VAULT                              |
|                (Decoupled Anonymous Quantum Wallet Storage)                     |
|                                                                                 |
|  - Hybrid Multi-Primitive Core (M-LWE Lattice + Syndrome Decoding Code)         |
|  - On-Chain Threshold Fully Homomorphic Encryption (TFHE) Ciphertext States     |
|  - Hardware Level: Silicon SRAM PUF Fuzzy Extractor (Keyless Memory)            |
|  - 5D Hypercube Disjoint Path Secret Sharing Routing (Q_5 Network)              |
+---------------------------------------------------------------------------------+
```

*The diagram above is the whitepaper's target end-state, not this crate's
current implementation — see the implementation status note above.*

Aethel-Vault implements a wallet architecture where:

- **Balances are never decrypted on-chain.** All balance state exists exclusively as `FheUint64` ciphertexts (Torus FHE encrypted 64-bit integers).
- **Smart contracts execute homomorphically.** Deposits, withdrawals, and transfers are computed directly over encrypted ciphertexts using the TFHE evaluation key (`ServerKey`), without any validator node ever seeing plaintext values.
- **The wallet is decoupled from identity.** Vault IDs are anonymous ephemeral identifiers with zero mathematical relation to the Aethel-ID identifier engine. The two systems interact exclusively through short-lived Zero-Knowledge Evidence Hooks.
- **The WASM runtime is constrained and auditable.** The smart contract targets `wasm32-unknown-unknown` with `#![no_std]`, a 4MB memory cap, and no dynamic heap allocation.

### Core Design Principle: Blind-State Deterministic Execution

Classical crypto wallets expose balance state to validators. Even privacy-preserving systems like Zcash and Monero rely on UTXO shielded pools where ingress/egress transactions expose metadata. Aethel-Vault eliminates this entirely:

> **FHE Blind State:** User balances exist on-chain solely as encrypted ciphertexts. Smart contracts execute operations (e.g., `E(balance) − E(amount)`) using `tfhe-rs` without ever decrypting the underlying data on validator nodes. A quantum computer reading the public state only sees encrypted ciphertext blocks that are computationally indistinguishable from random noise under lattice hardness assumptions.

---

## 2. TFHE Homomorphic Encryption: Server-Blind Balance Management

### 2.1 What is TFHE?

**TFHE (Torus Fully Homomorphic Encryption)** is a fully homomorphic encryption scheme operating over the Torus (real numbers modulo 1). It enables arbitrary computation over encrypted data without decryption. The `tfhe-rs` library (by Zama) provides a production-grade Rust implementation targeting WASM.

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
| `CompactPublicKey` | Client (shareable) | Encrypt plaintext → compact ciphertext (size-optimized) |

The `ServerKey` contains only the public bootstrap and key-switching parameters. It allows arbitrary additions, subtractions, and comparisons directly over ciphertexts without having the ability to decrypt.

### 2.3 Homomorphic Balance Operations

**Deposit (register_vault_ciphertext):**
```
Client: ct_balance = Encrypt(initial_balance, client_key)
Client → Contract: (vault_id, ct_balance)
Contract: store(vault_id, ct_balance)  // No decryption
```

**Transfer (homomorphic_transfer):**
```
// 1. Homomorphic Solvency Check
is_sufficient = sk.ge(sender_balance_ct, transfer_amount_ct)

// 2. Conditional Subtraction (Homomorphic Branching)
actual_deduction = sk.select_parallelized(is_sufficient, transfer_amount_ct, zero_ct)

// 3. Update Balances Homomorphically
new_sender_balance = sk.sub(sender_balance_ct, actual_deduction)
new_receiver_balance = sk.add(receiver_balance_ct, actual_deduction)
```

The critical property: `is_sufficient` is an encrypted boolean. The WASM execution engine cannot read it. Classical `if/else` control flow would leak state. Instead, `select_parallelized` acts as a homomorphic multiplexer — the transfer either applies or doesn't, entirely within ciphertext space.

### 2.4 TFHE Parameter Choices

| Parameter Set | N (GLWE Dim) | Bits of Precision | Server Key Size |
|---|---|---|---|
| `PARAM_MESSAGE_1_CARRY_0` | 2^9 = 512 | 1-bit (Boolean) | ~3–8 MB |
| `PARAM_MESSAGE_2_CARRY_2_PBS_KS` | 2^10 = 1024 | 2-bit + 2-bit Carry | ~30–50 MB |
| `PARAM_MESSAGE_4_CARRY_4_KS_PBS` | 2^11 = 2048 | 4-bit + 4-bit Carry | ~120+ MB |

Aethel-Vault uses `PARAM_MESSAGE_2_CARRY_2_KS_PBS` as the default parameter set, balancing precision and server key size within WASM memory constraints.

---

## 3. WASM Smart Contract Architecture

### 3.1 Runtime Target

The Aethel-Vault smart contract targets `wasm32-unknown-unknown` — a bare-metal WebAssembly target with no operating system, no standard library, and no dynamic linker.

```
#![no_std]
extern crate alloc;
```

This ensures:
- **Minimal attack surface**: No OS syscalls, no file I/O, no network access from within the contract.
- **Deterministic execution**: Every validator node running the WASM binary produces identical state transitions.
- **Auditability**: The binary is fully self-contained and inspectable.

### 3.2 Memory Layout

```
WASM Linear Memory (64 pages = 4 MB maximum):
+-----------------------+---------------------+-----------------------------+
| Memory Region         | Offset Range        | Purpose                     |
+-----------------------+---------------------+-----------------------------+
| Execution Stack       | 0x000000 - 0x07FFFF | Function frames & local vars|
| Static Constants      | 0x080000 - 0x0FFFFF | Pre-computed NTT twiddles   |
| SRAM PUF Buffer       | 0x100000 - 0x11FFFF | Raw/Reconstructed PUF data  |
| Polynomial Scratchpad | 0x120000 - 0x2FFFFF | Working R_q matrices & z, y |
| Protected Output Pool | 0x300000 - 0x3FFFFF | Final SAAP proof transcript |
+-----------------------+---------------------+-----------------------------+
```

*This memory map is a target layout, not this crate's current build:
`src/lib.rs` has no `#![no_std]` attribute (the `std` feature is on by
default), there is no custom arena allocator, and there is no SRAM PUF
buffer or SAAP proof transcript pool — vault state is an in-memory `Vec` in
a `thread_local!`, serialized with `bincode`.*

Constraints:
- **Memory Boundary Cap**: Maximum allocation of 64 pages (4 Megabytes).
- **No Dynamic Heap Allocator**: All internal buffers use a deterministic arena allocator backed by a fixed stack footprint.
- **Binary Size Target**: `<3.4 MB` after `wasm-opt -Oz` optimization.

### 3.3 Contract Entry Points

The contract exposes three `#[no_mangle] pub extern "C"` functions as WASM exports:

| Function | Parameters | Returns | Purpose |
|---|---|---|---|
| `init_vault` | `server_key_bytes_ptr`, `len` | `u32` (0=OK) | Initialize contract with TFHE ServerKey |
| `register_vault_ciphertext` | `vault_id_ptr`, `vault_id_len`, `initial_ct_ptr`, `initial_ct_len` | `u32` | Deposit encrypted balance |
| `homomorphic_transfer` | sender/receiver IDs + transfer ciphertext | `u32` | Execute blind transfer |

### 3.4 State Serialization

Contract state is serialized using `bincode` (binary encoding, `no_std` compatible):

```rust
#[derive(Serialize, Deserialize)]
pub struct VaultState {
    pub balances: Vec<(Vec<u8>, FheUint64)>,
    pub server_key: Option<ServerKey>,
}
```

- `balances`: A vector of `(vault_id_bytes, FheUint64_ciphertext)` pairs.
- `server_key`: The TFHE evaluation key, deserialized once at `init_vault`.

---

## 4. HelixDB: Vector-Graph Hybrid Storage Layer

### 4.1 What is HelixDB?

**HelixDB** is a vector-graph hybrid database purpose-built for Aethel's spatial-temporal state trajectory storage. It combines:

- **Graph traversal** (temporal trajectory edges between state nodes)
- **Vector proximity search** (256-dimensional HNSW approximate nearest-neighbor indexing over M-LWE coefficient vectors)
- **Raft consensus** (distributed replication across a 3-node minimum cluster)

### 4.2 Architecture

```
+------------------------------------------------------------------+
|                    HelixDB Cluster (3+ Nodes)                    |
|                                                                  |
|  ┌─────────────────────────────────────────────────────────┐    |
|  │  Manifold Coordinate System                              │    |
|  │  M = (V, E, T) where V ⊂ R^256, T ∈ R^1               │    |
|  │  Node attribute vectors: v_i ∈ R^256                    │    |
|  └─────────────────────────────────────────────────────────┘    |
|                                                                  |
|  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  |
|  │  HNSW Vector     │  │  Graph Engine    │  │  Raft        │  |
|  │  Index (d=256)   │  │  (Temporal       │  │  Consensus   │  |
|  │  Cosine Distance │  │   Trajectories)  │  │  (2N+1)      │  |
|  └──────────────────┘  └──────────────────┘  └──────────────┘  |
|                                                                  |
|  ┌──────────────────────────────────────────────────────────┐   |
|  │  API Surface: HelixQL DSL | gRPC v3 | GraphQL v2026      │   |
|  └──────────────────────────────────────────────────────────┘   |
+------------------------------------------------------------------+
```

### 4.3 HNSW Vector Index Parameters

| Parameter | Value |
|---|---|
| Dimension | 256 |
| Distance Metric | Cosine Distance over normalized R_q coefficients |
| M (max edges per node) | 32 |
| ef_construction | 200 |
| ef_search | 128 |
| Index sync mode | Asynchronous |

### 4.4 Raft Consensus Configuration

| Parameter | Value |
|---|---|
| Minimum cluster size | 3 nodes (2N+1) |
| Heartbeat interval | 150ms |
| Election timeout | 1500ms |
| Snapshot threshold | 100,000 events |
| Inter-node security | mTLS 1.3 |

### 4.5 Port Allocation

| Service | Port |
|---|---|
| Envoy Proxy | 443 |
| Aethel Gateway HTTP | 8080 |
| Aethel Gateway gRPC | 9090 |
| HelixDB Engine | 7070 |
| HelixDB Raft | 7071 |
| HelixDB Gossip | 7072 |
| Prometheus | 9100 |

### 4.6 Schema Design for Encrypted Vault State

HelixDB stores vault state as `StateNode` graph nodes with encrypted attribute vectors. The schema uses HelixQL native DSL:

```
N::StateNode {
    node_id:           String,
    temporal_coord_t:  Float64,
    context_id:        String,
    attribute_mask:    Int32,
    h_commit:          Bytes,
    V::attr_vector:    Vector<Float32, 256>
}

E::EVOLVED_TO {
    time_delta:        Float64,
    geodesic_distance: Float32
}
```

Attribute vectors stored in HelixDB are **masked with homomorphic lattice noise** to ensure that spatial proximity queries reveal relationship validity without exposing exact scalar attribute values.

---

## 5. Integration with Aethel-ID

*This section describes the target ZK-bridge design. What this crate
actually implements today is narrower: `homomorphic_transfer_authenticated`
verifies a caller's `aethel-core` PLP ownership proof against the exact
projection a vault was registered under, via `aethel_core::plp::Verifier`.
There is no nullifier tree, no ZK-STARK bridge, and no separate
attestation/spend-nullifier pair as described below.*

### 5.1 Decoupling Principle

Aethel-Vault and Aethel-ID share **zero mathematical relation**. They cannot be linked on-chain by:
- Transaction history
- Co-location in memory
- Shared public key hashes
- Deterministic derivation pathways

```
+-----------------------------------------------------------------------------+
|                                HUMAN LAYER                                  |
|   Decentralized Identifier (DID)           Native Wallet Handle             |
|   e.g., did:pqc:9x8f... (or plaintext)      e.g., @ken.pqc                   |
+-----------------------------------------------------------------------------+
         |                                           |
         v                                           v
+-----------------------------------------------------------------------------+
|                             ZERO-KNOWLEDGE HOOKS                            |
|   ZK-Attestation Proof                     ZK-Nullifier & Nullifier Tree    |
|   "I hold identity credential C"            "I have right to spend state S" |
+-----------------------------------------------------------------------------+
          \                                           /
           \                                         /
            v                                       v
+-----------------------------------------------------------------------------+
|                             BLIND STATE ENGINE                              |
|   - Lattice-Based FHE State Machine (FIPS 203–206 Base Hardness)           |
|   - Ephemeral Key Encapsulation (ML-KEM per transaction)                   |
|   - Encrypted State Ciphertexts with Differential Privacy Noise             |
+-----------------------------------------------------------------------------+
```

### 5.2 ZK Bridge Mechanism

To execute a transaction requiring an identity check (e.g., a permissioned liquidity pool or compliant transfer):

1. **Aethel-ID** generates a One-Time Context-Bound Nullifier `N_DID`.
2. **Aethel-Vault** generates an Independent Spend Nullifier `N_W`.
3. A zero-knowledge circuit proves that `N_DID` and `N_W` were derived from two private keys that hold a valid secret agreement — **without revealing**:
   - What that agreement is
   - Who the parties are
   - Any static lattice points

### 5.3 Identifier Binding Without Linkability

The vault ID used in `register_vault_ciphertext` is an **anonymous ephemeral vault identifier** — not a public key, not a DID, not a wallet address. It is a short-lived context-bound commitment that:

- Changes with every interaction epoch
- Leaves no persistent on-chain footprint
- Cannot be correlated across transactions by any observer, including quantum-capable adversaries

---

## 6. Security Properties

### 6.1 What the Server Can Learn

| Observable | Server Knowledge |
|---|---|
| Vault ID bytes | Opaque byte string; no semantic meaning |
| Balance ciphertext | Computationally indistinguishable from random noise under TFHE lattice hardness |
| Transfer ciphertext | Opaque; amount is never revealed |
| Solvency result | Encrypted boolean; server cannot read it |
| Transaction graph | Vault IDs are ephemeral; no persistent linkage |

### 6.2 What the Server Cannot Learn

- Plaintext balance of any vault
- Transfer amounts
- Whether a transfer succeeded or failed (the homomorphic select always executes)
- The identity of any vault holder
- Any correlation between vault IDs across epochs

### 6.3 Post-Quantum Hardness

The security of Aethel-Vault rests on:

1. **TFHE Semantic Security**: Under the hardness of the Learning With Errors (LWE) problem over the Torus, `FheUint64` ciphertexts are computationally indistinguishable from uniform random noise.
2. **M-LWE Vault ID Unlinkability**: Vault IDs derived from Polymorphic Lattice Projections satisfy `Adv_Adversary_Link(b_{τ1}, b_{τ2}) ≤ Negl(λ)` under Decision M-LWE.
3. **Hybrid Cross-Primitive Core** *(design target — not implemented)*: the
   whitepaper describes a core binding simultaneously to M-LWE (Module
   Learning With Errors, `R_q = Z_q[X]/(X^256 + 1)`) and a Code-Based
   (HQC/Syndrome Decoding) or Isogeny (SQIsign) assumption, so breaking one
   layer alone yields zero information about the master seed. This crate
   uses only `tfhe-rs` (LWE-based FHE) for balance ciphertexts and
   `aethel-core`'s M-LWE-based PLP for identity proofs — no code-based or
   isogeny primitive is implemented anywhere in this codebase.

---

## 7. Threat Model

*The defenses in the table below are the whitepaper's target defenses, not
all of which this crate implements. Concretely implemented today:
`aethel-core`'s PLP uses constant-time rejection sampling (real, see its own
docs); this crate's ephemeral vault IDs and TFHE ciphertexts are real. Not
implemented in this crate: Kolmogorov-Blind nullifiers / ε-DP noise
injection, SRAM PUF, first-order masking, and PRNG jitter injection.*

### 7.1 Adversary Capabilities

| Adversary Class | Capabilities | Aethel-Vault Defense |
|---|---|---|
| Classical Network Observer | Read all on-chain state; analyze transaction graphs | TFHE ciphertexts are random noise; ephemeral vault IDs prevent graph analysis |
| Quantum Adversary (Shor's) | Break ECC (secp256k1, Ed25519); solve discrete logarithms | M-LWE hardness is not susceptible to Shor's algorithm |
| Quantum Adversary (Grover's) | Quadratic speedup for brute-force search | ≥256-bit post-quantum security margins; collision-resistant hashes |
| Validator Node Compromise | Read WASM memory during execution | ServerKey cannot decrypt; all state is ciphertext |
| Graph Neural Network (GNN) | Statistical correlation of transaction graphs | Kolmogorov-Blind nullifiers with ε-DP noise injection |
| HNDL ("Harvest Now, Decrypt Later") | Store ciphertexts for future quantum decryption | TFHE security reduces to LWE, which is post-quantum hard |
| Side-Channel (Power/EM) | Extract keys during ZK proof generation | Constant-time rejection sampling; first-order masking; PRNG jitter injection |
| Physical Device Capture | Extract master seed from non-volatile storage | SRAM PUF: master secret never written to disk; zeroized after use |

### 7.2 Out-of-Scope Threats

The following are **not** in Aethel-Vault's threat model (they are addressed at the Aethel-ID layer or infrastructure layer):

- Side-channel attacks on the client device during key generation (addressed by SRAM PUF + enclave in Aethel-ID)
- DNS/BGP hijacking of the HelixDB endpoint (addressed by mTLS 1.3 + certificate pinning)
- Bugs in the `tfhe-rs` library itself (mitigated by formal verification and upstream audits)

### 7.3 Implementation Realities

> **"Impossible" vs. Implementation Realities:** Math can be proven quantum-safe, but side-channel attacks (e.g., power analysis on mobile devices during FN-DSA/ML-DSA signature generation) or memory leakage on local devices remain classical vectors. Implementations must enforce constant-time execution and secure enclave isolation (e.g., Apple Secure Enclave or ARM TrustZone).

> **Signature & Proof Sizes:** ML-DSA and SLH-DSA produce significantly larger signatures than ECDSA (kilobytes vs. 64 bytes). Combining lattice signatures with FHE ciphertexts requires ZK-rollup/STARK compression layer-1 execution to prevent network bloat.

---

## 8. Comparative Architecture

*This table compares the whitepaper's target architecture against other
systems, not this crate's current implementation — several "Aethel-Vault"
column claims (hybrid code-based/isogeny binding, zero HNDL surface as a
completed property rather than a design goal) describe primitives not
implemented here. See the implementation status note at the top of this
document.*

| Dimension / Metric | Aethel-Vault | Zcash (Halo 2 / Orchard) | Monero (CLSAG) | Zama fhEVM |
|---|---|---|---|---|
| Primary Cryptographic Primitives | M-LWE (R_q^k), HQC (Code-Based), TFHE (Torus FHE over lattices) | Pasta Curves (Pallas/Vesta), Halo 2 (Recursive PlonK), Poseidon Hash | Ed25519 (Curve), Pedersen Commitments, Ring Signatures | ECC + FHE (EVM-compatible) |
| Post-Quantum Hardness (Soundness) | Post-Quantum Resistant (Reduced to Module-LWE / M-SIS lattice problems) | Vulnerable (Pairing-free ECC broken by Shor's Algorithm) | Vulnerable (Discrete Logarithm on curves completely broken by Shor's) | Partially (FHE is PQ-hard; ECC key exchange is not) |
| On-Chain State Execution Model | Blind-State TFHE Execution (Computes directly over encrypted balance vectors) | Shielded State Nullifiers (Private balance tracking via UTXO zero-knowledge spends) | RingCT Confidential Transactions (Pedersen Commitments, range proofs, UTXOs) | FHE over EVM state (linked to static 0x address) |
| Identity Linkability | Zero Static Identifiers (Ephemeral vault IDs, no persistent address) | Static Unified Addresses (Diversified keys reduce, but do not eliminate, wallet linkage) | Stealth Addresses (One-time keys derived from persistent public key) | Static Ethereum address (0x123...) |
| HNDL Attack Surface | None (TFHE + M-LWE are post-quantum hard) | High (ECC key exchanges captured today, decryptable by future quantum hardware) | High (Key Images broken under Shor's) | Partial |

```
                    THE ANONYMITY & SECURITY FRONTIER
   Post-Quantum  ^
   Hardness      |                     [ AETHEL-ID / AETHEL-VAULT ]
                 |                       (Lattice M-LWE + TFHE + PUF)
                 |
                 |      [ Zcash Orchard ]
                 |        (Halo 2 / ZK)
                 |
                 |                             [ Monero CLSAG ]
                 |                               (RingCT / ECC)
                 |
                 |                                                [ W3C DIDs ]
                 +------------------------------------------------------------>
                 Zero Linkability / Ephemeral State         Static Identity
```

---

*See also:*
- [`TFHE-VAULT-SPEC.md`](./TFHE-VAULT-SPEC.md) — Full TFHE vault technical specification
- [`HELIXDB-ADAPTER.md`](./HELIXDB-ADAPTER.md) — HelixDB storage adapter specification
- [`WASM-DEPLOYMENT.md`](./WASM-DEPLOYMENT.md) — WASM compilation and deployment guide
- [`CLIENT-SDK.md`](./CLIENT-SDK.md) — Client SDK documentation
