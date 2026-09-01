---
title: "Aethel-Vault: TFHE Vault Technical Specification"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-vault"
---

# TFHE Vault Technical Specification

> **Implementation status.** Sections 1–3's description of what the
> homomorphic transfer computes is accurate. Several other sections describe
> either a target spec or a stale/earlier version of the code rather than
> what's in `src/` today — flagged inline where they occur: Section 4's
> memory layout (SRAM PUF buffer, custom arena allocator, `#![no_std]`),
> Section 6's `VaultState` shape, Section 9's error codes, and Section 10.4's
> static-mut state pattern. For accurate error codes and entry points, see
> [`README.md`](../README.md)'s Error Codes table and `src/vault.rs`
> directly. For the identity check this crate now also implements
> (`homomorphic_transfer_authenticated`, not covered by this document at
> all), see [`README.md`](../README.md) and [`ROADMAP.md`](./ROADMAP.md).

## Table of Contents

1. [Overview](#1-overview)
2. [FheUint64 Ciphertext Management](#2-fheuint64-ciphertext-management)
3. [Homomorphic Balance Operations](#3-homomorphic-balance-operations)
4. [WASM Execution Bounds and Memory Constraints](#4-wasm-execution-bounds-and-memory-constraints)
5. [Key Management](#5-key-management)
6. [State Serialization Format](#6-state-serialization-format)
7. [Parameter Choices and Rationale](#7-parameter-choices-and-rationale)
8. [Contract Entry Points Reference](#8-contract-entry-points-reference)
9. [Error Codes](#9-error-codes)
10. [Architectural Highlights](#10-architectural-highlights)

---

## 1. Overview

The TFHE Vault Smart Contract is a production-grade, standalone Rust smart contract architecture targeting WebAssembly (`wasm32-unknown-unknown`). It utilizes **TFHE-rs** (Zama's Fully Homomorphic Encryption library over the Torus) to execute homomorphic operations directly on encrypted integer state vectors (encrypted balances) without decrypting them on-chain.

```
+------------------------------------------------------------------+
|                    AETHEL-VAULT TFHE CONTRACT                    |
|                                                                  |
|  Client Side                    On-Chain (WASM)                  |
|  ─────────────────              ─────────────────────────────    |
|  ClientKey (secret)             ServerKey (public eval key)      |
|  CompactPublicKey               VaultState { balances: Vec<     |
|                                   (vault_id, FheUint64)> }       |
|                                                                  |
|  Encrypt(balance) ──────────>  register_vault_ciphertext()       |
|  Encrypt(amount)  ──────────>  homomorphic_transfer()            |
|                                  ├─ sk.ge(bal, amt)              |
|                                  ├─ sk.select_parallelized(...)  |
|                                  ├─ sk.sub(bal, deduction)       |
|                                  └─ sk.add(recv_bal, deduction)  |
|                                                                  |
|  decrypt(ct) <──────────────   [ciphertext returned to client]   |
+------------------------------------------------------------------+
```

**Key invariant:** The WASM host environment never sees cleartext values. Balances are encrypted off-chain using the Client Key and submitted as `FheUint64` ciphertexts.

---

## 2. FheUint64 Ciphertext Management

### 2.1 Ciphertext Type

`FheUint64` is a TFHE-rs encrypted 64-bit unsigned integer. It represents a balance value encrypted under the client's `ClientKey`. The ciphertext is:

- **Semantically secure**: Computationally indistinguishable from uniform random noise under LWE hardness.
- **Homomorphically operable**: Supports addition, subtraction, comparison, and conditional selection without decryption.
- **Serializable**: Can be serialized to/from `Vec<u8>` using `bincode` for on-chain storage and transmission.

### 2.2 Ciphertext Lifecycle

```
[Client]                          [On-Chain Contract]
   |                                      |
   |  1. Generate ClientKey + ServerKey   |
   |  2. Encrypt(balance) → FheUint64 ct  |
   |  3. Serialize ct → Vec<u8>           |
   |  4. Submit (vault_id, ct_bytes) ─────>  register_vault_ciphertext()
   |                                      |  5. Deserialize ct_bytes → FheUint64
   |                                      |  6. Store (vault_id, FheUint64) in state
   |                                      |
   |  7. Encrypt(amount) → FheUint64 amt  |
   |  8. Submit transfer request ─────────>  homomorphic_transfer()
   |                                      |  9. Homomorphic ops on FheUint64
   |                                      |  10. Update state (no decryption)
   |                                      |
   |  11. Request balance ciphertext <────   [return serialized FheUint64]
   |  12. Decrypt(ct) → plaintext balance |
```

### 2.3 Compact Public Key Encryption

For size-optimized public encryptions, the client SDK uses `CompactPublicKey`:

```rust
let ct = FheUint64::encrypt_with_compact_public_key(amount, &self.public_key);
```

`CompactPublicKey` produces smaller ciphertexts than standard encryption, reducing on-chain storage and transmission costs.

---

## 3. Homomorphic Balance Operations

### 3.1 Vault Registration (Deposit)

**Function:** `register_vault_ciphertext`

Deposits an encrypted initial balance into an anonymous vault. The vault ID is an opaque byte string (anonymous ephemeral identifier).

```rust
#[no_mangle]
pub extern "C" fn register_vault_ciphertext(
    vault_id_ptr: *const u8, vault_id_len: usize,
    initial_ct_ptr: *const u8, initial_ct_len: usize,
) -> u32 {
    let state = get_state_mut();
    let vault_id = unsafe { core::slice::from_raw_parts(vault_id_ptr, vault_id_len) };
    let ct_bytes = unsafe { core::slice::from_raw_parts(initial_ct_ptr, initial_ct_len) };
    let initial_balance: FheUint64 = match bincode::deserialize(ct_bytes) {
        Ok(ct) => ct,
        Err(_) => return 101,
    };
    state.balances.push((vault_id.to_vec(), initial_balance));
    0
}
```

**Operation:** Pure storage — no homomorphic computation required. The ciphertext is deserialized and stored as-is.

### 3.2 Homomorphic Transfer

**Function:** `homomorphic_transfer`

Executes an encrypted transfer between two vaults. All balance adjustments and validation occur homomorphically on encrypted ciphertexts.

```rust
#[no_mangle]
pub extern "C" fn homomorphic_transfer(
    sender_id_ptr: *const u8, sender_id_len: usize,
    receiver_id_ptr: *const u8, receiver_id_len: usize,
    transfer_ct_ptr: *const u8, transfer_ct_len: usize,
) -> u32 {
    let state = get_state_mut();
    let sk = match &state.server_key {
        Some(k) => k,
        None => return 100, // Error: Uninitialized Server Key
    };
    let sender_id = unsafe { core::slice::from_raw_parts(sender_id_ptr, sender_id_len) };
    let receiver_id = unsafe { core::slice::from_raw_parts(receiver_id_ptr, receiver_id_len) };
    let ct_bytes = unsafe { core::slice::from_raw_parts(transfer_ct_ptr, transfer_ct_len) };
    let transfer_amount: FheUint64 = match bincode::deserialize(ct_bytes) {
        Ok(ct) => ct,
        Err(_) => return 101, // Error: Invalid Ciphertext
    };
    let sender_idx = match state.balances.iter().position(|(id, _)| id == sender_id) {
        Some(idx) => idx,
        None => return 102, // Sender Vault Not Found
    };
    let receiver_idx = match state.balances.iter().position(|(id, _)| id == receiver_id) {
        Some(idx) => idx,
        None => return 103, // Receiver Vault Not Found
    };
    // 1. Homomorphic Solvency Check (Sender_Balance >= Transfer_Amount)
    let is_sufficient = sk.ge(&state.balances[sender_idx].1, &transfer_amount);
    // 2. Conditional Subtraction (Sender Balance)
    let actual_deduction = sk.select_parallelized(&is_sufficient, &transfer_amount, &sk.create_trivial_zero());
    // Perform Homomorphic Subtraction: New_Sender_Bal = Sender_Bal - Actual_Deduction
    state.balances[sender_idx].1 = sk.sub(&state.balances[sender_idx].1, &actual_deduction);
    // 3. Conditional Addition (Receiver Balance)
    state.balances[receiver_idx].1 = sk.add(&state.balances[receiver_idx].1, &actual_deduction);
    0 // Success
}
```

**Step-by-step homomorphic execution:**

| Step | Operation | TFHE Function | Result Type |
|---|---|---|---|
| 1 | Solvency check | `sk.ge(sender_bal, transfer_amt)` | `FheBool` (encrypted boolean) |
| 2 | Conditional deduction | `sk.select_parallelized(is_sufficient, transfer_amt, zero)` | `FheUint64` |
| 3 | Sender balance update | `sk.sub(sender_bal, actual_deduction)` | `FheUint64` |
| 4 | Receiver balance update | `sk.add(receiver_bal, actual_deduction)` | `FheUint64` |

### 3.3 Homomorphic Branching: Why `select_parallelized`?

Classical `if/else` control flow is impossible in blind-state execution:

```rust
// WRONG — leaks state by branching on encrypted boolean:
if is_sufficient {
    // This branch reveals that sender has sufficient funds
    state.balances[sender_idx].1 = sk.sub(...);
}

// CORRECT — homomorphic multiplexer, always executes both paths:
let actual_deduction = sk.select_parallelized(
    &is_sufficient,    // Encrypted condition
    &transfer_amount,  // Value if true
    &sk.create_trivial_zero(), // Value if false (zero deduction)
);
```

`select_parallelized` computes `condition ? true_val : false_val` entirely within ciphertext space. The execution path is identical regardless of the encrypted condition value, preventing any timing or control-flow side-channel leakage.

### 3.4 Trivial Zero Ciphertext

`sk.create_trivial_zero()` creates a "trivially encrypted" zero — a ciphertext that encrypts the value 0 without requiring a client key. It is used as the "no-op" branch in conditional transfers. This is safe because:
- The value 0 is public knowledge (it's the identity element for addition)
- The encryption is still semantically secure under the server key

---

## 4. WASM Execution Bounds and Memory Constraints

### 4.1 Target Platform

```
Target: wasm32-unknown-unknown
ABI: C (extern "C" #[no_mangle] exports)
std: #![no_std] + extern crate alloc
```

### 4.2 Memory Constraints

```
WASM Linear Memory Layout:
+-----------------------+---------------------+-----------------------------+
| Memory Region         | Offset Range        | Purpose                     |
+-----------------------+---------------------+-----------------------------+
| Execution Stack       | 0x000000 - 0x07FFFF | Function frames & local vars|
| Static Constants      | 0x080000 - 0x0FFFFF | Pre-computed NTT twiddles   |
| SRAM PUF Buffer       | 0x100000 - 0x11FFFF | Raw/Reconstructed PUF data  |
| Polynomial Scratchpad | 0x120000 - 0x2FFFFF | Working R_q matrices & z, y |
| Protected Output Pool | 0x300000 - 0x3FFFFF | Final SAAP proof transcript |
+-----------------------+---------------------+-----------------------------+
Maximum: 64 WASM pages = 4,194,304 bytes (4 MB)
```

*Target layout, not this crate's current build: there is no `#![no_std]`
attribute (the `std` feature is on by default), no custom arena allocator,
no SRAM PUF buffer, and no SAAP proof transcript pool. Vault state is an
in-memory `Vec` in a `thread_local!`, serialized with `bincode`.*

**Constraints enforced:**
- **Memory Boundary Cap**: Maximum allocation of 64 pages (4 Megabytes).
- **No Dynamic Heap Allocator**: All internal buffers MUST use a deterministic arena allocator backed by a fixed stack footprint.
- **Binary Size Ceiling**: MUST NOT exceed 256 Kilobytes for the enclave binary; `<3.4 MB` for the full WASM binary after `wasm-opt -Oz`.
- **Stack Depth Ceiling**: MUST NOT exceed 32 Kilobytes.
- **Zero External System Calls**: The execution binary MUST be fully self-contained.

### 4.3 Execution Bounds

| Metric | Unoptimized tfhe-rs Build | Optimized WASM Pipeline |
|---|---|---|
| WASM Binary Footprint | ~18.5 MB | ~2.1 MB - 3.4 MB |
| Bootstrap Cycle Latency | ~140ms / gate | ~38ms / gate (with SIMD128) |
| Gas / Fuel Consumed | Baseline (100%) | ~32% of baseline |

### 4.4 `#![no_std]` Compatibility

*Not accurate as written: the crate has no `#![no_std]` attribute (`src/lib.rs`
has no such attribute, and the `std` feature is on by default). It does use
`extern crate alloc;` for `no_std`-*style* module bodies alongside `std`,
which is not the same as building `no_std`.*

The contract uses `#![no_std]` with `extern crate alloc` to access heap allocation primitives (`Vec`, `String`) without the full standard library. This is required for `wasm32-unknown-unknown` targets that lack OS-level memory management.

```rust
#![no_std]
extern crate alloc;
use alloc::vec::Vec;
```

---

## 5. Key Management

### 5.1 Client-Side Key Generation

*Stale relative to `src/client.rs`: the wasm-bindgen `AethelVaultClient::new()`
constructor is a placeholder that returns empty key bytes — on WASM, key
generation happens in JS via the tfhe JS API, and the generated bytes are
loaded with `from_key_bytes` afterward, not generated inline as shown below.
The snippet below matches `NativeVaultClient::new()`'s intent
(`ConfigBuilder`/`generate_keys`) more than the wasm-bindgen path it's
attached to, though the exact API shape shown (`ClientKey::new(params)`,
`CompactPublicKey::new`) doesn't match either one verbatim.*

The client generates the TFHE key pair locally. The `ClientKey` **never leaves the client**:

```rust
#[wasm_bindgen(constructor)]
pub fn new() -> Result<AethelVaultClient, JsError> {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let client_key = ClientKey::new(params);
    let public_key = CompactPublicKey::new(&client_key);
    Ok(AethelVaultClient { client_key, public_key })
}
```

### 5.2 Server Key Deployment

The `ServerKey` (evaluation key) is derived from the `ClientKey` and uploaded to the contract during initialization:

```rust
#[no_mangle]
pub extern "C" fn init_vault(server_key_bytes_ptr: *const u8, len: usize) -> u32 {
    let key_bytes = unsafe { core::slice::from_raw_parts(server_key_bytes_ptr, len) };
    let server_key: ServerKey = match bincode::deserialize(key_bytes) {
        Ok(k) => k,
        Err(_) => return 1, // Error: Deserialization failed
    };
    let state = get_state_mut();
    state.server_key = Some(server_key);
    0 // Success
}
```

### 5.3 Key Separation Properties

| Property | Guarantee |
|---|---|
| `ClientKey` confidentiality | Never transmitted; held only in client volatile memory |
| `ServerKey` public safety | Contains only bootstrap/key-switching parameters; cannot decrypt |
| `CompactPublicKey` safety | Can be shared publicly; encrypts but cannot decrypt |
| Evaluation key decoupling | Contract stores `ServerKey`; this key allows arbitrary FHE ops but zero decryption capability |

### 5.4 Secure Key Cleanup

The client SDK uses `zeroize` for secure key cleanup:

```rust
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKeyContainer {
    pub raw_key_bytes: Vec<u8>,
}
```

When `SecretKeyContainer` is dropped, `zeroize` overwrites the key bytes with zeros before deallocation, preventing key material from persisting in freed memory.

---

## 6. State Serialization Format

### 6.1 VaultState Structure

*Stale relative to `src/vault.rs`: ciphertexts and the server key are stored
as raw `Vec<u8>`, not typed `FheUint64`/`ServerKey` (bincode serializes the
bytes either way, so this is a documentation gap, not a behavioral one), and
there is now a third field, `identity_projections`, for vaults registered
via `register_vault_with_identity`. Current shape:*

```rust
#[derive(Serialize, Deserialize)]
pub struct VaultState {
    pub balances: Vec<([u8; 32], Vec<u8>)>,
    pub server_key_bytes: Option<Vec<u8>>,
    pub identity_projections: Vec<([u8; 32], Vec<u8>)>,
}
```

The below is this document's original (stale) description, kept for
context:

```rust
#[derive(Serialize, Deserialize)]
pub struct VaultState {
    /// Mapping of Anonymous Ephemeral Vault IDs to encrypted balance ciphertexts
    pub balances: Vec<(Vec<u8>, FheUint64)>,
    /// Global Homomorphic Evaluation Key (ServerKey) for FHE execution
    pub server_key: Option<ServerKey>,
}
```

### 6.2 Serialization Library

State is serialized using `bincode` (binary encoding):

```toml
bincode = { version = "1.3", default-features = false }
```

`bincode` is chosen for:
- **`no_std` compatibility** (with `default-features = false`)
- **Compact binary format** (smaller than JSON/CBOR for binary data)
- **Deterministic encoding** (required for consensus)

### 6.3 Ciphertext Wire Format

`FheUint64` ciphertexts are serialized as opaque `Vec<u8>` byte arrays. The internal format is defined by `tfhe-rs` and includes:
- GLWE ciphertext components
- Bootstrap key references
- Carry bits and precision metadata

The contract treats ciphertext bytes as opaque blobs — it never inspects the internal structure.

### 6.4 Vault ID Format

Vault IDs are opaque byte strings (`Vec<u8>`). They are anonymous ephemeral identifiers derived from the Aethel-ID Polymorphic Lattice Projection system. The contract performs only byte-equality comparison:

```rust
state.balances.iter().position(|(id, _)| id == sender_id)
```

No semantic interpretation of vault IDs occurs within the contract.

---

## 7. Parameter Choices and Rationale

### 7.1 TFHE Parameter Set: `PARAM_MESSAGE_2_CARRY_2_KS_PBS`

| Parameter | Value | Rationale |
|---|---|---|
| Message bits | 2 | Sufficient for 64-bit integer arithmetic via bootstrapping |
| Carry bits | 2 | Allows 4 additions before bootstrapping required |
| Key switching | KS_PBS (Key Switch then Programmable Bootstrap) | Optimal for integer arithmetic operations |
| GLWE dimension N | 2^10 = 1024 | Balances security and performance |
| Server Key Size | ~30–50 MB | Fits within WASM memory constraints |

**Rationale for `PARAM_MESSAGE_2_CARRY_2_KS_PBS` over alternatives:**
- `PARAM_MESSAGE_1_CARRY_0`: Too limited (1-bit precision); insufficient for balance arithmetic.
- `PARAM_MESSAGE_4_CARRY_4_KS_PBS`: Server key ~120+ MB; exceeds WASM 4MB memory cap.
- `PARAM_MESSAGE_2_CARRY_2_KS_PBS`: Optimal balance — 2-bit precision with 2-bit carry supports 64-bit integer operations via multi-bit decomposition, with server key fitting in WASM memory.

### 7.2 `FheUint64` vs. Smaller Types

`FheUint64` is chosen for balance representation because:
- 64-bit unsigned integers can represent balances up to `2^64 - 1` (sufficient for any realistic token supply)
- TFHE-rs natively supports `FheUint64` with optimized bootstrapping circuits
- Smaller types (`FheUint32`, `FheUint16`) would limit maximum balance values

### 7.3 `bincode` vs. Alternative Serialization

| Library | `no_std` | Binary Size | Deterministic | Choice |
|---|---|---|---|---|
| `bincode` | ✅ (with `default-features = false`) | Compact | ✅ | **Selected** |
| `serde_json` | ❌ (requires `std`) | Large | ✅ | Rejected |
| `cbor` | Partial | Medium | ✅ | Rejected |
| `postcard` | ✅ | Very compact | ✅ | Alternative |

### 7.4 `serde` Feature Flags

```toml
serde = { version = "1.0", default-features = false, features = ["alloc", "derive"] }
```

- `default-features = false`: Disables `std` dependency
- `features = ["alloc"]`: Enables `Vec`, `String` serialization without `std`
- `features = ["derive"]`: Enables `#[derive(Serialize, Deserialize)]` macros

---

## 8. Contract Entry Points Reference

*The signatures below match `src/vault.rs`; the return codes originally
listed here did not (100/101/102/103 were never real — the actual codes
have always been 0–4, now 0–5). Corrected below.*

### 8.1 `init_vault`

```
Signature: init_vault(server_key_bytes_ptr: *const u8, len: usize) -> u32
Purpose:   Initialize contract and set the TFHE Server Key (Evaluation Key).
           The Server Key allows the contract to compute on ciphertexts
           without being able to decrypt.
Returns:   0 = ERR_OK
           3 = ERR_DESER (key bytes invalid)
```

### 8.2 `register_vault_ciphertext`

```
Signature: register_vault_ciphertext(
               vault_id_ptr: *const u8, vault_id_len: usize,
               initial_ct_ptr: *const u8, initial_ct_len: usize
           ) -> u32
Purpose:   Deposit/Initialize an encrypted balance into an anonymous vault.
Returns:   0 = ERR_OK
           3 = ERR_DESER (vault_id is not 32 bytes)
```

### 8.3 `homomorphic_transfer`

```
Signature: homomorphic_transfer(
               sender_id_ptr: *const u8, sender_id_len: usize,
               receiver_id_ptr: *const u8, receiver_id_len: usize,
               transfer_ct_ptr: *const u8, transfer_ct_len: usize
           ) -> u32
Purpose:   Execute an encrypted transfer/update between sender and receiver
           vaults. Balance adjustments and validation occur homomorphically
           on encrypted ciphertexts.
Returns:   0 = ERR_OK (including insufficient-funds — blind execution)
           1 = ERR_NOT_FOUND (sender or receiver vault not registered)
           3 = ERR_DESER (any ciphertext malformed)
           4 = ERR_INVALID_KEY (native only: ServerKey not initialized)
```

---

## 9. Error Codes

*Corrected — see [`README.md`](../README.md#error-codes) for the
canonical, up-to-date table, which also has `ERR_UNAUTHORIZED` (5) for
`homomorphic_transfer_authenticated`, not covered by this document.*

| Code | Constant | Meaning |
|---|---|---|
| 0 | `ERR_OK` | Success |
| 1 | `ERR_NOT_FOUND` | Vault ID not registered |
| 2 | `ERR_INSUFFICIENT_BALANCE` | Homomorphic solvency check failed (not currently returned; solvency is handled blindly) |
| 3 | `ERR_DESER` | Deserialization error |
| 4 | `ERR_INVALID_KEY` | Invalid server key |
| 5 | `ERR_UNAUTHORIZED` | `homomorphic_transfer_authenticated` only |

---

## 10. Architectural Highlights

### 10.1 Zero Plaintext Leakage

The WASM host environment never sees cleartext values. Balances are encrypted off-chain using the Client Key and submitted as `FheUint64` ciphertexts.

### 10.2 Evaluation Key Decoupling

The contract stores a `ServerKey`. This key contains the public bootstrap and key-switching parameters allowing arbitrary additions, subtractions, and comparisons directly over ciphertexts without having the ability to decrypt.

### 10.3 Homomorphic Branching (`select_parallelized`)

Because the WASM execution engine cannot read encrypted boolean states (`is_sufficient`), execution paths cannot use classical `if/else` control flow without leaking state. Instead, execution relies on homomorphic selection masks to conditionally apply transfers on-chain.

### 10.4 Static Global State

*Stale: the contract does not use a `static mut` global. It uses a safe
`thread_local!` `RefCell` instead:*

```rust
thread_local! {
    static STATE: RefCell<Option<VaultState>> = RefCell::new(None);
}

fn with_state_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut VaultState) -> R,
{
    STATE.with(|s| {
        let mut borrow = s.borrow_mut();
        let state = borrow.get_or_insert_with(VaultState::new);
        f(state)
    })
}
```

The document's original description, kept for context:

```rust
static mut STATE: Option<VaultState> = None;

fn get_state_mut() -> &'static mut VaultState {
    unsafe {
        STATE.get_or_insert_with(|| VaultState {
            balances: Vec::new(),
            server_key: None,
        })
    }
}
```

This is the standard pattern for `#![no_std]` WASM smart contracts where there is no OS-level process isolation — the WASM linear memory IS the process memory, and the contract is the sole occupant.

---

*See also:*
- [`OVERVIEW.md`](./OVERVIEW.md) — High-level architecture overview
- [`WASM-DEPLOYMENT.md`](./WASM-DEPLOYMENT.md) — Compilation flags and deployment guide
- [`CLIENT-SDK.md`](./CLIENT-SDK.md) — Client SDK for key generation and encryption
- [`src/vault.rs`](../src/vault.rs) — TFHE vault contract source code
- [`src/client.rs`](../src/client.rs) — TFHE client SDK source code
