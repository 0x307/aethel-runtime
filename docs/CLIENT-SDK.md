---
title: "Aethel-Vault: Client SDK Documentation"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-vault"
---

# Client SDK Documentation

## Table of Contents

1. [Overview](#1-overview)
2. [Key Generation Workflow](#2-key-generation-workflow)
3. [Balance Encryption](#3-balance-encryption)
4. [Payload Construction](#4-payload-construction)
5. [Proof Submission](#5-proof-submission)
6. [Rust SDK Usage](#6-rust-sdk-usage)
7. [TypeScript SDK Usage](#7-typescript-sdk-usage)
8. [HelixDB TypeScript SDK Note](#8-helixdb-typescript-sdk-note)
9. [Security Considerations](#9-security-considerations)

---

## 1. Overview

The Aethel-Vault Client SDK provides client-side tooling for:

1. **TFHE Key Generation**: Generating `ClientKey` + `ServerKey` + `CompactPublicKey` for the TFHE homomorphic encryption scheme.
2. **Balance Encryption**: Encrypting plaintext `u64` balances into `FheUint64` ciphertexts using the `CompactPublicKey`.
3. **Payload Construction**: Building serialized `ContractPayload` structures for submission to the WASM vault contract.
4. **Balance Decryption**: Decrypting `FheUint64` ciphertexts back to plaintext `u64` values using the `ClientKey`.

The SDK is implemented in two forms:
- **Rust SDK** (`src/client.rs`): Native Rust with `wasm-bindgen` for WASM compilation
- **TypeScript SDK** (`src/sdk/client.ts`): Vault-specific stub extending the shared HelixDB SDK

```
+------------------------------------------------------------------+
|                    CLIENT SDK ARCHITECTURE                       |
|                                                                  |
|  AethelVaultClient (Rust/WASM)                                   |
|  ├── ClientKey (secret, never transmitted)                       |
|  ├── CompactPublicKey (shareable, for encryption)                |
|  │                                                               |
|  ├── new() → generate key pair                                   |
|  ├── encrypt_u64_balance(amount) → Vec<u8>                       |
|  ├── build_wasm_payload(tag, amount, target) → Vec<u8>           |
|  └── decrypt_u64_balance(encrypted_bytes) → u64                  |
+------------------------------------------------------------------+
```

---

## 2. Key Generation Workflow

### 2.1 Overview

TFHE key generation produces three keys:

| Key | Type | Purpose | Transmission |
|---|---|---|---|
| `ClientKey` | Secret | Encrypt + Decrypt | Never transmitted |
| `ServerKey` | Public (eval) | Homomorphic computation | Uploaded to contract once |
| `CompactPublicKey` | Public | Compact encryption | Can be shared |

### 2.2 Rust Key Generation

```rust
use tfhe::integer::{ClientKey, CompactPublicKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

// Generate key pair
let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
let client_key = ClientKey::new(params);
let public_key = CompactPublicKey::new(&client_key);

// Derive server key for contract initialization
use tfhe::integer::ServerKey;
let server_key = ServerKey::new(&client_key);

// Serialize server key for upload to contract
let server_key_bytes = bincode::serialize(&server_key)
    .expect("ServerKey serialization failed");
```

### 2.3 WASM Key Generation (via wasm-bindgen)

```javascript
import init, { AethelVaultClient } from './pkg/aethel_vault.js';

await init();

// Generate key pair in browser
const client = new AethelVaultClient();

// The client internally holds:
// - client_key: ClientKey (secret, in WASM memory)
// - public_key: CompactPublicKey (for encryption)
```

### 2.4 Key Lifecycle

```
[Factory Provisioning / First Run]
1. Generate ClientKey (PARAM_MESSAGE_2_CARRY_2_KS_PBS)
2. Derive ServerKey from ClientKey
3. Derive CompactPublicKey from ClientKey
4. Serialize ServerKey → bytes
5. Upload ServerKey bytes to contract via init_vault()
6. Store ClientKey securely (client-side only)
   - In browser: IndexedDB with encryption
   - In native: Secure enclave / keychain
   - In WASM: Volatile memory (zeroized on drop)

[Per-Transaction]
7. Encrypt amount using CompactPublicKey → FheUint64 ciphertext
8. Submit ciphertext to contract
9. Contract computes homomorphically (no decryption)
10. Retrieve result ciphertext
11. Decrypt result using ClientKey → plaintext balance
```

---

## 3. Balance Encryption

### 3.1 Rust Encryption

```rust
use tfhe::integer::{FheUint64, CompactPublicKey};
use tfhe::prelude::*;

// Encrypt a u64 balance using CompactPublicKey
pub fn encrypt_u64_balance(amount: u64, public_key: &CompactPublicKey) -> Vec<u8> {
    let ct = FheUint64::encrypt_with_compact_public_key(amount, public_key);
    bincode::serialize(&ct).expect("Ciphertext serialization failed")
}
```

### 3.2 WASM Encryption (via AethelVaultClient)

```rust
#[wasm_bindgen]
impl AethelVaultClient {
    pub fn encrypt_u64_balance(&self, amount: u64) -> Result<Vec<u8>, JsError> {
        let ct = FheUint64::encrypt_with_compact_public_key(amount, &self.public_key);
        bincode::serialize(&ct)
            .map_err(|e| JsError::new(&format!("Ciphertext serialization failed: {}", e)))
    }
}
```

### 3.3 JavaScript Usage

```javascript
// Encrypt a balance of 1000 tokens
const encryptedBalance = client.encrypt_u64_balance(BigInt(1000));
// Returns: Uint8Array (serialized FheUint64 ciphertext)

// Encrypt a transfer amount of 50 tokens
const encryptedAmount = client.encrypt_u64_balance(BigInt(50));
```

### 3.4 Ciphertext Properties

- **Size**: ~1-4 KB per `FheUint64` ciphertext (depends on parameter set)
- **Semantic security**: Computationally indistinguishable from random noise under LWE hardness
- **Homomorphic**: Supports addition, subtraction, comparison without decryption
- **Serialization**: `bincode`-encoded binary format

---

## 4. Payload Construction

### 4.1 ContractPayload Structure

```rust
#[derive(Serialize, Deserialize)]
pub struct ContractPayload {
    pub context_tag: [u8; 32],      // 32-byte context identifier τ
    pub encrypted_amount: Vec<u8>,   // Serialized FheUint64 ciphertext
    pub encrypted_target: Vec<u8>,   // Serialized FheUint64 ciphertext
}
```

### 4.2 Rust Payload Construction

```rust
#[wasm_bindgen]
impl AethelVaultClient {
    pub fn build_wasm_payload(
        &self,
        context_tag: &[u8],
        amount: u64,
        target_account: u64,
    ) -> Result<Vec<u8>, JsError> {
        if context_tag.len() != 32 {
            return Err(JsError::new("Context tag must be exactly 32 bytes"));
        }
        let mut tag_bytes = [0u8; 32];
        tag_bytes.copy_from_slice(context_tag);
        let encrypted_amount = self.encrypt_u64_balance(amount)?;
        let encrypted_target = self.encrypt_u64_balance(target_account)?;
        let payload = ContractPayload {
            context_tag: tag_bytes,
            encrypted_amount,
            encrypted_target,
        };
        bincode::serialize(&payload)
            .map_err(|e| JsError::new(&format!("Payload assembly failed: {}", e)))
    }
}
```

### 4.3 JavaScript Payload Construction

```javascript
import { sha3_256 } from '@noble/hashes/sha3';

// Generate context tag from block height + domain separator
const blockHeight = BigInt(1000);
const domainSeparator = new TextEncoder().encode("AETHEL_VAULT_TRANSFER_V1");
const contextInput = new Uint8Array([
    ...new Uint8Array(new BigInt64Array([blockHeight]).buffer),
    ...domainSeparator,
]);
const contextTag = sha3_256(contextInput); // 32-byte context tag

// Build transfer payload
const transferAmount = BigInt(100);
const targetAccountId = BigInt(42);

const payload = client.build_wasm_payload(
    contextTag,
    transferAmount,
    targetAccountId,
);
// Returns: Uint8Array (serialized ContractPayload)
```

### 4.4 Context Tag Generation

The context tag `τ` is a 32-byte value derived from:
```
τ = SHA3-256(block_height || domain_separator || nonce)
```

This ensures:
- Each payload is bound to a specific block context
- Replay attacks across different blocks are prevented
- The context tag is publicly verifiable

---

## 5. Proof Submission

### 5.1 Vault Registration

```javascript
// Step 1: Generate initial encrypted balance
const initialBalance = BigInt(10000); // 10,000 tokens
const encryptedBalance = client.encrypt_u64_balance(initialBalance);

// Step 2: Generate anonymous vault ID
// (derived from Aethel-ID ephemeral projection, not shown here)
const vaultId = generateEphemeralVaultId(contextTag);

// Step 3: Submit to contract
await contractClient.registerVaultCiphertext(
    vaultId,           // Uint8Array: anonymous vault identifier
    encryptedBalance,  // Uint8Array: serialized FheUint64
);
```

### 5.2 Transfer Submission

```javascript
// Step 1: Build transfer payload
const transferPayload = client.build_wasm_payload(
    contextTag,    // 32-byte context tag
    BigInt(500),   // Transfer amount (encrypted)
    BigInt(0),     // Target account (encrypted, used for routing)
);

// Step 2: Submit homomorphic transfer
await contractClient.homomorphicTransfer(
    senderVaultId,    // Uint8Array: sender vault ID
    receiverVaultId,  // Uint8Array: receiver vault ID
    encryptedAmount,  // Uint8Array: serialized FheUint64 transfer amount
);
```

### 5.3 Balance Query and Decryption

```javascript
// Step 1: Request encrypted balance from contract
const encryptedBalance = await contractClient.getEncryptedBalance(vaultId);

// Step 2: Decrypt locally using ClientKey
const plaintextBalance = client.decrypt_u64_balance(encryptedBalance);
console.log(`Balance: ${plaintextBalance} tokens`);
```

### 5.4 Rust Decryption

```rust
#[wasm_bindgen]
impl AethelVaultClient {
    pub fn decrypt_u64_balance(&self, encrypted_bytes: &[u8]) -> Result<u64, JsError> {
        let ct: FheUint64 = bincode::deserialize(encrypted_bytes)
            .map_err(|e| JsError::new(&format!("Ciphertext parse error: {}", e)))?;
        let plaintext: u64 = ct.decrypt(&self.client_key);
        Ok(plaintext)
    }
}
```

---

## 6. Rust SDK Usage

### 6.1 Complete Rust Example

```rust
use aethel_vault::client::AethelVaultClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize client (generates key pair)
    let client = AethelVaultClient::new()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // 2. Encrypt initial balance
    let initial_balance: u64 = 10_000;
    let encrypted_balance = client.encrypt_u64_balance(initial_balance)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    println!("Encrypted balance: {} bytes", encrypted_balance.len());

    // 3. Build transfer payload
    let context_tag = [0x42u8; 32]; // Example context tag
    let transfer_amount: u64 = 500;
    let target_account: u64 = 1;

    let payload = client.build_wasm_payload(&context_tag, transfer_amount, target_account)
        .map_err(|e| format!("Payload construction failed: {:?}", e))?;
    println!("Payload: {} bytes", payload.len());

    // 4. Decrypt balance (after receiving from contract)
    let decrypted = client.decrypt_u64_balance(&encrypted_balance)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    println!("Decrypted balance: {}", decrypted);
    assert_eq!(decrypted, initial_balance);

    Ok(())
}
```

### 6.2 Cargo.toml for Rust Client

```toml
[package]
name = "aethel-vault-client"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
tfhe = { version = "0.10", features = ["integer", "boolean", "wasm-api"] }
wasm-bindgen = "0.2"
serde = { version = "1.0", features = ["derive"] }
bincode = "1.3"
zeroize = { version = "1.7", features = ["zeroize_derive"] }
```

### 6.3 SecretKeyContainer (Secure Cleanup)

```rust
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKeyContainer {
    pub raw_key_bytes: Vec<u8>,
}

// Usage: SecretKeyContainer is automatically zeroized when dropped
{
    let key_container = SecretKeyContainer {
        raw_key_bytes: client_key_bytes,
    };
    // ... use key_container ...
} // key_container dropped here: raw_key_bytes zeroed before deallocation
```

---

## 7. TypeScript SDK Usage

### 7.1 Installation

```bash
# Install the compiled WASM package
npm install ./pkg

# Or from npm (when published)
npm install @aethel/vault-sdk
```

### 7.2 Browser Usage

```html
<script type="module">
import init, { AethelVaultClient } from './pkg/aethel_vault.js';

async function main() {
    // Initialize WASM module
    await init();

    // Create vault client (generates TFHE key pair)
    const client = new AethelVaultClient();

    // Encrypt a balance
    const encrypted = client.encrypt_u64_balance(BigInt(1000));
    console.log('Encrypted balance:', encrypted.length, 'bytes');

    // Build a transfer payload
    const contextTag = new Uint8Array(32).fill(0x42);
    const payload = client.build_wasm_payload(
        contextTag,
        BigInt(100),  // amount
        BigInt(1),    // target
    );

    // Decrypt a balance
    const decrypted = client.decrypt_u64_balance(encrypted);
    console.log('Decrypted balance:', decrypted);
}

main().catch(console.error);
</script>
```

### 7.3 Node.js Usage

```javascript
const { default: init, AethelVaultClient } = require('./pkg/aethel_vault.js');

async function main() {
    await init();

    const client = new AethelVaultClient();

    // Encrypt balance
    const encrypted = client.encrypt_u64_balance(BigInt(5000));

    // Build payload with SHA3-256 context tag
    const { sha3_256 } = require('@noble/hashes/sha3');
    const contextTag = sha3_256(Buffer.from('block:1000:vault:transfer'));

    const payload = client.build_wasm_payload(contextTag, BigInt(250), BigInt(2));

    // Decrypt
    const balance = client.decrypt_u64_balance(encrypted);
    console.log('Balance:', balance.toString());
}

main();
```

### 7.4 TypeScript Types

```typescript
// Types exported from the WASM package
declare class AethelVaultClient {
    constructor(): AethelVaultClient;
    encrypt_u64_balance(amount: bigint): Uint8Array;
    build_wasm_payload(
        context_tag: Uint8Array,
        amount: bigint,
        target_account: bigint
    ): Uint8Array;
    decrypt_u64_balance(encrypted_bytes: Uint8Array): bigint;
    free(): void;
}
```

---

## 8. HelixDB TypeScript SDK Note

> **Important:** The Aethel-Vault project does **not** include a separate, standalone HelixDB TypeScript SDK distinct from the one in `aethel-id`.

The TypeScript SDK for HelixDB integration (Snippet 12 from the extracted content — `AethelClientSDK` with `mapCoeffsToVector256`, `createIngestionPayload`, `verifySaapProof`) is the **shared SDK** that lives canonically in:

```
aethel-id/src/sdk/client.ts
```

This SDK serves both `aethel-id` and `aethel-vault` because:
1. HelixDB is a shared storage layer used by both subsystems
2. The `mapCoeffsToVector256` and `createIngestionPayload` methods operate on M-LWE polynomial coefficients, which are generated by the Aethel-ID PLP engine
3. The `verifySaapProof` method verifies SAAP proofs, which are an Aethel-ID primitive

The `aethel-vault/src/sdk/client.ts` file provides a **vault-specific stub** that:
- Re-exports the shared `AethelClientSDK` from `aethel-id`
- Adds vault-specific TypeScript utilities (payload serialization, ciphertext handling)
- Documents the integration points between the vault WASM SDK and HelixDB

### 8.1 Vault-Specific TypeScript Utilities

```typescript
// aethel-vault/src/sdk/client.ts

/**
 * Serialize a ContractPayload for submission to the vault contract.
 */
export function serializeContractPayload(
    contextTag: Uint8Array,
    encryptedAmount: Uint8Array,
    encryptedTarget: Uint8Array,
): Uint8Array {
    // bincode-compatible serialization
    // [context_tag: 32 bytes][amount_len: 8 bytes LE][amount: N bytes][target_len: 8 bytes LE][target: M bytes]
    const amountLen = new DataView(new ArrayBuffer(8));
    amountLen.setBigUint64(0, BigInt(encryptedAmount.length), true);
    const targetLen = new DataView(new ArrayBuffer(8));
    targetLen.setBigUint64(0, BigInt(encryptedTarget.length), true);

    const result = new Uint8Array(
        32 + 8 + encryptedAmount.length + 8 + encryptedTarget.length
    );
    let offset = 0;
    result.set(contextTag, offset); offset += 32;
    result.set(new Uint8Array(amountLen.buffer), offset); offset += 8;
    result.set(encryptedAmount, offset); offset += encryptedAmount.length;
    result.set(new Uint8Array(targetLen.buffer), offset); offset += 8;
    result.set(encryptedTarget, offset);
    return result;
}

/**
 * Generate an anonymous vault ID from a context tag and nonce.
 * The vault ID is an ephemeral identifier with no relation to any public key.
 */
export async function generateEphemeralVaultId(
    contextTag: Uint8Array,
    nonce: Uint8Array,
): Promise<Uint8Array> {
    const { sha3_256 } = await import('@noble/hashes/sha3');
    const input = new Uint8Array(contextTag.length + nonce.length);
    input.set(contextTag, 0);
    input.set(nonce, contextTag.length);
    return sha3_256(input);
}
```

---

## 9. Security Considerations

### 9.1 ClientKey Confidentiality

The `ClientKey` is the master decryption key. It MUST:
- Never be transmitted over any network
- Never be written to non-volatile storage in plaintext
- Be stored in a secure enclave (Apple Secure Enclave, ARM TrustZone) when possible
- Be zeroized from memory when no longer needed (use `SecretKeyContainer` with `zeroize`)

### 9.2 CompactPublicKey Safety

The `CompactPublicKey` can be shared publicly. It allows anyone to encrypt values for the vault, but cannot decrypt. It is safe to:
- Store in a public registry
- Transmit over untrusted networks
- Include in transaction metadata

### 9.3 Context Tag Binding

Every payload MUST use a fresh context tag `τ` derived from the current block height and a domain separator. Reusing context tags across different transactions enables replay attacks.

### 9.4 Zeroization

The `SecretKeyContainer` struct uses `#[derive(Zeroize)] #[zeroize(drop)]` to ensure key material is overwritten with zeros before memory deallocation. This prevents key material from persisting in freed memory pages.

### 9.5 WASM Memory Isolation

In browser environments, WASM linear memory is isolated from JavaScript heap memory. The `ClientKey` stored in WASM memory is not directly accessible from JavaScript. However:
- The WASM module can be inspected via browser DevTools
- Memory snapshots can capture key material
- For high-security deployments, use a hardware security module (HSM) or secure enclave

---

*See also:*
- [`OVERVIEW.md`](./OVERVIEW.md) — High-level architecture overview
- [`TFHE-VAULT-SPEC.md`](./TFHE-VAULT-SPEC.md) — TFHE vault technical specification
- [`WASM-DEPLOYMENT.md`](./WASM-DEPLOYMENT.md) — WASM compilation and deployment guide
- [`src/client.rs`](../src/client.rs) — TFHE client SDK source code
- [`src/sdk/client.ts`](../src/sdk/client.ts) — TypeScript vault SDK stub
