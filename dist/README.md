# aethel-vault — Distribution Artifacts

This directory contains the release distribution artifacts for the `aethel-vault`
WebAssembly module. These files are generated automatically by `build.rs` during
the Cargo build process.

## Files

| File | Description |
|------|-------------|
| `aethel_vault.wasm` | Compiled WebAssembly binary (copied from `target/wasm32-unknown-unknown/`) |
| `aethel_vault.wit` | WIT (WebAssembly Interface Types) interface definition |
| `aethel_vault.abi.json` | ABI JSON descriptor for host-side binding generation |
| `README.md` | This file |

## Building the WASM Binary

```bash
# Build the WASM module with wasm-bindgen exports
cargo build \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm \
  --release

# Rebuild to trigger dist/ population (build.rs copies the artifact)
cargo build
```

Or use the wasm-release profile for size-optimized output:

```bash
cargo build \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm \
  --profile wasm-release
```

## Interface Summary

### `vault` — Blind-State Vault Operations

- **`vault_init(server_key_bytes: bytes) → u32`**
  Initialize the vault with a TFHE server evaluation key. Returns status code.

- **`vault_register(vault_id: bytes, initial_balance_ct: bytes) → u32`**
  Register a new vault with an initial encrypted balance ciphertext.

- **`vault_transfer(sender_id: bytes, receiver_id: bytes, transfer_ct: bytes) → u32`**
  Execute a homomorphic transfer between two vaults. All arithmetic is performed
  on encrypted ciphertexts via host FHE imports.

- **`vault_export_state() → bytes`**
  Export all vault state as serialized bytes for HelixDB persistence.

- **`vault_import_state(state_bytes: bytes) → u32`**
  Import vault state from HelixDB-serialized bytes.

- **`vault_derive_id(projection_bytes: bytes) → bytes`**
  Derive a vault ID from a PLP ephemeral projection (via SHA3-256).

### `client` — Vault Client SDK

- **`client_new() → bytes`**
  Create a new vault client with freshly generated TFHE key pair.
  Returns serialized `AethelVaultClient` handle.

- **`client_encrypt_balance(amount: u64) → bytes`**
  Encrypt a u64 balance value under the client's public key.

- **`client_decrypt_balance(encrypted_bytes: bytes) → u64`**
  Decrypt an encrypted balance ciphertext.

- **`client_build_payload(context_tag: bytes, amount: u64, target: bytes) → bytes`**
  Build a WASM transfer payload for submission to the vault contract.

## Host FHE Imports

The vault WASM module does **not** link TFHE directly. All homomorphic operations
are delegated to the host environment via the following imported functions:

| Import | Description |
|--------|-------------|
| `env::host_fhe_sub` | Homomorphic subtraction of two ciphertexts |
| `env::host_fhe_add` | Homomorphic addition of two ciphertexts |
| `env::host_fhe_ge` | Homomorphic greater-than-or-equal comparison |
| `env::host_fhe_select` | Homomorphic conditional select (MUX) |
| `env::host_fhe_zero` | Return an encrypted zero ciphertext |

All host imports use a pointer/length ABI: ciphertext bytes are passed as
`(ptr: i32, len: i32)` pairs, and output is written to a caller-provided buffer
at `out_ptr: i32`. Return value is the output byte length (`i32`).

## Memory Model

The WASM module exports its linear memory. The allocator is provided by
`wasm-bindgen`. All byte-array parameters are passed via wasm-bindgen's standard
ABI (pointer + length pairs). Return values are heap-allocated and ownership is
transferred to the caller.

## Integration Example (Wasmer Host)

```rust
use wasmer::{Store, Module, Instance, imports, Function};

let store = Store::default();
let module = Module::from_file(&store, "dist/aethel_vault.wasm")?;

// Provide host FHE functions
let import_object = imports! {
    "env" => {
        "host_fhe_add" => Function::new_typed(&store, host_fhe_add),
        "host_fhe_sub" => Function::new_typed(&store, host_fhe_sub),
        "host_fhe_ge"  => Function::new_typed(&store, host_fhe_ge),
        "host_fhe_select" => Function::new_typed(&store, host_fhe_select),
        "host_fhe_zero" => Function::new_typed(&store, host_fhe_zero),
    }
};

let instance = Instance::new(&store, &module, &import_object)?;

// Initialize vault with server key
let vault_init = instance.exports.get_function("vault_init")?;
```

## Security Notes

- The vault WASM binary stores **only serialized ciphertext bytes** — no plaintext
  balances are ever present in WASM memory.
- All homomorphic operations are performed by the trusted host environment which
  holds the TFHE server evaluation key.
- Vault IDs are derived via SHA3-256 from PLP ephemeral projections, ensuring
  unlinkability across contexts.
- For production deployments, use the `wasm-release` profile to strip debug
  symbols and minimize binary size.
