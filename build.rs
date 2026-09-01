// build.rs — aethel-vault build script
//
// Compiles the proto3 definition for the HelixDB gRPC service on native
// (non-WASM) targets. Skipped entirely for wasm32 targets since gRPC/HTTP2
// is not available in WASM; the WASM build uses a JS host bridge instead.
//
// Additionally, on opt-in (AETHEL_GENERATE_DIST=1), this script regenerates
// the dist/ release distribution artifacts:
//   dist/aethel_vault.wasm     — compiled WASM binary (best-effort copy from target/)
//   dist/aethel_vault.wit      — WIT interface definition
//   dist/aethel_vault.abi.json — ABI JSON descriptor
//   dist/README.md             — usage documentation
//
// Unconditional regeneration used to run on every build. That writes into
// the source tree from a build script, which `cargo publish`'s verification
// build rejects outright ("Source directory was modified by build.rs"), and
// which pollutes `git status` with line-ending-only diffs after any local
// build. `aethel-core` hit and fixed the identical anti-pattern in its own
// 0.1.5; this mirrors that fix.

use std::fs;
use std::path::PathBuf;

fn main() {
    // Detect target architecture from Cargo environment
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // Rerun triggers
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=target/wasm32-unknown-unknown/release/aethel_vault.wasm");
    println!("cargo:rerun-if-changed=target/wasm32-unknown-unknown/debug/aethel_vault.wasm");
    println!("cargo:rerun-if-env-changed=AETHEL_GENERATE_DIST");

    // ── Dist pipeline (opt-in only) ───────────────────────────────────────────
    if std::env::var("AETHEL_GENERATE_DIST").as_deref() == Ok("1") {
        generate_dist_artifacts();
    }

    // Skip proto compilation for WASM targets
    if target_arch == "wasm32" {
        return;
    }

    // Compile proto3 → Rust types using prost-build (native only)
    // This generates the gRPC client stubs used by HelixDbAdapter.
    //
    // Output is written to OUT_DIR and included via the `include!` macro
    // in src/storage/helixdb.rs when the `std` feature is enabled.
    match prost_build::Config::new()
        .out_dir(std::env::var("OUT_DIR").unwrap())
        .compile_protos(&["proto/aethel_helix.proto"], &["proto/"])
    {
        Ok(_) => {
            println!("cargo:rerun-if-changed=proto/aethel_helix.proto");
        }
        Err(e) => {
            // Non-fatal: proto compilation failure should not block the build
            // when tonic/prost are not yet wired up. Emit a warning instead.
            eprintln!("cargo:warning=Failed to compile proto/aethel_helix.proto: {}", e);
        }
    }

    // Rerun if build script itself changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn generate_dist_artifacts() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by Cargo");
    let manifest_path = PathBuf::from(&manifest_dir);
    let dist_dir = manifest_path.join("dist");

    // Create dist/ directory
    if let Err(e) = fs::create_dir_all(&dist_dir) {
        eprintln!("cargo:warning=Failed to create dist/ directory: {}", e);
        return;
    }

    // ── 1. Best-effort WASM binary copy ──────────────────────────────────────
    // build.rs runs during compilation, so the WASM binary from the *current*
    // build is not yet available. We copy from a previous build if present.
    //
    // Each crate has its own target/ directory (no shared workspace root),
    // so the WASM binary lives at <manifest_dir>/target/wasm32-unknown-unknown/.
    let release_wasm = manifest_path
        .join("target/wasm32-unknown-unknown/release/aethel_vault.wasm");
    let debug_wasm = manifest_path
        .join("target/wasm32-unknown-unknown/debug/aethel_vault.wasm");

    let wasm_dest = dist_dir.join("aethel_vault.wasm");

    if release_wasm.exists() {
        match fs::copy(&release_wasm, &wasm_dest) {
            Ok(_) => eprintln!("cargo:warning=dist: copied release WASM → dist/aethel_vault.wasm"),
            Err(e) => eprintln!("cargo:warning=dist: failed to copy release WASM: {}", e),
        }
    } else if debug_wasm.exists() {
        match fs::copy(&debug_wasm, &wasm_dest) {
            Ok(_) => eprintln!("cargo:warning=dist: copied debug WASM → dist/aethel_vault.wasm"),
            Err(e) => eprintln!("cargo:warning=dist: failed to copy debug WASM: {}", e),
        }
    } else {
        eprintln!(
            "cargo:warning=dist: WASM binary not found at {} or {} — \
             run `cargo build --target wasm32-unknown-unknown --features wasm` first, \
             then rebuild to populate dist/aethel_vault.wasm",
            release_wasm.display(),
            debug_wasm.display()
        );
    }

    // ── 2. WIT interface definition ───────────────────────────────────────────
    let wit_content = r#"package aethel:runtime@0.1.0;

interface vault {
  /// Initialize the vault with a server evaluation key
  vault-init: func(server-key-bytes: list<u8>) -> u32;

  /// Register a new vault with an initial encrypted balance
  vault-register: func(vault-id: list<u8>, initial-balance-ct: list<u8>) -> u32;

  /// Execute a homomorphic transfer between two vaults
  vault-transfer: func(sender-id: list<u8>, receiver-id: list<u8>, transfer-ct: list<u8>) -> u32;

  /// Export all vault state for HelixDB persistence
  vault-export-state: func() -> list<u8>;

  /// Import vault state from HelixDB
  vault-import-state: func(state-bytes: list<u8>) -> u32;

  /// Derive a vault ID from a PLP projection
  vault-derive-id: func(projection-bytes: list<u8>) -> list<u8>;
}

interface client {
  /// Create a new vault client with generated keys
  /// Returns serialized AethelVaultClient handle
  client-new: func() -> list<u8>;

  /// Encrypt a u64 balance value
  client-encrypt-balance: func(amount: u64) -> list<u8>;

  /// Decrypt an encrypted balance
  client-decrypt-balance: func(encrypted-bytes: list<u8>) -> u64;

  /// Build a WASM transfer payload
  client-build-payload: func(context-tag: list<u8>, amount: u64, target: list<u8>) -> list<u8>;
}

world aethel-runtime {
  import host-fhe: interface {
    host-fhe-sub: func(a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-add: func(a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-ge: func(a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-select: func(cond: list<u8>, a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-zero: func() -> list<u8>;
  }
  export vault;
  export client;
}
"#;

    let wit_path = dist_dir.join("aethel_vault.wit");
    match fs::write(&wit_path, wit_content) {
        Ok(_) => eprintln!("cargo:warning=dist: wrote dist/aethel_vault.wit"),
        Err(e) => eprintln!("cargo:warning=dist: failed to write WIT: {}", e),
    }

    // ── 3. ABI JSON descriptor ────────────────────────────────────────────────
    let abi_json = r#"{
  "name": "aethel-vault",
  "version": "0.1.0",
  "target": "wasm32-unknown-unknown",
  "exports": [
    { "name": "vault_init", "params": [{"name": "server_key_bytes", "type": "bytes"}], "returns": "u32" },
    { "name": "vault_register", "params": [{"name": "vault_id", "type": "bytes"}, {"name": "initial_balance_ct", "type": "bytes"}], "returns": "u32" },
    { "name": "vault_transfer", "params": [{"name": "sender_id", "type": "bytes"}, {"name": "receiver_id", "type": "bytes"}, {"name": "transfer_ct", "type": "bytes"}], "returns": "u32" },
    { "name": "vault_export_state", "params": [], "returns": "bytes" },
    { "name": "vault_import_state", "params": [{"name": "state_bytes", "type": "bytes"}], "returns": "u32" },
    { "name": "vault_derive_id", "params": [{"name": "projection_bytes", "type": "bytes"}], "returns": "bytes" }
  ],
  "imports": [
    { "module": "env", "name": "host_fhe_sub", "params": [{"name": "a_ptr", "type": "i32"}, {"name": "a_len", "type": "i32"}, {"name": "b_ptr", "type": "i32"}, {"name": "b_len", "type": "i32"}, {"name": "out_ptr", "type": "i32"}], "returns": "i32" },
    { "module": "env", "name": "host_fhe_add", "params": [{"name": "a_ptr", "type": "i32"}, {"name": "a_len", "type": "i32"}, {"name": "b_ptr", "type": "i32"}, {"name": "b_len", "type": "i32"}, {"name": "out_ptr", "type": "i32"}], "returns": "i32" },
    { "module": "env", "name": "host_fhe_ge", "params": [{"name": "a_ptr", "type": "i32"}, {"name": "a_len", "type": "i32"}, {"name": "b_ptr", "type": "i32"}, {"name": "b_len", "type": "i32"}, {"name": "out_ptr", "type": "i32"}], "returns": "i32" },
    { "module": "env", "name": "host_fhe_select", "params": [{"name": "cond_ptr", "type": "i32"}, {"name": "cond_len", "type": "i32"}, {"name": "a_ptr", "type": "i32"}, {"name": "a_len", "type": "i32"}, {"name": "b_ptr", "type": "i32"}, {"name": "b_len", "type": "i32"}, {"name": "out_ptr", "type": "i32"}], "returns": "i32" },
    { "module": "env", "name": "host_fhe_zero", "params": [{"name": "out_ptr", "type": "i32"}], "returns": "i32" }
  ],
  "memory": "exported",
  "allocator": "wasm-bindgen"
}
"#;

    let abi_path = dist_dir.join("aethel_vault.abi.json");
    match fs::write(&abi_path, abi_json) {
        Ok(_) => eprintln!("cargo:warning=dist: wrote dist/aethel_vault.abi.json"),
        Err(e) => eprintln!("cargo:warning=dist: failed to write ABI JSON: {}", e),
    }

    // ── 4. README.md ─────────────────────────────────────────────────────────
    let readme = r#"# aethel-vault — Distribution Artifacts

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
"#;

    let readme_path = dist_dir.join("README.md");
    match fs::write(&readme_path, readme) {
        Ok(_) => eprintln!("cargo:warning=dist: wrote dist/README.md"),
        Err(e) => eprintln!("cargo:warning=dist: failed to write README.md: {}", e),
    }
}
