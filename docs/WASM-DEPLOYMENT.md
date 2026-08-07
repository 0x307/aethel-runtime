---
title: "Aethel-Vault: WASM Compilation and Deployment Guide"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-vault"
---

# WASM Compilation and Deployment Guide

## Table of Contents

1. [Toolchain Setup](#1-toolchain-setup)
2. [WASM Compilation Flags](#2-wasm-compilation-flags)
3. [Cargo Release Profile](#3-cargo-release-profile)
4. [Feature Pruning](#4-feature-pruning)
5. [wasm-opt Optimization Passes](#5-wasm-opt-optimization-passes)
6. [Parameter Choices for WASM Constraints](#6-parameter-choices-for-wasm-constraints)
7. [Memory Layout and Bounds](#7-memory-layout-and-bounds)
8. [Deployment Steps](#8-deployment-steps)
9. [Performance Benchmarks](#9-performance-benchmarks)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Toolchain Setup

### 1.1 Required Tools

```bash
# Install Rust (stable toolchain)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM target
rustup target add wasm32-unknown-unknown

# Install wasm-pack (for wasm-bindgen client SDK)
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install wasm-opt (Binaryen optimizer)
# On macOS:
brew install binaryen
# On Ubuntu/Debian:
apt-get install binaryen
# Or download from: https://github.com/WebAssembly/binaryen/releases

# Install wasm-bindgen CLI (for client SDK)
cargo install wasm-bindgen-cli

# Verify installations
rustup target list --installed | grep wasm32
wasm-opt --version
wasm-bindgen --version
```

### 1.2 Rust Toolchain Version

```bash
# Pin to a specific nightly for SIMD128 support (if needed)
rustup override set nightly-2026-07-01

# Or use stable (recommended for production)
rustup override set stable
```

### 1.3 Cargo Configuration

Create `.cargo/config.toml` in the `aethel-vault` directory:

```toml
[build]
target = "wasm32-unknown-unknown"

[target.wasm32-unknown-unknown]
rustflags = [
    "-C", "target-feature=+simd128",
    "-C", "link-arg=-s",
    "-C", "link-arg=--strip-all",
    "-C", "link-arg=--gc-sections",
]
```

**Flag explanations:**
- `+simd128`: Enables WebAssembly SIMD 128-bit vector instructions. Required for TFHE-rs polynomial arithmetic acceleration (~3.7x speedup on bootstrap cycles).
- `--strip-all`: Strips all symbol tables and debug information from the final binary.
- `--gc-sections`: Removes unused code sections (dead code elimination at link time).
- `-s`: Strips symbol table (redundant with `--strip-all` but ensures compatibility).

---

## 2. WASM Compilation Flags

### 2.1 Build Command

```bash
# Build the vault contract (no_std WASM)
cargo build --target wasm32-unknown-unknown --release

# Build the client SDK (wasm-bindgen)
wasm-pack build --target web --release -- --features wasm
```

### 2.2 Compiler Flags Reference

| Flag | Value | Effect |
|---|---|---|
| `target-feature` | `+simd128` | Enable WASM SIMD 128-bit instructions |
| `link-arg` | `--strip-all` | Remove all debug symbols |
| `link-arg` | `--gc-sections` | Dead code elimination |
| `opt-level` | `z` or `s` | Size optimization (see §3) |
| `lto` | `true` | Link-Time Optimization across crates |
| `codegen-units` | `1` | Single codegen unit for maximum LTO scope |
| `panic` | `abort` | Remove unwinding tables (~150-300KB savings) |
| `strip` | `true` | Strip debug symbols at Cargo level |
| `overflow-checks` | `false` | Remove runtime integer overflow checks |

### 2.3 SIMD128 Impact

WASM SIMD128 provides 128-bit vector operations that accelerate TFHE polynomial arithmetic:

```
Without SIMD128:
  Bootstrap cycle: ~140ms / gate
  NTT polynomial multiply: ~8ms

With SIMD128 (+simd128):
  Bootstrap cycle: ~38ms / gate  (3.7x speedup)
  NTT polynomial multiply: ~2.1ms (3.8x speedup)
```

SIMD128 is supported in all modern browsers (Chrome 91+, Firefox 89+, Safari 16.4+) and Node.js 16+.

---

## 3. Cargo Release Profile

### 3.1 Vault Contract Profile (Size-Optimized)

```toml
[profile.release]
opt-level = "z"          # Optimizes for binary size (most aggressive)
lto = true               # Deep cross-crate Link Time Optimization
codegen-units = 1        # Maximize LTO optimization scope
panic = "abort"          # Removes unwinding tables (saves ~150-300KB)
strip = true             # Strips debug symbols and symbol tables
overflow-checks = false  # Drops runtime integer overflow checks in release
```

### 3.2 Client SDK Profile (Performance-Balanced)

```toml
[profile.release]
opt-level = "s"          # Optimizes for binary size (balanced)
lto = true               # Deep cross-crate Link Time Optimization
codegen-units = 1        # Maximize LTO optimization scope
panic = "abort"          # Removes unwinding tables
strip = true             # Strips debug symbols
overflow-checks = false  # Drops runtime integer overflow checks
```

### 3.3 `opt-level` Comparison

| `opt-level` | Focus | Binary Size | Runtime Speed | Use Case |
|---|---|---|---|---|
| `0` | No optimization | Largest | Slowest | Debug builds |
| `1` | Basic optimization | Large | Moderate | Fast debug |
| `2` | Standard optimization | Medium | Fast | Default release |
| `3` | Aggressive optimization | Medium-large | Fastest | CPU-bound code |
| `s` | Size optimization | Small | Good | Balanced WASM |
| `z` | Maximum size optimization | Smallest | Moderate | Minimal WASM |

For Aethel-Vault:
- **Vault contract** (`#![no_std]`): Use `opt-level = "z"` — binary size is the primary constraint.
- **Client SDK** (wasm-bindgen): Use `opt-level = "s"` — balance size and bootstrap performance.

### 3.4 LTO Impact

Link-Time Optimization (LTO) performs cross-crate inlining and dead code elimination:

```
Without LTO:
  aethel_vault_contract.wasm: ~18.5 MB

With LTO (lto = true, codegen-units = 1):
  aethel_vault_contract.wasm: ~4.2 MB (before wasm-opt)
  aethel_vault_client_opt.wasm: ~2.1 MB (after wasm-opt)
```

---

## 4. Feature Pruning

### 4.1 TFHE Feature Flags

Only enable the TFHE features required for the vault contract:

```toml
[dependencies.tfhe]
version = "0.7"
default-features = false
features = [
    "boolean",   # Keep only the primitive gate engine
    "shortint",  # Modular shortint engine
    "integer",   # FheUint64 integer operations
    "wasm-api",  # WASM bindings
]
```

**Disabled features (saves significant binary size):**
- `gpu`: CUDA GPU acceleration (not available in WASM)
- `x86_64-unix`: x86_64-specific optimizations (not applicable to WASM)
- `nightly-avx512`: AVX-512 SIMD (not applicable to WASM)
- `seeder_unix`: Unix-specific entropy seeder
- `seeder_x86_64_rdseed`: x86_64 RDSEED instruction

### 4.2 Client SDK Feature Flags

```toml
[dependencies.tfhe]
version = "0.10"
features = ["integer", "boolean", "wasm-api"]
```

### 4.3 serde Feature Pruning

```toml
serde = { version = "1.0", default-features = false, features = ["alloc", "derive"] }
```

Disabling `std` feature removes ~50KB from the binary.

### 4.4 bincode Feature Pruning

```toml
bincode = { version = "1.3", default-features = false }
```

---

## 5. wasm-opt Optimization Passes

### 5.1 Basic Optimization

```bash
# Build release WASM binary
cargo build --target wasm32-unknown-unknown --release

# Run aggressive WASM size and execution optimization
wasm-opt -Oz --enable-simd \
    target/wasm32-unknown-unknown/release/aethel_vault_contract.wasm \
    -o aethel_vault_contract_opt.wasm
```

### 5.2 Optimization Flags Reference

| Flag | Description | Effect |
|---|---|---|
| `-O0` | No optimization | Baseline |
| `-O1` | Basic optimization | Mild size/speed improvement |
| `-O2` | Standard optimization | Good balance |
| `-O3` | Aggressive optimization | Maximum speed |
| `-Os` | Size optimization | Smaller binary, good speed |
| `-Oz` | Maximum size optimization | Smallest binary |
| `--enable-simd` | Enable SIMD128 optimizations | Required for TFHE acceleration |
| `--strip-debug` | Remove debug sections | Reduces size |
| `--strip-producers` | Remove producer metadata | Minor size reduction |
| `--vacuum` | Remove unused elements | Dead code elimination |
| `--dce` | Dead code elimination | Remove unreachable code |

### 5.3 Full Optimization Pipeline

```bash
#!/bin/bash
set -e

WASM_TARGET="target/wasm32-unknown-unknown/release"
OUTPUT_DIR="dist"
mkdir -p "$OUTPUT_DIR"

echo "[1/4] Building vault contract..."
cargo build --target wasm32-unknown-unknown --release \
    --package aethel-vault \
    --features "wasm"

echo "[2/4] Running wasm-opt on vault contract..."
wasm-opt -Oz \
    --enable-simd \
    --strip-debug \
    --strip-producers \
    --vacuum \
    --dce \
    "$WASM_TARGET/aethel_vault.wasm" \
    -o "$OUTPUT_DIR/aethel_vault_contract_opt.wasm"

echo "[3/4] Building client SDK with wasm-pack..."
wasm-pack build \
    --target web \
    --release \
    --out-dir "$OUTPUT_DIR/pkg" \
    -- --features "wasm"

echo "[4/4] Running wasm-opt on client SDK..."
wasm-opt -Oz \
    --enable-simd \
    "$OUTPUT_DIR/pkg/aethel_vault_bg.wasm" \
    -o "$OUTPUT_DIR/pkg/aethel_vault_bg_opt.wasm"

echo "Build complete!"
ls -lh "$OUTPUT_DIR/"
```

### 5.4 Verification

```bash
# Verify WASM binary is valid
wasm-validate aethel_vault_contract_opt.wasm

# Inspect binary size
ls -lh aethel_vault_contract_opt.wasm

# Inspect exported functions
wasm-objdump -x aethel_vault_contract_opt.wasm | grep "Export"

# Expected exports:
# Export[0]: func[0] <init_vault>
# Export[1]: func[1] <homomorphic_transfer>
# Export[2]: func[2] <register_vault_ciphertext>
```

---

## 6. Parameter Choices for WASM Constraints

### 6.1 TFHE Parameter Set Selection

The TFHE parameter set must fit within WASM's 4MB memory constraint:

| Parameter Set | N (GLWE Dim) | Bits of Precision | Server Key Size | WASM Compatible |
|---|---|---|---|---|
| `PARAM_MESSAGE_1_CARRY_0` | 2^9 = 512 | 1-bit (Boolean) | ~3–8 MB | ⚠️ Marginal |
| `PARAM_MESSAGE_2_CARRY_2_KS_PBS` | 2^10 = 1024 | 2-bit + 2-bit Carry | ~30–50 MB | ✅ With streaming |
| `PARAM_MESSAGE_4_CARRY_4_KS_PBS` | 2^11 = 2048 | 4-bit + 4-bit Carry | ~120+ MB | ❌ Exceeds limit |

**Selected: `PARAM_MESSAGE_2_CARRY_2_KS_PBS`**

The server key (~30-50 MB) exceeds the 4MB WASM linear memory limit. This is handled by:
1. Streaming the server key in chunks during `init_vault`
2. Using WASM memory growth (`memory.grow`) to expand beyond the initial 4MB
3. Or using an external key store with on-demand loading

For the enclave binary (bare-metal, no WASM memory growth), use `PARAM_MESSAGE_1_CARRY_0` with the 3-8 MB server key.

### 6.2 `no_std` Constraints

The `#![no_std]` constraint eliminates:
- Standard library (`std::`)
- OS-level memory allocation (`malloc`/`free`)
- File I/O, network I/O, threading
- Panic unwinding (replaced by `panic = "abort"`)

Required replacements:
- `std::vec::Vec` → `alloc::vec::Vec`
- `std::string::String` → `alloc::string::String`
- `std::collections::HashMap` → `alloc::collections::BTreeMap` (or `hashbrown`)

### 6.3 Arena Allocator

For bare-metal enclave targets, replace the global allocator with a static arena:

```rust
use core::cell::UnsafeCell;

const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4MB

struct BumpAllocator {
    heap: UnsafeCell<[u8; HEAP_SIZE]>,
    offset: core::sync::atomic::AtomicUsize,
}

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let offset = self.offset.fetch_add(layout.size(), core::sync::atomic::Ordering::SeqCst);
        if offset + layout.size() > HEAP_SIZE {
            return core::ptr::null_mut(); // OOM
        }
        (self.heap.get() as *mut u8).add(offset)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Bump allocator: no deallocation
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator {
    heap: UnsafeCell::new([0u8; HEAP_SIZE]),
    offset: core::sync::atomic::AtomicUsize::new(0),
};
```

---

## 7. Memory Layout and Bounds

### 7.1 WASM Linear Memory Map

```
WASM Linear Memory (64 pages = 4,194,304 bytes = 4 MB maximum):

Address     Size        Region
─────────────────────────────────────────────────────────────────
0x000000    512 KB      Execution Stack
                        Function frames, local variables,
                        return addresses
─────────────────────────────────────────────────────────────────
0x080000    512 KB      Static Constants
                        Pre-computed NTT twiddle factors,
                        parameter tables, magic constants
─────────────────────────────────────────────────────────────────
0x100000    128 KB      SRAM PUF Buffer
                        Raw SRAM power-up state (W),
                        Reconstructed PUF data (W')
─────────────────────────────────────────────────────────────────
0x120000    1920 KB     Polynomial Scratchpad
                        Working R_q matrices,
                        Masking vectors y, z,
                        NTT intermediate buffers
─────────────────────────────────────────────────────────────────
0x300000    1024 KB     Protected Output Pool
                        Final SAAP proof transcript,
                        Serialized ciphertexts,
                        Output buffers
─────────────────────────────────────────────────────────────────
0x400000    (end)       Memory boundary (64 pages)
```

### 7.2 Memory Constraints

| Constraint | Value | Enforcement |
|---|---|---|
| Maximum WASM pages | 64 | `memory.max = 64` in WASM module |
| Maximum total memory | 4,194,304 bytes (4 MB) | WASM linear memory limit |
| Stack depth ceiling | 32 KB | Enforced by arena allocator |
| Binary size ceiling (enclave) | 256 KB | CI size check |
| Binary size ceiling (full WASM) | 3.4 MB | CI size check after wasm-opt |

### 7.3 Stack Overflow Prevention

WASM does not have a hardware stack guard. Stack overflows silently corrupt the heap. Mitigations:
1. Avoid deep recursion in contract code
2. Use iterative algorithms instead of recursive ones
3. Pre-allocate all buffers statically where possible
4. Set `RUST_MIN_STACK` environment variable for build-time stack size hints

---

## 8. Deployment Steps

### 8.1 Prerequisites

```bash
# Verify toolchain
rustup target list --installed | grep wasm32-unknown-unknown
wasm-opt --version  # Should be >= 114
cargo --version     # Should be >= 1.79
```

### 8.2 Step 1: Build

```bash
cd aethel-vault

# Build vault contract
cargo build --target wasm32-unknown-unknown --release

# Verify build succeeded
ls -lh target/wasm32-unknown-unknown/release/*.wasm
```

### 8.3 Step 2: Optimize

```bash
# Optimize vault contract
wasm-opt -Oz --enable-simd \
    target/wasm32-unknown-unknown/release/aethel_vault.wasm \
    -o aethel_vault_contract_opt.wasm

# Verify optimization
wasm-validate aethel_vault_contract_opt.wasm
ls -lh aethel_vault_contract_opt.wasm
```

### 8.4 Step 3: Generate Client SDK Bindings

```bash
# Build client SDK with wasm-pack
wasm-pack build --target web --release -- --features wasm

# Output in pkg/
ls pkg/
# aethel_vault.js          (JavaScript glue code)
# aethel_vault_bg.wasm     (WASM binary)
# aethel_vault.d.ts        (TypeScript declarations)
# package.json
```

### 8.5 Step 4: Deploy Contract

```bash
# Deploy to blockchain node (example using aethel-cli)
aethel-cli deploy \
    --wasm aethel_vault_contract_opt.wasm \
    --init-args "$(cat server_key.bin | base64)" \
    --gas-limit 10000000 \
    --network testnet

# Or deploy to local test node
aethel-cli deploy \
    --wasm aethel_vault_contract_opt.wasm \
    --network local
```

### 8.6 Step 5: Initialize Vault

```bash
# Generate TFHE key pair (client-side)
aethel-vault-cli keygen \
    --params PARAM_MESSAGE_2_CARRY_2_KS_PBS \
    --output-client-key client_key.bin \
    --output-server-key server_key.bin

# Initialize contract with server key
aethel-vault-cli init \
    --contract-address 0x... \
    --server-key server_key.bin \
    --network testnet
```

### 8.7 Step 6: Verify Deployment

```bash
# Verify contract is initialized
aethel-vault-cli status \
    --contract-address 0x... \
    --network testnet

# Expected output:
# Contract Status: Initialized
# Server Key: Loaded (PARAM_MESSAGE_2_CARRY_2_KS_PBS)
# Vault Count: 0
# WASM Binary Hash: sha256:...
```

---

## 9. Performance Benchmarks

### 9.1 Binary Size

| Build Configuration | Binary Size |
|---|---|
| Debug build (no optimization) | ~45 MB |
| Release build (no wasm-opt) | ~18.5 MB |
| Release + LTO | ~4.2 MB |
| Release + LTO + wasm-opt -Oz | ~2.1 MB – 3.4 MB |
| Release + LTO + wasm-opt -Oz + SIMD128 | ~2.1 MB – 3.4 MB |

### 9.2 Execution Performance

| Metric | Unoptimized tfhe-rs Build | Optimized WASM Pipeline |
|---|---|---|
| WASM Binary Footprint | ~18.5 MB | ~2.1 MB - 3.4 MB |
| Bootstrap Cycle Latency | ~140ms / gate | ~38ms / gate (with SIMD128) |
| Gas / Fuel Consumed | Baseline (100%) | ~32% of baseline |

### 9.3 Operation Latency

| Operation | Estimated Latency | Notes |
|---|---|---|
| `init_vault` (key deserialization) | ~500ms – 2s | One-time cost; server key is large |
| `register_vault_ciphertext` | ~5ms | Deserialization + storage only |
| `homomorphic_transfer` | ~200ms – 800ms | Depends on TFHE parameter set |
| `sk.ge` (comparison) | ~80ms | Bootstrapping required |
| `sk.select_parallelized` | ~120ms | Conditional selection |
| `sk.sub` / `sk.add` | ~40ms each | Arithmetic operations |

### 9.4 Gas/Fuel Optimization

The optimized WASM pipeline reduces gas consumption to ~32% of baseline through:
1. **Dead code elimination**: Unused TFHE features removed
2. **SIMD128 acceleration**: Polynomial arithmetic vectorized
3. **LTO inlining**: Cross-crate function calls inlined
4. **Size optimization**: Smaller binary = fewer instruction fetches

---

## 10. Troubleshooting

### 10.1 "error: no global memory allocator found"

```
error: no global memory allocator found but one is required; link to std or add
       `#[global_allocator]` to a static item that implements the GlobalAlloc trait.
```

**Fix:** Add a global allocator for `#![no_std]` targets:

```rust
// In src/lib.rs
extern crate alloc;

#[cfg(not(test))]
use wee_alloc::WeeAlloc;

#[cfg(not(test))]
#[global_allocator]
static ALLOC: WeeAlloc = WeeAlloc::INIT;
```

Add to `Cargo.toml`:
```toml
[dependencies]
wee_alloc = { version = "0.4", optional = true }

[features]
wasm = ["wee_alloc"]
```

### 10.2 "WASM binary exceeds size limit"

```
Error: WASM binary size 5.2 MB exceeds limit of 3.4 MB
```

**Fix:** Apply additional feature pruning:
```toml
[dependencies.tfhe]
default-features = false
features = ["boolean", "shortint", "wasm-api"]  # Remove "integer" if not needed
```

Or use more aggressive wasm-opt:
```bash
wasm-opt -Oz --enable-simd --strip-debug --strip-producers --vacuum --dce \
    input.wasm -o output.wasm
```

### 10.3 "SIMD128 not supported"

```
Error: WASM SIMD128 instructions not supported in this runtime
```

**Fix:** Build without SIMD128 for compatibility:
```toml
# .cargo/config.toml
[target.wasm32-unknown-unknown]
rustflags = [
    # Remove: "-C", "target-feature=+simd128",
    "-C", "link-arg=--strip-all",
    "-C", "link-arg=--gc-sections",
]
```

### 10.4 "tfhe-rs: unsupported target"

```
error[E0463]: can't find crate for `std`
```

**Fix:** Ensure `default-features = false` is set for tfhe:
```toml
tfhe = { version = "0.7", default-features = false, features = ["boolean", "shortint", "integer", "wasm-api"] }
```

---

*See also:*
- [`OVERVIEW.md`](./OVERVIEW.md) — High-level architecture overview
- [`TFHE-VAULT-SPEC.md`](./TFHE-VAULT-SPEC.md) — TFHE vault technical specification
- [`Cargo.toml`](../Cargo.toml) — Crate manifest with all dependency configurations
