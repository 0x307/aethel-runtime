# aethel-runtime — Blind-State Quantum Wallet Runtime

[![IETF Draft](https://img.shields.io/badge/IETF-draft--harper--aethel--id--00-blue)](https://datatracker.ietf.org/)
[![Crate](https://img.shields.io/badge/crate-aethel--vault-orange)](https://crates.io/)
[![WASM](https://img.shields.io/badge/target-wasm32--unknown--unknown-green)](https://webassembly.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**aethel-runtime** is the blind-state quantum wallet runtime for the Aethel Protocol. It implements the execution layer — a Threshold Fully Homomorphic Encryption (TFHE) vault contract that processes encrypted balances without ever seeing plaintext values — compiled to a standalone WebAssembly binary for deployment in wasmer.io containers.

> ⚠️ **Security Notice**: This is a pre-release implementation. Do not use in production without a formal security audit.

## Architecture

aethel-runtime implements Layer 3 (Execution) of the Aethel 5-layer stack:

```
┌─────────────────────────────────────────────────────┐
│  LAYER 3 — EXECUTION LAYER  (this crate)            │
│  Multi-Party Threshold-FHE (tfhe-rs)                │
│  E_k(Balance) ⊖ E_k(Transfer) — blind execution    │
│  HelixDB vector-temporal state storage              │
├─────────────────────────────────────────────────────┤
│  LAYER 2 — IDENTITY LAYER  (aethel-core)            │
│  Vault IDs derived from PLP projections             │
│  vault_id = SHAKE-256("AETHEL_VAULT_ID_V1"∥proj)   │
└─────────────────────────────────────────────────────┘
```

## Key Design Principles

- **Blind-state**: The vault contract never sees plaintext balances. All arithmetic is performed on `FheUint64` ciphertexts.
- **Homomorphic transfers**: `new_balance = FHE_sub(old_balance, transfer_amount)` — fully encrypted subtraction
- **Solvency proofs**: `is_solvent = FHE_ge(old_balance, transfer_amount)` — encrypted comparison, no plaintext leak
- **Identity binding**: Vault IDs are one-way derived from `aethel-core` PLP projections — no static key shared between identity and vault layers

## Modules

| Module | Description |
|--------|-------------|
| `vault` | TFHE vault contract — blind-state balance management, homomorphic transfers |
| `client` | Vault client SDK — key generation, balance encryption/decryption, payload construction |
| `storage::helixdb` | HelixDB adapter — vector-temporal graph storage for vault state nodes |
| `sdk` | Vault SDK utilities — payload serialization, ephemeral vault ID generation |

## WASM Exports

```wit
package aethel:runtime@0.1.0;

world aethel-runtime {
  import host-fhe: interface {
    host-fhe-sub: func(a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-add: func(a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-ge:  func(a: list<u8>, b: list<u8>) -> list<u8>;
    host-fhe-select: func(cond: list<u8>, a: list<u8>, b: list<u8>) -> list<u8>;
  }
  export vault;   // vault_init, vault_register, vault_transfer, vault_export_state, vault_import_state, vault_derive_id
  export client;  // client_new, client_encrypt_balance, client_decrypt_balance, client_build_payload
}
```

See [`dist/aethel_vault.wit`](dist/aethel_vault.wit) for the full WIT interface definition.

## Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `ERR_OK` | Success |
| `1` | `ERR_NOT_FOUND` | Vault ID not registered |
| `2` | `ERR_INSUFFICIENT_BALANCE` | Homomorphic solvency check failed |
| `3` | `ERR_DESER` | Deserialization error |
| `4` | `ERR_INVALID_KEY` | Invalid server key |

## Building

### Prerequisites
- Rust 1.75+ with `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- `protoc` (for native HelixDB gRPC): install from https://grpc.io/docs/protoc-installation/

### WASM Build
```bash
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm
```

Output: `target/wasm32-unknown-unknown/debug/aethel_vault.wasm`

### Native Build + Tests
```bash
cargo build
cargo test
```

### Full Pipeline (WASM + dist/)
```powershell
# From aethel-protocol/
./build-wasm.ps1
```

## Distribution Artifacts

| File | Description |
|------|-------------|
| `dist/aethel_vault.wasm` | Compiled WASM binary (4.4 MB) |
| `dist/aethel_vault.wit` | WIT interface definition |
| `dist/aethel_vault.abi.json` | ABI JSON descriptor (6 exports, 5 host FHE imports) |
| `dist/README.md` | Integration documentation |

## Wasmer Host Integration

The vault WASM binary imports 5 FHE functions from the wasmer.io host environment. The host must provide these via the `env` module:

```rust
// Wasmer host implementation example
use wasmer::{imports, Function, Store};

let import_object = imports! {
    "env" => {
        "host_fhe_sub"    => Function::new_typed(&mut store, host_fhe_sub),
        "host_fhe_add"    => Function::new_typed(&mut store, host_fhe_add),
        "host_fhe_ge"     => Function::new_typed(&mut store, host_fhe_ge),
        "host_fhe_select" => Function::new_typed(&mut store, host_fhe_select),
        "host_fhe_zero"   => Function::new_typed(&mut store, host_fhe_zero),
    }
};
```

## Vault ID Derivation

Vault IDs are derived from `aethel-core` PLP projections, creating a one-way cryptographic binding:

```
vault_id = SHAKE-256("AETHEL_VAULT_ID_V1" ∥ plp_projection_bytes)[0..32]
```

This ensures:
- The vault layer cannot be used without a valid identity projection
- No static key is shared between identity and vault layers
- Vault IDs are unlinkable across different identity contexts

## HelixDB Storage

Vault state is persisted in HelixDB, a vector-temporal graph database:

```protobuf
// proto/aethel_helix.proto
service HelixStateStore {
    rpc UpsertStateNode(StateNodeRequest) returns (StateNodeResponse);
    rpc VectorProximitySearch(VectorSearchRequest) returns (VectorSearchResponse);
    rpc TraverseTemporalTrajectory(TraversalRequest) returns (TraversalResponse);
    rpc PruneTemporalNode(PruneRequest) returns (PruneResponse);
}
```

## Security Properties

- **Blind-state**: Vault balances are always encrypted — the contract never processes plaintext
- **Post-quantum**: TFHE is conjectured secure against quantum adversaries
- **Identity-bound**: Vault IDs cryptographically bound to post-quantum identity projections
- **No traditional crypto**: Zero AES, RSA, ECDSA, or classical elliptic curve operations

## Shared WASM Modules

aethel-runtime is designed to run alongside these independently-upgradeable shared WASM modules:

| Module | Purpose |
|--------|---------|
| `pqvm` | Post-Quantum Virtual Machine for PQ operations |
| `qies` | Quantum-Isolated Enclave System (TEE bridge) |
| `awre` | Attested WebAssembly Runtime Engine |
| `wamr` | WebAssembly Micro Runtime sandboxed execution |

## License

MIT — see [LICENSE](LICENSE)

## References

- [IETF Draft: draft-harper-aethel-id-00](https://datatracker.ietf.org/)
- [tfhe-rs: Fully Homomorphic Encryption](https://github.com/zama-ai/tfhe-rs)
- [HelixDB](https://github.com/HelixDB/helix-db)
- [Aethel Whitepaper](https://github.com/0x307/aethel-docs/blob/main/whitepapers/WHITEPAPER.md)
