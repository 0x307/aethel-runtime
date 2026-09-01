# aethel-runtime — Blind-State Quantum Wallet Runtime

[![IETF Draft](https://img.shields.io/badge/IETF-draft--harper--aethel--id--00-blue)](https://datatracker.ietf.org/)
[![Crate](https://img.shields.io/badge/crate-aethel--vault-orange)](https://crates.io/)
[![WASM](https://img.shields.io/badge/target-wasm32--unknown--unknown-green)](https://webassembly.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**aethel-runtime** is a sibling product to `aethel-core`, built on top of it rather than a layer inside it: a single-party Fully Homomorphic Encryption (FHE) vault contract that processes encrypted balances without ever seeing plaintext values, compiled to a standalone WebAssembly binary for deployment in wasmer.io containers. It is the execution layer for blind-state balances; `aethel-core` is the identity layer it consumes, not a component it embeds. Multi-party threshold FHE across a validator network is a design target this crate does not implement — see [Architecture](#architecture).

> ⚠️ **Security Notice**: This is a pre-release implementation. Do not use in production without a formal security audit.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  EXECUTION LAYER  (this crate, aethel-runtime)      │
│  Single-party FHE today (tfhe-rs, one ServerKey)    │
│  Multi-party threshold FHE across a validator       │
│  network is a design target, not implemented here   │
│  E_k(Balance) ⊖ E_k(Transfer) — blind execution     │
│  HelixDB vector-temporal state storage              │
├─────────────────────────────────────────────────────┤
│  IDENTITY LAYER  (aethel-core, a separate crate)    │
│  Vault IDs derived from PLP projections             │
│  vault_id = SHAKE-256("AETHEL_VAULT_ID_V1"∥proj)   │
│  Transfers can require a PLP ownership proof,       │
│  verified via aethel-core::plp::Verifier            │
└─────────────────────────────────────────────────────┘
```

A single `ServerKey` held by one party performs every homomorphic operation:
no resharing, no distributed decryption, no validator set. That is
sufficient for the near-term consumer (a single-operator balance ledger);
it is not the threshold system some earlier planning documents described,
and code and docs should not describe it as one until resharing and
distributed decryption actually exist.

## Key Design Principles

- **Blind-state**: The vault contract never sees plaintext balances. All arithmetic is performed on `FheUint64` ciphertexts.
- **Homomorphic transfers**: `new_balance = FHE_sub(old_balance, transfer_amount)` — fully encrypted subtraction
- **Solvency proofs**: `is_solvent = FHE_ge(old_balance, transfer_amount)` — encrypted comparison, no plaintext leak
- **Identity-authorized transfers**: `homomorphic_transfer_authenticated` requires a caller-supplied `aethel-core` PLP ownership proof that verifies against the sender vault's registered identity projection, so moving a vault's funds requires proving control of the identity behind it, not merely knowing its ID and a `ServerKey`. The plain `homomorphic_transfer`/`register_vault_ciphertext` path is still present and still authorizes by ciphertext + `ServerKey` possession alone; use the `_with_identity` / `_authenticated` entry points where that matters. See [Vault ID Derivation](#vault-id-derivation) and [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
| `5` | `ERR_UNAUTHORIZED` | `homomorphic_transfer_authenticated`: sender has no identity binding, the supplied projection doesn't match it, or the PLP ownership proof failed to verify |

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

`derive_vault_id` hashes whatever bytes it is given:

```
vault_id = SHAKE-256("AETHEL_VAULT_ID_V1" ∥ plp_projection_bytes)[0..32]
```

That hash alone binds nothing: it derives the same ID from a real
`aethel-core` `EphemeralProjection`'s bytes as it would from any other 32+
bytes a caller hands it. Two registration paths use it differently:

- **`register_vault_ciphertext`** takes a caller-supplied vault ID directly.
  Nothing checks it came from a real projection, or from an identity that
  owns anything. Transfers against vaults registered this way
  (`homomorphic_transfer`) are authorized by ciphertext + `ServerKey`
  possession alone.
- **`register_vault_with_identity`** takes `aethel-core` `EphemeralProjection`
  bytes, validates they decode, and derives the vault ID from them
  server-side — the caller cannot pick an ID unrelated to the projection.
  Transfers against vaults registered this way
  (`homomorphic_transfer_authenticated`) additionally require a PLP
  ownership proof, verified via `aethel_core::plp::Verifier::verify`, against
  the exact projection the vault was registered under.

Both paths produce vault IDs that are unlinkable across different identity
contexts (a fresh projection per context, hashed the same way). Only the
second path ties spending to proof of identity ownership. See
[`docs/ROADMAP.md`](docs/ROADMAP.md) for why a caller-submitted ownership
proof can't yet cross the WASM/`extern "C"` boundary the rest of this
module's entry points use, and what would need to change upstream in
`aethel-core` to close that.

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
- **Post-quantum**: TFHE is conjectured secure against quantum adversaries; identity proofs reduce to M-LWE hardness (`aethel-core`)
- **Identity-authorized (where wired)**: `homomorphic_transfer_authenticated` requires a verified PLP ownership proof, not merely a vault ID. The plain `homomorphic_transfer` path does not, and still authorizes by `ServerKey` possession alone — see [Vault ID Derivation](#vault-id-derivation)
- **No traditional crypto**: Zero AES, RSA, ECDSA, or classical elliptic curve operations
- **Single-party FHE, not threshold**: one `ServerKey`, one operator. See [Architecture](#architecture)

## Known Gap: Balances Are Not the Whole Privacy Story

Encrypting a balance into an `FheUint64` hides transaction **amounts**. It
does nothing for the transaction **graph** if accounts are still keyed by a
public, correlatable identifier — a public EVM or Solana wallet address,
for instance, which is maximally correlatable by design. A consumer that
adopts blind-state balances while continuing to key accounts by such an
address gets encrypted amounts moving over a fully visible graph of who
paid whom, which is a materially weaker property than "blind state" implies.

**Blind state is only meaningful once the account is no longer keyed by a
correlatable public identifier.** That de-correlation work is sequenced
behind this crate's identity work broadly and is not part of it; see
[`docs/ROADMAP.md`](docs/ROADMAP.md).

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
