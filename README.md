# aethel-vault — the agent-held wallet

**Crate: `aethel-vault`. Repository: `aethel-runtime`.**

[![Crate](https://img.shields.io/badge/crate-aethel--vault-orange)](https://crates.io/crates/aethel-vault)
[![WASM](https://img.shields.io/badge/target-wasm32--unknown--unknown-green)](https://webassembly.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

> **Not to be confused with:** `pqc-privacy` has an unrelated AES-GCM +
> Reed-Solomon *shard* module historically also called "vault" there — that
> is a research component in a different crate. **This crate owns the word
> "wallet."**

> ⚠️ **Security Notice**: This is a pre-release implementation. Do not use
> in production without a formal security audit.

## Two assets, not one

This crate holds and moves two entirely separate things. There is **no
bridge** between them in this crate.

| | Confidential internal balance | Settlement asset |
|---|---|---|
| What | `FheUint64` ciphertext | USDC on Base / Ethereum / Arbitrum One |
| Feature | `fhe-state` (optional) | `signer` (**default**) |
| Where it lives | The agent's own storage (possibly hostile) | Public chain state |
| Privacy is against | That storage | Nothing — it's public by nature |
| Moved by | This crate's homomorphic transfer ([`vault`]) | An EIP-3009 authorization the *external* wallet signs ([`settlement`]) |
| Is it a token / on a chain? | **No.** Not a token, not on any chain, not USDC. | Yes — it is USDC. |

An FHE transfer never moves USDC. An EIP-3009 authorization never changes
an FHE balance unless the agent explicitly records it. See
[`src/vault.rs`](src/vault.rs)'s module docs for more.

## Zero ECDSA / 100% PQC signer

`secp256k1` never lives in this crate — not as a dependency, not as code.
This crate's own signatures (spend intents, settlement receipts, wallet
binds, HITL approvals) are **ML-DSA-65**, via `aethel_core::signing::Identity`,
under purpose-separated contexts (see `aethel-core`'s `docs/PURPOSES.md`).
The settlement authorization's ECDSA `(v, r, s)` is produced by the agent's
*own* external wallet through the injected [`settlement::SettlementSigner`]
trait — no implementation of that trait ships in this crate except a
test-only mock. `secp256k1` lives in the agent's wallet; a hybrid
(PQC + classical) posture, if wanted, lives at SAGP (the gateway), not here.

`tests/`/`src/settlement.rs`'s `manifest_contains_no_ecdsa_crates` test
greps this crate's own `Cargo.toml` for `k256`/`secp256k1`/`alloy`/`ethers`
and fails the build if any of them ever appear.

## Custody rule: the ServerKey — and the settlement signer — never leave the agent

- **ServerKey** (`fhe-state`): held only in a process-local, never-serialized
  runtime structure. It is never part of the persisted/exported
  `VaultState` — see [Vault ID Derivation](#vault-id-derivation) and
  `docs/TFHE-VAULT-SPEC.md`.
- **Settlement signer** (`signer`): the agent's own wallet process, hardware
  key, MPC signer, or HSM. This crate only builds the digest; it never
  holds a secp256k1 private key.
- **There is no "hosted vault" mode**, and there never will be. Enabling a
  Cargo feature literally named `hosted` is a hard `compile_error!` — see
  `src/lib.rs`. Do not host `aethel-vault` on third-party infrastructure.

## Two modes

| Mode | Feature | Default? | What it gives you |
|---|---|---|---|
| **Signer** | `signer` | **Yes** | EIP-3009/x402 settlement export, standing spend policy, optional signed receipts. No `tfhe`, no HelixDB. This is the Wave-1 "pay a 402 unattended" path. |
| **Confidential ledger** | `fhe-state` | No | The homomorphic internal balance state machine (`vault`/`client`). A differentiator for agents storing state on a hostile host — not a Wave-1 gate. |
| **HelixDB storage** | `helixdb` | No | The gRPC storage adapter for the confidential ledger. Pulls `tokio`/`tonic`/`prost`; runs `prost-build`. |

A plain `cargo add aethel-vault` builds `signer` only. Confirm with:

```powershell
cargo tree -e normal --no-default-features --features signer
```

— it must contain no `tfhe`, `tokio`, `tonic`, `prost`, `k256`, `secp256k1`,
or `ed25519-dalek`.

## Pay a 402 in three calls

```rust,ignore
use aethel_vault::{Chain, SpendPolicy, Rail, Wallet};
use aethel_core::signing::Identity;

// 1. An external, ECDSA-capable signer the agent already has (hardware,
//    MPC, HSM, browser wallet) — implement `SettlementSigner` around it.
let signer = MyHardwareWalletSigner::connect()?;

// 2. The vault's own ML-DSA-65 identity (for spend-intent/receipt
//    signatures — never for the on-chain authorization itself).
let identity = Identity::generate(&entropy)?;

// 3. A standing policy: no HITL below $0.50, hard cap at $2/day.
let policy = SpendPolicy {
    max_per_call: 50_000,      // 0.05 USDC (6dp)
    daily_cap: 2_000_000,      // 2.00 USDC
    allow_rails: vec![Rail::Eip3009Base],
    hitl_above: 500_000,       // 0.50 USDC
    ttl_secs: 3600,
    hitl_approver_pk: None,
};

let mut wallet = Wallet::new(signer, identity, policy);
let auth = wallet.authorize_eip3009(to, value, nonce, Chain::Base, now_unix, None)?;
// post `auth` (or its fields) in the `X-PAYMENT` header.
```

## Policy lives in the agent

```text
SpendPolicy {
    max_per_call:      50_000,   // 0.05 USDC
    daily_cap:       2_000_000,  // 2.00 USDC
    allow_rails:     [Eip3009Base],
    hitl_above:        500_000,  // 0.50 USDC
    ttl_secs:              3600,
    hitl_approver_pk:        None,
}
```

Enforced by `Wallet::authorize_eip3009` **before** anything is built or
signed — a denied or unsatisfied-HITL request produces no signature of any
kind. This is "G-POLICY living in the agent, not on the gateway."

## Receipts are the agent's to disclose

`Wallet::last_receipt()` / `Wallet::sign_receipt()` are separate, opt-in
calls. Nothing is signed or transmitted unless the agent explicitly asks —
see [`src/receipt.rs`](src/receipt.rs).

## Modules

| Module | Feature | Description |
|--------|---------|-------------|
| `settlement` | `signer` (default) | EIP-3009/x402 export: `Chain`, `TransferWithAuthorization`, `SettlementSigner`, `Wallet` |
| `policy` | `signer` (default) | `SpendPolicy`, `PolicyState`, `Rail`, `HitlApproval` |
| `receipt` | `signer` (default) | `Receipt`, `SignedReceipt` |
| `error` | `signer` (default) | `VaultError` |
| `vault` | always (FHE ops need `fhe-state`) | confidential-ledger state machine; `derive_vault_id` always available |
| `client` | `fhe-state` / `wasm` | confidential ledger client SDK |
| `storage::helixdb` | `helixdb` | HelixDB gRPC adapter |
| `sdk` | always | TypeScript/Rust SDK utilities |

## Error Codes (confidential-ledger `extern "C"` ABI, `vault` module)

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `ERR_OK` | Success |
| `1` | `ERR_NOT_FOUND` | Vault ID not registered |
| `2` | `ERR_INSUFFICIENT_BALANCE` | Homomorphic solvency check failed |
| `3` | `ERR_DESER` | Deserialization error |
| `4` | `ERR_INVALID_KEY` | Invalid or absent ServerKey (also returned when `fhe-state` is disabled — there is no FHE backend compiled in) |
| `5` | `ERR_UNAUTHORIZED` | `homomorphic_transfer_authenticated`: sender has no identity binding, the supplied projection doesn't match it, or the PLP ownership proof failed to verify |

The `signer`-mode surface (`settlement`/`policy`/`receipt`) uses the
Rust-native `VaultError` enum instead — see `src/error.rs`.

## Building

### Prerequisites
- Rust with the `wasm32-unknown-unknown` target for WASM builds:
  `rustup target add wasm32-unknown-unknown`
- `protoc` **only if** building with `--features helixdb`.

### Thin signer build (default)
```bash
cargo build
cargo test
```

### Confidential-ledger (`fhe-state`) build
```bash
cargo build --features fhe-state
cargo test --features fhe-state
```

### WASM (confidential-ledger contract)
```bash
cargo build --target wasm32-unknown-unknown --no-default-features --features "wasm fhe-state"
```

Output: `target/wasm32-unknown-unknown/debug/aethel_vault.wasm`

## Vault ID Derivation

`derive_vault_id` hashes whatever bytes it is given, and is available
regardless of the `fhe-state` feature (pure hashing, no TFHE dependency):

```
vault_id = SHAKE-256("AETHEL_VAULT_ID_V1" ∥ plp_projection_bytes)[0..32]
```

That hash alone binds nothing: it derives the same ID from a real
`aethel-core` `EphemeralProjection`'s bytes as it would from any other 32+
bytes a caller hands it. Two registration paths use it differently
(`fhe-state` feature):

- **`register_vault_ciphertext`** takes a caller-supplied vault ID directly.
  Nothing checks it came from a real projection. Transfers against vaults
  registered this way (`homomorphic_transfer`) are authorized by
  ciphertext possession alone.
- **`register_vault_with_identity`** takes `aethel-core` `EphemeralProjection`
  bytes, validates they decode, and derives the vault ID from them
  server-side. Transfers against vaults registered this way
  (`homomorphic_transfer_authenticated`) additionally require a PLP
  ownership proof, verified via `aethel_core::plp::Verifier::verify`.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for why a caller-submitted
ownership proof can't yet cross the WASM/`extern "C"` boundary.

## HelixDB Storage (`helixdb` feature)

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

- **Zero ECDSA in this crate**: no `k256`/`secp256k1`/`alloy`/`ethers`
  dependency, ever (enforced by a manifest-grep test).
- **100% PQC vault-side signer**: spend intents, receipts, wallet binds,
  and HITL approvals are all ML-DSA-65.
- **Policy before signature**: `Wallet::authorize_eip3009` checks
  `SpendPolicy` before calling the injected `SettlementSigner` or signing a
  `SpendIntent`. Denied ⇒ no signature at all.
- **Confidential-ledger blind-state** (`fhe-state`): balances are always
  encrypted; this crate never decrypts them.
- **No hosted mode**: enforced structurally (`hosted` feature ⇒
  `compile_error!`), not just documented.

## Known Gap: Balances Are Not the Whole Privacy Story

Encrypting a balance into an `FheUint64` hides transaction **amounts**. It
does nothing for the transaction **graph** if accounts are still keyed by a
public, correlatable identifier. **Blind state is only meaningful once the
account is no longer keyed by a correlatable public identifier.** See
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

Apache-2.0 — see [LICENSE](LICENSE)

## References

- [IETF Draft: draft-harper-aethel-id-00](https://datatracker.ietf.org/)
- [tfhe-rs: Fully Homomorphic Encryption](https://github.com/zama-ai/tfhe-rs)
- [HelixDB](https://github.com/HelixDB/helix-db)
- [aethel-core](https://crates.io/crates/aethel-core)
- [EIP-3009: Transfer With Authorization](https://eips.ethereum.org/EIPS/eip-3009)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
