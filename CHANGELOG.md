# Changelog — aethel-vault

All notable changes to this crate are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] — SAGP-PG-001 gap remediation (V-1 … V-7)

This is a **breaking release**: the default feature set changed, the
persisted `VaultState` snapshot format changed, and one type was renamed
(with a deprecated alias kept for source compatibility).

### Breaking changes

- **Default features changed (V-3).** `default` is now `["std", "signer"]`,
  not the old `["std"]` that pulled `tokio`/`tonic`/`prost` (HelixDB) and
  `tfhe` unconditionally on x86_64/aarch64-unix. A plain `cargo add
  aethel-vault` now builds the thin signer path only. The confidential
  internal ledger moved behind a new `fhe-state` feature; the HelixDB
  storage adapter moved behind a new `helixdb` feature.
- **`VaultState` snapshot format changed (V-2).** Persisted/exported state
  is now version-prefixed (`[VAULT_STATE_VERSION] ++ bincode(VaultState)`)
  and **no longer contains the ServerKey** — `VaultState.server_key_bytes`
  is gone. A snapshot exported by 0.1.x will be rejected by
  `import_vault_state` (`ERR_DESER`) rather than silently loaded. The
  ServerKey now lives only in a process-local, never-serialized runtime
  structure; call `init_vault` again after every `import_vault_state`.
- **`aethel-core` dependency bumped to 0.6** (from the previously-pinned
  `0.3`), resolved via a `path = "../aethel-core"` sibling-directory
  dependency (see `Cargo.toml`'s dependency comment for why: 0.6.0 is an
  unpublished, coordinated bump). `aethel-core` 0.6.0 removed its root
  re-export of `sampling::{PlpProof, RejectionError, VectorK}` and added
  the `wire`/`verify_projection` surface this crate's new modules consume.

### Added

- **V-1 — `src/settlement.rs`**: EIP-3009/x402 settlement export.
  `Chain` (Base/Ethereum/Arbitrum One, with `chain_id()`, `usdc_contract()`,
  `domain_separator()`), `TransferWithAuthorization` +
  `eip712_digest(&self, chain)`, `eip191_wallet_bind_digest` +
  `wallet_bind_canonical_json`, the injected `SettlementSigner` trait (no
  implementation ships except a test-only mock), `SpendIntent`,
  `SettlementAuthorization`, and `Wallet<S: SettlementSigner>` with
  `authorize_eip3009`. Zero ECDSA in this crate — see the module's
  "Zero ECDSA / 100% PQC signer" docs and
  `tests::manifest_contains_no_ecdsa_crates`.
- **V-2 — ServerKey custody fix** in `src/vault.rs`: `RuntimeKeys` (never
  serialized) split out of `VaultState`; `VAULT_STATE_VERSION` byte;
  `hosted` feature is a hard `compile_error!` in `src/lib.rs`.
- **V-3 — feature partition**: `signer` (default), `fhe-state`, `helixdb`,
  `wasm`, `hosted` (compile-error-only). `build.rs` skips `prost-build`
  unless `helixdb` is enabled.
- **V-4 — `src/policy.rs`**: `SpendPolicy`, `PolicyState`, `Rail`,
  `SpendRequest`, `Decision`, `PolicyViolation`, `HitlApproval` (ML-DSA-65
  under `aethel_core::signing::purpose::VAULT_HITL_APPROVAL_V1`).
- **V-5 — `src/receipt.rs`**: `Receipt`, `SignedReceipt`, `sign`/`verify`
  under `VAULT_SETTLEMENT_RECEIPT_V1`. Emitted only on request
  (`Wallet::last_receipt`/`sign_receipt`).
- **`src/error.rs`**: `VaultError`, the Rust-native error type for the
  `signer`-mode surface (distinct from `vault.rs`'s `extern "C"` `ERR_*`
  codes, which are unchanged).
- **V-3 residual — `vault::homomorphic_transfer_authenticated_bytes`**
  (`fhe-state`): the bytes-taking counterpart of
  `homomorphic_transfer_authenticated`, closing the `docs/ROADMAP.md` §2
  gap now that `aethel-core` 0.6.0 ships `aethel_core::wire::verify_projection`.
  Takes the PLP projection/proof as `&[u8]` `aethel-plp-1` envelopes plus a
  context, enforces the same registration-binding check as the
  struct-based path (`aethel_core::wire::decode_projection` vs. the
  registered projection bytes), and falls through to the identical shared
  transfer logic on success. New error code `ERR_WIRE_VERIFY_FAILED` (6)
  is returned for an undecodable proof or a proof that fails
  `verify_projection` (wrong context or bad cryptographic verification),
  distinct from `ERR_UNAUTHORIZED` (no such registered identity). Adds a
  `wasm_vault_transfer_authenticated_bytes` export (`wasm`+`fhe-state`) and
  a crate-root `vault_transfer_authenticated_bytes` wrapper (`lib.rs`).
  Tests in `tests/vault_tests.rs`: `test_homomorphic_transfer_authenticated_bytes_valid_proof_succeeds`,
  `test_homomorphic_transfer_authenticated_bytes_rejects_tampered_proof`,
  `test_homomorphic_transfer_authenticated_bytes_rejects_wrong_context`,
  `test_homomorphic_transfer_authenticated_bytes_rejects_bad_magic`,
  `test_struct_and_bytes_authenticated_paths_agree`.

### Changed / renamed

- **V-7**: `client::ContractPayload` renamed to `client::LedgerPayload`
  (soft rename — `ContractPayload` kept as a `#[deprecated]` type alias).
  Module docs across `lib.rs`/`vault.rs`/`client.rs` no longer describe the
  confidential ledger as "on-chain" or "validator"-processed; a new
  "Two assets, not one" statement makes explicit that the confidential
  internal balance is not the settlement asset (USDC).
- **V-6**: README/`lib.rs` now open with "aethel-vault — the agent-held
  wallet (crate `aethel-vault`, repo `aethel-runtime`)" and a
  not-to-be-confused-with note for `pqc-privacy`'s unrelated `vault` shard
  module.

## [0.1.1] and earlier

See git history. `0.1.0` was the first crates.io release (2026-09-01, see
`docs/ROADMAP.md` §4).
