# Changelog — aethel-vault

All notable changes to this crate are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.3] - 2026-10-23

No change to the API, the wire formats or behaviour. No version was yanked in this release:
0.3.1 and 0.3.2 stay published and supported.

### Changed

- **The aethel-core floor is now 0.7.5** (was 0.7). aethel-core 0.7.5 moves to pqc-sig 0.5 with
  byte-identical outputs. The vault's own vault-ID derivation and ML-DSA-65 signing tests pass
  unchanged against it. `default-features = false` and the features this crate uses are as
  before.
- **Apps on aethel-core 0.7.4 keep building.** A `"0.7.4"` requirement resolves to 0.7.5
  alongside this crate. Only an exact `=0.7.4` pin does not, and it keeps building on
  aethel-vault 0.3.2.
- **Apps on pqc-sig 0.4 keep building.** Cargo resolves pqc-sig 0.4 and 0.5 side by side. No
  pqc-sig type is in this crate's public API.
- **The pqc-sig 0.4 line is supported until 2027-05-31.** It gets security fixes until then and
  stays downloadable after. Move to 0.5 before that date.
- **The FHE ledger (`fhe-state`) and the HelixDB adapter (`helixdb`) are marked experimental** in
  the README and the crate docs. The ledger's core operations have no real tests: they are
  `#[ignore]` TODO stubs in `tests/vault_tests.rs`. The HelixDB adapter is stubs: every storage
  call returns `HelixError::NotImplemented`. The stubs stay in place. Only `signer` mode is
  tested and supported.
- **`STABILITY.md` has the family version policy.** We never yank, including for security
  bugs. A security bug is fixed forward and reported as a RustSec advisory. More than one line
  may be live. A legacy line gets security patches for 6 months after its successor ships,
  then is marked unsupported and stays downloadable. This replaces the old "Yanks" section.

### Added

- **`deny.toml` and a cargo-deny CI job** (advisories, bans, licenses, sources), matching the
  other family repos. It scans all features, runs on every PR and push to `main`, and weekly.
  Recorded exceptions, each with its reason in `deny.toml`:
  - `bincode` 1.3 (RUSTSEC-2025-0141) and `paste` (RUSTSEC-2024-0436) are unmaintained.
    bincode is the encoding of this crate's snapshots and signed receipts, so dropping it is a
    wire-format change for a later minor release. paste reaches the build only through `tfhe`.
  - `tfhe` and Zama's sub-crates are BSD-3-Clause-Clear with Zama's patent terms. They are
    allowed as a scoped exception only, behind the non-default `fhe-state` feature. Commercial
    use of `tfhe` needs Zama's terms.
  - `h2` 0.3 (RUSTSEC-2026-0258, low-severity denial of service) comes in through `tonic`
    0.11, behind the experimental `helixdb` feature. The fix needs a tonic major bump. No code
    path runs h2 today, because the HelixDB adapter never opens a gRPC channel.

### Lockfile

`Cargo.lock` only governs this repository's own builds. A crate that depends on this one
resolves these itself.

- aethel-core 0.7.0, which is yanked, moves to 0.7.5, and pqc-sig 0.4.2 moves to 0.5.0.
  SLH-DSA and its hashing crates leave the graph.
- `ctutils` moves from 0.4.2 to 0.4.5 for RUSTSEC-2026-0385 (non-constant-time mask
  generation, fixed in 0.4.4). It reaches this crate through pqc-sig's ML-DSA code. A
  downstream build picks up the fix with `cargo update -p ctutils`.

## [0.3.2] - 2026-09-30

Documentation only. No change to the API, the wire formats or behaviour.

- The README no longer carries a generic "do not use in production" banner. The tier
  (Preview) and the audit status are unchanged and still stated in the header and the
  crate-family section: not independently audited, no CMVP validation.
- `Cargo.lock` moves from pqc-sig 0.4.1, now yanked, to 0.4.2. This lockfile only governs this
  repository's own builds.

## [0.3.1] - 2026-09-23

Documentation and metadata only. No change to the API, the wire formats or behaviour.

- The README opens with the crate's tier, MSRV, license and audit status, and ends with the
  0x307 crate family: the six crates with their tiers, the runnable examples in
  [0x307/examples](https://github.com/0x307/examples), and one audit statement shared by all
  of them. The same section is in the crate docs, so it renders on docs.rs.
- `Cargo.toml` sets `documentation` (docs.rs) and `homepage` (0x307.com/crates).
- Adds `SECURITY.md` (how to report a vulnerability, what this crate does and does not protect)
  and `STABILITY.md` (the policy shared by every 0x307 crate), the only two the vault lacked.
- Declares `rust-version = "1.85"`, the family MSRV, checked by building on Rust 1.85.0.
- `Cargo.lock` moves from pqc-sig 0.4.0, now yanked, to 0.4.1. This lockfile only governs this
  repository's own builds; a crate that depends on this one resolves pqc-sig itself.

## [0.3.0] — aethel-core 0.7

Depends on aethel-core 0.7 (was 0.6). No other change.

This is **breaking** in Cargo's sense, not in behaviour: `aethel_core::signing::Identity`
appears in this crate's public API (`Receipt::sign`, `SettlementVault::new`), so an
application that also depends on aethel-core directly must use the same minor version.
With aethel-vault 0.2 and the latest aethel-core (0.7) in one project, cargo resolved two
aethel-core versions and the build failed with "expected `Identity`, found `Identity`".
Pair aethel-vault 0.3 with aethel-core 0.7.

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
  `0.3`), resolved from crates.io. `aethel-core` 0.6.0 removed its root
  re-export of `sampling::{PlpProof, RejectionError, VectorK}` and added
  the `wire`/`verify_projection` surface this crate's new modules consume.

### Fixed

- **HITL approval fails closed when no approver is configured.**
  `HitlApproval::verify` skipped the approver-key check when
  `SpendPolicy::hitl_approver_pk` was `None`, so an approval signed by any
  freshly generated key unblocked a spend above `hitl_above`. `None` now
  refuses every approval, matching the field's documented contract.

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
