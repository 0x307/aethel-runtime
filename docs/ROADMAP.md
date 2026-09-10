# aethel-runtime Roadmap

This tracks what's sequenced ahead of what in this repo, and why, so the
tempting-to-build-first part doesn't get built first.

## 0. SAGP-PG-001 gap remediation (V-1 … V-7) — landed in 0.2.0

The primitive-gap-analysis items tracked against this crate
(`aethel-docs/plan/PRIMITIVE-GAP-REMEDIATION.md` §3) are now implemented:

- **V-1** `src/settlement.rs` — EIP-3009/x402 export, `Wallet::authorize_eip3009`.
- **V-2** ServerKey custody fix in `src/vault.rs` (`RuntimeKeys`, version-prefixed snapshots, `hosted` feature is a hard compile error).
- **V-3** feature partition — `signer` (default), `fhe-state`, `helixdb`.
- **V-4** `src/policy.rs` — `SpendPolicy`/`PolicyState`/`HitlApproval`, enforced before any signature.
- **V-5** `src/receipt.rs` — optional signed receipts.
- **V-6/V-7** — naming/framing docs (README, this file's neighbors, module docs).

§2 below (the identity-proof wire-format gap) and §5 (deliberately not
attempted) are unaffected by this work and remain as written.

## 1. Account de-correlation comes before wider blind-state adoption

A downstream consumer of this crate keys accounts by DID and by public
EVM/Solana wallet addresses. Encrypting a balance into an `FheUint64` hides
transaction *amounts*. It does nothing for the transaction *graph*: a public
chain address is maximally correlatable by design, so every transfer between
two encrypted-balance accounts is still visible as an edge between two known
addresses.

**Blind state is only meaningful once the account is no longer keyed by a
correlatable public identifier.** Encrypting the balance is the demonstrable,
easy-to-build-first part of this arc; building it first would look like the
privacy property had shipped when only the amount-hiding half had. The
de-correlation work (replacing public-address account keys with something
that isn't trivially linkable, presumably PLP-projection-derived vault IDs
used consistently instead of addresses) is sequenced ahead of any broader
rollout of the blind-state balance path, not the other way around. This repo
does not attempt that work; it is called out here so the next person doesn't
reach for the encrypted-balance part first because it's the one with a demo.

## 2. Wiring an untrusted network caller's identity proof into the vault — landed

`homomorphic_transfer_authenticated` (`src/vault.rs`) verifies a
`aethel_core::plp::ZkIdentityProof` against a vault's registered
`EphemeralProjection` via `aethel_core::plp::Verifier::verify`. That call is
real, but it is native-struct-only: `ZkIdentityProof`'s field type has no
public constructor outside `aethel-core`, so this function is reachable only
by a caller that links `aethel-vault` and `aethel-core` together in the same
Rust binary and produces the proof in-process — a native validator or
gateway service, not a wallet submitting a proof over the wire.

That gap is now closed on the `aethel-core` side (A-4, 0.6.0): `aethel-core`
shipped a validated byte codec for both `EphemeralProjection` and
`ZkIdentityProof` under a versioned, self-describing envelope
(`aethel_core::wire`, codec name `aethel-plp-1`) plus the byte-only entry
point `aethel_core::wire::verify_projection(projection_bytes, proof_bytes,
context) -> Result<bool, IdentityError>`. This crate now has the
corresponding downstream consumer, closing out the "Downstream" note in
A-4's plan and the `ROADMAP §2 follow-up` this file used to describe as
future work:

- **`homomorphic_transfer_authenticated_bytes`** (`src/vault.rs`,
  `fhe-state` feature) — takes `projection_bytes: &[u8]` / `proof_bytes:
  &[u8]` (an `aethel-plp-1` envelope each) plus `context: &[u8]` instead of
  native `aethel-core` structs. It decodes the projection
  (`aethel_core::wire::decode_projection`) and checks it against the
  projection `sender_id` was registered under (the same registration-binding
  check the struct-based function performs), then calls
  `aethel_core::wire::verify_projection`. `Err(_)` or `Ok(false)` from that
  call — an undecodable proof envelope, a proof made for the wrong context,
  or a proof that fails cryptographic verification — is rejected with a new,
  distinct error code, `ERR_WIRE_VERIFY_FAILED` (6), so a caller can tell
  "no such registered identity" (`ERR_UNAUTHORIZED`, unchanged) apart from
  "the wire proof itself did not check out". Only on success does it fall
  through to the same transfer logic `homomorphic_transfer` /
  `homomorphic_transfer_authenticated` use — no transfer logic is
  duplicated. A `wasm_vault_transfer_authenticated_bytes` export
  (`wasm`+`fhe-state`) and a crate-root `vault_transfer_authenticated_bytes`
  wrapper (`lib.rs`) are included: every argument here is already `&[u8]`,
  so a wasm-bindgen wrapper was the natural, bytes-in/bytes-out shape.
- Tests added under `--features fhe-state` in `tests/vault_tests.rs`'s
  `fhe_state_tests` module: `test_homomorphic_transfer_authenticated_bytes_valid_proof_succeeds`,
  `test_homomorphic_transfer_authenticated_bytes_rejects_tampered_proof`,
  `test_homomorphic_transfer_authenticated_bytes_rejects_wrong_context`,
  `test_homomorphic_transfer_authenticated_bytes_rejects_bad_magic`,
  `test_struct_and_bytes_authenticated_paths_agree` (the last exercises both
  entry points against equivalent identity/proof/transfer inputs, each
  against its own pair of vaults since `register_vault_with_identity`
  derives the vault ID deterministically from the projection, and asserts
  both return `ERR_OK` and produce the identical balance effect).

The struct-based `homomorphic_transfer_authenticated` is unchanged and
remains available for in-process callers that already hold native
`aethel-core` structs; the two are alternatives, not a deprecation.

## 3. Doc debt beyond README.md and the crate-level doc comment — addressed

`README.md`, `src/lib.rs`'s crate doc comment, and `docs/OVERVIEW.md` now
describe only what `src/` actually implements: single-party FHE, PLP-derived
vault IDs, and the `homomorphic_transfer_authenticated` identity-proof path.
`docs/TFHE-VAULT-SPEC.md` and `docs/WASM-DEPLOYMENT.md` carry
implementation-status notes distinguishing the remaining design-target
material they describe (SRAM PUF, an "enclave binary" build) from what ships,
plus inline corrections at concrete claims that were simply wrong rather
than aspirational (e.g. `TFHE-VAULT-SPEC.md`'s error-code table listed
100/101/102/103, which were never the real values; `WASM-DEPLOYMENT.md`
§4.1 named a `tfhe` feature that doesn't exist and described the wasm32
contract as linking `tfhe` directly, which it never has).

Separately, since fixed: `build.rs` used to regenerate `dist/*`
unconditionally on every `cargo build`, which made those files show as
modified after any local build (line-ending churn under `core.autocrlf`) and
turned out to be a hard blocker, not just noise: `cargo publish --dry-run`
failed outright with "Source directory was modified by build.rs", since a
build script writing into the source tree is exactly what publish
verification rejects. Now env-gated behind `AETHEL_GENERATE_DIST=1`,
matching the identical fix `aethel-core` made in its own 0.1.5. `dist/` and
`docs/TFHE-VAULT-SPEC.md`/`docs/WASM-DEPLOYMENT.md` are also excluded from
what `cargo package` actually ships (`Cargo.toml`'s `exclude` list) — a
Rust consumer builds from `src/`, and both carry a stronger permanence bar
once published to crates.io than the mutable git repo.

## 4. Published to crates.io (2026-09-01)

`aethel-vault` 0.1.0 is live on crates.io. Sequencing: GitHub repo
visibility was flipped to public first (`0x307/aethel-runtime`, alongside
`aethel-core` and the SDK), then the crate was published, so
`Cargo.toml`'s `repository` link resolves rather than 404ing.

One retry needed: the first `cargo publish` attempt was rejected outright by
the registry — `"homomorphic-encryption"` in `keywords` is 22 characters,
over crates.io's 20-character keyword limit. Nothing was uploaded on that
attempt (it fails validation before accepting the upload). Fixed by
replacing it with `"encryption"` (the existing `"fhe"` keyword already
covers the distinction).

## 5. Not attempted in this pass, and deliberately so

- Wiring identity checks into every vault operation (registration,
  withdrawal, etc.) rather than just transfer. One operation is enough to
  prove the pattern works; wiring all of them multiplies the surface area of
  a decision (PLP proof vs. full SAAP presentation vs. host-delegated
  verification) that isn't settled yet.
- Full SAAP presentation verification (`aethel_core::credential::verify`)
  instead of a bare PLP ownership proof. It hits the identical
  no-external-constructor wall described above for `saap::Polynomial`
  (`SaapPresentation`'s field type), for materially more implementation
  work: an `IssuerParams`, a `Credential`, and a `BlindedCredential`, plus
  four distinct freshness-critical randomness values, versus one proof and
  one projection for the PLP path. If a future consumer needs selective
  attribute disclosure, revisit; the ownership-only case does not.
